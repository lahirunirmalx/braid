// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_sample.c - br_sample codec unit tests (phase 1b).
 *
 * Written from PROTOCOL.md v0.8 sections 6.1 / 6.2, A.13, SPEC-NOTES N7 and
 * the public header br_sample.h only. Covers:
 *   - LOW quantization (A.13 vector, rounding, clip, INVALID, bad args)
 *   - HIGH / LOW per-channel sample codec, digital and analog channels
 *   - MODE descriptor encode / decode / length and br_mode_check statuses
 *   - DATA header and whole-payload build
 *
 * Every group prints "name: PASS|FAIL (spec line)".
 */
#include <math.h>
#include <string.h>

#include "test_util.h"
#include "vectors_generated.h"
#include "braid/br_sample.h"

#define GROUP_BEGIN(name, cite)                                                \
    unsigned long grp_fail0_ = tu_failed;                                      \
    const char *grp_name_ = (name);                                            \
    const char *grp_cite_ = (cite);                                            \
    tu_ctx(grp_name_)

#define GROUP_END()                                                            \
    printf("%s: %s (%s)\n", grp_name_, tu_failed == grp_fail0_ ? "PASS" : "FAIL", grp_cite_)

/* ------------------------------------------------------------------------- */
/* Builders                                                                   */
/* ------------------------------------------------------------------------- */

static void mode_init(br_mode_t *m, uint8_t mode)
{
    memset(m, 0, sizeof *m);
    m->config_id = 1;
    m->mode = mode;
    m->ch_count = 1;
    m->period = 1;
    m->fec_k = 8;
    m->fec_m = 0;
    m->arq = 1;
    m->flags = BR_MODE_FLAG_PERIOD_MS;
    m->keepalive_ms = 5000;
    m->ch[0].kind = BR_CH_KIND_DIGITAL;
    m->ch[0].fmt = 1;
}

static void ch_analog(br_mode_t *m, unsigned i, uint8_t fmt)
{
    m->ch[i].kind = BR_CH_KIND_ANALOG;
    m->ch[i].fmt = fmt;
    m->ch[i].scale = BRV_A13_SCALE_F;
    m->ch[i].offset = BRV_A13_OFFSET_F;
}

static bool near_f(float a, float b, float tol)
{
    return fabsf(a - b) <= tol;
}

static uint8_t check_status(const br_mode_t *m, size_t max_payload, uint16_t caps)
{
    uint8_t st = 0xEE;
    br_err_t rc = br_mode_check(m, max_payload, caps, &st);
    CHECK_ERR(rc, BR_OK);
    return st;
}

#define CAPS_DEMO (BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY)

/* ------------------------------------------------------------------------- */
/* LOW quantization                                                           */
/* ------------------------------------------------------------------------- */

static void test_a13(void)
{
    GROUP_BEGIN("sample_a13_quantization", "PROTOCOL.md 6.2, A.13");
    for (unsigned i = 0; i < BRV_A13_COUNT; i++) {
        int16_t q = 99;
        uint8_t st = 0xEE;
        CHECK_ERR(br_low_quantize(BRV_A13_VOLTS[i], BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &q, &st), BR_OK);
        CHECK_EQ_U32((uint16_t)q, (uint16_t)BRV_A13_Q[i]);
        CHECK_EQ_U32(st & BR_DATA_ST_CLIP, BRV_A13_CLIP[i] ? BR_DATA_ST_CLIP : 0u);
        CHECK_EQ_U32(st & BR_DATA_ST_INVALID, 0);
        if (!BRV_A13_CLIP[i]) {
            float v = 0.0f;
            bool inv = true;
            CHECK_ERR(br_low_dequantize(q, BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &v, &inv), BR_OK);
            CHECK(!inv);
            CHECK(near_f(v, BRV_A13_VOLTS[i], BRV_A13_SCALE_F));
        }
    }
    GROUP_END();
}

static void test_quantize_edges(void)
{
    GROUP_BEGIN("sample_quantize_edges", "PROTOCOL.md 6.2 (LOW quantization), br_sample.h");
    int16_t q;
    uint8_t st;

    /* Half away from zero (C roundf), scale 1 offset 0. */
    CHECK_ERR(br_low_quantize(0.5f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 1u);
    CHECK_ERR(br_low_quantize(-0.5f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-1);
    CHECK_ERR(br_low_quantize(2.5f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 3u);
    CHECK_ERR(br_low_quantize(-2.5f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-3);
    CHECK_ERR(br_low_quantize(0.4f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 0u);
    CHECK_EQ_U32(st, 0u);

    /* Exactly at the rails: no clip. */
    CHECK_ERR(br_low_quantize(32767.0f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 32767u);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, 0);
    CHECK_ERR(br_low_quantize(-32767.0f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32767);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, 0);
    /* round(32767.4) = 32767: not clamped, no CLIP. */
    CHECK_ERR(br_low_quantize(32767.25f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 32767u);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, 0);
    /* round(32767.5) = 32768: clamped, CLIP. */
    CHECK_ERR(br_low_quantize(32767.5f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 32767u);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, BR_DATA_ST_CLIP);
    CHECK_ERR(br_low_quantize(32768.0f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 32767u);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, BR_DATA_ST_CLIP);
    /* Negative clip never produces -32768 (that is INVALID). */
    CHECK_ERR(br_low_quantize(-32768.0f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32767);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, BR_DATA_ST_CLIP);
    CHECK_EQ_U32(st & BR_DATA_ST_INVALID, 0);
    CHECK_ERR(br_low_quantize(-1.0e9f, 1.0f, 0.0f, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32767);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, BR_DATA_ST_CLIP);

    /* NaN / Inf -> INVALID, q = -32768. */
    CHECK_ERR(br_low_quantize(NAN, BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32768);
    CHECK_EQ_U32(st & BR_DATA_ST_INVALID, BR_DATA_ST_INVALID);
    CHECK_ERR(br_low_quantize(INFINITY, BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32768);
    CHECK_EQ_U32(st & BR_DATA_ST_INVALID, BR_DATA_ST_INVALID);
    CHECK_ERR(br_low_quantize(-INFINITY, BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32768);

    /* Bad arguments. */
    CHECK_ERR(br_low_quantize(1.0f, 1.0f, 0.0f, NULL, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, 1.0f, 0.0f, &q, NULL), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, 0.0f, 0.0f, &q, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, -1.0f, 0.0f, &q, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, NAN, 0.0f, &q, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, INFINITY, 0.0f, &q, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, 1.0f, NAN, &q, &st), BR_ERR_ARG);
    CHECK_ERR(br_low_quantize(1.0f, 1.0f, INFINITY, &q, &st), BR_ERR_ARG);

    /* Dequantize. */
    float v = 0.0f;
    bool inv = false;
    CHECK_ERR(br_low_dequantize(0, 2.0f, 10.0f, &v, &inv), BR_OK);
    CHECK(!inv && near_f(v, 10.0f, 1e-6f));
    CHECK_ERR(br_low_dequantize(100, 2.0f, 10.0f, &v, &inv), BR_OK);
    CHECK(!inv && near_f(v, 210.0f, 1e-4f));
    CHECK_ERR(br_low_dequantize(-100, 2.0f, 10.0f, &v, &inv), BR_OK);
    CHECK(!inv && near_f(v, -190.0f, 1e-4f));
    CHECK_ERR(br_low_dequantize(BR_LOW_Q_INVALID, 2.0f, 10.0f, &v, &inv), BR_OK);
    CHECK(inv);
    CHECK(isnan(v));
    CHECK_ERR(br_low_dequantize(1, 1.0f, 0.0f, NULL, &inv), BR_ERR_ARG);
    CHECK_ERR(br_low_dequantize(1, 1.0f, 0.0f, &v, NULL), BR_ERR_ARG);

    /* Range helper from 6.2: [0, 3.3] -> scale (max-min)/65534, offset mid. */
    float sc = 3.3f / 65534.0f;
    float of = 1.65f;
    CHECK_ERR(br_low_quantize(0.0f, sc, of, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, (uint16_t)-32767);
    CHECK_ERR(br_low_quantize(3.3f, sc, of, &q, &st), BR_OK);
    CHECK_EQ_U32((uint16_t)q, 32767u);
    CHECK_EQ_U32(st & BR_DATA_ST_CLIP, 0);
    GROUP_END();
}

/* ------------------------------------------------------------------------- */
/* Sample codec                                                               */
/* ------------------------------------------------------------------------- */

static void test_digital_button(void)
{
    GROUP_BEGIN("sample_digital_high_low", "PROTOCOL.md 6.2 table (digital), br_sample.h header");
    br_mode_t hi, lo;
    mode_init(&hi, BR_MODE_HIGH);
    mode_init(&lo, BR_MODE_LOW);
    size_t sz = 0;
    CHECK_ERR(br_sample_size(&hi, &sz), BR_OK);
    CHECK_EQ_U32(sz, 4);
    CHECK_ERR(br_sample_size(&lo, &sz), BR_OK);
    CHECK_EQ_U32(sz, 1);

    uint8_t buf[16];
    size_t w = 99;
    uint8_t status = 0;
    br_value_t v;
    br_value_t d;

    for (uint32_t press = 0; press <= 1; press++) {
        memset(&v, 0, sizeof v);
        v.lines = press;
        memset(buf, 0xAA, sizeof buf);
        CHECK_ERR(br_sample_encode(&hi, &v, buf, sizeof buf, &w, &status), BR_OK);
        CHECK_EQ_U32(w, 4);
        CHECK_EQ_U32(buf[0], press);
        CHECK_EQ_U32(buf[1] | buf[2] | buf[3], 0);
        memset(&d, 0xFF, sizeof d);
        CHECK_ERR(br_sample_decode(&hi, buf, w, &d), BR_OK);
        CHECK_EQ_U32(d.lines, press);

        memset(buf, 0xAA, sizeof buf);
        CHECK_ERR(br_sample_encode(&lo, &v, buf, sizeof buf, &w, &status), BR_OK);
        CHECK_EQ_U32(w, 1);
        CHECK_EQ_U32(buf[0], press);
        CHECK_EQ_U32(buf[1], 0xAA); /* nothing written past the sample */
        memset(&d, 0xFF, sizeof d);
        CHECK_ERR(br_sample_decode(&lo, buf, w, &d), BR_OK);
        CHECK_EQ_U32(d.lines, press);
    }
    CHECK_EQ_U32(status, 0);

    /* Bit above the line count is refused on encode (both modes). */
    memset(&v, 0, sizeof v);
    v.lines = 2;
    CHECK_ERR(br_sample_encode(&hi, &v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
    CHECK_ERR(br_sample_encode(&lo, &v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
    /* LOW decode refuses stray bits above the line count. */
    buf[0] = 0x02;
    CHECK_ERR(br_sample_decode(&lo, buf, 1, &d), BR_ERR_DECODE);
    /* Short input / short output. */
    CHECK_ERR(br_sample_decode(&hi, buf, 3, &d), BR_ERR_DECODE);
    CHECK_ERR(br_sample_decode(&lo, buf, 0, &d), BR_ERR_DECODE);
    v.lines = 1;
    CHECK_ERR(br_sample_encode(&hi, &v, buf, 3, &w, &status), BR_ERR_TOO_BIG);
    CHECK_ERR(br_sample_encode(&lo, &v, buf, 0, &w, &status), BR_ERR_TOO_BIG);
    /* NULL arguments. */
    CHECK_ERR(br_sample_encode(NULL, &v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
    CHECK_ERR(br_sample_encode(&hi, NULL, buf, sizeof buf, &w, &status), BR_ERR_ARG);
    CHECK_ERR(br_sample_encode(&hi, &v, NULL, sizeof buf, &w, &status), BR_ERR_ARG);
    CHECK_ERR(br_sample_decode(&hi, NULL, 4, &d), BR_ERR_ARG);
    CHECK_ERR(br_sample_decode(&hi, buf, 4, NULL), BR_ERR_ARG);
    CHECK_ERR(br_sample_size(NULL, &sz), BR_ERR_ARG);
    CHECK_ERR(br_sample_size(&hi, NULL), BR_ERR_ARG);
    GROUP_END();
}

static void test_digital_lines(void)
{
    GROUP_BEGIN("sample_digital_lines", "PROTOCOL.md 6.2 (line i = bit i, LOW ceil(lines/8) bytes)");
    static const struct {
        uint8_t lines;
        size_t low_bytes;
    } cases[] = { { 1, 1 }, { 8, 1 }, { 9, 2 }, { 12, 2 }, { 16, 2 }, { 17, 3 }, { 24, 3 }, { 25, 4 }, { 32, 4 } };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        br_mode_t hi, lo;
        mode_init(&hi, BR_MODE_HIGH);
        mode_init(&lo, BR_MODE_LOW);
        hi.ch[0].fmt = cases[c].lines;
        lo.ch[0].fmt = cases[c].lines;
        size_t sh = 0, sl = 0;
        CHECK_ERR(br_sample_size(&hi, &sh), BR_OK);
        CHECK_ERR(br_sample_size(&lo, &sl), BR_OK);
        CHECK_EQ_U32(sh, 4);
        CHECK_EQ_U32(sl, cases[c].low_bytes);

        uint32_t all = cases[c].lines == 32 ? 0xFFFFFFFFu : ((1u << cases[c].lines) - 1u);
        uint32_t pats[3] = { 0x5A5A5A5Au & all, all, 0x80000001u & all };
        for (int p = 0; p < 3; p++) {
            br_value_t v, d;
            uint8_t buf[8];
            size_t w = 0;
            uint8_t status = 0;
            memset(&v, 0, sizeof v);
            v.lines = pats[p];
            memset(buf, 0, sizeof buf);
            CHECK_ERR(br_sample_encode(&hi, &v, buf, sizeof buf, &w, &status), BR_OK);
            CHECK_EQ_U32(tu_get32(buf), pats[p]); /* u32 LE, line i = bit i */
            memset(&d, 0, sizeof d);
            CHECK_ERR(br_sample_decode(&hi, buf, w, &d), BR_OK);
            CHECK_EQ_U32(d.lines, pats[p]);

            memset(buf, 0, sizeof buf);
            CHECK_ERR(br_sample_encode(&lo, &v, buf, sizeof buf, &w, &status), BR_OK);
            CHECK_EQ_U32(w, cases[c].low_bytes);
            for (size_t i = 0; i < w; i++) {
                CHECK_EQ_U32(buf[i], (pats[p] >> (8u * i)) & 0xFFu); /* byte i/8, bit i%8 */
            }
            memset(&d, 0, sizeof d);
            CHECK_ERR(br_sample_decode(&lo, buf, w, &d), BR_OK);
            CHECK_EQ_U32(d.lines, pats[p]);
        }
        if (cases[c].lines < 32) {
            br_value_t v;
            uint8_t buf[8];
            size_t w;
            uint8_t status = 0;
            memset(&v, 0, sizeof v);
            v.lines = 1u << cases[c].lines;
            CHECK_ERR(br_sample_encode(&hi, &v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
            CHECK_ERR(br_sample_encode(&lo, &v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
        }
    }
    /* Invalid channel descriptions. */
    br_mode_t m;
    size_t sz;
    mode_init(&m, BR_MODE_HIGH);
    m.ch[0].fmt = 0;
    CHECK_ERR(br_sample_size(&m, &sz), BR_ERR_ARG);
    m.ch[0].fmt = 33;
    CHECK_ERR(br_sample_size(&m, &sz), BR_ERR_ARG);
    m.ch[0].fmt = 1;
    m.ch[0].kind = 7;
    CHECK_ERR(br_sample_size(&m, &sz), BR_ERR_ARG);
    mode_init(&m, BR_MODE_BULK);
    CHECK_ERR(br_sample_size(&m, &sz), BR_ERR_ARG);
    GROUP_END();
}

static void test_analog(void)
{
    GROUP_BEGIN("sample_analog_high_low", "PROTOCOL.md 6.2 table (analog), A.13");
    br_mode_t hi, lo;
    mode_init(&hi, BR_MODE_HIGH);
    mode_init(&lo, BR_MODE_LOW);
    hi.ch_count = lo.ch_count = 4;
    hi.ch[0].kind = lo.ch[0].kind = BR_CH_KIND_DIGITAL;
    hi.ch[0].fmt = lo.ch[0].fmt = 3;
    ch_analog(&hi, 1, BR_CH_FMT_F32);
    ch_analog(&lo, 1, BR_CH_FMT_F32);
    ch_analog(&hi, 2, BR_CH_FMT_U32);
    ch_analog(&lo, 2, BR_CH_FMT_U32);
    ch_analog(&hi, 3, BR_CH_FMT_I32);
    ch_analog(&lo, 3, BR_CH_FMT_I32);
    size_t sh = 0, sl = 0;
    CHECK_ERR(br_sample_size(&hi, &sh), BR_OK);
    CHECK_ERR(br_sample_size(&lo, &sl), BR_OK);
    CHECK_EQ_U32(sh, 16);  /* 4 bytes per channel in HIGH */
    CHECK_EQ_U32(sl, 7);   /* digital 3 lines = 1 byte, analog 2 bytes each in LOW */

    br_value_t v[4], d[4];
    uint8_t buf[32];
    size_t w = 0;
    uint8_t status = 0;
    memset(v, 0, sizeof v);
    v[0].lines = 5;
    v[1].f32 = 1.5f;
    v[2].u32 = 0xDEADBEEFu;
    v[3].i32 = -123456;
    CHECK_ERR(br_sample_encode(&hi, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_EQ_U32(w, 16);
    CHECK_EQ_U32(tu_get32(buf), 5);
    float f;
    uint32_t bits = tu_get32(buf + 4);
    memcpy(&f, &bits, sizeof f);
    CHECK(near_f(f, 1.5f, 0.0f));
    CHECK_EQ_U32(tu_get32(buf + 8), 0xDEADBEEFu);
    CHECK_EQ_U32(tu_get32(buf + 12), (uint32_t)-123456);
    memset(d, 0, sizeof d);
    CHECK_ERR(br_sample_decode(&hi, buf, w, d), BR_OK);
    CHECK_EQ_U32(d[0].lines, 5);
    CHECK(near_f(d[1].f32, 1.5f, 0.0f));
    CHECK_EQ_U32(d[2].u32, 0xDEADBEEFu);
    CHECK_EQ_U32((uint32_t)d[3].i32, (uint32_t)-123456);
    CHECK_EQ_U32(status, 0);

    /* HIGH float32: NaN / Inf pass through unflagged. */
    v[1].f32 = INFINITY;
    CHECK_ERR(br_sample_encode(&hi, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_EQ_U32(status, 0);
    CHECK_ERR(br_sample_decode(&hi, buf, w, d), BR_OK);
    CHECK(isinf(d[1].f32));
    v[1].f32 = NAN;
    CHECK_ERR(br_sample_encode(&hi, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_ERR(br_sample_decode(&hi, buf, w, d), BR_OK);
    CHECK(isnan(d[1].f32));

    /* LOW: float32 / u32 / i32 channels are quantized (value converted to float first). */
    memset(v, 0, sizeof v);
    v[0].lines = 4;
    v[1].f32 = 3.30f;    /* A.13: -> 32767 */
    v[2].u32 = 1;        /* (1 - 1.65) / scale -> about -12907 */
    v[3].i32 = 4;        /* clips */
    status = 0;
    CHECK_ERR(br_sample_encode(&lo, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_EQ_U32(w, 7);
    CHECK_EQ_U32(buf[0], 4);
    CHECK_EQ_U32(tu_get16(buf + 1), 32767u);
    int16_t q2 = 0;
    uint8_t s2 = 0;
    CHECK_ERR(br_low_quantize(1.0f, BRV_A13_SCALE_F, BRV_A13_OFFSET_F, &q2, &s2), BR_OK);
    CHECK_EQ_U32(tu_get16(buf + 3), (uint16_t)q2);
    CHECK_EQ_U32(tu_get16(buf + 5), 32767u);
    CHECK_EQ_U32(status & BR_DATA_ST_CLIP, BR_DATA_ST_CLIP);  /* 4.0 clipped */
    CHECK_EQ_U32(status & BR_DATA_ST_INVALID, 0);
    memset(d, 0, sizeof d);
    CHECK_ERR(br_sample_decode(&lo, buf, w, d), BR_OK);
    CHECK_EQ_U32(d[0].lines, 4);
    CHECK(near_f(d[1].f32, 3.30f, 2.0f * BRV_A13_SCALE_F));
    CHECK(near_f(d[2].f32, 1.0f, 2.0f * BRV_A13_SCALE_F));

    /* LOW float32 NaN -> INVALID flag and q = -32768, decoded as NaN. */
    memset(v, 0, sizeof v);
    v[1].f32 = NAN;
    status = 0;
    CHECK_ERR(br_sample_encode(&lo, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_EQ_U32(status & BR_DATA_ST_INVALID, BR_DATA_ST_INVALID);
    CHECK_EQ_U32(tu_get16(buf + 1), 0x8000u);
    CHECK_ERR(br_sample_decode(&lo, buf, w, d), BR_OK);
    CHECK(isnan(d[1].f32));

    /* status_io is OR-ed: a pre-set bit survives. */
    memset(v, 0, sizeof v);
    v[1].f32 = 1.65f;
    status = BR_DATA_ST_OVERRUN;
    CHECK_ERR(br_sample_encode(&lo, v, buf, sizeof buf, &w, &status), BR_OK);
    CHECK_EQ_U32(status, BR_DATA_ST_OVERRUN);
    CHECK_EQ_U32(tu_get16(buf + 1), 0u);

    /* BULK is not a sample mode. */
    br_mode_t bk;
    mode_init(&bk, BR_MODE_BULK);
    CHECK_ERR(br_sample_encode(&bk, v, buf, sizeof buf, &w, &status), BR_ERR_ARG);
    CHECK_ERR(br_sample_decode(&bk, buf, 4, d), BR_ERR_ARG);
    GROUP_END();
}

static void test_max_per_frame(void)
{
    GROUP_BEGIN("sample_max_per_frame", "PROTOCOL.md 6.1 (one sample must fit), 6.2, 3.3");
    br_mode_t hi, lo;
    mode_init(&hi, BR_MODE_HIGH);
    mode_init(&lo, BR_MODE_LOW);
    uint8_t n = 0;
    CHECK_ERR(br_sample_max_per_frame(&hi, 217, &n), BR_OK);
    CHECK_EQ_U32(n, (217u - 7u) / 4u);
    CHECK_ERR(br_sample_max_per_frame(&lo, 217, &n), BR_OK);
    CHECK_EQ_U32(n, 210);
    CHECK_ERR(br_sample_max_per_frame(&lo, 300, &n), BR_OK);
    CHECK_EQ_U32(n, 255); /* capped */
    CHECK_ERR(br_sample_max_per_frame(&hi, 11, &n), BR_OK);
    CHECK_EQ_U32(n, 1);
    CHECK_ERR(br_sample_max_per_frame(&hi, 10, &n), BR_ERR_TOO_BIG);
    CHECK_ERR(br_sample_max_per_frame(&hi, 3, &n), BR_ERR_TOO_BIG);
    /* FEC reserve. */
    hi.fec_m = 2;
    CHECK_ERR(br_sample_max_per_frame(&hi, 217, &n), BR_OK);
    CHECK_EQ_U32(n, (217u - BR_FEC_PAYLOAD_RESERVE - 7u) / 4u);
    CHECK_ERR(br_sample_max_per_frame(NULL, 217, &n), BR_ERR_ARG);
    CHECK_ERR(br_sample_max_per_frame(&hi, 217, NULL), BR_ERR_ARG);
    GROUP_END();
}

/* ------------------------------------------------------------------------- */
/* MODE descriptor                                                            */
/* ------------------------------------------------------------------------- */

static void test_mode_encode_layout(void)
{
    GROUP_BEGIN("mode_encode_layout", "PROTOCOL.md 6.1 (field order, LE, lengths)");
    br_mode_t m;
    mode_init(&m, BR_MODE_HIGH);
    m.config_id = 7;
    m.period = 1000;
    m.keepalive_ms = 5000;
    size_t len = 0;
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 15);
    uint8_t out[BR_MODE_MAX_LEN + 8];
    size_t w = 0;
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    CHECK_EQ_U32(w, 15);
    static const uint8_t exp[15] = { 0x07, 0x00, 0x01, 0xE8, 0x03, 0x00, 0x00, 0x08, 0x00, 0x01,
                                     0x01, 0x88, 0x13, 0x00, 0x01 };
    CHECK_MEM(exp, out, 15);

    /* LOW analog channel appends scale f32 + offset f32 (LE). */
    mode_init(&m, BR_MODE_LOW);
    m.config_id = 2;
    ch_analog(&m, 0, BR_CH_FMT_F32);
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 13u + 2u + 8u);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    CHECK_EQ_U32(w, 23);
    CHECK_EQ_U32(out[13], BR_CH_KIND_ANALOG);
    CHECK_EQ_U32(out[14], BR_CH_FMT_F32);
    uint32_t sbits, obits;
    memcpy(&sbits, &m.ch[0].scale, 4);
    memcpy(&obits, &m.ch[0].offset, 4);
    CHECK_EQ_U32(tu_get32(out + 15), sbits);
    CHECK_EQ_U32(tu_get32(out + 19), obits);

    /* LOW digital: no scale / offset. */
    mode_init(&m, BR_MODE_LOW);
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 15);
    /* HIGH analog: no scale / offset either. */
    mode_init(&m, BR_MODE_HIGH);
    ch_analog(&m, 0, BR_CH_FMT_U32);
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 15);

    /* 16 LOW analog channels: 13 + 16 x 10 = 173 = BR_MODE_MAX_LEN. */
    mode_init(&m, BR_MODE_LOW);
    m.ch_count = 16;
    for (unsigned i = 0; i < 16; i++) {
        ch_analog(&m, i, BR_CH_FMT_F32);
    }
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 173);
    CHECK_EQ_U32(BR_MODE_MAX_LEN, 173);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    CHECK_EQ_U32(w, 173);
    CHECK_ERR(br_mode_encode(&m, out, 172, &w), BR_ERR_TOO_BIG);
    m.ch_count = 17;
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_ERR_ARG);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_ERR_ARG);

    /* BULK: 13 + 40, ch_count 0, size u32 | sha256 | fw_build u32. */
    mode_init(&m, BR_MODE_BULK);
    m.ch_count = 0;
    m.bulk.size = 0x01020304u;
    for (unsigned i = 0; i < 32; i++) {
        m.bulk.sha256[i] = (uint8_t)(0xA0u + i);
    }
    m.bulk.fw_build = 0x0A0B0C0Du;
    CHECK_ERR(br_mode_encoded_len(&m, &len), BR_OK);
    CHECK_EQ_U32(len, 53);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    CHECK_EQ_U32(w, 53);
    CHECK_EQ_U32(out[1], BR_MODE_BULK);
    CHECK_EQ_U32(out[2], 0);
    CHECK_EQ_U32(tu_get32(out + 13), 0x01020304u);
    CHECK_EQ_U32(out[17], 0xA0);
    CHECK_EQ_U32(out[48], 0xBF);
    CHECK_EQ_U32(tu_get32(out + 49), 0x0A0B0C0Du);

    CHECK_ERR(br_mode_encoded_len(NULL, &len), BR_ERR_ARG);
    CHECK_ERR(br_mode_encoded_len(&m, NULL), BR_ERR_ARG);
    CHECK_ERR(br_mode_encode(NULL, out, sizeof out, &w), BR_ERR_ARG);
    CHECK_ERR(br_mode_encode(&m, NULL, sizeof out, &w), BR_ERR_ARG);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, NULL), BR_ERR_ARG);
    GROUP_END();
}

static void test_mode_roundtrip(void)
{
    GROUP_BEGIN("mode_roundtrip", "PROTOCOL.md 6.1, 3.6 line 302, SPEC-NOTES N7");
    br_mode_t m, r;
    uint8_t out[BR_MODE_MAX_LEN];
    size_t w = 0;
    uint8_t st = 0xEE;

    /* Demo mode: HIGH, 1 digital line. */
    mode_init(&m, BR_MODE_HIGH);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    memset(&r, 0xCC, sizeof r);
    CHECK_ERR(br_mode_decode(out, w, 217, CAPS_DEMO, &r, &st), BR_OK);
    CHECK_EQ_U32(st, BR_MODE_ACK_OK);
    CHECK_EQ_U32(r.config_id, 1);
    CHECK_EQ_U32(r.mode, BR_MODE_HIGH);
    CHECK_EQ_U32(r.ch_count, 1);
    CHECK_EQ_U32(r.period, 1);
    CHECK_EQ_U32(r.arq, 1);
    CHECK_EQ_U32(r.fec_m, 0);
    CHECK_EQ_U32(r.flags, BR_MODE_FLAG_PERIOD_MS);
    CHECK_EQ_U32(r.keepalive_ms, 5000);
    CHECK_EQ_U32(r.ch[0].kind, BR_CH_KIND_DIGITAL);
    CHECK_EQ_U32(r.ch[0].fmt, 1);

    /* Mixed LOW mode with FEC. */
    mode_init(&m, BR_MODE_LOW);
    m.config_id = 200;
    m.ch_count = 3;
    m.period = 123456;
    m.flags = 0; /* us */
    m.fec_k = 8;
    m.fec_m = 2;
    m.arq = 0;
    m.keepalive_ms = 1000;
    m.ch[0].kind = BR_CH_KIND_DIGITAL;
    m.ch[0].fmt = 12;
    ch_analog(&m, 1, BR_CH_FMT_F32);
    m.ch[2].kind = BR_CH_KIND_ANALOG;
    m.ch[2].fmt = BR_CH_FMT_I32;
    m.ch[2].scale = 0.25f;
    m.ch[2].offset = -3.0f;
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    CHECK_EQ_U32(w, 13u + 2u + 10u + 10u);
    memset(&r, 0xCC, sizeof r);
    CHECK_ERR(br_mode_decode(out, w, 217, CAPS_DEMO | BR_CAP_FEC, &r, &st), BR_OK);
    CHECK_EQ_U32(st, BR_MODE_ACK_OK);
    CHECK_EQ_U32(r.config_id, 200);
    CHECK_EQ_U32(r.mode, BR_MODE_LOW);
    CHECK_EQ_U32(r.ch_count, 3);
    CHECK_EQ_U32(r.period, 123456);
    CHECK_EQ_U32(r.fec_k, 8);
    CHECK_EQ_U32(r.fec_m, 2);
    CHECK_EQ_U32(r.arq, 0);
    CHECK_EQ_U32(r.flags, 0);
    CHECK_EQ_U32(r.keepalive_ms, 1000);
    CHECK_EQ_U32(r.ch[0].fmt, 12);
    CHECK_EQ_U32(r.ch[1].kind, BR_CH_KIND_ANALOG);
    CHECK_EQ_U32(r.ch[1].fmt, BR_CH_FMT_F32);
    CHECK(near_f(r.ch[1].scale, BRV_A13_SCALE_F, 0.0f));
    CHECK(near_f(r.ch[1].offset, 1.65f, 0.0f));
    CHECK_EQ_U32(r.ch[2].fmt, BR_CH_FMT_I32);
    CHECK(near_f(r.ch[2].scale, 0.25f, 0.0f));
    CHECK(near_f(r.ch[2].offset, -3.0f, 0.0f));

    /* BULK. */
    mode_init(&m, BR_MODE_BULK);
    m.ch_count = 0;
    m.bulk.size = 4096;
    m.bulk.fw_build = 77;
    memset(m.bulk.sha256, 0x5C, 32);
    CHECK_ERR(br_mode_encode(&m, out, sizeof out, &w), BR_OK);
    memset(&r, 0xCC, sizeof r);
    CHECK_ERR(br_mode_decode(out, w, 217, CAPS_DEMO, &r, &st), BR_OK);
    CHECK_EQ_U32(st, BR_MODE_ACK_OK);
    CHECK_EQ_U32(r.mode, BR_MODE_BULK);
    CHECK_EQ_U32(r.bulk.size, 4096);
    CHECK_EQ_U32(r.bulk.fw_build, 77);
    CHECK_MEM(m.bulk.sha256, r.bulk.sha256, 32);

    /* NULL arguments. */
    CHECK_ERR(br_mode_decode(NULL, 15, 217, CAPS_DEMO, &r, &st), BR_ERR_ARG);
    CHECK_ERR(br_mode_decode(out, 15, 217, CAPS_DEMO, NULL, &st), BR_ERR_ARG);
    CHECK_ERR(br_mode_decode(out, 15, 217, CAPS_DEMO, &r, NULL), BR_ERR_ARG);
    GROUP_END();
}

static void dec_expect(const br_mode_t *m, size_t cut_or_pad, bool pad, uint8_t want_status, int line)
{
    uint8_t buf[BR_MODE_MAX_LEN + 8];
    size_t w = 0;
    br_mode_t r;
    uint8_t st = 0xEE;
    if (br_mode_encode(m, buf, sizeof buf - 1, &w) != BR_OK) {
        tu_checks++;
        if (tu_begin_fail(__FILE__, line)) {
            fprintf(stderr, "encode of the case descriptor failed\n");
        }
        return;
    }
    size_t len = w;
    if (pad) {
        buf[w] = 0;
        len = w + cut_or_pad;
    } else {
        len = w - cut_or_pad;
    }
    br_err_t rc = br_mode_decode(buf, len, 217, CAPS_DEMO, &r, &st);
    tu_checks++;
    br_err_t want_rc = want_status == BR_MODE_ACK_OK ? BR_OK : BR_ERR_REJECT;
    if (rc != want_rc || st != want_status) {
        if (tu_begin_fail(__FILE__, line)) {
            fprintf(stderr, "decode: rc %s status %u, expected rc %s status %u\n", tu_err_name(rc), (unsigned)st,
                    tu_err_name(want_rc), (unsigned)want_status);
        }
    }
}

static void test_mode_decode_errors(void)
{
    GROUP_BEGIN("mode_decode_errors", "PROTOCOL.md 6.1, 3.6 line 302, SPEC-NOTES N7 (MODE_ACK 1/2/3, no bad_frame)");
    br_mode_t m;
    uint8_t buf[BR_MODE_MAX_LEN];
    size_t w = 0;
    br_mode_t r;
    uint8_t st;

    mode_init(&m, BR_MODE_HIGH);
    CHECK_ERR(br_mode_encode(&m, buf, sizeof buf, &w), BR_OK);

    /* Length problems -> BAD_ARG (3), never a frame-level error. */
    for (size_t l = 0; l < BR_LEN_MODE_FIXED; l++) {
        st = 0xEE;
        CHECK_ERR(br_mode_decode(buf, l, 217, CAPS_DEMO, &r, &st), BR_ERR_REJECT);
        CHECK_EQ_U32(st, BR_MODE_ACK_BAD_ARG);
    }
    dec_expect(&m, 1, false, BR_MODE_ACK_BAD_ARG, __LINE__);  /* descriptor truncated */
    dec_expect(&m, 1, true, BR_MODE_ACK_BAD_ARG, __LINE__);   /* trailing byte */

    /* config_id 0. */
    m.config_id = 0;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    mode_init(&m, BR_MODE_HIGH);

    /* Unknown mode -> UNSUPPORTED (1). */
    m.mode = 3;
    dec_expect(&m, 0, false, BR_MODE_ACK_UNSUPPORTED, __LINE__);
    mode_init(&m, BR_MODE_HIGH);

    /* ch_count 0 outside mode 2 -> BAD_ARG. */
    m.ch_count = 0;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    mode_init(&m, BR_MODE_LOW);
    m.ch_count = 0;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);

    /* Channel descriptor values. */
    mode_init(&m, BR_MODE_HIGH);
    m.ch[0].kind = 2;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    mode_init(&m, BR_MODE_HIGH);
    m.ch[0].fmt = 0;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.ch[0].fmt = 33;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.ch[0].fmt = 32;
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);
    mode_init(&m, BR_MODE_HIGH);
    ch_analog(&m, 0, 3);
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    ch_analog(&m, 0, 2);
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);

    /* FEC fields. */
    mode_init(&m, BR_MODE_HIGH);
    m.fec_m = 5;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.fec_m = 2;
    m.fec_k = 1;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.fec_k = 17;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.fec_m = 0;
    m.fec_k = 0; /* ignored when fec_m == 0 */
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);

    /* arq, flags, keepalive. */
    mode_init(&m, BR_MODE_HIGH);
    m.arq = 2;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    mode_init(&m, BR_MODE_HIGH);
    m.flags = 0x03;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.flags = 0x80;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    mode_init(&m, BR_MODE_HIGH);
    m.keepalive_ms = 999;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.keepalive_ms = 60001;
    dec_expect(&m, 0, false, BR_MODE_ACK_BAD_ARG, __LINE__);
    m.keepalive_ms = 1000;
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);
    m.keepalive_ms = 60000;
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);

    /* BULK needs ch_count 0. */
    mode_init(&m, BR_MODE_BULK);
    m.ch_count = 0;
    dec_expect(&m, 0, false, BR_MODE_ACK_OK, __LINE__);
    m.ch_count = 1;
    {
        /* Encode refuses nothing here (descriptor only), decode must not accept ch_count 1 in mode 2. */
        uint8_t b2[BR_MODE_MAX_LEN];
        size_t w2 = 0;
        if (br_mode_encode(&m, b2, sizeof b2, &w2) == BR_OK) {
            st = 0xEE;
            br_err_t rc = br_mode_decode(b2, w2, 217, CAPS_DEMO, &r, &st);
            CHECK(rc != BR_OK);
            CHECK_EQ_U32(st, BR_MODE_ACK_BAD_ARG);
        }
    }

    /* Capability gap: FEC requested from a probe without FEC -> UNSUPPORTED (1). */
    mode_init(&m, BR_MODE_HIGH);
    m.fec_m = 2;
    m.fec_k = 8;
    CHECK_ERR(br_mode_encode(&m, buf, sizeof buf, &w), BR_OK);
    st = 0xEE;
    CHECK_ERR(br_mode_decode(buf, w, 217, CAPS_DEMO, &r, &st), BR_ERR_REJECT);
    CHECK_EQ_U32(st, BR_MODE_ACK_UNSUPPORTED);
    st = 0xEE;
    CHECK_ERR(br_mode_decode(buf, w, 217, CAPS_DEMO | BR_CAP_FEC, &r, &st), BR_OK);
    CHECK_EQ_U32(st, BR_MODE_ACK_OK);
    GROUP_END();
}

static void test_mode_check(void)
{
    GROUP_BEGIN("mode_check_statuses", "PROTOCOL.md 6.1 (MODE_ACK status 0 ok, 1 unsupported, 2 too big, 3 bad arg)");
    br_mode_t m;
    mode_init(&m, BR_MODE_HIGH);
    CHECK_EQ_U32(check_status(&m, 217, CAPS_DEMO), BR_MODE_ACK_OK);

    /* BAD_ARG (3). */
    br_mode_t b = m;
    b.config_id = 0;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.ch_count = 0;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.ch_count = 17;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.ch[0].kind = 5;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.ch[0].fmt = 0;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.ch[0].fmt = 33;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.fec_m = 5;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO | BR_CAP_FEC), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.fec_m = 1;
    b.fec_k = 1;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO | BR_CAP_FEC), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.arq = 3;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.flags = 0x04;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);
    b = m;
    b.keepalive_ms = 500;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_BAD_ARG);

    /* UNSUPPORTED (1). */
    b = m;
    b.mode = 9;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_UNSUPPORTED);
    b = m;
    b.fec_m = 2;
    b.fec_k = 8;
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_UNSUPPORTED);
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO | BR_CAP_FEC), BR_MODE_ACK_OK);

    /* TOO_BIG (2): the encoded MODE must fit max_payload (15 bytes here) ... */
    CHECK_EQ_U32(check_status(&m, 15, CAPS_DEMO), BR_MODE_ACK_OK);
    CHECK_EQ_U32(check_status(&m, 14, CAPS_DEMO), BR_MODE_ACK_TOO_BIG);
    /* ... and one complete sample must fit a DATA frame (7 + size <= max_payload): 16 HIGH digital channels need
     * 7 + 64 = 71 bytes while their MODE is only 13 + 32 = 45. */
    b = m;
    b.ch_count = 16;
    for (unsigned i = 0; i < 16; i++) {
        b.ch[i].kind = BR_CH_KIND_DIGITAL;
        b.ch[i].fmt = 1;
    }
    CHECK_EQ_U32(check_status(&b, 71, CAPS_DEMO), BR_MODE_ACK_OK);
    CHECK_EQ_U32(check_status(&b, 70, CAPS_DEMO), BR_MODE_ACK_TOO_BIG);
    b.fec_m = 2;
    b.fec_k = 8;
    /* with FEC the DATA payload cap shrinks by BR_FEC_PAYLOAD_RESERVE */
    CHECK_EQ_U32(check_status(&b, 71u + BR_FEC_PAYLOAD_RESERVE, CAPS_DEMO | BR_CAP_FEC), BR_MODE_ACK_OK);
    CHECK_EQ_U32(check_status(&b, 70u + BR_FEC_PAYLOAD_RESERVE, CAPS_DEMO | BR_CAP_FEC), BR_MODE_ACK_TOO_BIG);
    /* The encoded MODE must fit too: 16 LOW analog channels need 173 bytes. */
    b = m;
    b.mode = BR_MODE_LOW;
    b.ch_count = 16;
    for (unsigned i = 0; i < 16; i++) {
        ch_analog(&b, i, BR_CH_FMT_F32);
    }
    CHECK_EQ_U32(check_status(&b, 217, CAPS_DEMO), BR_MODE_ACK_OK);
    CHECK_EQ_U32(check_status(&b, 173, CAPS_DEMO), BR_MODE_ACK_OK);
    CHECK_EQ_U32(check_status(&b, 172, CAPS_DEMO), BR_MODE_ACK_TOO_BIG);
    CHECK_EQ_U32(check_status(&b, 100, CAPS_DEMO), BR_MODE_ACK_TOO_BIG);

    /* IR example from 6.1: max payload 41 fits two LOW analog channels (33 bytes). */
    b = m;
    b.mode = BR_MODE_LOW;
    b.ch_count = 2;
    ch_analog(&b, 0, BR_CH_FMT_F32);
    ch_analog(&b, 1, BR_CH_FMT_F32);
    CHECK_EQ_U32(check_status(&b, 41, CAPS_DEMO), BR_MODE_ACK_OK);
    b.ch_count = 3;
    ch_analog(&b, 2, BR_CH_FMT_F32);
    CHECK_EQ_U32(check_status(&b, 41, CAPS_DEMO), BR_MODE_ACK_TOO_BIG);

    uint8_t st;
    CHECK_ERR(br_mode_check(NULL, 217, CAPS_DEMO, &st), BR_ERR_ARG);
    CHECK_ERR(br_mode_check(&m, 217, CAPS_DEMO, NULL), BR_ERR_ARG);
    GROUP_END();
}

/* ------------------------------------------------------------------------- */
/* DATA payload                                                               */
/* ------------------------------------------------------------------------- */

static void test_data_hdr(void)
{
    GROUP_BEGIN("data_header_and_build", "PROTOCOL.md 6.2 (DATA payload), 3.6 DATA row");
    br_data_hdr_t h;
    memset(&h, 0, sizeof h);
    h.config_id = 9;
    h.status = BR_DATA_ST_OVERRUN;
    h.t_first_us = 0x11223344u;
    h.n_samples = 2;
    uint8_t out[64];
    CHECK_ERR(br_data_hdr_encode(&h, out, sizeof out), BR_OK);
    static const uint8_t exp[7] = { 0x09, 0x02, 0x44, 0x33, 0x22, 0x11, 0x02 };
    CHECK_MEM(exp, out, 7);
    CHECK_ERR(br_data_hdr_encode(&h, out, 6), BR_ERR_TOO_BIG);
    h.n_samples = 0;
    CHECK_ERR(br_data_hdr_encode(&h, out, sizeof out), BR_ERR_ARG);
    CHECK_ERR(br_data_hdr_encode(NULL, out, sizeof out), BR_ERR_ARG);
    h.n_samples = 2;
    CHECK_ERR(br_data_hdr_encode(&h, NULL, sizeof out), BR_ERR_ARG);

    br_mode_t hi, lo;
    mode_init(&hi, BR_MODE_HIGH);
    mode_init(&lo, BR_MODE_LOW);
    hi.config_id = lo.config_id = 9;

    /* Decode with length check against the mode: 7 + n x size. */
    uint8_t pl[64];
    memset(pl, 0, sizeof pl);
    memcpy(pl, exp, 7);
    br_data_hdr_t d;
    memset(&d, 0, sizeof d);
    CHECK_ERR(br_data_hdr_decode(pl, 7 + 2 * 4, &hi, &d), BR_OK);
    CHECK_EQ_U32(d.config_id, 9);
    CHECK_EQ_U32(d.status, BR_DATA_ST_OVERRUN);
    CHECK_EQ_U32(d.t_first_us, 0x11223344u);
    CHECK_EQ_U32(d.n_samples, 2);
    CHECK_ERR(br_data_hdr_decode(pl, 7 + 2 * 4 - 1, &hi, &d), BR_ERR_DECODE);
    CHECK_ERR(br_data_hdr_decode(pl, 7 + 2 * 4 + 1, &hi, &d), BR_ERR_DECODE);
    CHECK_ERR(br_data_hdr_decode(pl, 7 + 2 * 1, &lo, &d), BR_OK);
    CHECK_ERR(br_data_hdr_decode(pl, 7 + 2 * 4, &lo, &d), BR_ERR_DECODE);
    CHECK_ERR(br_data_hdr_decode(pl, 6, &hi, &d), BR_ERR_DECODE);
    CHECK_ERR(br_data_hdr_decode(pl, 0, NULL, &d), BR_ERR_DECODE);
    /* mode NULL skips the length check. */
    CHECK_ERR(br_data_hdr_decode(pl, 7, NULL, &d), BR_OK);
    CHECK_ERR(br_data_hdr_decode(pl, 40, NULL, &d), BR_OK);
    /* n_samples 0 is malformed. */
    pl[6] = 0;
    CHECK_ERR(br_data_hdr_decode(pl, 7, &hi, &d), BR_ERR_DECODE);
    CHECK_ERR(br_data_hdr_decode(NULL, 7, &hi, &d), BR_ERR_ARG);
    CHECK_ERR(br_data_hdr_decode(pl, 7, &hi, NULL), BR_ERR_ARG);

    /* br_data_build: header + samples, sample-major. */
    br_value_t v[2];
    memset(v, 0, sizeof v);
    v[0].lines = 1;
    v[1].lines = 0;
    memset(&h, 0, sizeof h);
    h.config_id = 9;
    h.t_first_us = 1000;
    h.n_samples = 2;
    size_t w = 0;
    uint8_t st_out = 0xEE;
    CHECK_ERR(br_data_build(&hi, &h, v, out, sizeof out, &w, &st_out), BR_OK);
    CHECK_EQ_U32(w, 15);
    CHECK_EQ_U32(st_out, 0);
    CHECK_EQ_U32(out[0], 9);
    CHECK_EQ_U32(out[1], 0);
    CHECK_EQ_U32(tu_get32(out + 2), 1000);
    CHECK_EQ_U32(out[6], 2);
    CHECK_EQ_U32(tu_get32(out + 7), 1);
    CHECK_EQ_U32(tu_get32(out + 11), 0);
    CHECK_ERR(br_data_hdr_decode(out, w, &hi, &d), BR_OK);

    CHECK_ERR(br_data_build(&lo, &h, v, out, sizeof out, &w, NULL), BR_OK);
    CHECK_EQ_U32(w, 9);
    CHECK_EQ_U32(out[7], 1);
    CHECK_EQ_U32(out[8], 0);

    CHECK_ERR(br_data_build(&hi, &h, v, out, 14, &w, NULL), BR_ERR_TOO_BIG);
    CHECK_ERR(br_data_build(&hi, &h, v, out, 15, &w, NULL), BR_OK);
    h.config_id = 8; /* must equal mode->config_id */
    CHECK_ERR(br_data_build(&hi, &h, v, out, sizeof out, &w, NULL), BR_ERR_ARG);
    h.config_id = 9;
    h.n_samples = 0;
    CHECK_ERR(br_data_build(&hi, &h, v, out, sizeof out, &w, NULL), BR_ERR_ARG);
    h.n_samples = 2;
    CHECK_ERR(br_data_build(NULL, &h, v, out, sizeof out, &w, NULL), BR_ERR_ARG);
    CHECK_ERR(br_data_build(&hi, NULL, v, out, sizeof out, &w, NULL), BR_ERR_ARG);
    CHECK_ERR(br_data_build(&hi, &h, NULL, out, sizeof out, &w, NULL), BR_ERR_ARG);

    /* Status is the header status OR-ed with CLIP / INVALID raised while encoding (A.13: 4.00 V clips). */
    br_mode_t an;
    mode_init(&an, BR_MODE_LOW);
    an.config_id = 9;
    ch_analog(&an, 0, BR_CH_FMT_F32);
    br_value_t av[3];
    memset(av, 0, sizeof av);
    av[0].f32 = 1.65f;
    av[1].f32 = 4.00f;
    av[2].f32 = NAN;
    memset(&h, 0, sizeof h);
    h.config_id = 9;
    h.status = BR_DATA_ST_UNSYNCED;
    h.n_samples = 3;
    CHECK_ERR(br_data_build(&an, &h, av, out, sizeof out, &w, &st_out), BR_OK);
    CHECK_EQ_U32(w, 7u + 3u * 2u);
    CHECK_EQ_U32(st_out, BR_DATA_ST_UNSYNCED | BR_DATA_ST_CLIP | BR_DATA_ST_INVALID);
    CHECK_EQ_U32(out[1], st_out);
    CHECK_EQ_U32(tu_get16(out + 7), 0u);
    CHECK_EQ_U32(tu_get16(out + 9), 32767u);
    CHECK_EQ_U32(tu_get16(out + 11), 0x8000u);
    GROUP_END();
}

int main(void)
{
    test_a13();
    test_quantize_edges();
    test_digital_button();
    test_digital_lines();
    test_analog();
    test_max_per_frame();
    test_mode_encode_layout();
    test_mode_roundtrip();
    test_mode_decode_errors();
    test_mode_check();
    test_data_hdr();
    return tu_summary("test_sample");
}
