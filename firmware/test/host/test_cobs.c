// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_cobs.c - COBS (spec 1.2 UART row, 3.2, A.3; SPEC-NOTES N11).
 *
 * N11: br_cobs_encode() writes the trailing 0x00 delimiter; br_cobs_decode()
 * accepts its input with or without that final delimiter.
 */
#include "braid/br_cobs.h"
#include "test_util.h"
#include "test_vectab.h"

static void enc_expect(const uint8_t *in, size_t n, const uint8_t *exp, size_t exp_len, const char *name)
{
    uint8_t out[600];
    size_t out_len = 12345;
    tu_ctx(name);
    CHECK_ERR(br_cobs_encode(in, n, out, sizeof out, &out_len), BR_OK);
    CHECK_EQ_U32(out_len, exp_len);
    if (out_len == exp_len) {
        CHECK_MEM(exp, out, exp_len);
    }
    /* decode both with and without the delimiter */
    uint8_t back[600];
    size_t back_len = 99999;
    CHECK_ERR(br_cobs_decode(exp, exp_len, back, sizeof back, &back_len), BR_OK);
    CHECK_EQ_U32(back_len, n);
    if (back_len == n) {
        CHECK_MEM(in, back, n);
    }
    back_len = 99999;
    CHECK_ERR(br_cobs_decode(exp, exp_len - 1u, back, sizeof back, &back_len), BR_OK);
    CHECK_EQ_U32(back_len, n);
    if (back_len == n) {
        CHECK_MEM(in, back, n);
    }
}

static void test_a3(void)
{
    tu_ctx("A.3 COBS vector");
    uint8_t out[128];
    size_t out_len = 0;
    CHECK_ERR(br_cobs_encode(BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, out, sizeof out, &out_len), BR_OK);
    CHECK_EQ_U32(out_len, BRV_A3_COBS_WIRE_LEN); /* 52 = 1 code + 50 + delimiter (N11) */
    CHECK_MEM(BRV_A3_COBS_WIRE, out, BRV_A3_COBS_WIRE_LEN);
    CHECK_EQ_U32(out[out_len - 1u], 0x00u);
    for (size_t i = 0; i + 1u < out_len; i++) {
        CHECK(out[i] != 0x00u); /* no zero before the delimiter */
    }
    /* reference oracle agrees with the vector */
    uint8_t ref[128];
    size_t rn = tu_ref_cobs_encode(BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, ref, false);
    CHECK_EQ_U32(rn, BRV_A3_COBS_WIRE_LEN);
    CHECK_MEM(BRV_A3_COBS_WIRE, ref, BRV_A3_COBS_WIRE_LEN);

    uint8_t back[128];
    size_t back_len = 0;
    /* with delimiter */
    CHECK_ERR(br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN, back, sizeof back, &back_len), BR_OK);
    CHECK_EQ_U32(back_len, BRV_A3_COBS_INPUT_LEN);
    CHECK_MEM(BRV_A3_COBS_INPUT, back, BRV_A3_COBS_INPUT_LEN);
    /* without delimiter (N11) */
    back_len = 0;
    memset(back, 0xEE, sizeof back);
    CHECK_ERR(br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN - 1u, back, sizeof back, &back_len), BR_OK);
    CHECK_EQ_U32(back_len, BRV_A3_COBS_INPUT_LEN);
    CHECK_MEM(BRV_A3_COBS_INPUT, back, BRV_A3_COBS_INPUT_LEN);
    /* exact-size destination */
    uint8_t *exact = tu_alloc(BRV_A3_COBS_INPUT_LEN);
    back_len = 0;
    CHECK_ERR(br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN, exact, BRV_A3_COBS_INPUT_LEN, &back_len), BR_OK);
    CHECK_MEM(BRV_A3_COBS_INPUT, exact, BRV_A3_COBS_INPUT_LEN);
    /* one byte short */
    CHECK_ERR(br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN, exact, BRV_A3_COBS_INPUT_LEN - 1u, &back_len),
              BR_ERR_TOO_BIG);
    free(exact);

    /* A.3 frame || parity is BRV_A3_FRAME followed by BRV_A3_RS_PARITY */
    uint8_t cat[50];
    memcpy(cat, BRV_A3_FRAME, BRV_A3_FRAME_LEN);
    memcpy(cat + BRV_A3_FRAME_LEN, BRV_A3_RS_PARITY, BRV_A3_RS_PARITY_LEN);
    CHECK_MEM(BRV_A3_COBS_INPUT, cat, 50);
}

static void test_known_small(void)
{
    {
        const uint8_t e[] = {0x01, 0x00};
        enc_expect(NULL, 0, e, sizeof e, "empty -> 01 00");
    }
    {
        const uint8_t in[] = {0x00};
        const uint8_t e[] = {0x01, 0x01, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "00");
    }
    {
        const uint8_t in[] = {0x00, 0x00};
        const uint8_t e[] = {0x01, 0x01, 0x01, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "00 00");
    }
    {
        const uint8_t in[] = {0x11, 0x22, 0x00, 0x33};
        const uint8_t e[] = {0x03, 0x11, 0x22, 0x02, 0x33, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "11 22 00 33");
    }
    {
        const uint8_t in[] = {0x11, 0x22, 0x33, 0x44};
        const uint8_t e[] = {0x05, 0x11, 0x22, 0x33, 0x44, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "11 22 33 44");
    }
    {
        const uint8_t in[] = {0x11, 0x00, 0x00, 0x00};
        const uint8_t e[] = {0x02, 0x11, 0x01, 0x01, 0x01, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "11 00 00 00");
    }
    {
        const uint8_t in[] = {0x00, 0x11, 0x00};
        const uint8_t e[] = {0x01, 0x02, 0x11, 0x01, 0x00};
        enc_expect(in, sizeof in, e, sizeof e, "00 11 00");
    }
}

static void test_decode_variants(void)
{
    uint8_t out[600];
    size_t n = 0;
    tu_ctx("decode conventions");
    /* 254 non-zero bytes: lazy form FF <254> 00 and eager form FF <254> 01 00 both decode to the same data */
    uint8_t in[254];
    for (size_t i = 0; i < sizeof in; i++) {
        in[i] = (uint8_t)(1u + (i % 255u));
    }
    uint8_t lazy[300], eager[300];
    size_t ln = tu_ref_cobs_encode(in, sizeof in, lazy, false);
    size_t en = tu_ref_cobs_encode(in, sizeof in, eager, true);
    CHECK_EQ_U32(ln, 256u);
    CHECK_EQ_U32(en, 257u);
    CHECK_EQ_U32(lazy[0], 0xFFu);
    CHECK_ERR(br_cobs_decode(lazy, ln, out, sizeof out, &n), BR_OK);
    CHECK_EQ_U32(n, 254u);
    CHECK_MEM(in, out, 254);
    CHECK_ERR(br_cobs_decode(eager, en, out, sizeof out, &n), BR_OK);
    CHECK_EQ_U32(n, 254u);
    CHECK_MEM(in, out, 254);
    CHECK_ERR(br_cobs_decode(eager, en - 1u, out, sizeof out, &n), BR_OK);
    CHECK_EQ_U32(n, 254u);
    /* br_cobs_encode must emit one of the two recognised conventions */
    uint8_t got[300];
    size_t gn = 0;
    CHECK_ERR(br_cobs_encode(in, sizeof in, got, sizeof got, &gn), BR_OK);
    CHECK((gn == ln && memcmp(got, lazy, ln) == 0) || (gn == en && memcmp(got, eager, en) == 0));

    /* code points exactly at the end: 03 11 22 -> 11 22 (no delimiter, no trailing zero) */
    {
        const uint8_t s[] = {0x03, 0x11, 0x22};
        CHECK_ERR(br_cobs_decode(s, sizeof s, out, sizeof out, &n), BR_OK);
        CHECK_EQ_U32(n, 2u);
        CHECK_EQ_U32(out[0], 0x11u);
        CHECK_EQ_U32(out[1], 0x22u);
    }
    /* 01 (no delimiter) -> empty */
    {
        const uint8_t s[] = {0x01};
        n = 77;
        CHECK_ERR(br_cobs_decode(s, sizeof s, out, sizeof out, &n), BR_OK);
        CHECK_EQ_U32(n, 0u);
        const uint8_t s2[] = {0x01, 0x00};
        n = 77;
        CHECK_ERR(br_cobs_decode(s2, sizeof s2, out, sizeof out, &n), BR_OK);
        CHECK_EQ_U32(n, 0u);
    }
}

static void test_malformed(void)
{
    uint8_t out[64];
    size_t n = 0;
    tu_ctx("malformed");
    /* embedded zero (not the last byte) */
    {
        const uint8_t s[] = {0x03, 0x11, 0x00, 0x22, 0x00};
        CHECK_ERR(br_cobs_decode(s, sizeof s, out, sizeof out, &n), BR_ERR_DECODE);
    }
    /* zero code byte in the middle of data without delimiter at the end */
    {
        const uint8_t s[] = {0x02, 0x11, 0x00, 0x02, 0x33};
        CHECK_ERR(br_cobs_decode(s, sizeof s, out, sizeof out, &n), BR_ERR_DECODE);
    }
    /* code byte points past the end */
    {
        const uint8_t s[] = {0x05, 0x11, 0x22};
        CHECK_ERR(br_cobs_decode(s, sizeof s, out, sizeof out, &n), BR_ERR_DECODE);
        const uint8_t s2[] = {0x05, 0x11, 0x22, 0x00};
        CHECK_ERR(br_cobs_decode(s2, sizeof s2, out, sizeof out, &n), BR_ERR_DECODE);
        const uint8_t s3[] = {0xFF};
        CHECK_ERR(br_cobs_decode(s3, sizeof s3, out, sizeof out, &n), BR_ERR_DECODE);
    }
    /* args */
    {
        const uint8_t s[] = {0x01, 0x00};
        CHECK_ERR(br_cobs_decode(NULL, 2, out, sizeof out, &n), BR_ERR_ARG);
        CHECK_ERR(br_cobs_decode(s, 0, out, sizeof out, &n), BR_ERR_ARG);
        CHECK_ERR(br_cobs_decode(s, 2, NULL, sizeof out, &n), BR_ERR_ARG);
        CHECK_ERR(br_cobs_decode(s, 2, out, sizeof out, NULL), BR_ERR_ARG);
        const uint8_t d[] = {0x00};
        CHECK_ERR(br_cobs_decode(d, 1, out, sizeof out, &n), BR_ERR_ARG); /* only a delimiter */
    }
    /* encode args and capacity */
    {
        const uint8_t in[] = {1, 2, 3};
        uint8_t o[16];
        size_t on = 4242;
        CHECK_ERR(br_cobs_encode(NULL, 3, o, sizeof o, &on), BR_ERR_ARG);
        CHECK_ERR(br_cobs_encode(in, 3, NULL, sizeof o, &on), BR_ERR_ARG);
        CHECK_ERR(br_cobs_encode(in, 3, o, sizeof o, NULL), BR_ERR_ARG);
        CHECK_ERR(br_cobs_encode(NULL, 0, o, sizeof o, &on), BR_OK);
        CHECK_EQ_U32(on, 2u);
        /* needs 5 bytes: 04 01 02 03 00 */
        on = 4242;
        uint8_t *exact = tu_alloc(5);
        CHECK_ERR(br_cobs_encode(in, 3, exact, 5, &on), BR_OK);
        CHECK_EQ_U32(on, 5u);
        free(exact);
        on = 4242;
        uint8_t *shy = tu_alloc(4);
        CHECK_ERR(br_cobs_encode(in, 3, shy, 4, &on), BR_ERR_TOO_BIG);
        CHECK_EQ_U32(on, 4242u); /* untouched */
        free(shy);
        CHECK_ERR(br_cobs_encode(in, 3, o, 0, &on), BR_ERR_TOO_BIG);
    }
}

static size_t fill_pattern(tu_rng_t *rng, unsigned kind, uint8_t *b, size_t n)
{
    switch (kind) {
    case 0: /* uniform random */
        tu_rng_fill(rng, b, n);
        break;
    case 1: /* all zero */
        memset(b, 0, n);
        break;
    case 2: /* no zero */
        for (size_t i = 0; i < n; i++) {
            b[i] = (uint8_t)(1u + tu_rng_below(rng, 255));
        }
        break;
    case 3: /* sparse zeros */
        for (size_t i = 0; i < n; i++) {
            b[i] = (tu_rng_below(rng, 20) == 0) ? 0u : (uint8_t)(1u + tu_rng_below(rng, 255));
        }
        break;
    default: { /* runs of 253/254/255/256 non-zero bytes separated by zeros */
        size_t i = 0;
        while (i < n) {
            static const unsigned runs[] = {253, 254, 255, 256, 1, 2, 0};
            unsigned r = runs[tu_rng_below(rng, 7)];
            for (unsigned k = 0; k < r && i < n; k++) {
                b[i++] = (uint8_t)(1u + tu_rng_below(rng, 255));
            }
            if (i < n && tu_rng_below(rng, 4) != 0) {
                b[i++] = 0;
            }
        }
        break;
    }
    }
    return n;
}

static void roundtrip_one(const uint8_t *in, size_t n)
{
    size_t cap = BR_COBS_MAX_ENCODED(n);
    uint8_t *enc = tu_alloc(cap);
    size_t en = 0;
    CHECK_ERR(br_cobs_encode(in, n, enc, cap, &en), BR_OK);
    CHECK(en >= n + 2u && en <= cap);
    if (en == 0 || en > cap) {
        free(enc);
        return;
    }
    CHECK_EQ_U32(enc[en - 1u], 0x00u);
    bool nozero = true;
    for (size_t i = 0; i + 1u < en; i++) {
        if (enc[i] == 0x00u) {
            nozero = false;
        }
    }
    CHECK(nozero);
    /* matches one of the two accepted conventions */
    uint8_t *lz = tu_alloc(cap + 2u), *eg = tu_alloc(cap + 2u);
    size_t ln = tu_ref_cobs_encode(in, n, lz, false), egn = tu_ref_cobs_encode(in, n, eg, true);
    CHECK((en == ln && memcmp(enc, lz, ln) == 0) || (en == egn && memcmp(enc, eg, egn) == 0));
    /* decode with delimiter into exact-size buffer, and without */
    uint8_t *dec = tu_alloc(n);
    size_t dn = 0;
    CHECK_ERR(br_cobs_decode(enc, en, dec, n, &dn), BR_OK);
    CHECK_EQ_U32(dn, n);
    CHECK_MEM(in, dec, n);
    dn = 0;
    memset(dec, 0xAA, n);
    CHECK_ERR(br_cobs_decode(enc, en - 1u, dec, n, &dn), BR_OK);
    CHECK_EQ_U32(dn, n);
    CHECK_MEM(in, dec, n);
    /* the reference encoder's output also decodes (decoder accepts both conventions) */
    dn = 0;
    CHECK_ERR(br_cobs_decode(lz, ln, dec, n, &dn), BR_OK);
    CHECK_EQ_U32(dn, n);
    CHECK_MEM(in, dec, n);
    dn = 0;
    CHECK_ERR(br_cobs_decode(eg, egn, dec, n, &dn), BR_OK);
    CHECK_EQ_U32(dn, n);
    CHECK_MEM(in, dec, n);
    /* destination one byte short must fail with TOO_BIG, not overrun */
    if (n > 0) {
        uint8_t *shy = tu_alloc(n - 1u);
        CHECK_ERR(br_cobs_decode(enc, en, shy, n - 1u, &dn), BR_ERR_TOO_BIG);
        free(shy);
    }
    /* encoder with exactly the needed capacity, and one short */
    uint8_t *ex = tu_alloc(en);
    size_t xn = 0;
    CHECK_ERR(br_cobs_encode(in, n, ex, en, &xn), BR_OK);
    CHECK_EQ_U32(xn, en);
    free(ex);
    uint8_t *sh = tu_alloc(en - 1u);
    CHECK_ERR(br_cobs_encode(in, n, sh, en - 1u, &xn), BR_ERR_TOO_BIG);
    free(sh);
    free(dec);
    free(lz);
    free(eg);
    free(enc);
}

static void test_roundtrip(void)
{
    tu_ctx("round trip");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xC0B5u);
    uint8_t buf[1100];
    /* every length 0..300 with every pattern kind, then boundary lengths */
    for (size_t n = 0; n <= 300; n++) {
        for (unsigned kind = 0; kind < 5; kind++) {
            fill_pattern(&rng, kind, buf, n);
            uint8_t *d = tu_dup(buf, n);
            roundtrip_one(d, n);
            free(d);
        }
    }
    static const size_t special[] = {253, 254, 255, 256, 507, 508, 509, 510, 511, 512, 600, 700};
    for (size_t s = 0; s < sizeof special / sizeof special[0]; s++) {
        for (unsigned kind = 0; kind < 5; kind++) {
            fill_pattern(&rng, kind, buf, special[s]);
            uint8_t *d = tu_dup(buf, special[s]);
            roundtrip_one(d, special[s]);
            free(d);
        }
    }
    /* exact runs: 254 / 255 non-zero, with and without a trailing and leading zero */
    for (size_t run = 252; run <= 256; run++) {
        for (unsigned pre = 0; pre < 2; pre++) {
            for (unsigned post = 0; post < 2; post++) {
                size_t n = 0;
                if (pre) {
                    buf[n++] = 0;
                }
                for (size_t i = 0; i < run; i++) {
                    buf[n++] = (uint8_t)(1u + (i % 255u));
                }
                if (post) {
                    buf[n++] = 0;
                }
                uint8_t *d = tu_dup(buf, n);
                roundtrip_one(d, n);
                free(d);
            }
        }
    }
    /* all 256 single-byte inputs and all two-byte inputs with a zero */
    for (unsigned v = 0; v < 256; v++) {
        uint8_t one = (uint8_t)v;
        roundtrip_one(&one, 1);
        uint8_t two[2] = {0, (uint8_t)v};
        roundtrip_one(two, 2);
        two[0] = (uint8_t)v;
        two[1] = 0;
        roundtrip_one(two, 2);
    }
    /* BR_COBS_MAX_ENCODED bound is tight enough: all-nonzero input of 254*k bytes */
    for (size_t k = 1; k <= 4; k++) {
        size_t n = 254u * k;
        for (size_t i = 0; i < n; i++) {
            buf[i] = 0x5A;
        }
        uint8_t enc[1100];
        size_t en = 0;
        CHECK_ERR(br_cobs_encode(buf, n, enc, BR_COBS_MAX_ENCODED(n), &en), BR_OK);
        CHECK(en <= BR_COBS_MAX_ENCODED(n));
    }
}

/* Decoder robustness: mutated and random wire data must never overrun the exact-size destination. */
static void test_decoder_fuzz(void)
{
    tu_ctx("decoder fuzz");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xDEC0DE);
    uint8_t base[400];
    for (unsigned it = 0; it < 20000; it++) {
        size_t n = tu_rng_below(&rng, 300);
        fill_pattern(&rng, tu_rng_below(&rng, 5), base, n);
        uint8_t enc[BR_COBS_MAX_ENCODED(300)];
        size_t en = 0;
        if (br_cobs_encode(base, n, enc, sizeof enc, &en) != BR_OK) {
            continue; /* a stub: nothing to mutate; the encode checks elsewhere already fail */
        }
        unsigned m = 1u + tu_rng_below(&rng, 4);
        for (unsigned k = 0; k < m; k++) {
            enc[tu_rng_below(&rng, (uint32_t)en)] = tu_rng_u8(&rng);
        }
        size_t sl = en;
        if (tu_rng_below(&rng, 4) == 0 && sl > 1) {
            sl = 1u + tu_rng_below(&rng, (uint32_t)sl);
        }
        if (tu_rng_below(&rng, 8) == 0) {
            sl = tu_rng_below(&rng, (uint32_t)sl + 1u); /* may be 0 -> ARG */
        }
        uint8_t *src = tu_dup(enc, sl);
        size_t cap = sl ? sl : 1u;
        uint8_t *dst = tu_alloc(cap); /* src_len bytes is always enough */
        size_t dn = 0;
        int rc = (int)br_cobs_decode(src, sl, dst, cap, &dn);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE || rc == BR_ERR_ARG || rc == BR_ERR_TOO_BIG);
        if (rc == BR_OK) {
            CHECK(dn <= sl);
        }
        free(src);
        free(dst);
    }
    /* pure random bytes */
    for (unsigned it = 0; it < 20000; it++) {
        size_t sl = 1u + tu_rng_below(&rng, 300);
        uint8_t tmp[300];
        tu_rng_fill(&rng, tmp, sl);
        if (tu_rng_below(&rng, 2)) {
            for (size_t i = 0; i < sl; i++) { /* mostly non-zero bytes so decoding goes deeper */
                if (tmp[i] == 0 && tu_rng_below(&rng, 8) != 0) {
                    tmp[i] = 1;
                }
            }
        }
        uint8_t *src = tu_dup(tmp, sl);
        uint8_t *dst = tu_alloc(sl);
        size_t dn = 0;
        int rc = (int)br_cobs_decode(src, sl, dst, sl, &dn);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE || rc == BR_ERR_ARG || rc == BR_ERR_TOO_BIG);
        if (rc == BR_OK) {
            CHECK(dn <= sl);
            /* what decodes cleanly must re-encode to something that decodes back to the same bytes */
            uint8_t enc[BR_COBS_MAX_ENCODED(300)];
            size_t en = 0;
            uint8_t back[300];
            size_t bn = 0;
            CHECK_ERR(br_cobs_encode(dst, dn, enc, sizeof enc, &en), BR_OK);
            CHECK_ERR(br_cobs_decode(enc, en, back, sizeof back, &bn), BR_OK);
            CHECK_EQ_U32(bn, dn);
            CHECK_MEM(dst, back, dn);
        }
        free(src);
        free(dst);
    }
}

int main(void)
{
    test_a3();
    test_known_small();
    test_decode_variants();
    test_malformed();
    test_roundtrip();
    test_decoder_fuzz();
    return tu_summary("test_cobs");
}
