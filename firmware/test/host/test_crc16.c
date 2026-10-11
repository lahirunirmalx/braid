// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_crc16.c - CRC-16/CCITT-FALSE (spec 3.1, A.1) and the fallback unit ID (section 2).
 */
#include "braid/br_crc16.h"
#include "test_util.h"
#include "test_vectab.h"

static void test_a1(void)
{
    tu_ctx("A.1");
    uint16_t crc = 0;
    CHECK_ERR(br_crc16(BRV_A1_CRC_INPUT, BRV_A1_CRC_INPUT_LEN, &crc), BR_OK);
    CHECK_EQ_U32(crc, BRV_A1_CRC_EXPECTED);
    CHECK_EQ_U32(crc, 0x29B1u);
    CHECK_EQ_U32(tu_ref_crc16(BRV_A1_CRC_INPUT, BRV_A1_CRC_INPUT_LEN), 0x29B1u); /* oracle self-check */
}

static void test_args(void)
{
    tu_ctx("args");
    uint16_t crc = 0x1234;
    const uint8_t b[1] = {0};
    CHECK_ERR(br_crc16(NULL, 0, &crc), BR_OK);
    CHECK_EQ_U32(crc, 0xFFFFu); /* empty input */
    CHECK_ERR(br_crc16(b, 0, &crc), BR_OK);
    CHECK_EQ_U32(crc, 0xFFFFu);
    CHECK_ERR(br_crc16(NULL, 1, &crc), BR_ERR_ARG);
    CHECK_ERR(br_crc16(b, 1, NULL), BR_ERR_ARG);
    CHECK_ERR(br_crc16_update(BR_CRC16_INIT, NULL, 1, &crc), BR_ERR_ARG);
    CHECK_ERR(br_crc16_update(BR_CRC16_INIT, b, 1, NULL), BR_ERR_ARG);
    crc = 0;
    CHECK_ERR(br_crc16_update(0xABCDu, NULL, 0, &crc), BR_OK);
    CHECK_EQ_U32(crc, 0xABCDu); /* no data: register unchanged */
    CHECK_EQ_U32(BR_CRC16_INIT, 0xFFFFu);
    /* known single-byte values */
    CHECK_ERR(br_crc16(b, 1, &crc), BR_OK);
    CHECK_EQ_U32(crc, tu_ref_crc16(b, 1));
    CHECK_EQ_U32(crc, 0xE1F0u); /* CRC-16/CCITT-FALSE of one 0x00 byte */
}

static void test_frame_vectors(void)
{
    for (size_t i = 0; i < TU_N_FRAME_VECS; i++) {
        const tu_frame_vec_t *v = &TU_FRAME_VECS[i];
        tu_ctx(v->name);
        /* CRC covers byte 0 .. end of hop_tag (end of payload without AUTH) = len - 2 */
        uint16_t crc = 0;
        CHECK_ERR(br_crc16(v->frame, v->len - 2u, &crc), BR_OK);
        CHECK_EQ_U32(crc, v->crc);
        CHECK_EQ_U32(tu_get16(v->frame + v->len - 2u), v->crc); /* LE trailer */
        CHECK_EQ_U32(tu_ref_crc16(v->frame, v->len - 2u), v->crc); /* oracle agrees with the vector */
        /* sent little-endian: low byte first */
        CHECK_EQ_U32(v->frame[v->len - 2u], v->crc & 0xFFu);
        CHECK_EQ_U32(v->frame[v->len - 1u], v->crc >> 8);

        /* incremental == one-shot at every split point */
        for (size_t cut = 0; cut <= v->len - 2u; cut++) {
            uint16_t r = BR_CRC16_INIT;
            uint16_t r2 = 0;
            CHECK_ERR(br_crc16_update(r, v->frame, cut, &r2), BR_OK);
            CHECK_ERR(br_crc16_update(r2, v->frame + cut, v->len - 2u - cut, &r), BR_OK);
            CHECK_EQ_U32(r, v->crc);
        }

        /* Single-bit flip anywhere in the covered span changes the CRC (detects all 1-bit errors). */
        uint8_t tmp[256];
        memcpy(tmp, v->frame, v->len);
        for (size_t bit = 0; bit < (v->len - 2u) * 8u; bit += 7u) {
            tmp[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
            uint16_t c2 = 0;
            CHECK_ERR(br_crc16(tmp, v->len - 2u, &c2), BR_OK);
            CHECK(c2 != v->crc);
            tmp[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
        }
    }
}

/* Spec 3.1: detects all 1-, 2- and 3-bit errors at frame sizes (A.2 frame = 40 covered bytes). */
static void test_error_detection(void)
{
    tu_ctx("1/2/3-bit detection");
    uint8_t f[BRV_A2_FRAME_LEN];
    memcpy(f, BRV_A2_FRAME, sizeof f);
    const size_t n = BRV_A2_FRAME_LEN - 2u;
    const size_t bits = n * 8u;
    uint16_t good = 0;
    CHECK_ERR(br_crc16(f, n, &good), BR_OK);
    unsigned undetected = 0;
    for (size_t a = 0; a < bits; a++) {
        f[a / 8u] ^= (uint8_t)(1u << (a % 8u));
        uint16_t c = 0;
        (void)br_crc16(f, n, &c);
        if (c == good) {
            undetected++;
        }
        for (size_t b = a + 1u; b < bits; b++) {
            f[b / 8u] ^= (uint8_t)(1u << (b % 8u));
            (void)br_crc16(f, n, &c);
            if (c == good) {
                undetected++;
            }
            f[b / 8u] ^= (uint8_t)(1u << (b % 8u));
        }
        f[a / 8u] ^= (uint8_t)(1u << (a % 8u));
    }
    CHECK_EQ_U32(undetected, 0u);
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x3B17u);
    for (unsigned it = 0; it < 20000; it++) {
        size_t p[3];
        p[0] = tu_rng_below(&rng, (uint32_t)bits);
        do { p[1] = tu_rng_below(&rng, (uint32_t)bits); } while (p[1] == p[0]);
        do { p[2] = tu_rng_below(&rng, (uint32_t)bits); } while (p[2] == p[0] || p[2] == p[1]);
        uint8_t g[BRV_A2_FRAME_LEN];
        memcpy(g, BRV_A2_FRAME, sizeof g);
        for (int k = 0; k < 3; k++) {
            g[p[k] / 8u] ^= (uint8_t)(1u << (p[k] % 8u));
        }
        uint16_t c = 0;
        CHECK_ERR(br_crc16(g, n, &c), BR_OK);
        CHECK(c != good);
    }
}

static void test_property(void)
{
    tu_ctx("random vs reference");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xC4C16u);
    uint8_t buf[600];
    for (unsigned it = 0; it < 3000; it++) {
        size_t n = tu_rng_below(&rng, 600);
        tu_rng_fill(&rng, buf, n);
        uint8_t *d = tu_dup(buf, n); /* exact-size heap copy: ASan catches overreads */
        uint16_t c = 0;
        CHECK_ERR(br_crc16(d, n, &c), BR_OK);
        CHECK_EQ_U32(c, tu_ref_crc16(buf, n));
        /* three-chunk incremental */
        size_t c1 = n ? tu_rng_below(&rng, (uint32_t)n + 1u) : 0;
        size_t c2 = (n > c1) ? c1 + tu_rng_below(&rng, (uint32_t)(n - c1) + 1u) : c1;
        uint16_t r = BR_CRC16_INIT;
        uint16_t t = 0;
        CHECK_ERR(br_crc16_update(r, d, c1, &t), BR_OK);
        CHECK_ERR(br_crc16_update(t, d + c1, c2 - c1, &r), BR_OK);
        CHECK_ERR(br_crc16_update(r, d + c2, n - c2, &t), BR_OK);
        CHECK_EQ_U32(t, c);
        free(d);
    }
    /* in-place style aliasing of crc_out with nothing else: update(crc, ..., &crc) */
    uint16_t run = BR_CRC16_INIT;
    CHECK_ERR(br_crc16_update(run, BRV_A1_CRC_INPUT, 4, &run), BR_OK);
    CHECK_ERR(br_crc16_update(run, BRV_A1_CRC_INPUT + 4, 5, &run), BR_OK);
    CHECK_EQ_U32(run, 0x29B1u);
}

static uint16_t ref_fallback(const uint8_t mac[6])
{
    uint32_t id = tu_ref_crc16(mac, 6);
    if (id < 0x0010u || id >= 0xFF00u) {
        id = (id % 0xFEEFu) + 0x0010u;
    }
    return (uint16_t)id;
}

static void test_fallback_id(void)
{
    tu_ctx("fallback unit id");
    uint16_t id = 0;
    const uint8_t mac[6] = {0x24, 0x6F, 0x28, 0x01, 0x02, 0x03};
    CHECK_ERR(br_fallback_unit_id(NULL, &id), BR_ERR_ARG);
    CHECK_ERR(br_fallback_unit_id(mac, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fallback_unit_id(mac, &id), BR_OK);
    CHECK_EQ_U32(id, ref_fallback(mac));

    tu_rng_t rng;
    tu_rng_seed(&rng, 0xFA11BAC4u);
    unsigned remapped = 0;
    for (unsigned it = 0; it < 200000; it++) {
        uint8_t m[6];
        tu_rng_fill(&rng, m, 6);
        uint16_t crc = tu_ref_crc16(m, 6);
        bool edge = crc < 0x0010u || crc >= 0xFF00u;
        if (!edge && (it & 7u) != 0) {
            continue; /* always test edge cases, sample the rest */
        }
        if (edge) {
            remapped++;
        }
        CHECK_ERR(br_fallback_unit_id(m, &id), BR_OK);
        CHECK_EQ_U32(id, ref_fallback(m));
        CHECK(id >= BR_ID_UNIT_FIRST && id <= BR_ID_UNIT_LAST); /* always a unit ID */
    }
    CHECK(remapped > 100u); /* the sweep really exercised the remap branch */
}

int main(void)
{
    test_a1();
    test_args();
    test_frame_vectors();
    test_error_detection();
    test_property();
    test_fallback_id();
    return tu_summary("test_crc16");
}
