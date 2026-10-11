// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_fec.c - group FEC, systematic RS erasure code across frames (spec 3.3, A.5).
 *
 * Model: column-wise RS with nsym = m (prim 0x11D, fcr 0, alpha 2, parity
 * appended); data block i is codeword position i, parity block j is position
 * k + j; any k of the k + m blocks reconstruct the rest.
 */
#include "braid/br_fec.h"
#include "test_util.h"
#include "test_vectab.h"

#define MAXB BR_FEC_MAX_BLOCK_LEN
#define MAXN (BR_FEC_K_MAX + BR_FEC_M_MAX)

/* Reference parity: for every byte column RS-encode the k data bytes with nsym = m. */
static void ref_parity(const uint8_t *const *data, unsigned k, unsigned m, size_t bl, uint8_t out[BR_FEC_M_MAX][MAXB])
{
    for (size_t p = 0; p < bl; p++) {
        uint8_t col[BR_FEC_K_MAX];
        uint8_t par[BR_FEC_M_MAX];
        for (unsigned i = 0; i < k; i++) {
            col[i] = data[i][p];
        }
        tu_ref_rs_encode(col, k, m, par);
        for (unsigned j = 0; j < m; j++) {
            out[j][p] = par[j];
        }
    }
}

static void test_a5(void)
{
    tu_ctx("A.5 k2/m1");
    {
        const uint8_t *data[2] = {BRV_A5_K2M1_BLOCK0, BRV_A5_K2M1_BLOCK1};
        uint8_t p0[5] = {0};
        uint8_t *par[1] = {p0};
        CHECK_ERR(br_fec_encode(data, BRV_A5_K2M1_K, BRV_A5_K2M1_M, 5, par), BR_OK);
        CHECK_MEM(BRV_A5_K2M1_PARITY0, p0, BRV_A5_K2M1_PARITY0_LEN);
        uint8_t ref[BR_FEC_M_MAX][MAXB];
        ref_parity(data, 2, 1, 5, ref);
        CHECK_MEM(BRV_A5_K2M1_PARITY0, ref[0], 5); /* oracle agrees with the vector */
        /* m = 1 is XOR of the blocks */
        uint8_t x[5];
        for (unsigned i = 0; i < 5; i++) {
            x[i] = (uint8_t)(BRV_A5_K2M1_BLOCK0[i] ^ BRV_A5_K2M1_BLOCK1[i]);
        }
        CHECK_MEM(x, p0, 5);

        /* erase each single block in turn (data0, data1, parity) */
        for (unsigned lost = 0; lost < 3; lost++) {
            uint8_t b0[5], b1[5], bp[5];
            memcpy(b0, BRV_A5_K2M1_BLOCK0, 5);
            memcpy(b1, BRV_A5_K2M1_BLOCK1, 5);
            memcpy(bp, BRV_A5_K2M1_PARITY0, 5);
            uint8_t *blocks[3] = {b0, b1, bp};
            bool present[3] = {true, true, true};
            present[lost] = false;
            memset(blocks[lost], 0xA5, 5);
            uint8_t rec = 99;
            CHECK_ERR(br_fec_decode(blocks, present, 2, 1, 5, &rec), BR_OK);
            CHECK_MEM(BRV_A5_K2M1_BLOCK0, b0, 5);
            CHECK_MEM(BRV_A5_K2M1_BLOCK1, b1, 5);
            CHECK_EQ_U32(rec, lost < 2 ? 1u : 0u);
            if (lost == 2) {
                /* parity is not regenerated */
                CHECK_EQ_U32(bp[0], 0xA5u);
            }
        }
        /* two losses of 3 with k 2 -> not recoverable */
        uint8_t b0[5], b1[5], bp[5];
        memcpy(b0, BRV_A5_K2M1_BLOCK0, 5);
        memset(b1, 0xA5, 5);
        memset(bp, 0xA5, 5);
        uint8_t *blocks[3] = {b0, b1, bp};
        bool present[3] = {true, false, false};
        CHECK_ERR(br_fec_decode(blocks, present, 2, 1, 5, NULL), BR_ERR_UNCORRECTABLE);
        CHECK_EQ_U32(b1[0], 0xA5u); /* nothing written */
    }

    tu_ctx("A.5 k4/m2");
    {
        const uint8_t *data[4] = {BRV_A5_K4M2_BLOCK0, BRV_A5_K4M2_BLOCK1, BRV_A5_K4M2_BLOCK2, BRV_A5_K4M2_BLOCK3};
        uint8_t p0[4] = {0}, p1[4] = {0};
        uint8_t *par[2] = {p0, p1};
        CHECK_ERR(br_fec_encode(data, BRV_A5_K4M2_K, BRV_A5_K4M2_M, 4, par), BR_OK);
        CHECK_MEM(BRV_A5_K4M2_PARITY0, p0, BRV_A5_K4M2_PARITY0_LEN);
        CHECK_MEM(BRV_A5_K4M2_PARITY1, p1, BRV_A5_K4M2_PARITY1_LEN);
        uint8_t ref[BR_FEC_M_MAX][MAXB];
        ref_parity(data, 4, 2, 4, ref);
        CHECK_MEM(BRV_A5_K4M2_PARITY0, ref[0], 4);
        CHECK_MEM(BRV_A5_K4M2_PARITY1, ref[1], 4);

        /* erasure positions {1, 3} reproduce blocks 1 and 3 */
        CHECK_EQ_U32(BRV_A5_K4M2_ERASED[0], 1u);
        CHECK_EQ_U32(BRV_A5_K4M2_ERASED[1], 3u);
        uint8_t d[4][4];
        memcpy(d[0], BRV_A5_K4M2_BLOCK0, 4);
        memset(d[1], 0xA5, 4);
        memcpy(d[2], BRV_A5_K4M2_BLOCK2, 4);
        memset(d[3], 0xA5, 4);
        uint8_t q0[4], q1[4];
        memcpy(q0, BRV_A5_K4M2_PARITY0, 4);
        memcpy(q1, BRV_A5_K4M2_PARITY1, 4);
        uint8_t *blocks[6] = {d[0], d[1], d[2], d[3], q0, q1};
        bool present[6] = {true, false, true, false, true, true};
        uint8_t rec = 99;
        CHECK_ERR(br_fec_decode(blocks, present, 4, 2, 4, &rec), BR_OK);
        CHECK_EQ_U32(rec, 2u);
        CHECK_MEM(BRV_A5_K4M2_BLOCK1, d[1], 4);
        CHECK_MEM(BRV_A5_K4M2_BLOCK3, d[3], 4);
        CHECK_MEM(BRV_A5_K4M2_BLOCK0, d[0], 4);
        CHECK_MEM(BRV_A5_K4M2_BLOCK2, d[2], 4);
        CHECK_MEM(BRV_A5_K4M2_PARITY0, q0, 4); /* present blocks untouched */
        CHECK_MEM(BRV_A5_K4M2_PARITY1, q1, 4);

        /* the data blocks carry payloads: [len][payload][pad] */
        const uint8_t *pl;
        uint8_t pn = 99;
        CHECK_ERR(br_fec_payload_from_block(d[1], 4, &pl, &pn), BR_OK);
        CHECK_EQ_U32(pn, 3u);
        CHECK_MEM(BRV_A5_K4M2_BLOCK1 + 1, pl, 3);
        CHECK(pl == d[1] + 1);
        CHECK_ERR(br_fec_payload_from_block(d[3], 4, &pl, &pn), BR_OK);
        CHECK_EQ_U32(pn, 3u);
        CHECK_MEM(BRV_A5_K4M2_BLOCK3 + 1, pl, 3);
    }
}

static void test_block_codec(void)
{
    tu_ctx("block <-> payload");
    uint8_t blk[MAXB];
    /* the vector blocks are exactly [len][payload][zero pad] */
    {
        const uint8_t pay[3] = {0x01, 0x02, 0x03};
        memset(blk, 0xEE, sizeof blk);
        CHECK_ERR(br_fec_block_from_payload(pay, 3, 5, blk), BR_OK);
        CHECK_MEM(BRV_A5_K2M1_BLOCK0, blk, 5);
        const uint8_t pay2[4] = {0x10, 0x20, 0x30, 0x40};
        CHECK_ERR(br_fec_block_from_payload(pay2, 4, 5, blk), BR_OK);
        CHECK_MEM(BRV_A5_K2M1_BLOCK1, blk, 5);
        const uint8_t pay3[2] = {0xAA, 0xBB};
        CHECK_ERR(br_fec_block_from_payload(pay3, 2, 4, blk), BR_OK);
        CHECK_MEM(BRV_A5_K4M2_BLOCK0, blk, 4);
        const uint8_t pay4[1] = {0xFF};
        CHECK_ERR(br_fec_block_from_payload(pay4, 1, 4, blk), BR_OK);
        CHECK_MEM(BRV_A5_K4M2_BLOCK2, blk, 4);
    }
    /* empty payload: [00][zeros] */
    memset(blk, 0xEE, sizeof blk);
    CHECK_ERR(br_fec_block_from_payload(NULL, 0, 6, blk), BR_OK);
    for (unsigned i = 0; i < 6; i++) {
        CHECK_EQ_U32(blk[i], 0u);
    }
    /* limits */
    uint8_t big[255];
    memset(big, 0x42, sizeof big);
    CHECK_ERR(br_fec_block_from_payload(big, 229, (uint16_t)MAXB, blk), BR_OK);
    CHECK_EQ_U32(blk[0], 229u);
    CHECK_ERR(br_fec_block_from_payload(big, 230, (uint16_t)MAXB, blk), BR_ERR_TOO_BIG); /* 230 + 1 > 230 */
    CHECK_ERR(br_fec_block_from_payload(big, 5, 5, blk), BR_ERR_TOO_BIG);
    CHECK_ERR(br_fec_block_from_payload(big, 4, 5, blk), BR_OK);
    CHECK_ERR(br_fec_block_from_payload(big, 1, 0, blk), BR_ERR_ARG);
    CHECK_ERR(br_fec_block_from_payload(big, 1, (uint16_t)(MAXB + 1u), blk), BR_ERR_ARG);
    CHECK_ERR(br_fec_block_from_payload(NULL, 1, 5, blk), BR_ERR_ARG);
    CHECK_ERR(br_fec_block_from_payload(big, 1, 5, NULL), BR_ERR_ARG);

    /* payload_from_block */
    const uint8_t *pl = NULL;
    uint8_t pn = 0;
    {
        const uint8_t b[5] = {0x02, 0xAA, 0xBB, 0x00, 0x00};
        CHECK_ERR(br_fec_payload_from_block(b, 5, &pl, &pn), BR_OK);
        CHECK_EQ_U32(pn, 2u);
        CHECK(pl == b + 1);
        const uint8_t bz[1] = {0x00};
        CHECK_ERR(br_fec_payload_from_block(bz, 1, &pl, &pn), BR_OK);
        CHECK_EQ_U32(pn, 0u);
        const uint8_t bad_len[3] = {0x03, 0x01, 0x02}; /* 3 + 1 > 3 */
        CHECK_ERR(br_fec_payload_from_block(bad_len, 3, &pl, &pn), BR_ERR_DECODE);
        const uint8_t bad_pad[5] = {0x02, 0xAA, 0xBB, 0x00, 0x01}; /* non-zero pad */
        CHECK_ERR(br_fec_payload_from_block(bad_pad, 5, &pl, &pn), BR_ERR_DECODE);
        const uint8_t just_fit[3] = {0x02, 0x01, 0x02};
        CHECK_ERR(br_fec_payload_from_block(just_fit, 3, &pl, &pn), BR_OK);
        CHECK_ERR(br_fec_payload_from_block(NULL, 3, &pl, &pn), BR_ERR_ARG);
        CHECK_ERR(br_fec_payload_from_block(b, 5, NULL, &pn), BR_ERR_ARG);
        CHECK_ERR(br_fec_payload_from_block(b, 5, &pl, NULL), BR_ERR_ARG);
        CHECK_ERR(br_fec_payload_from_block(b, 0, &pl, &pn), BR_ERR_ARG);
        uint8_t large[300] = {0};
        CHECK_ERR(br_fec_payload_from_block(large, (uint16_t)(MAXB + 1u), &pl, &pn), BR_ERR_ARG);
    }
    /* round trip, random */
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xB10Cu);
    for (unsigned it = 0; it < 500; it++) {
        uint16_t bl = (uint16_t)(1u + tu_rng_below(&rng, MAXB));
        uint8_t n = (uint8_t)tu_rng_below(&rng, bl); /* 0 .. bl-1 */
        uint8_t pay[255];
        tu_rng_fill(&rng, pay, n);
        uint8_t *b = tu_alloc(bl);
        CHECK_ERR(br_fec_block_from_payload(pay, n, bl, b), BR_OK);
        CHECK_ERR(br_fec_payload_from_block(b, bl, &pl, &pn), BR_OK);
        CHECK_EQ_U32(pn, n);
        CHECK_MEM(pay, pl, n);
        free(b);
    }
}

static void test_parity_hdr(void)
{
    tu_ctx("PARITY header");
    br_fec_parity_hdr_t h;
    memset(&h, 0, sizeof h);
    h.first_seq = 0x1234;
    h.k = 8;
    h.m = 2;
    h.idx = 1;
    h.block_len = 0x00C9;
    h.reserved = 0;
    uint8_t out[16];
    memset(out, 0xEE, sizeof out);
    CHECK_ERR(br_fec_parity_hdr_encode(&h, out, sizeof out), BR_OK);
    /* first_seq u16, k u8, m u8, idx u8, block_len u16, reserved u8 (little-endian) */
    const uint8_t exp[8] = {0x34, 0x12, 0x08, 0x02, 0x01, 0xC9, 0x00, 0x00};
    CHECK_MEM(exp, out, 8);
    CHECK_EQ_U32(out[8], 0xEEu); /* writes exactly 8 bytes */
    CHECK_EQ_U32(BR_FEC_PARITY_HDR_LEN, 8u);

    /* decode: header + block_len parity bytes */
    uint8_t pay[8 + 0xC9];
    memset(pay, 0x77, sizeof pay);
    memcpy(pay, exp, 8);
    br_fec_parity_hdr_t d;
    memset(&d, 0xFF, sizeof d);
    CHECK_ERR(br_fec_parity_hdr_decode(pay, sizeof pay, &d), BR_OK);
    CHECK_EQ_U32(d.first_seq, 0x1234u);
    CHECK_EQ_U32(d.k, 8u);
    CHECK_EQ_U32(d.m, 2u);
    CHECK_EQ_U32(d.idx, 1u);
    CHECK_EQ_U32(d.block_len, 0xC9u);
    CHECK_EQ_U32(d.reserved, 0u);
    /* reserved is copied out as received */
    pay[7] = 0x5A;
    CHECK_ERR(br_fec_parity_hdr_decode(pay, sizeof pay, &d), BR_OK);
    CHECK_EQ_U32(d.reserved, 0x5Au);
    pay[7] = 0;
    /* block_len must equal len - 8 */
    CHECK_ERR(br_fec_parity_hdr_decode(pay, sizeof pay - 1u, &d), BR_ERR_DECODE);
    CHECK_ERR(br_fec_parity_hdr_decode(pay, 7, &d), BR_ERR_DECODE);
    CHECK_ERR(br_fec_parity_hdr_decode(pay, 0, &d), BR_ERR_DECODE);
    CHECK_ERR(br_fec_parity_hdr_decode(NULL, 20, &d), BR_ERR_ARG);
    CHECK_ERR(br_fec_parity_hdr_decode(pay, sizeof pay, NULL), BR_ERR_ARG);

    /* encode argument rules */
    CHECK_ERR(br_fec_parity_hdr_encode(NULL, out, sizeof out), BR_ERR_ARG);
    CHECK_ERR(br_fec_parity_hdr_encode(&h, NULL, sizeof out), BR_ERR_ARG);
    CHECK_ERR(br_fec_parity_hdr_encode(&h, out, 7), BR_ERR_TOO_BIG);
    CHECK_ERR(br_fec_parity_hdr_encode(&h, out, 8), BR_OK);
    {
        br_fec_parity_hdr_t b = h;
        b.k = 0; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.k = 17; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.k = 16; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_OK);
        b = h; b.m = 0; b.idx = 0; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.m = 5; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.m = 4; b.idx = 3; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_OK);
        b = h; b.idx = 2; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG); /* idx >= m */
        b = h; b.block_len = 0; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.block_len = (uint16_t)(MAXB + 1u); CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_ERR_ARG);
        b = h; b.block_len = (uint16_t)MAXB; CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_OK);
        b = h; b.reserved = 0x42;
        CHECK_ERR(br_fec_parity_hdr_encode(&b, out, sizeof out), BR_OK);
        CHECK_EQ_U32(out[7], 0x42u); /* reserved written as given */
    }
    /* round trip, random valid headers */
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x9A81u);
    for (unsigned it = 0; it < 500; it++) {
        br_fec_parity_hdr_t a;
        a.first_seq = (uint16_t)tu_rng_below(&rng, 65536);
        a.k = (uint8_t)(1u + tu_rng_below(&rng, 16));
        a.m = (uint8_t)(1u + tu_rng_below(&rng, 4));
        a.idx = (uint8_t)tu_rng_below(&rng, a.m);
        a.block_len = (uint16_t)(1u + tu_rng_below(&rng, MAXB));
        a.reserved = 0;
        uint8_t w[8 + MAXB];
        memset(w, 0, sizeof w);
        CHECK_ERR(br_fec_parity_hdr_encode(&a, w, sizeof w), BR_OK);
        br_fec_parity_hdr_t r;
        CHECK_ERR(br_fec_parity_hdr_decode(w, 8u + a.block_len, &r), BR_OK);
        CHECK_EQ_U32(r.first_seq, a.first_seq);
        CHECK_EQ_U32(r.k, a.k);
        CHECK_EQ_U32(r.m, a.m);
        CHECK_EQ_U32(r.idx, a.idx);
        CHECK_EQ_U32(r.block_len, a.block_len);
        CHECK_EQ_U32(tu_get16(w), a.first_seq);
        CHECK_EQ_U32(tu_get16(w + 5), a.block_len);
    }
}

static void test_args(void)
{
    tu_ctx("args");
    uint8_t a[8] = {0}, b[8] = {0}, p[8] = {0};
    const uint8_t *data[2] = {a, b};
    uint8_t *par[1] = {p};
    CHECK_ERR(br_fec_encode(NULL, 2, 1, 8, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 1, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 0, 1, 8, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 17, 1, 8, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 0, 8, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 5, 8, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 1, 0, par), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 1, (uint16_t)(MAXB + 1u), par), BR_ERR_ARG);
    const uint8_t *data_null[2] = {a, NULL};
    CHECK_ERR(br_fec_encode(data_null, 2, 1, 8, par), BR_ERR_ARG);
    uint8_t *par_null[1] = {NULL};
    CHECK_ERR(br_fec_encode(data, 2, 1, 8, par_null), BR_ERR_ARG);
    CHECK_ERR(br_fec_encode(data, 2, 1, 8, par), BR_OK);

    uint8_t *blocks[3] = {a, b, p};
    bool present[3] = {true, true, true};
    CHECK_ERR(br_fec_decode(NULL, present, 2, 1, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, NULL, 2, 1, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 0, 1, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 17, 1, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 2, 0, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 2, 5, 8, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 2, 1, 0, NULL), BR_ERR_ARG);
    CHECK_ERR(br_fec_decode(blocks, present, 2, 1, (uint16_t)(MAXB + 1u), NULL), BR_ERR_ARG);
    uint8_t *blocks_null[3] = {a, NULL, p};
    CHECK_ERR(br_fec_decode(blocks_null, present, 2, 1, 8, NULL), BR_ERR_ARG);
    uint8_t rec = 99;
    CHECK_ERR(br_fec_decode(blocks, present, 2, 1, 8, &rec), BR_OK); /* nothing missing */
    CHECK_EQ_U32(rec, 0u);
}

static unsigned recovered_trials;
static unsigned failed_trials;

static void one_trial(tu_rng_t *rng, unsigned k, unsigned m, size_t bl, unsigned n_erase, bool prefer_data)
{
    unsigned n = k + m;
    uint8_t *blk[MAXN];
    uint8_t *orig[MAXN];
    for (unsigned i = 0; i < n; i++) {
        blk[i] = tu_alloc(bl);
        orig[i] = tu_alloc(bl);
    }
    /* realistic data blocks: [len][payload][pad] */
    for (unsigned i = 0; i < k; i++) {
        uint8_t plen = (uint8_t)tu_rng_below(rng, (uint32_t)bl);
        uint8_t pay[255];
        tu_rng_fill(rng, pay, plen);
        CHECK_ERR(br_fec_block_from_payload(pay, plen, (uint16_t)bl, orig[i]), BR_OK);
    }
    const uint8_t *dptr[BR_FEC_K_MAX];
    for (unsigned i = 0; i < k; i++) {
        dptr[i] = orig[i];
    }
    uint8_t *pptr[BR_FEC_M_MAX];
    for (unsigned j = 0; j < m; j++) {
        pptr[j] = orig[k + j];
    }
    CHECK_ERR(br_fec_encode(dptr, (uint8_t)k, (uint8_t)m, (uint16_t)bl, pptr), BR_OK);
    {
        uint8_t ref[BR_FEC_M_MAX][MAXB];
        ref_parity(dptr, k, m, bl, ref);
        for (unsigned j = 0; j < m; j++) {
            CHECK_MEM(ref[j], orig[k + j], bl);
        }
        if (m == 1) {
            uint8_t x[MAXB];
            memset(x, 0, sizeof x);
            for (unsigned i = 0; i < k; i++) {
                for (size_t p = 0; p < bl; p++) {
                    x[p] ^= orig[i][p];
                }
            }
            CHECK_MEM(x, orig[k], bl); /* XOR special case */
        }
    }

    /* choose n_erase distinct blocks, optionally biased towards data blocks */
    bool present[MAXN];
    for (unsigned i = 0; i < n; i++) {
        present[i] = true;
    }
    unsigned erased = 0;
    unsigned missing_data = 0;
    while (erased < n_erase) {
        unsigned pick = (prefer_data && tu_rng_below(rng, 4) != 0) ? tu_rng_below(rng, k) : tu_rng_below(rng, n);
        if (present[pick]) {
            present[pick] = false;
            erased++;
            if (pick < k) {
                missing_data++;
            }
        }
    }
    for (unsigned i = 0; i < n; i++) {
        if (present[i]) {
            memcpy(blk[i], orig[i], bl);
        } else {
            memset(blk[i], 0xA5, bl);
        }
    }
    uint8_t rec = 99;
    int rc = (int)br_fec_decode(blk, present, (uint8_t)k, (uint8_t)m, (uint16_t)bl, &rec);
    if (n_erase <= m) {
        CHECK_ERR(rc, BR_OK);
        if (rc == BR_OK) {
            recovered_trials++;
            CHECK_EQ_U32(rec, missing_data);
            for (unsigned i = 0; i < k; i++) {
                CHECK_MEM(orig[i], blk[i], bl);
            }
            for (unsigned i = 0; i < n; i++) {
                if (present[i]) {
                    CHECK_MEM(orig[i], blk[i], bl); /* present blocks untouched */
                } else if (i >= k) {
                    /* missing parity is not regenerated */
                    bool unchanged = true;
                    for (size_t p = 0; p < bl; p++) {
                        if (blk[i][p] != 0xA5) {
                            unchanged = false;
                        }
                    }
                    CHECK(unchanged);
                }
            }
            /* recovered blocks decode back into valid payloads */
            for (unsigned i = 0; i < k; i++) {
                const uint8_t *pl;
                uint8_t pn;
                CHECK_ERR(br_fec_payload_from_block(blk[i], (uint16_t)bl, &pl, &pn), BR_OK);
            }
        }
    } else {
        failed_trials++;
        CHECK_ERR(rc, BR_ERR_UNCORRECTABLE);
        for (unsigned i = 0; i < n; i++) {
            if (!present[i]) { /* nothing written */
                bool unchanged = true;
                for (size_t p = 0; p < bl; p++) {
                    if (blk[i][p] != 0xA5) {
                        unchanged = false;
                    }
                }
                CHECK(unchanged);
            } else {
                CHECK_MEM(orig[i], blk[i], bl);
            }
        }
    }
    for (unsigned i = 0; i < n; i++) {
        free(blk[i]);
        free(orig[i]);
    }
}

static void test_properties(void)
{
    tu_ctx("FEC properties");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xFEC0DEu);
    /* every (k, m) in the spec ranges (k 1..16, m 1..4) at a few block lengths, any m erasures */
    for (unsigned k = 1; k <= BR_FEC_K_MAX; k++) {
        for (unsigned m = 1; m <= BR_FEC_M_MAX; m++) {
            static const size_t bls[] = {1, 2, 9, 64};
            for (size_t bi = 0; bi < sizeof bls / sizeof bls[0]; bi++) {
                for (unsigned rep = 0; rep < 6; rep++) {
                    one_trial(&rng, k, m, bls[bi], m, rep & 1u);          /* exactly m erased: recovered */
                    one_trial(&rng, k, m, bls[bi], rep % (m + 1u), true);   /* 0..m erased */
                    one_trial(&rng, k, m, bls[bi], m + 1u, rep & 1u);      /* m + 1 erased: error */
                }
            }
        }
    }
    /* random k, m, block_len up to the maximum */
    for (unsigned it = 0; it < 400; it++) {
        unsigned k = 1u + tu_rng_below(&rng, BR_FEC_K_MAX);
        unsigned m = 1u + tu_rng_below(&rng, BR_FEC_M_MAX);
        size_t bl = (it % 5 == 0) ? MAXB : 1u + tu_rng_below(&rng, MAXB);
        one_trial(&rng, k, m, bl, tu_rng_below(&rng, m + 1u), true);
        one_trial(&rng, k, m, bl, m, true);
        one_trial(&rng, k, m, bl, m + 1u, false);
    }
    /* spec table defaults: 8/2, 8/4, 2/1, 16/2 */
    static const unsigned km[4][2] = {{8, 2}, {8, 4}, {2, 1}, {16, 2}};
    for (unsigned t = 0; t < 4; t++) {
        one_trial(&rng, km[t][0], km[t][1], MAXB, km[t][1], true);
        one_trial(&rng, km[t][0], km[t][1], 100, km[t][1], false);
    }
    CHECK(recovered_trials > 200u);
    CHECK(failed_trials > 100u);
}

int main(void)
{
    test_a5();
    test_block_codec();
    test_parity_hdr();
    test_args();
    test_properties();
    return tu_summary("test_fec");
}
