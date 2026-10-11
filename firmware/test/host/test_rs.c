// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_rs.c - Reed-Solomon over GF(2^8) (spec 3.2, A.3, A.4, A.15 parity).
 *
 * Conventions under test (br_rs.h): poly 0x11D, fcr 0, alpha 2, systematic with
 * the parity appended, erasure positions are 0-based codeword indices,
 * capacity 2 * errors + erasures <= nsym.
 */
#include "braid/br_rs.h"
#include "test_util.h"
#include "test_vectab.h"

static void synd_zero(const uint8_t *cw, size_t len, unsigned nsym, bool expect_zero)
{
    uint8_t s[BR_RS_MAX_NSYM];
    memset(s, 0xEE, sizeof s);
    CHECK_ERR(br_rs_syndromes(cw, len, (uint8_t)nsym, s), BR_OK);
    bool all0 = true;
    for (unsigned i = 0; i < nsym; i++) {
        if (s[i] != 0) {
            all0 = false;
        }
    }
    CHECK(all0 == expect_zero);
}

static void parity_vec(const char *name, const uint8_t *msg, size_t n, unsigned nsym, const uint8_t *exp)
{
    uint8_t par[BR_RS_MAX_NSYM];
    tu_ctx(name);
    memset(par, 0xEE, sizeof par);
    CHECK_ERR(br_rs_encode(msg, n, (uint8_t)nsym, par), BR_OK);
    CHECK_MEM(exp, par, nsym);
    /* reference oracle agrees with the vector */
    uint8_t ref[BR_RS_MAX_NSYM];
    tu_ref_rs_encode(msg, n, nsym, ref);
    CHECK_MEM(exp, ref, nsym);
    /* message || parity is a valid codeword */
    uint8_t cw[256];
    memcpy(cw, msg, n);
    memcpy(cw + n, exp, nsym);
    synd_zero(cw, n + nsym, nsym, true);
    uint8_t *w = tu_dup(cw, n + nsym);
    uint8_t cnt = 99;
    CHECK_ERR(br_rs_decode(w, n + nsym, (uint8_t)nsym, NULL, 0, &cnt), BR_OK);
    CHECK_EQ_U32(cnt, 0u);
    CHECK_MEM(cw, w, n + nsym);
    free(w);
}

static void test_vectors(void)
{
    parity_vec("A.3 RS(8) of UART SEEK", BRV_A3_FRAME, BRV_A3_FRAME_LEN, BRV_A3_RS_NSYM, BRV_A3_RS_PARITY);
    parity_vec("A.4 RS(6) 'ProbeLink'", BRV_A4_RS6_MESSAGE, BRV_A4_RS6_MESSAGE_LEN, BRV_A4_RS6_NSYM, BRV_A4_RS6_PARITY);
    parity_vec("A.4 RS(1)", BRV_A4_RS1_MESSAGE, BRV_A4_RS1_MESSAGE_LEN, BRV_A4_RS1_NSYM, BRV_A4_RS1_PARITY);
    parity_vec("A.15 RS(6) IR SEEK", BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, BRV_A15_SEEK_RS_NSYM, BRV_A15_SEEK_RS_PARITY);
    parity_vec("A.15 RS(6) IR HELLO", BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, BRV_A15_HELLO_RS_NSYM, BRV_A15_HELLO_RS_PARITY);

    tu_ctx("A.4 nsym=1 is XOR");
    uint8_t x = 0;
    for (size_t i = 0; i < BRV_A4_RS1_MESSAGE_LEN; i++) {
        x ^= BRV_A4_RS1_MESSAGE[i];
    }
    CHECK_EQ_U32(x, 0x92u);
    CHECK_EQ_U32(BRV_A4_RS1_PARITY[0], x);
    uint8_t p = 0;
    CHECK_ERR(br_rs_encode(BRV_A4_RS1_MESSAGE, BRV_A4_RS1_MESSAGE_LEN, 1, &p), BR_OK);
    CHECK_EQ_U32(p, 0x92u);
}

static void test_xor_property(void)
{
    tu_ctx("nsym=1 == XOR");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x1B1u);
    for (unsigned it = 0; it < 400; it++) {
        size_t n = 1u + tu_rng_below(&rng, 254);
        uint8_t m[255];
        tu_rng_fill(&rng, m, n);
        uint8_t x = 0;
        for (size_t i = 0; i < n; i++) {
            x ^= m[i];
        }
        uint8_t par = 0;
        CHECK_ERR(br_rs_encode(m, n, 1, &par), BR_OK);
        CHECK_EQ_U32(par, x);
        /* one erasure (any position, parity included) is repaired */
        uint8_t cw[256];
        memcpy(cw, m, n);
        cw[n] = x;
        uint8_t pos = (uint8_t)tu_rng_below(&rng, (uint32_t)n + 1u);
        uint8_t *w = tu_dup(cw, n + 1u);
        w[pos] = (uint8_t)(w[pos] ^ (uint8_t)(1u + tu_rng_below(&rng, 255)));
        uint8_t cnt = 99;
        CHECK_ERR(br_rs_decode(w, n + 1u, 1, &pos, 1, &cnt), BR_OK);
        CHECK_MEM(cw, w, n + 1u);
        CHECK_EQ_U32(cnt, 1u);
        free(w);
    }
}

static void pick_distinct(tu_rng_t *rng, size_t len, unsigned count, uint8_t *pos)
{
    for (unsigned i = 0; i < count; i++) {
        bool dup;
        do {
            pos[i] = (uint8_t)tu_rng_below(rng, (uint32_t)len);
            dup = false;
            for (unsigned j = 0; j < i; j++) {
                if (pos[j] == pos[i]) {
                    dup = true;
                }
            }
        } while (dup);
    }
}

static unsigned miscorrect_count;
static unsigned beyond_cases;

static void run_case(tu_rng_t *rng, size_t mlen, unsigned nsym, unsigned e, unsigned f)
{
    uint8_t msg[255];
    uint8_t cw[255];
    tu_rng_fill(rng, msg, mlen);
    memcpy(cw, msg, mlen);
    tu_ref_rs_encode(msg, mlen, nsym, cw + mlen);
    size_t len = mlen + nsym;

    uint8_t pos[64];
    pick_distinct(rng, len, e + f, pos); /* first e = unknown errors, next f = erasures */
    uint8_t *w = tu_dup(cw, len);
    for (unsigned i = 0; i < e; i++) {
        w[pos[i]] = (uint8_t)(w[pos[i]] ^ (uint8_t)(1u + tu_rng_below(rng, 255)));
    }
    for (unsigned i = 0; i < f; i++) {
        w[pos[e + i]] = tu_rng_u8(rng); /* garbage, may coincide with the true value */
    }
    uint8_t orig_damaged[255];
    memcpy(orig_damaged, w, len);

    uint8_t cnt = 99;
    uint8_t *er = f ? &pos[e] : NULL;
    int rc = (int)br_rs_decode(w, len, (uint8_t)nsym, er, (uint8_t)f, &cnt);
    if (2u * e + f <= nsym) {
        CHECK_ERR(rc, BR_OK);
        if (rc == BR_OK) {
            CHECK_MEM(cw, w, len);
            if (f == 0) {
                CHECK_EQ_U32(cnt, e);
            } else {
                CHECK(cnt <= e + f);
            }
        }
    } else {
        beyond_cases++;
        CHECK(rc == BR_OK || rc == BR_ERR_UNCORRECTABLE);
        if (rc == BR_ERR_UNCORRECTABLE) {
            CHECK_MEM(orig_damaged, w, len); /* "on any error the buffer is left unmodified" */
        } else if (rc == BR_OK) {
            /* allowed mis-correction, but the result must be a valid codeword */
            synd_zero(w, len, nsym, true);
            uint8_t par[BR_RS_MAX_NSYM];
            tu_ref_rs_encode(w, mlen, nsym, par);
            CHECK_MEM(par, w + mlen, nsym);
            if (memcmp(w, cw, len) != 0) {
                miscorrect_count++;
            }
        }
    }
    free(w);
}

static void test_properties(void)
{
    tu_ctx("RS properties");
    static const unsigned nsyms[] = {1, 2, 3, 4, 6, 8, 10, 16, 32};
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x5EED5u);
    for (size_t si = 0; si < sizeof nsyms / sizeof nsyms[0]; si++) {
        unsigned nsym = nsyms[si];
        for (unsigned it = 0; it < 120; it++) {
            size_t maxm = 255u - nsym;
            size_t mlen;
            switch (it % 6) {
            case 0: mlen = 1; break;
            case 1: mlen = maxm; break;
            case 2: mlen = 42; break;
            case 3: mlen = 1u + tu_rng_below(&rng, 20); break;
            default: mlen = 1u + tu_rng_below(&rng, (uint32_t)maxm); break;
            }
            /* parity vs reference + valid codeword */
            {
                uint8_t msg[255], par[BR_RS_MAX_NSYM], ref[BR_RS_MAX_NSYM];
                tu_rng_fill(&rng, msg, mlen);
                uint8_t *dm = tu_dup(msg, mlen);
                CHECK_ERR(br_rs_encode(dm, mlen, (uint8_t)nsym, par), BR_OK);
                tu_ref_rs_encode(msg, mlen, nsym, ref);
                CHECK_MEM(ref, par, nsym);
                free(dm);
                uint8_t cw[255];
                memcpy(cw, msg, mlen);
                memcpy(cw + mlen, par, nsym);
                synd_zero(cw, mlen + nsym, nsym, true);
                cw[tu_rng_below(&rng, (uint32_t)(mlen + nsym))] ^= 0x5A;
                synd_zero(cw, mlen + nsym, nsym, false);
            }
            /* errors only, up to capacity */
            for (unsigned e = 0; e <= nsym / 2u; e++) {
                run_case(&rng, mlen, nsym, e, 0);
            }
            /* erasures only, up to nsym */
            for (unsigned f = 1; f <= nsym; f += (nsym > 8 ? 3u : 1u)) {
                run_case(&rng, mlen, nsym, 0, f);
            }
            /* mixed at and below capacity */
            for (unsigned e = 1; 2u * e < nsym; e++) {
                unsigned fmax = nsym - 2u * e;
                run_case(&rng, mlen, nsym, e, fmax);
                run_case(&rng, mlen, nsym, e, 1u + tu_rng_below(&rng, fmax));
            }
            /* beyond capacity: one more error / erasure than allowed */
            if (mlen + nsym >= nsym / 2u + 2u) {
                run_case(&rng, mlen, nsym, nsym / 2u + 1u, 0);
                run_case(&rng, mlen, nsym, nsym / 2u + 3u > (mlen + nsym) ? nsym / 2u + 1u : nsym / 2u + 3u, 0);
            }
            if (nsym >= 2 && mlen + nsym > nsym) {
                unsigned e = nsym / 2u;
                unsigned f = nsym - 2u * e + 1u; /* 2e + f == nsym + 1 */
                if (e + f <= mlen + nsym && f <= nsym) {
                    run_case(&rng, mlen, nsym, e, f);
                }
            }
        }
    }
    CHECK(beyond_cases > 100u);
    printf("test_rs: %u beyond-capacity cases, %u mis-corrected (allowed)\n", beyond_cases, miscorrect_count);
}

static void test_vector_damage(void)
{
    tu_ctx("vector damage");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xBEEF);
    for (unsigned t = 0; t < 2; t++) {
        const uint8_t *frame = t ? BRV_A15_SEEK_FRAME : BRV_A3_FRAME;
        size_t flen = t ? BRV_A15_SEEK_FRAME_LEN : BRV_A3_FRAME_LEN;
        const uint8_t *par = t ? BRV_A15_SEEK_RS_PARITY : BRV_A3_RS_PARITY;
        unsigned nsym = t ? 6u : 8u;
        size_t len = flen + nsym;
        uint8_t cw[255];
        memcpy(cw, frame, flen);
        memcpy(cw + flen, par, nsym);
        /* a burst of nsym/2 bytes anywhere (the spec's sizing rule: rs_nsym >= 2 * B_max + 2 is for margin; capacity is nsym/2) */
        for (size_t start = 0; start + nsym / 2u <= len; start++) {
            uint8_t *w = tu_dup(cw, len);
            for (unsigned k = 0; k < nsym / 2u; k++) {
                w[start + k] = (uint8_t)~w[start + k];
            }
            uint8_t cnt = 0;
            CHECK_ERR(br_rs_decode(w, len, (uint8_t)nsym, NULL, 0, &cnt), BR_OK);
            CHECK_MEM(cw, w, len);
            CHECK_EQ_U32(cnt, nsym / 2u);
            free(w);
        }
        /* a whole-frame sweep of single-byte errors: all 256 values at one position */
        for (unsigned v = 1; v < 256; v++) {
            uint8_t *w = tu_dup(cw, len);
            size_t at = tu_rng_below(&rng, (uint32_t)len);
            w[at] = (uint8_t)(w[at] ^ v);
            CHECK_ERR(br_rs_decode(w, len, (uint8_t)nsym, NULL, 0, NULL), BR_OK); /* n_corrected_out may be NULL */
            CHECK_MEM(cw, w, len);
            free(w);
        }
        /* after RS the CRC must still verify (3.2: CRC checked after RS) */
        uint8_t *w = tu_dup(cw, len);
        w[3] ^= 0xFF;
        w[len - 1u] ^= 0x01;
        CHECK_ERR(br_rs_decode(w, len, (uint8_t)nsym, NULL, 0, NULL), BR_OK);
        CHECK_EQ_U32(tu_ref_crc16(w, flen - 2u), tu_get16(w + flen - 2u));
        free(w);
    }
}

static void test_args(void)
{
    tu_ctx("args");
    uint8_t m[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t par[40];
    CHECK_ERR(br_rs_encode(NULL, 8, 4, par), BR_ERR_ARG);
    CHECK_ERR(br_rs_encode(m, 8, 4, NULL), BR_ERR_ARG);
    CHECK_ERR(br_rs_encode(m, 8, 0, par), BR_ERR_ARG);
    CHECK_ERR(br_rs_encode(m, 8, 33, par), BR_ERR_ARG);
    {
        uint8_t zeros[300];
        memset(zeros, 0x11, sizeof zeros);
        CHECK_ERR(br_rs_encode(zeros, 224, 32, par), BR_ERR_TOO_BIG); /* 224 + 32 = 256 > 255 */
    }
    CHECK_ERR(br_rs_encode(m, 8, 4, par), BR_OK);
    {
        uint8_t big[223];
        memset(big, 0x37, sizeof big);
        CHECK_ERR(br_rs_encode(big, 223, 32, par), BR_OK); /* 255 exactly */
        uint8_t big2[255];
        memset(big2, 0x37, sizeof big2);
        CHECK_ERR(br_rs_encode(big2, 251, 4, par), BR_OK);
        CHECK_ERR(br_rs_encode(big2, 252, 4, par), BR_ERR_TOO_BIG);
    }
    /* empty message: allowed for encode (0..255-nsym); parity of nothing is zero */
    memset(par, 0xEE, sizeof par);
    CHECK_ERR(br_rs_encode(NULL, 0, 4, par), BR_OK);
    CHECK_EQ_U32(par[0] | par[1] | par[2] | par[3], 0u);

    uint8_t s_unused[BR_RS_MAX_NSYM];
    uint8_t cw[16];
    memcpy(cw, m, 8);
    tu_ref_rs_encode(m, 8, 4, cw + 8);
    uint8_t w[16];
    uint8_t pos[2] = {1, 2};
    memcpy(w, cw, 12);
    CHECK_ERR(br_rs_decode(NULL, 12, 4, NULL, 0, NULL), BR_ERR_ARG);
    CHECK_ERR(br_rs_decode(w, 12, 0, NULL, 0, NULL), BR_ERR_ARG);
    CHECK_ERR(br_rs_decode(w, 12, 33, NULL, 0, NULL), BR_ERR_ARG);
    CHECK_ERR(br_rs_decode(w, 4, 4, NULL, 0, NULL), BR_ERR_ARG);  /* len must be >= nsym + 1 */
    {
        uint8_t huge[300];
        memset(huge, 0, sizeof huge);
        CHECK_ERR(br_rs_decode(huge, 256, 4, NULL, 0, NULL), BR_ERR_ARG);
        CHECK_ERR(br_rs_syndromes(huge, 256, 4, s_unused), BR_ERR_ARG);
    }
    CHECK_ERR(br_rs_decode(w, 12, 4, NULL, 1, NULL), BR_ERR_ARG); /* erasures without a list */
    {
        uint8_t dup[2] = {3, 3};
        CHECK_ERR(br_rs_decode(w, 12, 4, dup, 2, NULL), BR_ERR_ARG);
        uint8_t oob[1] = {12};
        CHECK_ERR(br_rs_decode(w, 12, 4, oob, 1, NULL), BR_ERR_ARG);
        uint8_t many[5] = {0, 1, 2, 3, 4};
        CHECK_ERR(br_rs_decode(w, 12, 4, many, 5, NULL), BR_ERR_ARG); /* n_erase > nsym */
    }
    CHECK_ERR(br_rs_decode(w, 12, 4, pos, 2, NULL), BR_OK);
    CHECK_MEM(cw, w, 12);
    {
        int rc5 = (int)br_rs_decode(w, 5, 4, NULL, 0, NULL); /* shortest legal: 1 message byte; arbitrary content */
        CHECK(rc5 == BR_OK || rc5 == BR_ERR_UNCORRECTABLE);
    }
    /* nsym + 1 .. is accepted by syndromes too */
    uint8_t s[BR_RS_MAX_NSYM];
    CHECK_ERR(br_rs_syndromes(NULL, 12, 4, s), BR_ERR_ARG);
    CHECK_ERR(br_rs_syndromes(cw, 12, 4, NULL), BR_ERR_ARG);
    CHECK_ERR(br_rs_syndromes(cw, 12, 0, s), BR_ERR_ARG);
    CHECK_ERR(br_rs_syndromes(cw, 12, 33, s), BR_ERR_ARG);
    CHECK_ERR(br_rs_syndromes(cw, 4, 4, s), BR_ERR_ARG); /* nsym < len */
}

/* Random garbage: never crash, never read outside the buffer, valid result if OK. */
static void test_garbage(void)
{
    tu_ctx("random codewords");
    tu_rng_t rng;
    tu_rng_seed(&rng, 0xBADC0DEu);
    for (unsigned it = 0; it < 30000; it++) {
        unsigned nsym = 1u + tu_rng_below(&rng, BR_RS_MAX_NSYM);
        size_t len = nsym + 1u + tu_rng_below(&rng, 255u - nsym);
        uint8_t tmp[255];
        tu_rng_fill(&rng, tmp, len);
        if (tu_rng_below(&rng, 3) == 0) { /* near-valid: encode, then damage lightly */
            tu_ref_rs_encode(tmp, len - nsym, nsym, tmp + len - nsym);
            unsigned d = tu_rng_below(&rng, nsym + 3u);
            for (unsigned k = 0; k < d; k++) {
                tmp[tu_rng_below(&rng, (uint32_t)len)] ^= (uint8_t)(1u + tu_rng_below(&rng, 255));
            }
        }
        uint8_t *w = tu_dup(tmp, len);
        uint8_t er[32];
        unsigned f = tu_rng_below(&rng, 3) == 0 ? tu_rng_below(&rng, nsym + 1u) : 0;
        if (f > len) {
            f = 0;
        }
        for (unsigned i = 0; i < f; i++) {
            bool dup;
            do {
                er[i] = (uint8_t)tu_rng_below(&rng, (uint32_t)len);
                dup = false;
                for (unsigned j = 0; j < i; j++) {
                    dup = dup || er[j] == er[i];
                }
            } while (dup);
        }
        int rc = (int)br_rs_decode(w, len, (uint8_t)nsym, f ? er : NULL, (uint8_t)f, NULL);
        CHECK(rc == BR_OK || rc == BR_ERR_UNCORRECTABLE);
        if (rc == BR_OK) {
            uint8_t par[BR_RS_MAX_NSYM];
            tu_ref_rs_encode(w, len - nsym, nsym, par);
            CHECK_MEM(par, w + len - nsym, nsym);
        } else {
            CHECK_MEM(tmp, w, len);
        }
        free(w);
    }
}

int main(void)
{
    test_vectors();
    test_xor_property();
    test_properties();
    test_vector_damage();
    test_args();
    test_garbage();
    return tu_summary("test_rs");
}
