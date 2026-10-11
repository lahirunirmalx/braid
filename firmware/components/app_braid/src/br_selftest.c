// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_selftest.c - Appendix A replay for the phase 1a modules (see br_selftest.h).
 *
 * Every expected value comes from vectors_generated.h (tools/vectors.py).
 * Values computed here are either derived through the public API (key
 * schedule, frame layout) or algebraic identities (HMAC key hashing, CCM
 * round trips); no expected bytes are typed in by hand.
 */
#if !defined(BR_SELFTEST) || !BR_SELFTEST
#error "br_selftest.c is built only with BR_SELFTEST=1 (CMake option BR_SELFTEST)"
#endif

#include <string.h>

#include "braid/br_cobs.h"
#include "braid/br_crc16.h"
#include "braid/br_crypto.h"
#include "braid/br_fec.h"
#include "braid/br_frame.h"
#include "braid/br_platform.h"
#include "braid/br_rs.h"
#include "braid/br_selftest.h"

#include "mbedtls/sha256.h"

/* Appendix A vectors, TEST ONLY keys. From firmware/test/host (include path
 * added by the build only when BR_SELFTEST is set). */
#include "vectors_generated.h"

/* ------------------------------------------------------------------------- */
/* Check bookkeeping and logging                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *group;
    uint32_t run;
    uint32_t failed;
} st_t;

#define ST_TAG "br_selftest"
#define ST_LINE_CAP 160u

/*
 * Log lines are assembled with the small appenders below instead of
 * snprintf: no <stdio.h> in the core (newlib's stdio.h trips -Wpedantic on
 * ESP-IDF) and a few dozen bytes of stack instead of newlib vfprintf's ~1 KB.
 */
typedef struct {
    char s[ST_LINE_CAP];
    size_t n;
} st_line_t;

static void ln_str(st_line_t *l, const char *str)
{
    while (*str != '\0' && l->n + 1u < ST_LINE_CAP) {
        l->s[l->n++] = *str++;
    }
    l->s[l->n] = '\0';
}

/* Unsigned decimal, right-aligned in at least width characters. */
static void ln_u32(st_line_t *l, uint32_t v, size_t width)
{
    char d[10];
    size_t k = 0u;
    do {
        d[k++] = (char)('0' + (char)(v % 10u));
        v /= 10u;
    } while (v != 0u);
    for (size_t pad = k; pad < width; pad++) {
        ln_str(l, " ");
    }
    while (k > 0u && l->n + 1u < ST_LINE_CAP) {
        l->s[l->n++] = d[--k];
    }
    l->s[l->n] = '\0';
}

/* String left-aligned in at least width characters. */
static void ln_pad(st_line_t *l, const char *str, size_t width)
{
    const size_t start = l->n;
    ln_str(l, str);
    while (l->n - start < width) {
        ln_str(l, " ");
    }
}

static void st_emit(br_log_level_t level, const st_line_t *l)
{
    br_platform_t p;
    if (br_platform_get(&p) == BR_OK) {
        p.log(p.user, level, ST_TAG, l->s);
    }
}

static bool st_check(st_t *t, bool ok, const char *item, const char *what, int line)
{
    t->run++;
    if (!ok) {
        t->failed++;
        st_line_t l = {{0}, 0u};
        ln_str(&l, "FAIL [");
        ln_str(&l, t->group);
        ln_str(&l, "] br_selftest.c:");
        ln_u32(&l, (uint32_t)line, 0u);
        ln_str(&l, " ");
        ln_str(&l, item);
        ln_str(&l, ": ");
        ln_str(&l, what);
        st_emit(BR_LOG_ERROR, &l);
    }
    return ok;
}

/** Count one check; log the failing expression, the vector name and the line. */
#define CHK(t, item, cond) st_check((t), (cond), (item), #cond, __LINE__)

static bool eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static const uint8_t *str_u8(const char *s)
{
    return (const uint8_t *)s;
}

/* Scratch for frame-sized work (selftest builds only; keeps the task stack small). */
static struct {
    uint8_t a[BR_RS_MAX_CODEWORD + 8u];
    uint8_t b[BR_COBS_MAX_ENCODED(BR_RS_MAX_CODEWORD)];
    uint8_t c[BR_RS_MAX_CODEWORD + 8u];
} s_buf;

/* ------------------------------------------------------------------------- */
/* Vector tables (names and pointers only)                                    */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    const uint8_t *frame;    /* header .. CRC, no RS parity */
    size_t len;
    uint16_t crc;            /* expected CRC from the generator */
    uint8_t rs_nsym;         /* 0 packet, 8 UART, 6 IR */
    const uint8_t *parity;   /* rs_nsym bytes or NULL */
    uint16_t max_frame;      /* arrival link */
} st_frame_t;

static const st_frame_t k_frames[] = {
    {"A.2 SEEK", BRV_A2_FRAME, BRV_A2_FRAME_LEN, BRV_A2_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.3 SEEK UART", BRV_A3_FRAME, BRV_A3_FRAME_LEN, BRV_A3_CRC, BR_RS_NSYM_UART, BRV_A3_RS_PARITY, BR_MAX_FRAME_MESH},
    {"A.7 DATA", BRV_A7_FRAME, BRV_A7_FRAME_LEN, BRV_A7_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.8 SEEK hop1", BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, BRV_A8_SEEK_HOP1_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.8 SEEK hop2", BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, BRV_A8_SEEK_HOP2_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.8 DATA hop1", BRV_A8_DATA_HOP1_FRAME, BRV_A8_DATA_HOP1_FRAME_LEN, BRV_A8_DATA_HOP1_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.8 DATA hop2", BRV_A8_DATA_HOP2_FRAME, BRV_A8_DATA_HOP2_FRAME_LEN, BRV_A8_DATA_HOP2_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.8 DATA hop2 K0", BRV_A8_DATA_HOP2_K0_FRAME, BRV_A8_DATA_HOP2_K0_FRAME_LEN, BRV_A8_DATA_HOP2_K0_CRC, 0, NULL,
     BR_MAX_FRAME_MESH},
    {"A.9 HELLO", BRV_A9_HELLO_FRAME, BRV_A9_HELLO_FRAME_LEN, BRV_A9_HELLO_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.9 BIND", BRV_A9_BIND_FRAME, BRV_A9_BIND_FRAME_LEN, BRV_A9_BIND_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.10 DATA ROC1", BRV_A10_DATA_ROC1_FRAME, BRV_A10_DATA_ROC1_FRAME_LEN, BRV_A10_DATA_ROC1_CRC, 0, NULL,
     BR_MAX_FRAME_MESH},
    {"A.11 RESUME", BRV_A11_RESUME_FRAME, BRV_A11_RESUME_FRAME_LEN, BRV_A11_RESUME_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.12 MGMT_REQ", BRV_A12_REQ_FRAME, BRV_A12_REQ_FRAME_LEN, BRV_A12_REQ_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.12 MGMT_RESP", BRV_A12_RESP_FRAME, BRV_A12_RESP_FRAME_LEN, BRV_A12_RESP_CRC, 0, NULL, BR_MAX_FRAME_MESH},
    {"A.15 IR SEEK", BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, BRV_A15_SEEK_CRC, BR_RS_NSYM_IR, BRV_A15_SEEK_RS_PARITY,
     BR_MAX_FRAME_IR},
    {"A.15 IR HELLO", BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, BRV_A15_HELLO_CRC, BR_RS_NSYM_IR,
     BRV_A15_HELLO_RS_PARITY, BR_MAX_FRAME_IR},
};
#define N_FRAMES (sizeof k_frames / sizeof k_frames[0])

/* Every authenticated frame vector with its keys and CCM parameters. */
typedef struct {
    const char *name;
    const uint8_t *frame;
    size_t flen;
    const uint8_t *key;        /* Ke_* (16) */
    const uint8_t *hop_key;    /* K_hop (32) */
    const uint8_t *wrong_hop;  /* another epoch's K_hop (32) */
    uint8_t dir;
    uint32_t ctr_hi;
    const uint8_t *plain;      /* plaintext of the encrypted part; NULL if empty */
    size_t clear_len;
    const uint8_t *exp_nonce;  /* NULL if the generator gives none */
    const uint8_t *exp_aad;    /* NULL if the generator gives none */
    size_t exp_aad_len;
    const uint8_t *exp_tag;
} st_e2e_t;

static const st_e2e_t k_e2e[] = {
    {"A.7 DATA", BRV_A7_FRAME, BRV_A7_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0, BR_DIR_TO_PROBE, 0,
     BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 SEEK hop1", BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, BRV_A8_SEEK_KEY, BRV_A8_SEEK_HOP_KEY,
     BRV_A6_K_HOP_0, BR_DIR_TO_PROBE, 1, NULL, BR_LEN_SEEK, BRV_A8_SEEK_NONCE, BRV_A8_SEEK_AAD, BRV_A8_SEEK_AAD_LEN,
     BRV_A8_SEEK_CCM_TAG},
    {"A.8 SEEK hop2", BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, BRV_A8_SEEK_KEY, BRV_A8_SEEK_HOP_KEY,
     BRV_A6_K_HOP_0, BR_DIR_TO_PROBE, 1, NULL, BR_LEN_SEEK, BRV_A8_SEEK_NONCE, BRV_A8_SEEK_AAD, BRV_A8_SEEK_AAD_LEN,
     BRV_A8_SEEK_CCM_TAG},
    {"A.8 DATA hop1", BRV_A8_DATA_HOP1_FRAME, BRV_A8_DATA_HOP1_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0,
     BR_DIR_TO_PROBE, 0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 DATA hop2", BRV_A8_DATA_HOP2_FRAME, BRV_A8_DATA_HOP2_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0,
     BR_DIR_TO_PROBE, 0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN, BRV_A7_CCM_TAG},
    {"A.8 DATA hop2 K0", BRV_A8_DATA_HOP2_K0_FRAME, BRV_A8_DATA_HOP2_K0_FRAME_LEN, BRV_A7_KEY, BRV_A8_DATA_HOP2_K0_KEY,
     BRV_A6_K_HOP_1, BR_DIR_TO_PROBE, 0, BRV_A7_PLAINTEXT, 0, BRV_A7_NONCE, BRV_A7_AAD, BRV_A7_AAD_LEN,
     BRV_A7_CCM_TAG},
    {"A.9 HELLO", BRV_A9_HELLO_FRAME, BRV_A9_HELLO_FRAME_LEN, BRV_A9_KE_HELLO, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0,
     BR_DIR_FROM_PROBE, BRV_A9_HELLO_CTR_HI, BRV_A9_HELLO_SECRET, BR_LEN_PRE_CTR, BRV_A9_HELLO_NONCE, BRV_A9_HELLO_AAD,
     BRV_A9_HELLO_AAD_LEN, BRV_A9_HELLO_TAG},
    {"A.9 BIND", BRV_A9_BIND_FRAME, BRV_A9_BIND_FRAME_LEN, BRV_A9_KE_HS, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0,
     BR_DIR_TO_PROBE, 1, BRV_A9_BIND_SECRET, BR_LEN_PRE_CTR, BRV_A9_BIND_NONCE, NULL, 0, BRV_A9_BIND_TAG},
    {"A.10 DATA ROC1", BRV_A10_DATA_ROC1_FRAME, BRV_A10_DATA_ROC1_FRAME_LEN, BRV_A7_KEY, BRV_A7_HOP_KEY,
     BRV_A6_K_HOP_0, BR_DIR_TO_PROBE, BRV_A10_ROC, BRV_A7_PLAINTEXT, 0, BRV_A10_NONCE, NULL, 0, BRV_A10_CCM_TAG},
    {"A.11 RESUME", BRV_A11_RESUME_FRAME, BRV_A11_RESUME_FRAME_LEN, BRV_A11_KEY, BRV_A7_HOP_KEY, BRV_A6_K_HOP_0,
     BR_DIR_TO_PROBE, 0, NULL, BR_LEN_RESUME, BRV_A11_NONCE, NULL, 0, BRV_A11_CCM_TAG},
    {"A.12 MGMT_REQ", BRV_A12_REQ_FRAME, BRV_A12_REQ_FRAME_LEN, BRV_A12_K_MGMT_0042_0001, BRV_A7_HOP_KEY,
     BRV_A6_K_HOP_0, BR_DIR_TO_PROBE, 1, BRV_A12_REQ_SECRET, BR_LEN_PRE_CTR, BRV_A12_REQ_NONCE, BRV_A12_REQ_AAD,
     BRV_A12_REQ_AAD_LEN, BRV_A12_REQ_TAG},
    {"A.12 MGMT_RESP", BRV_A12_RESP_FRAME, BRV_A12_RESP_FRAME_LEN, BRV_A12_K_MGMT_0042_0001, BRV_A7_HOP_KEY,
     BRV_A6_K_HOP_0, BR_DIR_FROM_PROBE, 2, BRV_A12_RESP_SECRET, BR_LEN_PRE_CTR, BRV_A12_RESP_NONCE,
     BRV_A12_RESP_AAD, BRV_A12_RESP_AAD_LEN, BRV_A12_RESP_TAG},
    {"A.15 IR SEEK", BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, BRV_A15_KE_EDGE, BRV_A15_K_HOP_EDGE, BRV_A7_HOP_KEY,
     BR_DIR_TO_PROBE, 0, NULL, BR_LEN_SEEK, NULL, NULL, 0, BRV_A15_SEEK_CCM_TAG},
    {"A.15 IR HELLO", BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, BRV_A15_KE_HELLO_EDGE, BRV_A15_K_HOP_EDGE,
     BRV_A7_HOP_KEY, BR_DIR_FROM_PROBE, 0, BRV_A15_HELLO_SECRET, BR_LEN_PRE_CTR, NULL, NULL, 0, BRV_A15_HELLO_TAG},
};
#define N_E2E (sizeof k_e2e / sizeof k_e2e[0])

/* Layout of a laid-out frame vector (header parsed through the public codec). */
typedef struct {
    br_hdr_t hdr;
    size_t hl;
    size_t auth_off;
    size_t hop_off;
} st_layout_t;

static bool layout(const uint8_t *frame, size_t len, st_layout_t *l)
{
    if (br_hdr_decode(frame, len, &l->hdr, &l->hl) != BR_OK) {
        return false;
    }
    l->auth_off = l->hl + l->hdr.len;
    l->hop_off = l->auth_off + BR_AUTH_TAG_LEN;
    return l->hop_off + BR_HOP_TAG_LEN + BR_CRC_LEN <= len;
}

/* ------------------------------------------------------------------------- */
/* crc                                                                        */
/* ------------------------------------------------------------------------- */

static void group_crc(st_t *t)
{
    uint16_t crc = 0u;
    CHK(t, "A.1", br_crc16(BRV_A1_CRC_INPUT, BRV_A1_CRC_INPUT_LEN, &crc) == BR_OK);
    CHK(t, "A.1", crc == BRV_A1_CRC_EXPECTED);

    uint16_t part = 0u;
    CHK(t, "A.1 incremental", br_crc16_update(BR_CRC16_INIT, BRV_A1_CRC_INPUT, 4u, &part) == BR_OK);
    CHK(t, "A.1 incremental",
        br_crc16_update(part, BRV_A1_CRC_INPUT + 4, BRV_A1_CRC_INPUT_LEN - 4u, &part) == BR_OK);
    CHK(t, "A.1 incremental", part == BRV_A1_CRC_EXPECTED);

    for (size_t i = 0u; i < N_FRAMES; i++) {
        const st_frame_t *v = &k_frames[i];
        const size_t body = v->len - BR_CRC_LEN;
        CHK(t, v->name, br_crc16(v->frame, body, &crc) == BR_OK);
        CHK(t, v->name, crc == v->crc);
        CHK(t, v->name, br_rd_le16(&v->frame[body]) == v->crc);
    }
}

/* ------------------------------------------------------------------------- */
/* cobs                                                                       */
/* ------------------------------------------------------------------------- */

static void group_cobs(st_t *t)
{
    size_t n = 0u;
    /* A.3: the COBS input is the UART frame followed by its RS(8) parity. */
    CHK(t, "A.3", BRV_A3_COBS_INPUT_LEN == BRV_A3_FRAME_LEN + BRV_A3_RS_PARITY_LEN);
    CHK(t, "A.3", eq(BRV_A3_COBS_INPUT, BRV_A3_FRAME, BRV_A3_FRAME_LEN));
    CHK(t, "A.3", eq(BRV_A3_COBS_INPUT + BRV_A3_FRAME_LEN, BRV_A3_RS_PARITY, BRV_A3_RS_PARITY_LEN));

    CHK(t, "A.3 encode",
        br_cobs_encode(BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, s_buf.b, sizeof s_buf.b, &n) == BR_OK);
    CHK(t, "A.3 encode", n == BRV_A3_COBS_WIRE_LEN && eq(s_buf.b, BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN));

    CHK(t, "A.3 decode", br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN, s_buf.a, sizeof s_buf.a, &n) == BR_OK);
    CHK(t, "A.3 decode", n == BRV_A3_COBS_INPUT_LEN && eq(s_buf.a, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN));
    /* without the trailing delimiter (N11) */
    CHK(t, "A.3 decode no delim",
        br_cobs_decode(BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN - 1u, s_buf.a, sizeof s_buf.a, &n) == BR_OK);
    CHK(t, "A.3 decode no delim", n == BRV_A3_COBS_INPUT_LEN && eq(s_buf.a, BRV_A3_COBS_INPUT, n));

    /* an embedded 0x00 is a framing error */
    memcpy(s_buf.c, BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN);
    s_buf.c[10] = 0x00u;
    CHK(t, "A.3 embedded zero",
        br_cobs_decode(s_buf.c, BRV_A3_COBS_WIRE_LEN, s_buf.a, sizeof s_buf.a, &n) == BR_ERR_DECODE);

    /* every frame vector (with RS parity on RAW links) survives a round trip */
    for (size_t i = 0u; i < N_FRAMES; i++) {
        const st_frame_t *v = &k_frames[i];
        size_t wl = v->len;
        memcpy(s_buf.c, v->frame, v->len);
        if (v->rs_nsym > 0u) {
            memcpy(&s_buf.c[v->len], v->parity, v->rs_nsym);
            wl += v->rs_nsym;
        }
        size_t el = 0u;
        size_t dl = 0u;
        CHK(t, v->name, br_cobs_encode(s_buf.c, wl, s_buf.b, sizeof s_buf.b, &el) == BR_OK);
        CHK(t, v->name, el <= BR_COBS_MAX_ENCODED(wl) && el >= 2u);
        CHK(t, v->name, memchr(s_buf.b, 0, el - 1u) == NULL && s_buf.b[el - 1u] == BR_COBS_DELIM);
        CHK(t, v->name, br_cobs_decode(s_buf.b, el, s_buf.a, sizeof s_buf.a, &dl) == BR_OK);
        CHK(t, v->name, dl == wl && eq(s_buf.a, s_buf.c, wl));
    }
}

/* ------------------------------------------------------------------------- */
/* rs                                                                         */
/* ------------------------------------------------------------------------- */

/* Codeword = frame || parity into dst; returns its length. */
static size_t codeword(const st_frame_t *v, uint8_t *dst)
{
    memcpy(dst, v->frame, v->len);
    memcpy(&dst[v->len], v->parity, v->rs_nsym);
    return v->len + v->rs_nsym;
}

static void group_rs(st_t *t)
{
    uint8_t par[BR_RS_MAX_NSYM];
    CHK(t, "A.4 RS6", br_rs_encode(BRV_A4_RS6_MESSAGE, BRV_A4_RS6_MESSAGE_LEN, (uint8_t)BRV_A4_RS6_NSYM, par) == BR_OK);
    CHK(t, "A.4 RS6", eq(par, BRV_A4_RS6_PARITY, BRV_A4_RS6_PARITY_LEN));
    CHK(t, "A.4 RS1", br_rs_encode(BRV_A4_RS1_MESSAGE, BRV_A4_RS1_MESSAGE_LEN, (uint8_t)BRV_A4_RS1_NSYM, par) == BR_OK);
    CHK(t, "A.4 RS1", eq(par, BRV_A4_RS1_PARITY, BRV_A4_RS1_PARITY_LEN));

    for (size_t i = 0u; i < N_FRAMES; i++) {
        const st_frame_t *v = &k_frames[i];
        if (v->rs_nsym == 0u) {
            continue;
        }
        CHK(t, v->name, br_rs_encode(v->frame, v->len, v->rs_nsym, par) == BR_OK);
        CHK(t, v->name, eq(par, v->parity, v->rs_nsym));
        const size_t cl = codeword(v, s_buf.a);
        uint8_t synd[BR_RS_MAX_NSYM];
        uint8_t zero[BR_RS_MAX_NSYM];
        memset(zero, 0, sizeof zero);
        CHK(t, v->name, br_rs_syndromes(s_buf.a, cl, v->rs_nsym, synd) == BR_OK);
        CHK(t, v->name, eq(synd, zero, v->rs_nsym));
        uint8_t nc = 0xFFu;
        CHK(t, v->name, br_rs_decode(s_buf.a, cl, v->rs_nsym, NULL, 0u, &nc) == BR_OK && nc == 0u);
    }

    /* A.3 UART codeword, nsym 8: 4 errors (2e = 8) */
    const st_frame_t *u = &k_frames[1];
    const st_frame_t *ir = &k_frames[N_FRAMES - 1u];
    size_t cl = codeword(u, s_buf.c);
    uint8_t nc = 0u;
    {
        static const uint8_t pos[] = {0u, 13u, 27u, 49u};
        memcpy(s_buf.a, s_buf.c, cl);
        for (size_t k = 0u; k < sizeof pos; k++) {
            s_buf.a[pos[k]] ^= (uint8_t)(0x5Au + k);
        }
        CHK(t, "A.3 4 errors", br_rs_decode(s_buf.a, cl, u->rs_nsym, NULL, 0u, &nc) == BR_OK);
        CHK(t, "A.3 4 errors", nc == 4u && eq(s_buf.a, s_buf.c, cl));
    }
    /* 2 errors + 4 erasures (2e + f = 8) */
    {
        static const uint8_t err[] = {5u, 40u};
        static const uint8_t ers[] = {1u, 2u, 30u, 45u};
        memcpy(s_buf.a, s_buf.c, cl);
        for (size_t k = 0u; k < sizeof err; k++) {
            s_buf.a[err[k]] ^= 0xA5u;
        }
        for (size_t k = 0u; k < sizeof ers; k++) {
            s_buf.a[ers[k]] = 0x00u;
        }
        CHK(t, "A.3 2 errors + 4 erasures",
            br_rs_decode(s_buf.a, cl, u->rs_nsym, ers, (uint8_t)sizeof ers, &nc) == BR_OK);
        CHK(t, "A.3 2 errors + 4 erasures", eq(s_buf.a, s_buf.c, cl));
    }
    /* 8 erasures, parity included */
    {
        static const uint8_t ers[] = {0u, 7u, 14u, 21u, 28u, 35u, 42u, 49u};
        memcpy(s_buf.a, s_buf.c, cl);
        for (size_t k = 0u; k < sizeof ers; k++) {
            s_buf.a[ers[k]] = (uint8_t)~s_buf.a[ers[k]];
        }
        CHK(t, "A.3 8 erasures", br_rs_decode(s_buf.a, cl, u->rs_nsym, ers, (uint8_t)sizeof ers, &nc) == BR_OK);
        CHK(t, "A.3 8 erasures", nc == 8u && eq(s_buf.a, s_buf.c, cl));
    }
    /* beyond capacity (5 errors): never the original frame accepted silently.
     * Either UNCORRECTABLE with the buffer untouched, or a mis-correction
     * that the CRC (checked after RS, 3.2) rejects. */
    {
        static const uint8_t pos[] = {3u, 11u, 19u, 33u, 47u};
        memcpy(s_buf.a, s_buf.c, cl);
        for (size_t k = 0u; k < sizeof pos; k++) {
            s_buf.a[pos[k]] ^= 0x3Cu;
        }
        memcpy(s_buf.b, s_buf.a, cl);
        const br_err_t rc = br_rs_decode(s_buf.a, cl, u->rs_nsym, NULL, 0u, &nc);
        bool safe = false;
        if (rc == BR_ERR_UNCORRECTABLE) {
            safe = eq(s_buf.a, s_buf.b, cl);
        } else if (rc == BR_OK) {
            uint16_t crc = 0u;
            const size_t body = u->len - BR_CRC_LEN;
            safe = !eq(s_buf.a, s_buf.c, cl) && br_crc16(s_buf.a, body, &crc) == BR_OK &&
                   crc != br_rd_le16(&s_buf.a[body]);
        }
        CHK(t, "A.3 5 errors (beyond capacity)", safe);
    }
    /* A.15 IR HELLO codeword, nsym 6: 3 errors, then 1 error + 4 erasures */
    cl = codeword(ir, s_buf.c);
    {
        static const uint8_t pos[] = {2u, 30u, 66u};
        memcpy(s_buf.a, s_buf.c, cl);
        for (size_t k = 0u; k < sizeof pos; k++) {
            s_buf.a[pos[k]] ^= 0xFFu;
        }
        CHK(t, "A.15 3 errors", br_rs_decode(s_buf.a, cl, ir->rs_nsym, NULL, 0u, &nc) == BR_OK);
        CHK(t, "A.15 3 errors", nc == 3u && eq(s_buf.a, s_buf.c, cl));
    }
    {
        static const uint8_t ers[] = {0u, 20u, 40u, 60u};
        memcpy(s_buf.a, s_buf.c, cl);
        s_buf.a[10] ^= 0x01u;
        for (size_t k = 0u; k < sizeof ers; k++) {
            s_buf.a[ers[k]] ^= 0x80u;
        }
        CHK(t, "A.15 1 error + 4 erasures",
            br_rs_decode(s_buf.a, cl, ir->rs_nsym, ers, (uint8_t)sizeof ers, &nc) == BR_OK);
        CHK(t, "A.15 1 error + 4 erasures", eq(s_buf.a, s_buf.c, cl));
    }
}

/* ------------------------------------------------------------------------- */
/* fec                                                                        */
/* ------------------------------------------------------------------------- */

static void group_fec(st_t *t)
{
    /* k 2 / m 1 */
    {
        uint8_t p0[BRV_A5_K2M1_PARITY0_LEN];
        const uint8_t *data[2] = {BRV_A5_K2M1_BLOCK0, BRV_A5_K2M1_BLOCK1};
        uint8_t *const par[1] = {p0};
        const uint16_t bl = (uint16_t)BRV_A5_K2M1_BLOCK0_LEN;
        CHK(t, "A.5 k2m1", br_fec_encode(data, (uint8_t)BRV_A5_K2M1_K, (uint8_t)BRV_A5_K2M1_M, bl, par) == BR_OK);
        CHK(t, "A.5 k2m1", eq(p0, BRV_A5_K2M1_PARITY0, BRV_A5_K2M1_PARITY0_LEN));

        uint8_t b0[BRV_A5_K2M1_BLOCK0_LEN];
        uint8_t b1[BRV_A5_K2M1_BLOCK1_LEN];
        memset(b0, 0xEE, sizeof b0);
        memcpy(b1, BRV_A5_K2M1_BLOCK1, sizeof b1);
        uint8_t *const blocks[3] = {b0, b1, p0};
        const bool present[3] = {false, true, true};
        uint8_t nrec = 0u;
        CHK(t, "A.5 k2m1 erase 0", br_fec_decode(blocks, present, 2u, 1u, bl, &nrec) == BR_OK);
        CHK(t, "A.5 k2m1 erase 0", nrec == 1u && eq(b0, BRV_A5_K2M1_BLOCK0, sizeof b0));
        const uint8_t *pl = NULL;
        uint8_t plen = 0u;
        CHK(t, "A.5 k2m1 payload", br_fec_payload_from_block(b0, bl, &pl, &plen) == BR_OK);
        CHK(t, "A.5 k2m1 payload", plen == b0[0] && pl == &b0[1]);
        uint8_t rb[BRV_A5_K2M1_BLOCK0_LEN];
        CHK(t, "A.5 k2m1 block", br_fec_block_from_payload(pl, plen, bl, rb) == BR_OK);
        CHK(t, "A.5 k2m1 block", eq(rb, BRV_A5_K2M1_BLOCK0, sizeof rb));
    }
    /* k 4 / m 2 */
    {
        const uint16_t bl = (uint16_t)BRV_A5_K4M2_BLOCK0_LEN;
        uint8_t p[2][BRV_A5_K4M2_PARITY0_LEN];
        const uint8_t *data[4] = {BRV_A5_K4M2_BLOCK0, BRV_A5_K4M2_BLOCK1, BRV_A5_K4M2_BLOCK2, BRV_A5_K4M2_BLOCK3};
        uint8_t *const par[2] = {p[0], p[1]};
        CHK(t, "A.5 k4m2", br_fec_encode(data, (uint8_t)BRV_A5_K4M2_K, (uint8_t)BRV_A5_K4M2_M, bl, par) == BR_OK);
        CHK(t, "A.5 k4m2", eq(p[0], BRV_A5_K4M2_PARITY0, BRV_A5_K4M2_PARITY0_LEN));
        CHK(t, "A.5 k4m2", eq(p[1], BRV_A5_K4M2_PARITY1, BRV_A5_K4M2_PARITY1_LEN));

        uint8_t b[6][BRV_A5_K4M2_BLOCK0_LEN];
        uint8_t *const blocks[6] = {b[0], b[1], b[2], b[3], b[4], b[5]};
        bool present[6];
        uint8_t nrec = 0u;

        /* the generator's erasure set {1, 3} */
        for (size_t i = 0u; i < 4u; i++) {
            memcpy(b[i], data[i], bl);
        }
        memcpy(b[4], p[0], bl);
        memcpy(b[5], p[1], bl);
        for (size_t i = 0u; i < 6u; i++) {
            present[i] = true;
        }
        for (size_t i = 0u; i < BRV_A5_K4M2_ERASED_LEN; i++) {
            const size_t e = BRV_A5_K4M2_ERASED[i];
            memset(b[e], 0xEE, bl);
            present[e] = false;
        }
        CHK(t, "A.5 k4m2 erase {1,3}", br_fec_decode(blocks, present, 4u, 2u, bl, &nrec) == BR_OK);
        CHK(t, "A.5 k4m2 erase {1,3}", nrec == BRV_A5_K4M2_ERASED_LEN);
        for (size_t i = 0u; i < 4u; i++) {
            CHK(t, "A.5 k4m2 erase {1,3}", eq(b[i], data[i], bl));
        }

        /* one data and one parity block lost */
        for (size_t i = 0u; i < 4u; i++) {
            memcpy(b[i], data[i], bl);
            present[i] = true;
        }
        memset(b[0], 0xEE, bl);
        present[0] = false;
        present[4] = false;
        CHK(t, "A.5 k4m2 erase {0,P0}", br_fec_decode(blocks, present, 4u, 2u, bl, &nrec) == BR_OK);
        CHK(t, "A.5 k4m2 erase {0,P0}", nrec == 1u && eq(b[0], data[0], bl));

        /* three of six lost: fewer than k present */
        present[0] = false;
        present[1] = false;
        present[2] = false;
        present[4] = true;
        CHK(t, "A.5 k4m2 3 lost", br_fec_decode(blocks, present, 4u, 2u, bl, &nrec) == BR_ERR_UNCORRECTABLE);
    }
    /* PARITY payload header round trip (3.3) */
    {
        const br_fec_parity_hdr_t h = {0xFFFEu, 4u, 2u, 1u, (uint16_t)BRV_A5_K4M2_BLOCK0_LEN, 0u};
        uint8_t raw[BR_FEC_PARITY_HDR_LEN + BRV_A5_K4M2_PARITY1_LEN];
        br_fec_parity_hdr_t d;
        memcpy(&raw[BR_FEC_PARITY_HDR_LEN], BRV_A5_K4M2_PARITY1, BRV_A5_K4M2_PARITY1_LEN);
        CHK(t, "PARITY hdr", br_fec_parity_hdr_encode(&h, raw, sizeof raw) == BR_OK);
        CHK(t, "PARITY hdr", br_rd_le16(raw) == 0xFFFEu && raw[2] == 4u && raw[3] == 2u && raw[4] == 1u);
        CHK(t, "PARITY hdr", br_fec_parity_hdr_decode(raw, sizeof raw, &d) == BR_OK);
        CHK(t, "PARITY hdr", d.first_seq == h.first_seq && d.k == h.k && d.m == h.m && d.idx == h.idx &&
                                 d.block_len == h.block_len);
        CHK(t, "PARITY hdr", br_fec_parity_hdr_decode(raw, sizeof raw - 1u, &d) == BR_ERR_DECODE);
    }
}

/* ------------------------------------------------------------------------- */
/* frame                                                                      */
/* ------------------------------------------------------------------------- */

static void group_frame(st_t *t)
{
    for (size_t i = 0u; i < N_FRAMES; i++) {
        const st_frame_t *v = &k_frames[i];
        br_hdr_t h;
        size_t hl = 0u;
        if (!CHK(t, v->name, br_hdr_decode(v->frame, v->len, &h, &hl) == BR_OK)) {
            continue;
        }
        CHK(t, v->name, hl == br_hdr_len_for_type(h.type));
        const bool auth = (h.flags & BR_FLAG_AUTH) != 0u;
        const size_t tags = auth ? BR_TAGS_LEN : 0u;
        CHK(t, v->name, hl + h.len + tags + BR_CRC_LEN == v->len);

        /* header re-encode */
        uint8_t hb[BR_HDR_LEN_SEEK];
        size_t hw = 0u;
        CHK(t, v->name, br_hdr_encode(&h, hb, sizeof hb, &hw) == BR_OK && hw == hl && eq(hb, v->frame, hl));

        /* whole-frame encode reproduces the vector byte for byte */
        const uint8_t *at = auth ? &v->frame[hl + h.len] : NULL;
        const uint8_t *ht = auth ? &v->frame[hl + h.len + BR_AUTH_TAG_LEN] : NULL;
        size_t out = 0u;
        CHK(t, v->name, br_frame_encode(&h, &v->frame[hl], h.len, at, ht, s_buf.a, sizeof s_buf.a, &out) == BR_OK);
        CHK(t, v->name, out == v->len && eq(s_buf.a, v->frame, v->len));
        CHK(t, v->name, br_frame_seal_crc(s_buf.a, v->len - BR_CRC_LEN, sizeof s_buf.a, &out) == BR_OK &&
                            out == v->len && eq(s_buf.a, v->frame, v->len));

        /* receive validation on its arrival link (endpoint) */
        const br_link_params_t link = {v->max_frame, v->rs_nsym};
        size_t wl = v->len;
        memcpy(s_buf.c, v->frame, v->len);
        if (v->rs_nsym > 0u) {
            memcpy(&s_buf.c[v->len], v->parity, v->rs_nsym);
            wl += v->rs_nsym;
        }
        br_frame_view_t view;
        br_reject_t rej = BR_REJ_LEN_SHORT;
        CHK(t, v->name, br_frame_validate(s_buf.c, wl, &link, true, &view, &rej) == BR_OK && rej == BR_REJ_NONE);
        CHK(t, v->name, view.crc == v->crc && view.payload_len == h.len && view.total_len == wl &&
                            view.has_auth == auth && view.rs_nsym == v->rs_nsym);
        if (auth) {
            CHK(t, v->name, view.auth_tag_off == hl + h.len && view.hop_tag_off == hl + h.len + BR_AUTH_TAG_LEN);
        }
        CHK(t, v->name, br_frame_check_type_len(h.type, h.len, &rej) == BR_OK && rej == BR_REJ_NONE);

        /* frames carrying a clear pre_ctr: header seq == low 16 bits (session_id 0) */
        size_t clear = 0u;
        CHK(t, v->name, br_frame_clear_len(h.type, h.session_id, h.len, &clear) == BR_OK);
        if (clear >= BR_LEN_PRE_CTR) {
            uint32_t pre = 0u;
            CHK(t, v->name, br_frame_pre_ctr(s_buf.c, &view, &pre, &rej) == BR_OK && rej == BR_REJ_NONE);
            CHK(t, v->name, pre == br_rd_le32(&v->frame[hl]));
        }

        /* one flipped payload bit is a CRC reject (crc_fail) */
        memcpy(s_buf.a, s_buf.c, wl);
        s_buf.a[hl] ^= 0x01u;
        CHK(t, v->name, br_frame_validate(s_buf.a, wl, &link, true, NULL, &rej) == BR_ERR_REJECT && rej == BR_REJ_CRC);

        /* RAW link receive path: RS repairs line damage, then the frame validates */
        if (v->rs_nsym > 0u) {
            s_buf.a[1] ^= 0x40u;
            uint8_t nc = 0u;
            CHK(t, v->name, br_rs_decode(s_buf.a, wl, v->rs_nsym, NULL, 0u, &nc) == BR_OK && nc == 2u);
            CHK(t, v->name, br_frame_validate(s_buf.a, wl, &link, true, NULL, &rej) == BR_OK);
            CHK(t, v->name, eq(s_buf.a, s_buf.c, wl));
        }
    }

    /* A.10 ROC estimate cases */
    for (size_t i = 0u; i < BRV_A10_ROC_CASE_COUNT; i++) {
        const brv_roc_case_t *rc = &BRV_A10_ROC_CASES[i];
        uint32_t roc = 0xFFFFFFFFu;
        CHK(t, "A.10 ROC", br_roc_estimate(rc->seq, rc->highest, rc->roc, &roc) == BR_OK && roc == rc->expected);
    }
}

/* ------------------------------------------------------------------------- */
/* Key schedule helpers (8.2)                                                 */
/* ------------------------------------------------------------------------- */

/** Expand(Extract(BR_LABEL_V1, ikm32), label || tail, outlen). */
static bool kdf_v1(br_crypto_t *c, const uint8_t *ikm, const char *label, const uint8_t *tail, size_t tail_len,
                   uint8_t *out, size_t outlen)
{
    uint8_t prk[BR_SHA256_LEN];
    uint8_t info[48];
    const size_t ll = strlen(label);
    if (ll + tail_len > sizeof info) {
        return false;
    }
    memcpy(info, label, ll);
    if (tail_len > 0u) {
        memcpy(&info[ll], tail, tail_len);
    }
    bool ok = br_hkdf_extract(c, str_u8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), ikm, 32u, prk) == BR_OK &&
              br_hkdf_expand(c, prk, sizeof prk, info, ll + tail_len, out, outlen) == BR_OK;
    br_secure_zero(prk, sizeof prk);
    return ok;
}

static bool k_mesh(br_crypto_t *c, uint8_t e, uint8_t out[32])
{
    return br_hkdf_sha256(c, str_u8(BR_LABEL_MESH), BR_LABEL_LEN(BR_LABEL_MESH), BRV_A6_K_SITE, 32u, &e, 1u, out, 32u) == BR_OK;
}

static bool k_pair(br_crypto_t *c, uint16_t a, uint16_t b, uint8_t e, uint8_t out[32])
{
    uint8_t info[5];
    br_wr_le16(&info[0], (a < b) ? a : b);
    br_wr_le16(&info[2], (a < b) ? b : a);
    info[4] = e;
    return br_hkdf_sha256(c, str_u8(BR_LABEL_PAIR), BR_LABEL_LEN(BR_LABEL_PAIR), BRV_A6_K_SITE, 32u, info, sizeof info, out, 32u) == BR_OK;
}

static bool k_node(br_crypto_t *c, uint16_t n, uint8_t out[32])
{
    uint8_t info[2];
    br_wr_le16(info, n);
    return br_hkdf_sha256(c, str_u8(BR_LABEL_NODE), BR_LABEL_LEN(BR_LABEL_NODE), BRV_A6_K_SITE, 32u, info, sizeof info, out, 32u) == BR_OK;
}

/* e2e header (8.3): bytes 0..5 || session_id || seq || len, type-dependent offsets. */
static void e2e_hdr(const uint8_t *frame, uint8_t out[BR_E2E_HDR_LEN])
{
    const size_t o = (frame[BR_OFF_TYPE] == (uint8_t)BR_TYPE_SEEK) ? BR_OFF_SESSION_ID_SEEK : BR_OFF_SESSION_ID;
    memcpy(out, frame, 6u);
    memcpy(&out[6], &frame[o], 4u);
}

/* Ke_* = Expand(PRK, label || src u16 || dst u16 [|| session] || transcript, 16) */
static bool ke_hs(br_crypto_t *c, const uint8_t *prk, const char *label, uint16_t s, uint16_t p, int session,
                  const uint8_t *transcript, uint8_t out[16])
{
    uint8_t info[48];
    size_t n = strlen(label);
    memcpy(info, label, n);
    br_wr_le16(&info[n], s);
    n += 2u;
    br_wr_le16(&info[n], p);
    n += 2u;
    if (session >= 0) {
        info[n++] = (uint8_t)session;
    }
    memcpy(&info[n], transcript, 32u);
    n += 32u;
    return br_hkdf_expand(c, prk, 32u, info, n, out, 16u) == BR_OK;
}

static bool sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
    return mbedtls_sha256(p, n, out, 0) == 0;
}

/* ------------------------------------------------------------------------- */
/* hkdf                                                                       */
/* ------------------------------------------------------------------------- */

static void group_hkdf_body(st_t *t, br_crypto_t *c)
{
    uint8_t k[32];
    uint8_t k2[32];
    uint8_t ke[16];

    /* A.6 */
    bool site_ok = true;
    for (size_t i = 0u; i < 32u; i++) {
        site_ok = site_ok && BRV_A6_K_SITE[i] == (uint8_t)i;
    }
    CHK(t, "A.6 K_site", site_ok);
    CHK(t, "A.6 K_mesh(1)", k_mesh(c, 1u, k) && eq(k, BRV_A6_K_MESH_1, 32u));
    CHK(t, "A.6 K_hop(1)", kdf_v1(c, BRV_A6_K_MESH_1, "hop", NULL, 0u, k, 32u) && eq(k, BRV_A6_K_HOP_1, 32u));
    CHK(t, "A.6 Ke_mesh(1)", kdf_v1(c, BRV_A6_K_MESH_1, "mesh-enc", NULL, 0u, ke, 16u) && eq(ke, BRV_A6_KE_MESH_1, 16u));
    CHK(t, "A.6 K_hop(0)", k_mesh(c, 0u, k2) && kdf_v1(c, k2, "hop", NULL, 0u, k, 32u) && eq(k, BRV_A6_K_HOP_0, 32u));
    CHK(t, "A.6 K_pair", k_pair(c, 0x0042u, 0x1234u, 1u, k) && eq(k, BRV_A6_K_PAIR_0042_1234_1, 32u));
    CHK(t, "A.6 K_pair order", k_pair(c, 0x1234u, 0x0042u, 1u, k) && eq(k, BRV_A6_K_PAIR_0042_1234_1, 32u));
    CHK(t, "A.6 PRK", br_hkdf_extract(c, str_u8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A6_K_PAIR_0042_1234_1, 32u, k) == BR_OK &&
                          eq(k, BRV_A6_PRK, 32u));
    CHK(t, "A.6 HKDF = Expand(Extract)",
        br_hkdf_sha256(c, str_u8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A6_K_PAIR_0042_1234_1, 32u, NULL, 0u, k, 32u) == BR_OK &&
            br_hkdf_expand(c, BRV_A6_PRK, 32u, NULL, 0u, k2, 32u) == BR_OK && eq(k, k2, 32u));

    /* A.9: T0, Ke_hello, T, Ke_hs, Ke_s2p, Ke_p2s (S 0x1234, P 0x0042) */
    uint8_t *buf = s_buf.a;
    uint8_t t0[32];
    uint8_t tt[32];
    e2e_hdr(BRV_A8_SEEK_HOP1_FRAME, buf);
    memcpy(&buf[10], BRV_A8_SEEK_PAYLOAD, BRV_A8_SEEK_PAYLOAD_LEN);
    CHK(t, "A.9 T0", sha256(buf, 10u + BRV_A8_SEEK_PAYLOAD_LEN, t0) && eq(t0, BRV_A9_T0, 32u));
    CHK(t, "A.9 Ke_hello", ke_hs(c, BRV_A6_PRK, "hello", 0x1234u, 0x0042u, -1, BRV_A9_T0, ke) &&
                               eq(ke, BRV_A9_KE_HELLO, 16u));
    e2e_hdr(BRV_A9_HELLO_FRAME, &buf[28]);
    memcpy(&buf[38], BRV_A9_HELLO_CLEAR, BRV_A9_HELLO_CLEAR_LEN);
    memcpy(&buf[42], BRV_A9_HELLO_SECRET, BRV_A9_HELLO_SECRET_LEN);
    CHK(t, "A.9 T", sha256(buf, 42u + BRV_A9_HELLO_SECRET_LEN, tt) && eq(tt, BRV_A9_T, 32u));
    CHK(t, "A.9 Ke_hs", ke_hs(c, BRV_A6_PRK, "hs", 0x1234u, 0x0042u, -1, BRV_A9_T, ke) && eq(ke, BRV_A9_KE_HS, 16u));
    CHK(t, "A.9 Ke_s2p", ke_hs(c, BRV_A6_PRK, "s2p", 0x1234u, 0x0042u, BRV_A9_SESSION_ID, BRV_A9_T, ke) &&
                             eq(ke, BRV_A9_KE_S2P, 16u));
    CHK(t, "A.9 Ke_p2s", ke_hs(c, BRV_A6_PRK, "p2s", 0x1234u, 0x0042u, BRV_A9_SESSION_ID, BRV_A9_T, ke) &&
                             eq(ke, BRV_A9_KE_P2S, 16u));
    CHK(t, "A.7 key = Ke_s2p", eq(BRV_A7_KEY, BRV_A9_KE_S2P, 16u));

    /* A.12 K_mgmt(0042 -> 0001) = KDF_v1(K_pair(0001, 0042, 1), "mgmt" || N || M) */
    uint8_t tail[4];
    br_wr_le16(&tail[0], 0x0042u);
    br_wr_le16(&tail[2], 0x0001u);
    CHK(t, "A.12 K_pair", k_pair(c, 0x0001u, 0x0042u, 1u, k) && eq(k, BRV_A12_K_PAIR_0001_0042_1, 32u));
    CHK(t, "A.12 K_mgmt", kdf_v1(c, k, "mgmt", tail, sizeof tail, ke, 16u) && eq(ke, BRV_A12_K_MGMT_0042_0001, 16u));

    /* A.14 */
    CHK(t, "A.14 K_node", k_node(c, 0x0042u, k) && eq(k, BRV_A14_K_NODE_0042, 32u));
    CHK(t, "A.14 Kb", kdf_v1(c, k, "bundle", NULL, 0u, ke, 16u) && eq(ke, BRV_A14_KB, 16u));
    CHK(t, "A.14 K_node per node", k_node(c, 0x0043u, k2) && !eq(k, k2, 32u));
    CHK(t, "A.14 K_mesh(2)", k_mesh(c, 2u, k) && eq(k, BRV_A14_K_MESH_2, 32u));
    CHK(t, "A.14 K_pair(2)", k_pair(c, 0x0042u, 0x1234u, 2u, k) && eq(k, BRV_A14_K_PAIR_0042_1234_2, 32u));

    /* A.15 edge keys and Ke_hello for the edge pair (S 0x0020, P 0x0021) */
    CHK(t, "A.15 K_pair", k_pair(c, 0x0020u, 0x0021u, 1u, k) && eq(k, BRV_A15_K_PAIR_0020_0021_1, 32u));
    CHK(t, "A.15 K_hop_edge", kdf_v1(c, BRV_A15_K_PAIR_0020_0021_1, "edge-hop", NULL, 0u, k, 32u) &&
                                  eq(k, BRV_A15_K_HOP_EDGE, 32u));
    CHK(t, "A.15 Ke_edge", kdf_v1(c, BRV_A15_K_PAIR_0020_0021_1, "edge-enc", NULL, 0u, ke, 16u) &&
                               eq(ke, BRV_A15_KE_EDGE, 16u));
    e2e_hdr(BRV_A15_SEEK_FRAME, buf);
    memcpy(&buf[10], BRV_A15_SEEK_PAYLOAD, BRV_A15_SEEK_PAYLOAD_LEN);
    CHK(t, "A.15 T0", sha256(buf, 10u + BRV_A15_SEEK_PAYLOAD_LEN, t0) && eq(t0, BRV_A15_T0_EDGE, 32u));
    CHK(t, "A.15 Ke_hello",
        br_hkdf_extract(c, str_u8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A15_K_PAIR_0020_0021_1, 32u, k) == BR_OK &&
            ke_hs(c, k, "hello", 0x0020u, 0x0021u, -1, BRV_A15_T0_EDGE, ke) && eq(ke, BRV_A15_KE_HELLO_EDGE, 16u));

    br_secure_zero(k, sizeof k);
    br_secure_zero(k2, sizeof k2);
    br_secure_zero(ke, sizeof ke);
}

/* ------------------------------------------------------------------------- */
/* hmac                                                                       */
/* ------------------------------------------------------------------------- */

static void group_hmac_body(st_t *t, br_crypto_t *c)
{
    uint8_t mac[32];
    uint8_t mac2[32];
    uint8_t h[32];

    /* HKDF-Extract is HMAC(salt, ikm): A.6 PRK */
    CHK(t, "A.6 PRK", br_hmac_sha256(c, str_u8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), BRV_A6_K_PAIR_0042_1234_1, 32u, mac) == BR_OK &&
                          eq(mac, BRV_A6_PRK, 32u));
    /* K_mesh(1) is a single HKDF block: T(1) = HMAC(HMAC(BR_LABEL_MESH, K_site), 0x01 || 0x01) */
    const uint8_t info1[2] = {0x01u, 0x01u};
    CHK(t, "A.6 K_mesh(1) by hand",
        br_hmac_sha256(c, str_u8(BR_LABEL_MESH), BR_LABEL_LEN(BR_LABEL_MESH), BRV_A6_K_SITE, 32u, h) == BR_OK &&
            br_hmac_sha256(c, h, 32u, info1, sizeof info1, mac) == BR_OK && eq(mac, BRV_A6_K_MESH_1, 32u));
    /* hop_tag is HMAC(K_hop, frame[0 .. 37])[0..3] (A.7) */
    CHK(t, "A.7 hop_tag by hand", br_hmac_sha256(c, BRV_A7_HOP_KEY, 32u, BRV_A7_FRAME, 38u, mac) == BR_OK &&
                                      eq(mac, BRV_A7_HOP_TAG, BR_HOP_TAG_LEN));
    /* RFC 2104: a key longer than the block (64) is hashed first */
    uint8_t *key = s_buf.c;
    for (size_t i = 0u; i < 100u; i++) {
        key[i] = (uint8_t)(i * 7u);
    }
    CHK(t, "long key", sha256(key, 100u, h) && br_hmac_sha256(c, key, 100u, BRV_A7_FRAME, 44u, mac) == BR_OK &&
                           br_hmac_sha256(c, h, 32u, BRV_A7_FRAME, 44u, mac2) == BR_OK && eq(mac, mac2, 32u));
    /* a short key is zero padded: empty key == 32 zero bytes */
    memset(key, 0, 32u);
    CHK(t, "empty key", br_hmac_sha256(c, NULL, 0u, NULL, 0u, mac) == BR_OK &&
                            br_hmac_sha256(c, key, 32u, NULL, 0u, mac2) == BR_OK && eq(mac, mac2, 32u));
    /* N20 precedence: NULL -> ARG before STATE; STATE before range -> ARG */
    br_crypto_t z;
    memset(&z, 0, sizeof z);
    CHK(t, "N20", br_hmac_sha256(NULL, key, 1u, key, 1u, mac) == BR_ERR_ARG);
    CHK(t, "N20", br_hmac_sha256(&z, NULL, 1u, key, 1u, mac) == BR_ERR_ARG);
    CHK(t, "N20", br_hmac_sha256(&z, key, 1u, key, 1u, mac) == BR_ERR_STATE);
    CHK(t, "N20", br_hkdf_expand(&z, BRV_A6_PRK, 31u, NULL, 0u, mac, 16u) == BR_ERR_STATE);
    CHK(t, "N20", br_hkdf_expand(c, BRV_A6_PRK, 31u, NULL, 0u, mac, 16u) == BR_ERR_ARG);
    br_secure_zero(mac, sizeof mac);
    br_secure_zero(mac2, sizeof mac2);
    br_secure_zero(h, sizeof h);
}

/* ------------------------------------------------------------------------- */
/* ccm                                                                        */
/* ------------------------------------------------------------------------- */

static void ccm_one(st_t *t, br_crypto_t *c, const st_e2e_t *e)
{
    st_layout_t l;
    if (!CHK(t, e->name, layout(e->frame, e->flen, &l))) {
        return;
    }
    const br_hdr_t *h = &l.hdr;
    size_t clear = 0u;
    CHK(t, e->name, br_frame_clear_len(h->type, h->session_id, h->len, &clear) == BR_OK && clear == e->clear_len);
    const size_t ct_len = h->len - e->clear_len;
    const uint8_t *ct = &e->frame[l.hl + e->clear_len];
    const uint8_t *tag = &e->frame[l.auth_off];

    uint8_t nonce[BR_CCM_NONCE_LEN];
    CHK(t, e->name, br_ccm_nonce(e->dir, h->src_id, h->dst_id, h->session_id, e->ctr_hi, h->seq, nonce) == BR_OK);
    if (e->exp_nonce != NULL) {
        CHK(t, e->name, eq(nonce, e->exp_nonce, BR_CCM_NONCE_LEN));
    }
    uint8_t aad[BR_AAD_MAX_LEN];
    size_t al = 0u;
    CHK(t, e->name, br_ccm_aad(e->frame, e->flen, e->ctr_hi, e->clear_len, aad, sizeof aad, &al) == BR_OK);
    CHK(t, e->name, al == BR_E2E_HDR_LEN + 4u + e->clear_len);
    if (e->exp_aad != NULL) {
        CHK(t, e->name, al == e->exp_aad_len && eq(aad, e->exp_aad, al));
    }
    CHK(t, e->name, eq(tag, e->exp_tag, BR_CCM_TAG_LEN));

    /* encrypt reproduces ciphertext and tag */
    uint8_t *out = s_buf.a;
    uint8_t tg[BR_CCM_TAG_LEN];
    CHK(t, e->name, br_ccm_encrypt(c, e->key, nonce, aad, al, e->plain, ct_len, out, tg) == BR_OK);
    CHK(t, e->name, eq(out, ct, ct_len) && eq(tg, tag, BR_CCM_TAG_LEN));
    /* in place */
    if (ct_len > 0u) {
        memcpy(out, e->plain, ct_len);
        CHK(t, e->name, br_ccm_encrypt(c, e->key, nonce, aad, al, out, ct_len, out, tg) == BR_OK &&
                            eq(out, ct, ct_len) && eq(tg, tag, BR_CCM_TAG_LEN));
    }
    /* decrypt */
    CHK(t, e->name, br_ccm_decrypt(c, e->key, nonce, aad, al, ct, ct_len, tag, out) == BR_OK);
    if (ct_len > 0u) {
        CHK(t, e->name, eq(out, e->plain, ct_len));
    }

    /* tamper: tag, ciphertext, AAD, nonce (counter) -> AUTH, plaintext zeroed */
    uint8_t *w = s_buf.c;
    uint8_t bad[BR_CCM_TAG_LEN];
    memcpy(bad, tag, sizeof bad);
    bad[BR_CCM_TAG_LEN - 1u] ^= 0x01u;
    memset(out, 0xEE, ct_len + 1u);
    CHK(t, e->name, br_ccm_decrypt(c, e->key, nonce, aad, al, ct, ct_len, bad, out) == BR_ERR_AUTH);
    if (ct_len > 0u) {
        bool zero = true;
        for (size_t i = 0u; i < ct_len; i++) {
            zero = zero && out[i] == 0u;
        }
        CHK(t, e->name, zero);
        memcpy(w, ct, ct_len);
        w[ct_len / 2u] ^= 0x80u;
        CHK(t, e->name, br_ccm_decrypt(c, e->key, nonce, aad, al, w, ct_len, tag, out) == BR_ERR_AUTH);
    }
    memcpy(w, aad, al);
    w[al - 1u] ^= 0x01u;
    CHK(t, e->name, br_ccm_decrypt(c, e->key, nonce, w, al, ct, ct_len, tag, out) == BR_ERR_AUTH);
    uint8_t n2[BR_CCM_NONCE_LEN];
    CHK(t, e->name, br_ccm_nonce(e->dir, h->src_id, h->dst_id, h->session_id, e->ctr_hi + 1u, h->seq, n2) == BR_OK);
    CHK(t, e->name, br_ccm_decrypt(c, e->key, n2, aad, al, ct, ct_len, tag, out) == BR_ERR_AUTH);
}

static void ccm_bundle(st_t *t, br_crypto_t *c)
{
    const char *const name = "A.14 bundle";
    uint8_t nonce[BR_CCM_NONCE_LEN];
    CHK(t, name, br_ccm_nonce(BR_DIR_BUNDLE, 0x0042u, 0u, 0u, BRV_A14_BUNDLE_NO, 0u, nonce) == BR_OK);
    CHK(t, name, eq(nonce, BRV_A14_NONCE, BR_CCM_NONCE_LEN));
    CHK(t, name, br_ccm_nonce(BR_DIR_BUNDLE, 0x0042u, 1u, 0u, BRV_A14_BUNDLE_NO, 0u, nonce) == BR_ERR_ARG);
    CHK(t, name, br_ccm_nonce(BR_DIR_BUNDLE + 1u, 0x0042u, 0u, 0u, 0u, 0u, nonce) == BR_ERR_ARG);

    uint8_t aad[10];
    memcpy(aad, "PLB1", 4u);
    br_wr_le16(&aad[4], 0x0042u);
    br_wr_le32(&aad[6], BRV_A14_BUNDLE_NO);
    CHK(t, name, BRV_A14_AAD_LEN == sizeof aad && eq(aad, BRV_A14_AAD, sizeof aad));

    /* wire = bundle_no u32 || ciphertext || tag */
    uint8_t *w = s_buf.a;
    br_wr_le32(w, BRV_A14_BUNDLE_NO);
    CHK(t, name, br_ccm_encrypt(c, BRV_A14_KB, nonce, aad, sizeof aad, BRV_A14_TLVS, BRV_A14_TLVS_LEN, &w[4],
                                &w[4u + BRV_A14_TLVS_LEN]) == BR_OK);
    CHK(t, name, 4u + BRV_A14_TLVS_LEN + BR_CCM_TAG_LEN == BRV_A14_BUNDLE_WIRE_LEN &&
                     eq(w, BRV_A14_BUNDLE_WIRE, BRV_A14_BUNDLE_WIRE_LEN));
    uint8_t *pt = s_buf.c;
    CHK(t, name, br_ccm_decrypt(c, BRV_A14_KB, nonce, aad, sizeof aad, &BRV_A14_BUNDLE_WIRE[4], BRV_A14_TLVS_LEN,
                                &BRV_A14_BUNDLE_WIRE[4u + BRV_A14_TLVS_LEN], pt) == BR_OK &&
                     eq(pt, BRV_A14_TLVS, BRV_A14_TLVS_LEN));
    /* a different bundle_no changes nonce and AAD: rejected */
    uint8_t n2[BR_CCM_NONCE_LEN];
    CHK(t, name, br_ccm_nonce(BR_DIR_BUNDLE, 0x0042u, 0u, 0u, BRV_A14_BUNDLE_NO - 1u, 0u, n2) == BR_OK);
    CHK(t, name, br_ccm_decrypt(c, BRV_A14_KB, n2, aad, sizeof aad, &BRV_A14_BUNDLE_WIRE[4], BRV_A14_TLVS_LEN,
                                &BRV_A14_BUNDLE_WIRE[4u + BRV_A14_TLVS_LEN], pt) == BR_ERR_AUTH);
    /* a frame nonce never equals a bundle nonce (leading byte) */
    CHK(t, name, br_ccm_nonce(BR_DIR_TO_PROBE, 0x0042u, 0u, 0u, BRV_A14_BUNDLE_NO, 0u, n2) == BR_OK &&
                     !eq(n2, nonce, BR_CCM_NONCE_LEN));
}

static void group_ccm_body(st_t *t, br_crypto_t *c)
{
    for (size_t i = 0u; i < N_E2E; i++) {
        ccm_one(t, c, &k_e2e[i]);
    }
    ccm_bundle(t, c);
}

/* ------------------------------------------------------------------------- */
/* hop_tag                                                                    */
/* ------------------------------------------------------------------------- */

static void group_hop_tag_body(st_t *t, br_crypto_t *c)
{
    uint8_t ht[BR_HOP_TAG_LEN];
    CHK(t, "A.7 K_hop(1)", eq(BRV_A7_HOP_KEY, BRV_A6_K_HOP_1, 32u) && eq(BRV_A8_SEEK_HOP_KEY, BRV_A6_K_HOP_1, 32u));
    CHK(t, "A.8 K_hop(0)", eq(BRV_A8_DATA_HOP2_K0_KEY, BRV_A6_K_HOP_0, 32u));
    CHK(t, "A.7 hop_tag", eq(&BRV_A7_FRAME[38], BRV_A7_HOP_TAG, BR_HOP_TAG_LEN));

    for (size_t i = 0u; i < N_E2E; i++) {
        const st_e2e_t *e = &k_e2e[i];
        st_layout_t l;
        if (!CHK(t, e->name, layout(e->frame, e->flen, &l))) {
            continue;
        }
        const uint8_t *tag = &e->frame[l.hop_off];
        CHK(t, e->name, br_hop_tag(c, e->hop_key, e->frame, l.hop_off, ht) == BR_OK && eq(ht, tag, BR_HOP_TAG_LEN));
        CHK(t, e->name, br_hop_tag_verify(c, e->hop_key, e->frame, l.hop_off, tag) == BR_OK);
        CHK(t, e->name, br_hop_tag_verify(c, e->wrong_hop, e->frame, l.hop_off, tag) == BR_ERR_AUTH);
        /* bound to the per-hop fields: a changed hop_seq fails */
        memcpy(s_buf.a, e->frame, e->flen);
        s_buf.a[BR_OFF_HOP_SEQ] ^= 0x01u;
        CHK(t, e->name, br_hop_tag_verify(c, e->hop_key, s_buf.a, l.hop_off, tag) == BR_ERR_AUTH);
    }
    CHK(t, "A.8 hop2 K0 tag", eq(&BRV_A8_DATA_HOP2_K0_FRAME[38], BRV_A8_DATA_HOP2_K0_HOP_TAG, BR_HOP_TAG_LEN));
    CHK(t, "A.8 hop2 under K0", br_hop_tag(c, BRV_A6_K_HOP_0, BRV_A8_DATA_HOP2_FRAME, 38u, ht) == BR_OK &&
                                    eq(ht, BRV_A8_DATA_HOP2_K0_HOP_TAG, BR_HOP_TAG_LEN));

    /* covered_len minimum (N18): 27 for 19-byte headers, 30 for SEEK */
    CHK(t, "N18 DATA 26", br_hop_tag(c, BRV_A7_HOP_KEY, BRV_A7_FRAME, 26u, ht) == BR_ERR_ARG);
    CHK(t, "N18 DATA 27", br_hop_tag(c, BRV_A7_HOP_KEY, BRV_A7_FRAME, 27u, ht) == BR_OK);
    CHK(t, "N18 SEEK 29", br_hop_tag(c, BRV_A7_HOP_KEY, BRV_A8_SEEK_HOP1_FRAME, 29u, ht) == BR_ERR_ARG);
    CHK(t, "N18 SEEK 30", br_hop_tag(c, BRV_A7_HOP_KEY, BRV_A8_SEEK_HOP1_FRAME, 30u, ht) == BR_OK);
}

/* ------------------------------------------------------------------------- */
/* blacklist                                                                  */
/* ------------------------------------------------------------------------- */

static void group_blacklist_body(st_t *t, br_crypto_t *c)
{
    uint8_t k[32];
    CHK(t, "A.6 K_mesh(1)", br_key_check_field(BRV_A6_K_MESH_1, 32u) == BR_ERR_AUTH);
    CHK(t, "A.14 K_mesh(2)", br_key_check_field(BRV_A14_K_MESH_2, 32u) == BR_ERR_AUTH);
    /* every epoch of the test K_site */
    uint32_t refused = 0u;
    for (unsigned e = 0u; e < 256u; e++) {
        if (k_mesh(c, (uint8_t)e, k) && br_key_check_field(k, 32u) == BR_ERR_AUTH) {
            refused++;
        }
    }
    CHK(t, "K_mesh(0..255)", refused == 256u);
    /* one flipped bit is a different key */
    memcpy(k, BRV_A6_K_MESH_1, 32u);
    k[31] ^= 0x01u;
    CHK(t, "K_mesh(1) bit flip", br_key_check_field(k, 32u) == BR_OK);
    /* degenerate keys, any length */
    memset(k, 0x00, sizeof k);
    CHK(t, "all-zero 32", br_key_check_field(k, 32u) == BR_ERR_AUTH);
    memset(k, 0xAA, sizeof k);
    CHK(t, "all-0xAA 16", br_key_check_field(k, 16u) == BR_ERR_AUTH);
    CHK(t, "1 byte", br_key_check_field(k, 1u) == BR_ERR_AUTH);
    /* documented non-refusals (N14): other test-K_site keys pass */
    CHK(t, "N14 K_site", br_key_check_field(BRV_A6_K_SITE, 32u) == BR_OK);
    CHK(t, "N14 K_hop(1)", br_key_check_field(BRV_A6_K_HOP_1, 32u) == BR_OK);
    CHK(t, "N14 Ke_mesh(1)", br_key_check_field(BRV_A6_KE_MESH_1, 16u) == BR_OK);
    CHK(t, "args", br_key_check_field(NULL, 32u) == BR_ERR_ARG && br_key_check_field(k, 0u) == BR_ERR_ARG);
    br_secure_zero(k, sizeof k);
}

/* ------------------------------------------------------------------------- */
/* Runner                                                                     */
/* ------------------------------------------------------------------------- */

typedef void (*st_crypto_fn)(st_t *t, br_crypto_t *c);

/* Crypto groups own one context each: the only heap use, freed before return. */
static void with_crypto(st_t *t, st_crypto_fn fn)
{
    br_crypto_t c;
    if (CHK(t, "br_crypto_init", br_crypto_init(&c) == BR_OK)) {
        fn(t, &c);
    }
    br_crypto_free(&c);
}

static void group_hkdf(st_t *t) { with_crypto(t, group_hkdf_body); }
static void group_hmac(st_t *t) { with_crypto(t, group_hmac_body); }
static void group_ccm(st_t *t) { with_crypto(t, group_ccm_body); }
static void group_hop_tag(st_t *t) { with_crypto(t, group_hop_tag_body); }
static void group_blacklist(st_t *t) { with_crypto(t, group_blacklist_body); }

typedef struct {
    const char *name;
    void (*fn)(st_t *t);
} st_group_t;

static const st_group_t k_groups[] = {
    {"crc", group_crc},     {"cobs", group_cobs}, {"rs", group_rs},         {"fec", group_fec},
    {"frame", group_frame}, {"hkdf", group_hkdf}, {"hmac", group_hmac},     {"ccm", group_ccm},
    {"hop_tag", group_hop_tag},                   {"blacklist", group_blacklist},
};

br_err_t br_selftest_run(uint32_t *checks_run, uint32_t *checks_failed)
{
    if (checks_run == NULL || checks_failed == NULL) {
        return BR_ERR_ARG;
    }
    br_platform_t p;
    const bool timed = (br_platform_get(&p) == BR_OK);
    uint32_t run = 0u;
    uint32_t failed = 0u;
    for (size_t i = 0u; i < sizeof k_groups / sizeof k_groups[0]; i++) {
        st_t t = {k_groups[i].name, 0u, 0u};
        const uint64_t t0 = timed ? p.now_us(p.user) : 0u;
        k_groups[i].fn(&t);
        const uint64_t t1 = timed ? p.now_us(p.user) : 0u;
        const uint64_t us = t1 - t0;
        st_line_t l = {{0}, 0u};
        ln_str(&l, "group ");
        ln_pad(&l, t.group, 10u);
        ln_u32(&l, t.run, 4u);
        ln_str(&l, " checks ");
        ln_u32(&l, t.failed, 3u);
        ln_str(&l, " failed ");
        ln_u32(&l, (us > UINT32_MAX) ? UINT32_MAX : (uint32_t)us, 8u);
        ln_str(&l, " us");
        st_emit(BR_LOG_INFO, &l);
        run += t.run;
        failed += t.failed;
    }
    br_secure_zero(&s_buf, sizeof s_buf);
    *checks_run = run;
    *checks_failed = failed;
    return (failed == 0u) ? BR_OK : BR_ERR_REJECT;
}
