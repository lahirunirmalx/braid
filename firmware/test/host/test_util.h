// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_util.h - tiny shared test harness + independent reference oracles for
 * the Braid host unit tests.
 *
 * Everything here is written from the spec (PROTOCOL.md v0.8, SPEC-NOTES.md)
 * and the public headers only. The reference CRC-16, RS, COBS, frame builder
 * and receive validator below deliberately do NOT use any br_* function so a
 * bug in the firmware cannot hide behind the same bug in the test.
 *
 * Usage: each test_*.c includes this header, calls CHECK* macros, and ends
 * with `return tu_summary("test_name");`.
 */
#ifndef BR_TEST_UTIL_H
#define BR_TEST_UTIL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "braid/br_types.h"

/* ------------------------------------------------------------------------- */
/* Assert / report                                                            */
/* ------------------------------------------------------------------------- */

#define TU_MAX_FAIL_PRINTS 40u

static unsigned long tu_checks;
static unsigned long tu_failed;
static unsigned long tu_skips;
static const char *tu_ctx_str = "";

/** Set a label that is printed with every failure (e.g. the vector name). */
static inline void tu_ctx(const char *s) { tu_ctx_str = s ? s : ""; }

/** Count a failure; returns true while the message should still be printed. */
static inline bool tu_begin_fail(const char *file, int line)
{
    tu_failed++;
    if (tu_failed > TU_MAX_FAIL_PRINTS) {
        if (tu_failed == TU_MAX_FAIL_PRINTS + 1u) {
            fprintf(stderr, "... further failures suppressed ...\n");
        }
        return false;
    }
    fprintf(stderr, "FAIL %s:%d [%s] ", file, line, tu_ctx_str);
    return true;
}

static inline const char *tu_err_name(int e)
{
    switch (e) {
    case BR_OK: return "BR_OK";
    case BR_ERR_ARG: return "BR_ERR_ARG";
    case BR_ERR_STATE: return "BR_ERR_STATE";
    case BR_ERR_NO_PROBE: return "BR_ERR_NO_PROBE";
    case BR_ERR_TIMEOUT: return "BR_ERR_TIMEOUT";
    case BR_ERR_BUSY: return "BR_ERR_BUSY";
    case BR_ERR_TOO_BIG: return "BR_ERR_TOO_BIG";
    case BR_ERR_AUTH: return "BR_ERR_AUTH";
    case BR_ERR_QUEUE_FULL: return "BR_ERR_QUEUE_FULL";
    case BR_ERR_NOT_IMPLEMENTED: return "BR_ERR_NOT_IMPLEMENTED";
    case BR_ERR_NO_MEM: return "BR_ERR_NO_MEM";
    case BR_ERR_CRC: return "BR_ERR_CRC";
    case BR_ERR_DECODE: return "BR_ERR_DECODE";
    case BR_ERR_UNCORRECTABLE: return "BR_ERR_UNCORRECTABLE";
    case BR_ERR_CRYPTO: return "BR_ERR_CRYPTO";
    case BR_ERR_REJECT: return "BR_ERR_REJECT";
    default: return "?";
    }
}

static inline void tu_hex(FILE *f, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", p[i]);
    }
}

/** Plain condition. */
#define CHECK(cond)                                                            \
    do {                                                                       \
        tu_checks++;                                                           \
        if (!(cond)) {                                                         \
            if (tu_begin_fail(__FILE__, __LINE__)) {                           \
                fprintf(stderr, "%s\n", #cond);                                \
            }                                                                  \
        }                                                                      \
    } while (0)

/** Condition with a fixed explanation string. */
#define CHECK_MSG(cond, msg)                                                   \
    do {                                                                       \
        tu_checks++;                                                           \
        if (!(cond)) {                                                         \
            if (tu_begin_fail(__FILE__, __LINE__)) {                           \
                fprintf(stderr, "%s (%s)\n", #cond, (msg));                    \
            }                                                                  \
        }                                                                      \
    } while (0)

/** Unsigned 32-bit equality: CHECK_EQ_U32(actual, expected). */
#define CHECK_EQ_U32(actual, expected)                                         \
    do {                                                                       \
        uint32_t a_ = (uint32_t)(actual);                                      \
        uint32_t e_ = (uint32_t)(expected);                                    \
        tu_checks++;                                                           \
        if (a_ != e_) {                                                        \
            if (tu_begin_fail(__FILE__, __LINE__)) {                           \
                fprintf(stderr, "%s: got 0x%08" PRIx32 " (%" PRIu32            \
                        "), expected 0x%08" PRIx32 " (%" PRIu32 ")\n",         \
                        #actual, a_, a_, e_, e_);                              \
            }                                                                  \
        }                                                                      \
    } while (0)

/** br_err_t / br_reject_t style equality with names: CHECK_ERR(actual, expected). */
#define CHECK_ERR(actual, expected)                                            \
    do {                                                                       \
        int a_ = (int)(actual);                                                \
        int e_ = (int)(expected);                                              \
        tu_checks++;                                                           \
        if (a_ != e_) {                                                        \
            if (tu_begin_fail(__FILE__, __LINE__)) {                           \
                fprintf(stderr, "%s: got %s (%d), expected %s (%d)\n",         \
                        #actual, tu_err_name(a_), a_, tu_err_name(e_), e_);    \
            }                                                                  \
        }                                                                      \
    } while (0)

/** Byte-string equality with hex diff: CHECK_MEM(expected, actual, n). */
static inline bool tu_check_mem(const char *file, int line, const char *en,
                                const char *an, const uint8_t *exp,
                                const uint8_t *act, size_t n)
{
    tu_checks++;
    if (n == 0 || (exp != NULL && act != NULL && memcmp(exp, act, n) == 0)) {
        return true;
    }
    if (tu_begin_fail(file, line)) {
        size_t first = 0;
        if (exp != NULL && act != NULL) {
            while (first < n && exp[first] == act[first]) {
                first++;
            }
        }
        fprintf(stderr, "memory differs: %s vs %s, %zu bytes, first diff at %zu\n",
                en, an, n, first);
        if (exp != NULL && act != NULL) {
            size_t lo = first > 8 ? first - 8 : 0;
            size_t hi = (n - lo > 48) ? lo + 48 : n;
            fprintf(stderr, "  expected[%zu..%zu): ", lo, hi);
            tu_hex(stderr, exp + lo, hi - lo);
            fprintf(stderr, "\n  actual  [%zu..%zu): ", lo, hi);
            tu_hex(stderr, act + lo, hi - lo);
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr, "  NULL pointer\n");
        }
    }
    return false;
}
#define CHECK_MEM(exp, act, n)                                                 \
    tu_check_mem(__FILE__, __LINE__, #exp, #act, (const uint8_t *)(exp),       \
                 (const uint8_t *)(act), (size_t)(n))

/** Print a SKIP line naming the missing API (not counted as pass or fail). */
#define TU_SKIP(what, missing_api)                                             \
    do {                                                                       \
        tu_skips++;                                                            \
        printf("SKIP: %s - missing API: %s\n", (what), (missing_api));         \
    } while (0)

/** Print the summary; returns the process exit code (0 iff no failure). */
static inline int tu_summary(const char *name)
{
    printf("%s: %lu checks, %lu failed, %lu skipped -> %s\n", name, tu_checks,
           tu_failed, tu_skips, tu_failed == 0 ? "PASS" : "FAIL");
    if (tu_checks == 0) {
        return 1;
    }
    return tu_failed == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------------- */
/* Fixed-seed PRNG (xorshift64*)                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint64_t s;
} tu_rng_t;

static inline void tu_rng_seed(tu_rng_t *r, uint64_t seed)
{
    r->s = seed ? seed : 0x9E3779B97F4A7C15ull;
}

static inline uint64_t tu_rng_next(tu_rng_t *r)
{
    uint64_t x = r->s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    r->s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/** Uniform-ish value in [0, n); n must be > 0. */
static inline uint32_t tu_rng_below(tu_rng_t *r, uint32_t n)
{
    return (uint32_t)((tu_rng_next(r) >> 16) % n);
}

static inline uint8_t tu_rng_u8(tu_rng_t *r) { return (uint8_t)(tu_rng_next(r) >> 24); }

static inline void tu_rng_fill(tu_rng_t *r, uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = tu_rng_u8(r);
    }
}

/** Heap copy of exactly n bytes (so ASan sees any overread). n == 0 gives a 1-byte block. */
static inline uint8_t *tu_dup(const uint8_t *p, size_t n)
{
    uint8_t *q = (uint8_t *)malloc(n ? n : 1u);
    if (q == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    if (n) {
        memcpy(q, p, n);
    }
    return q;
}

static inline uint8_t *tu_alloc(size_t n)
{
    uint8_t *q = (uint8_t *)calloc(n ? n : 1u, 1u);
    if (q == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    return q;
}

/* ------------------------------------------------------------------------- */
/* Byte helpers (explicit shifts: no dependency on br_frame.h)                */
/* ------------------------------------------------------------------------- */

static inline uint16_t tu_get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t tu_get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void tu_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}
static inline void tu_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)(v >> 24);
}

/* ------------------------------------------------------------------------- */
/* Reference CRC-16/CCITT-FALSE (bitwise, spec 3.1)                           */
/* ------------------------------------------------------------------------- */

static inline uint16_t tu_ref_crc16_update(uint16_t crc, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        crc = (uint16_t)(crc ^ (uint16_t)(d[i] << 8));
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}
static inline uint16_t tu_ref_crc16(const uint8_t *d, size_t n)
{
    return tu_ref_crc16_update(0xFFFFu, d, n);
}

/* ------------------------------------------------------------------------- */
/* Reference Reed-Solomon over GF(2^8), poly 0x11D, fcr 0, alpha 2 (spec 3.2) */
/* ------------------------------------------------------------------------- */

static uint8_t tu_gf_exp[512];
static uint8_t tu_gf_log[256];
static bool tu_gf_ready;

static inline void tu_gf_init(void)
{
    if (tu_gf_ready) {
        return;
    }
    unsigned x = 1;
    for (unsigned i = 0; i < 255; i++) {
        tu_gf_exp[i] = (uint8_t)x;
        tu_gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100u) {
            x ^= 0x11Du;
        }
    }
    for (unsigned i = 255; i < 512; i++) {
        tu_gf_exp[i] = tu_gf_exp[i - 255];
    }
    tu_gf_ready = true;
}

static inline uint8_t tu_gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return tu_gf_exp[tu_gf_log[a] + tu_gf_log[b]];
}

/** Parity of msg (highest-degree first), nsym 1..32; msg_len + nsym <= 255 required by caller. */
static inline void tu_ref_rs_encode(const uint8_t *msg, size_t msg_len, unsigned nsym, uint8_t *parity)
{
    tu_gf_init();
    uint8_t g[40];
    memset(g, 0, sizeof g);
    g[0] = 1;
    unsigned deg = 0;
    for (unsigned i = 0; i < nsym; i++) {
        uint8_t r = tu_gf_exp[i];
        for (unsigned j = deg + 1; j >= 1; j--) {
            g[j] = (uint8_t)(g[j] ^ tu_gf_mul(r, g[j - 1]));
        }
        deg++;
    }
    uint8_t reg[40];
    memset(reg, 0, sizeof reg);
    for (size_t i = 0; i < msg_len; i++) {
        uint8_t fb = (uint8_t)(msg[i] ^ reg[0]);
        for (unsigned j = 0; j + 1 < nsym; j++) {
            reg[j] = (uint8_t)(reg[j + 1] ^ tu_gf_mul(fb, g[j + 1]));
        }
        reg[nsym - 1] = tu_gf_mul(fb, g[nsym]);
    }
    memcpy(parity, reg, nsym);
}

/* ------------------------------------------------------------------------- */
/* Reference COBS encoder (Cheshire-Baker). eager = emit a trailing 0x01 code */
/* after a full 0xFF block that ends exactly at the end of the input (the     */
/* other common implementation convention). Appends the 0x00 delimiter.       */
/* ------------------------------------------------------------------------- */

static inline size_t tu_ref_cobs_encode(const uint8_t *src, size_t n, uint8_t *dst, bool eager)
{
    size_t out = 1;      /* position after the current code byte */
    size_t code_at = 0;
    uint8_t code = 1;
    for (size_t i = 0; i < n; i++) {
        if (src[i] == 0) {
            dst[code_at] = code;
            code_at = out++;
            code = 1;
        } else {
            dst[out++] = src[i];
            code++;
            if (code == 0xFFu) {
                dst[code_at] = code;
                code_at = out++;
                code = 1;
                if (i + 1 == n && !eager) {
                    /* lazy: drop the empty trailing block */
                    out--;
                    dst[out++] = 0x00;
                    return out;
                }
            }
        }
    }
    dst[code_at] = code;
    dst[out++] = 0x00;
    return out;
}

/* ------------------------------------------------------------------------- */
/* Reference frame layout / builder / validator (spec 3, 3.6, SPEC-NOTES)     */
/* ------------------------------------------------------------------------- */

#define TU_ID_IS_UNIT(id) ((id) >= 0x0010u && (id) <= 0xFEFFu)
#define TU_ID_IS_MGR(id) ((id) >= 0x0001u && (id) <= 0x000Fu)

typedef struct {
    uint8_t version, flags, type, ttl, hops, session_id, len;
    uint16_t src, dst, prev, next, path_mtu, seq;
    uint8_t path_cost;
    uint32_t hop_seq;
    size_t hdr_len;
} tu_ref_hdr_t;

/** Parse a header by spec offsets; buf must hold >= 22 bytes for SEEK, >= 19 otherwise. */
static inline void tu_ref_parse(const uint8_t *b, tu_ref_hdr_t *h)
{
    memset(h, 0, sizeof *h);
    h->version = (uint8_t)(b[0] >> 4);
    h->flags = (uint8_t)(b[0] & 0x0Fu);
    h->type = b[1];
    h->src = tu_get16(b + 2);
    h->dst = tu_get16(b + 4);
    h->prev = tu_get16(b + 6);
    h->next = tu_get16(b + 8);
    h->ttl = (uint8_t)(b[10] >> 4);
    h->hops = (uint8_t)(b[10] & 0x0Fu);
    h->hop_seq = tu_get32(b + 11);
    if (b[1] == 0x01) {
        h->hdr_len = 22;
        h->path_mtu = tu_get16(b + 15);
        h->path_cost = b[17];
        h->session_id = b[18];
        h->seq = tu_get16(b + 19);
        h->len = b[21];
    } else {
        h->hdr_len = 19;
        h->session_id = b[15];
        h->seq = tu_get16(b + 16);
        h->len = b[18];
    }
}

/** Fill the fields of a typical valid DATA header (direct link S 0x1234 -> P 0x0042). */
static inline void tu_ref_default_hdr(tu_ref_hdr_t *h, uint8_t type)
{
    memset(h, 0, sizeof *h);
    h->version = 1;
    h->flags = 0;
    h->type = type;
    h->src = 0x1234;
    h->dst = 0x0042;
    h->prev = 0x1234;
    h->next = 0x0042;
    h->ttl = 4;
    h->hops = 0;
    h->hop_seq = 9;
    h->path_mtu = 242;
    h->path_cost = 0;
    h->session_id = 7;
    h->seq = 5;
    h->hdr_len = (type == 0x01) ? 22u : 19u;
}

/** Write a header (len field = plen) at out; returns header length. */
static inline size_t tu_ref_write_hdr(const tu_ref_hdr_t *h, size_t plen, uint8_t *out)
{
    out[0] = (uint8_t)(((h->version & 0x0Fu) << 4) | (h->flags & 0x0Fu));
    out[1] = h->type;
    tu_put16(out + 2, h->src);
    tu_put16(out + 4, h->dst);
    tu_put16(out + 6, h->prev);
    tu_put16(out + 8, h->next);
    out[10] = (uint8_t)(((h->ttl & 0x0Fu) << 4) | (h->hops & 0x0Fu));
    tu_put32(out + 11, h->hop_seq);
    if (h->type == 0x01) {
        tu_put16(out + 15, h->path_mtu);
        out[17] = h->path_cost;
        out[18] = h->session_id;
        tu_put16(out + 19, h->seq);
        out[21] = (uint8_t)plen;
        return 22;
    }
    out[15] = h->session_id;
    tu_put16(out + 16, h->seq);
    out[18] = (uint8_t)plen;
    return 19;
}

/**
 * Recompute the CRC at [total - nsym - 2] over [0, total - nsym - 2) and refill
 * the RS parity (nsym bytes) when the RS block fits in 255 bytes (else zeros).
 */
static inline void tu_ref_seal(uint8_t *buf, size_t total, unsigned nsym)
{
    size_t crc_at = total - nsym - 2u;
    tu_put16(buf + crc_at, tu_ref_crc16(buf, crc_at));
    if (nsym) {
        if (total <= 255u) {
            tu_ref_rs_encode(buf, total - nsym, nsym, buf + total - nsym);
        } else {
            memset(buf + total - nsym, 0, nsym);
        }
    }
}

/**
 * Build a complete on-wire frame: header || payload || [tags 12] || crc || rs parity.
 * tags may be NULL (zeros used) and is only read when FLAG_AUTH (bit 1) is set.
 * Returns the total length. out must hold >= 22 + 255 + 12 + 2 + 32 bytes.
 */
static inline size_t tu_ref_build(const tu_ref_hdr_t *h, const uint8_t *payload, size_t plen,
                                  const uint8_t *tags, unsigned nsym, uint8_t *out)
{
    size_t off = tu_ref_write_hdr(h, plen, out);
    if (plen) {
        memcpy(out + off, payload, plen);
    }
    off += plen;
    if (h->flags & 0x02u) {
        if (tags) {
            memcpy(out + off, tags, 12);
        } else {
            memset(out + off, 0, 12);
        }
        off += 12;
    }
    off += 2; /* crc */
    off += nsym;
    tu_ref_seal(out, off, nsym);
    return off;
}

typedef struct {
    uint16_t max_frame;
    uint8_t rs_nsym;
} tu_link_t;

/**
 * Reference receive validator, written from 3.6 + SPEC-NOTES N1-N6 and the
 * documented check order of br_frame_validate(). Returns the br_reject_t value
 * (as int, 0 = accept). Reasons use the numeric br_reject_t enum order, which
 * test code maps with the enum names from br_frame.h; here we return a small
 * private code and the caller converts via the table in tu_ref_reason().
 */
enum {
    TU_R_NONE = 0, TU_R_LEN_SHORT, TU_R_LEN_MISMATCH, TU_R_LEN_PAYLOAD, TU_R_LEN_MAX_FRAME,
    TU_R_CRC, TU_R_TTL, TU_R_HOPS, TU_R_PREV_HOP, TU_R_SRC_ID, TU_R_NEXT_HOP, TU_R_DST_ID,
    TU_R_PATH_MTU, TU_R_PATH_COST, TU_R_VERSION
};

static inline int tu_ref_validate(const uint8_t *b, size_t len, const tu_link_t *lk, bool endpoint)
{
    if (len < 2) {
        return TU_R_LEN_SHORT;
    }
    size_t hl = (b[1] == 0x01) ? 22u : 19u;
    size_t nsym = lk->rs_nsym;
    if (len < hl + 2u + nsym) {
        return TU_R_LEN_SHORT;
    }
    size_t crc_at = len - nsym - 2u;
    if (tu_get16(b + crc_at) != tu_ref_crc16(b, crc_at)) {
        return TU_R_CRC;
    }
    if (len > lk->max_frame) {
        return TU_R_LEN_MAX_FRAME;
    }
    unsigned flags = b[0] & 0x0Fu;
    bool auth = (flags & 0x02u) != 0;
    size_t plen = b[hl - 1u];
    if (len != hl + plen + (auth ? 12u : 0u) + 2u + nsym) {
        return TU_R_LEN_MISMATCH;
    }
    size_t cap = (auth ? 217u : 229u) - nsym;
    if (plen > cap) {
        return TU_R_LEN_PAYLOAD;
    }
    unsigned ttl = b[10] >> 4, hops = b[10] & 0x0Fu;
    uint16_t src = tu_get16(b + 2), dst = tu_get16(b + 4), prev = tu_get16(b + 6), next = tu_get16(b + 8);
    if (ttl > 8u) {
        return TU_R_TTL;
    }
    if (hops >= 8u) {
        return TU_R_HOPS;
    }
    if (!(TU_ID_IS_UNIT(prev) || TU_ID_IS_MGR(prev))) {
        return TU_R_PREV_HOP;
    }
    if (!(TU_ID_IS_UNIT(src) || TU_ID_IS_MGR(src))) {
        return TU_R_SRC_ID;
    }
    if (!(TU_ID_IS_UNIT(next) || TU_ID_IS_MGR(next) || next == 0xFFFFu)) {
        return TU_R_NEXT_HOP;
    }
    if (dst == 0) {
        return TU_R_DST_ID;
    }
    if (b[1] == 0x01) {
        uint16_t mtu = tu_get16(b + 15);
        if (mtu < 48u || mtu > (unsigned)lk->max_frame - nsym) {
            return TU_R_PATH_MTU;
        }
        if (b[17] > 250u) {
            return TU_R_PATH_COST;
        }
    }
    if (endpoint && (b[0] >> 4) != 1u) {
        return TU_R_VERSION;
    }
    return TU_R_NONE;
}

/* Reference counters / helpers for 3.5 (used by several tests). */
static inline bool tu_ref_seq16_newer(uint16_t a, uint16_t b)
{
    return a != b && (uint16_t)(a - b) < 0x8000u;
}

/** Returns BR_OK, BR_ERR_REJECT (roc - 1 underflow) or BR_ERR_TOO_BIG (roc + 1 overflow). */
static inline int tu_ref_roc(uint16_t seq, uint16_t s_l, uint32_t roc, uint32_t *out)
{
    if (s_l < 32768u && (int)seq - (int)s_l > 32768) {
        if (roc == 0) {
            return BR_ERR_REJECT;
        }
        *out = roc - 1u;
    } else if (s_l >= 32768u && (int)s_l - 32768 > (int)seq) {
        if (roc == UINT32_MAX) {
            return BR_ERR_TOO_BIG;
        }
        *out = roc + 1u;
    } else {
        *out = roc;
    }
    return BR_OK;
}

#endif /* BR_TEST_UTIL_H */
