// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_rs.c - Reed-Solomon over GF(2^8), prim 0x11D, fcr 0, alpha 2 (spec 3.2, 3.3).
 *
 * Bit-exact with Python reedsolo.RSCodec(nsym, fcr=0, prim=0x11d, generator=2):
 * codeword = message || parity, byte 0 is the highest-degree coefficient, so
 * codeword index i carries the locator X = alpha^(len - 1 - i).
 *
 * Decoder: syndromes -> erasure locator Gamma -> Berlekamp-Massey seeded with
 * Gamma (errors and erasures, Blahut) -> Chien search restricted to the
 * shortened code's positions -> Forney (fcr 0: Y = X * Omega(X^-1) /
 * Lambda'(X^-1)) -> re-check syndromes. All work happens on a stack copy;
 * the caller's buffer is written only on success.
 *
 * No heap, no VLAs, tables are static const. Worst-case frame: br_rs_decode
 * 896 bytes (xtensa-esp32 gcc -Og -fstack-usage), under the 1 KB of br_rs.h.
 */
#include <string.h>

#include "braid/br_rs.h"

#include "br_internal.h"

/* GF(2^8) prim 0x11D, alpha 2: exp table doubled to 512 so exp[log a + log b] needs no mod. */
static const uint8_t s_gf_exp[512] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
    0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
    0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
    0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
    0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
    0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
    0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
    0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
    0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
    0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
    0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
    0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
    0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
    0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26, 0x4c,
    0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x9d,
    0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23, 0x46,
    0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1, 0x5f,
    0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0, 0xfd,
    0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2, 0xd9,
    0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce, 0x81,
    0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc, 0x85,
    0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54, 0xa8,
    0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73, 0xe6,
    0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff, 0xe3,
    0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41, 0x82,
    0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6, 0x51,
    0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09, 0x12,
    0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16, 0x2c,
    0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01, 0x02,
};
/* log[0] is unused (log of 0 is undefined); set to 0. */
static const uint8_t s_gf_log[256] = {
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6, 0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
    0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81, 0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
    0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21, 0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
    0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9, 0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
    0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd, 0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd, 0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
    0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e, 0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
    0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b, 0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
    0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d, 0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
    0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c, 0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
    0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd, 0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
    0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e, 0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
    0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76, 0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
    0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa, 0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
    0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51, 0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
    0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8, 0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf,
};

/* Polynomial buffers: degree can reach 2 * nsym transiently inside BM. */
#define RS_POLY_CAP (2u * BR_RS_MAX_NSYM + 2u)

static inline uint8_t gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0u || b == 0u) {
        return 0u;
    }
    return s_gf_exp[(unsigned)s_gf_log[a] + (unsigned)s_gf_log[b]];
}

/* a / b, b != 0. */
static inline uint8_t gf_div(uint8_t a, uint8_t b)
{
    if (a == 0u) {
        return 0u;
    }
    return s_gf_exp[(unsigned)s_gf_log[a] + 255u - (unsigned)s_gf_log[b]];
}

/* alpha^e for any e >= 0. */
static inline uint8_t gf_alpha_pow(unsigned e)
{
    return s_gf_exp[e % 255u];
}

/* Evaluate a low-degree-first polynomial p[0..n-1] at x (Horner from the top). */
static uint8_t poly_eval_low(const uint8_t *p, size_t n, uint8_t x)
{
    uint8_t y = 0u;
    for (size_t i = n; i > 0u; i--) {
        y = (uint8_t)(gf_mul(y, x) ^ p[i - 1u]);
    }
    return y;
}

/* g(x) = prod_{i=0}^{nsym-1} (x - alpha^i), highest degree first, g[0] = 1. */
static void rs_generator(uint8_t nsym, uint8_t g[BR_RS_MAX_NSYM + 1u])
{
    memset(g, 0, BR_RS_MAX_NSYM + 1u);
    g[0] = 1u;
    for (unsigned i = 0u; i < nsym; i++) {
        uint8_t root = gf_alpha_pow(i);
        /* multiply the (i+1)-term polynomial by (x + root), in place, from the tail */
        for (unsigned j = i + 1u; j > 0u; j--) {
            g[j] = (uint8_t)(g[j] ^ gf_mul(g[j - 1u], root));
        }
    }
}

static void rs_syndromes_raw(const uint8_t *cw, size_t len, uint8_t nsym, uint8_t *synd)
{
    for (unsigned j = 0u; j < nsym; j++) {
        uint8_t x = gf_alpha_pow(j);
        uint8_t s = 0u;
        for (size_t i = 0u; i < len; i++) {
            s = (uint8_t)(gf_mul(s, x) ^ cw[i]);
        }
        synd[j] = s;
    }
}

static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0u;
    for (size_t i = 0u; i < n; i++) {
        acc = (uint8_t)(acc | p[i]);
    }
    return acc == 0u;
}

/* Gamma(x) = prod (1 + X_k x), low degree first; returns its degree (n_erase). */
static void rs_erasure_locator(size_t len, const uint8_t *erase_pos, uint8_t n_erase,
                               uint8_t gamma[RS_POLY_CAP])
{
    memset(gamma, 0, RS_POLY_CAP);
    gamma[0] = 1u;
    for (unsigned k = 0u; k < n_erase; k++) {
        uint8_t x = gf_alpha_pow((unsigned)(len - 1u - erase_pos[k]));
        for (unsigned j = k + 1u; j > 0u; j--) {
            gamma[j] = (uint8_t)(gamma[j] ^ gf_mul(gamma[j - 1u], x));
        }
    }
}

/* Omega(x) = S(x) * Lambda(x) mod x^nsym, low degree first. */
static void rs_omega(const uint8_t *synd, uint8_t nsym, const uint8_t *lambda,
                     uint8_t omega[BR_RS_MAX_NSYM])
{
    for (unsigned i = 0u; i < nsym; i++) {
        uint8_t acc = 0u;
        for (unsigned j = 0u; j <= i; j++) {
            acc = (uint8_t)(acc ^ gf_mul(synd[j], lambda[i - j]));
        }
        omega[i] = acc;
    }
}

/*
 * Forney error value at codeword index pos (fcr 0):
 *   Y = X * Omega(X^-1) / Lambda'(X^-1), X = alpha^(len-1-pos).
 * Returns false if Lambda'(X^-1) == 0 (not a simple root).
 */
static bool rs_forney(size_t len, size_t pos, const uint8_t *omega, uint8_t nsym,
                      const uint8_t *lambda, unsigned lambda_deg, uint8_t *y_out)
{
    unsigned e = (unsigned)(len - 1u - pos);
    uint8_t x = gf_alpha_pow(e);
    uint8_t xinv = gf_alpha_pow(255u - e % 255u);
    uint8_t num = gf_mul(x, poly_eval_low(omega, nsym, xinv));
    /* Formal derivative in GF(2^m): only odd-degree terms survive. */
    uint8_t den = 0u;
    uint8_t xinv2 = gf_mul(xinv, xinv);
    uint8_t xp = 1u; /* xinv^(j-1) for odd j */
    for (unsigned j = 1u; j <= lambda_deg; j += 2u) {
        den = (uint8_t)(den ^ gf_mul(lambda[j], xp));
        xp = gf_mul(xp, xinv2);
    }
    if (den == 0u) {
        return false;
    }
    *y_out = gf_div(num, den);
    return true;
}

br_err_t br_rs_encode(const uint8_t *msg, size_t msg_len, uint8_t nsym, uint8_t *parity_out)
{
    if (parity_out == NULL || (msg == NULL && msg_len > 0u) ||
        nsym == 0u || nsym > BR_RS_MAX_NSYM) {
        return BR_ERR_ARG;
    }
    if (msg_len > (size_t)BR_RS_MAX_CODEWORD - nsym) {
        return BR_ERR_TOO_BIG;
    }

    uint8_t g[BR_RS_MAX_NSYM + 1u];
    uint8_t reg[BR_RS_MAX_NSYM];
    rs_generator(nsym, g);
    memset(reg, 0, sizeof reg);

    /* LFSR form of the synthetic division of msg(x) * x^nsym by g(x). */
    for (size_t i = 0u; i < msg_len; i++) {
        uint8_t fb = (uint8_t)(msg[i] ^ reg[0]);
        for (unsigned j = 0u; j + 1u < nsym; j++) {
            reg[j] = (uint8_t)(reg[j + 1u] ^ gf_mul(g[j + 1u], fb));
        }
        reg[nsym - 1u] = gf_mul(g[nsym], fb);
    }
    memcpy(parity_out, reg, nsym);
    return BR_OK;
}

br_err_t br_rs_syndromes(const uint8_t *codeword, size_t len, uint8_t nsym, uint8_t *synd_out)
{
    if (codeword == NULL || synd_out == NULL || nsym == 0u || nsym > BR_RS_MAX_NSYM ||
        len == 0u || len > BR_RS_MAX_CODEWORD || (size_t)nsym >= len) {
        return BR_ERR_ARG;
    }
    rs_syndromes_raw(codeword, len, nsym, synd_out);
    return BR_OK;
}

br_err_t br_rs_decode(uint8_t *codeword, size_t len, uint8_t nsym,
                      const uint8_t *erase_pos, uint8_t n_erase,
                      uint8_t *n_corrected_out)
{
    if (codeword == NULL || nsym == 0u || nsym > BR_RS_MAX_NSYM ||
        len <= (size_t)nsym || len > BR_RS_MAX_CODEWORD ||
        n_erase > nsym || (erase_pos == NULL && n_erase > 0u)) {
        return BR_ERR_ARG;
    }
    {
        bool seen[BR_RS_MAX_CODEWORD];
        memset(seen, 0, sizeof seen);
        for (unsigned k = 0u; k < n_erase; k++) {
            if ((size_t)erase_pos[k] >= len || seen[erase_pos[k]]) {
                return BR_ERR_ARG;
            }
            seen[erase_pos[k]] = true;
        }
    }

    uint8_t synd[BR_RS_MAX_NSYM];
    rs_syndromes_raw(codeword, len, nsym, synd);
    if (all_zero(synd, nsym)) {
        if (n_corrected_out != NULL) {
            *n_corrected_out = 0u;
        }
        return BR_OK;
    }

    /* Berlekamp-Massey seeded with the erasure locator (Blahut). */
    uint8_t lambda[RS_POLY_CAP];
    uint8_t b[RS_POLY_CAP];
    uint8_t t[RS_POLY_CAP];
    rs_erasure_locator(len, erase_pos, n_erase, lambda);
    memcpy(b, lambda, sizeof b);
    unsigned L = n_erase;
    const unsigned e = n_erase;

    for (unsigned r = e + 1u; r <= nsym; r++) {
        /* discrepancy: sum_j lambda[j] * S[r-1-j] */
        uint8_t delta = 0u;
        for (unsigned j = 0u; j < r && j < RS_POLY_CAP; j++) {
            delta = (uint8_t)(delta ^ gf_mul(lambda[j], synd[r - 1u - j]));
        }
        /* b <- x * b (the top coefficient is provably 0: deg b <= 2 * nsym) */
        memmove(&b[1], &b[0], RS_POLY_CAP - 1u);
        b[0] = 0u;
        if (delta == 0u) {
            continue;
        }
        for (unsigned j = 0u; j < RS_POLY_CAP; j++) {
            t[j] = (uint8_t)(lambda[j] ^ gf_mul(delta, b[j]));
        }
        if (2u * L <= r + e - 1u) {
            uint8_t dinv = gf_div(1u, delta);
            for (unsigned j = 0u; j < RS_POLY_CAP; j++) {
                b[j] = gf_mul(lambda[j], dinv);
            }
            L = r + e - L;
        }
        memcpy(lambda, t, sizeof t);
    }

    unsigned deg = 0u;
    for (unsigned j = 0u; j < RS_POLY_CAP; j++) {
        if (lambda[j] != 0u) {
            deg = j;
        }
    }
    /* 2 * errors + erasures <= nsym, errors = L - e. */
    if (deg != L || L > nsym || 2u * L - e > nsym || L == 0u) {
        return BR_ERR_UNCORRECTABLE;
    }

    /* Chien search over the shortened code's positions only. */
    uint8_t roots[BR_RS_MAX_NSYM];
    unsigned n_roots = 0u;
    for (size_t pos = 0u; pos < len; pos++) {
        unsigned ex = (unsigned)(len - 1u - pos);
        uint8_t xinv = gf_alpha_pow(255u - ex % 255u);
        if (poly_eval_low(lambda, deg + 1u, xinv) == 0u) {
            if (n_roots >= L) {
                return BR_ERR_UNCORRECTABLE;
            }
            roots[n_roots] = (uint8_t)pos;
            n_roots++;
        }
    }
    if (n_roots != L) {
        return BR_ERR_UNCORRECTABLE;
    }

    uint8_t omega[BR_RS_MAX_NSYM];
    rs_omega(synd, nsym, lambda, omega);

    uint8_t tmp[BR_RS_MAX_CODEWORD];
    memcpy(tmp, codeword, len);
    unsigned changed = 0u;
    for (unsigned k = 0u; k < n_roots; k++) {
        uint8_t y;
        if (!rs_forney(len, roots[k], omega, nsym, lambda, deg, &y)) {
            return BR_ERR_UNCORRECTABLE;
        }
        if (y != 0u) {
            tmp[roots[k]] = (uint8_t)(tmp[roots[k]] ^ y);
            changed++;
        }
    }

    rs_syndromes_raw(tmp, len, nsym, synd);
    if (!all_zero(synd, nsym)) {
        return BR_ERR_UNCORRECTABLE;
    }
    memcpy(codeword, tmp, len);
    if (n_corrected_out != NULL) {
        *n_corrected_out = (uint8_t)changed;
    }
    return BR_OK;
}

br_err_t br_rs_erasure_fill(uint8_t *codeword, size_t len, uint8_t nsym,
                            const uint8_t *erase_pos, uint8_t n_erase)
{
    uint8_t synd[BR_RS_MAX_NSYM];
    rs_syndromes_raw(codeword, len, nsym, synd);
    if (all_zero(synd, nsym)) {
        return BR_OK;
    }
    uint8_t gamma[RS_POLY_CAP];
    uint8_t omega[BR_RS_MAX_NSYM];
    rs_erasure_locator(len, erase_pos, n_erase, gamma);
    rs_omega(synd, nsym, gamma, omega);
    for (unsigned k = 0u; k < n_erase; k++) {
        uint8_t y;
        if (!rs_forney(len, erase_pos[k], omega, nsym, gamma, n_erase, &y)) {
            return BR_ERR_UNCORRECTABLE;
        }
        codeword[erase_pos[k]] = (uint8_t)(codeword[erase_pos[k]] ^ y);
    }
    return BR_OK;
}
