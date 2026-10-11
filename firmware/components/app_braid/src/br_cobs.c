// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_cobs.c - COBS for the UART carrier (spec 1.2, 3.2; Appendix A.3; SPEC-NOTES N11).
 *
 * Encoding matches tools/vectors.py cobs_encode(): a block of 254 non-zero
 * bytes is closed with code 0xFF, and the final block is always emitted
 * (so 254 non-zero bytes encode to FF <254 bytes> 01). The encoder appends
 * the 0x00 delimiter. The decoder accepts input with or without it.
 */
#include "braid/br_cobs.h"

#include "br_internal.h"

br_err_t br_cobs_encode(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    if (dst == NULL || out_len == NULL || (src == NULL && src_len > 0u)) {
        return BR_ERR_ARG;
    }

    size_t code_pos = 0u; /* where the current block's code byte goes */
    size_t w = 1u;        /* next data write position */
    uint8_t code = 1u;

    if (dst_cap < 2u) {
        return BR_ERR_TOO_BIG;
    }
    for (size_t i = 0u; i < src_len; i++) {
        uint8_t b = src[i];
        if (b == 0u) {
            dst[code_pos] = code;
            code_pos = w;
            w++;
            code = 1u;
        } else {
            dst[w] = b;
            w++;
            code++;
            if (code == 0xFFu) {
                dst[code_pos] = code;
                code_pos = w;
                w++;
                code = 1u;
            }
        }
        /* Invariant: w <= dst_cap - 1 keeps room for the final code + delimiter
         * logic below; check before the next write. */
        if (w >= dst_cap) {
            return BR_ERR_TOO_BIG;
        }
    }
    dst[code_pos] = code;
    /* w < dst_cap holds here; the delimiter needs dst[w]. */
    dst[w] = BR_COBS_DELIM;
    w++;
    *out_len = w;
    return BR_OK;
}

br_err_t br_cobs_decode(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    if (src == NULL || dst == NULL || out_len == NULL || src_len == 0u) {
        return BR_ERR_ARG;
    }
    size_t n = src_len;
    if (src[n - 1u] == BR_COBS_DELIM) {
        n--; /* one trailing delimiter is ignored */
    }
    if (n == 0u) {
        return BR_ERR_ARG; /* only a delimiter */
    }

    size_t r = 0u;
    size_t w = 0u;
    while (r < n) {
        uint8_t code = src[r];
        if (code == 0u) {
            return BR_ERR_DECODE;
        }
        r++;
        size_t run = (size_t)code - 1u;
        if (run > n - r) {
            return BR_ERR_DECODE; /* code points past the end */
        }
        for (size_t j = 0u; j < run; j++) {
            uint8_t b = src[r + j];
            if (b == 0u) {
                return BR_ERR_DECODE;
            }
            if (w >= dst_cap) {
                return BR_ERR_TOO_BIG;
            }
            dst[w] = b;
            w++;
        }
        r += run;
        if (code != 0xFFu && r < n) {
            if (w >= dst_cap) {
                return BR_ERR_TOO_BIG;
            }
            dst[w] = 0u;
            w++;
        }
    }
    *out_len = w;
    return BR_OK;
}
