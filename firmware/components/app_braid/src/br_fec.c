// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_fec.c - group FEC across frames (spec 3.3, Appendix A.5).
 *
 * Column-wise RS with the br_rs.h conventions: for byte position p the
 * codeword is data[0][p] .. data[k-1][p] || parity[0][p] .. parity[m-1][p].
 * Decoding is erasure-only (present blocks passed CRC / CCM and are trusted).
 *
 * No heap; scratch is one 20-byte column on the stack.
 */
#include <string.h>

#include "braid/br_fec.h"
#include "braid/br_frame.h"
#include "braid/br_rs.h"

#include "br_internal.h"

#define FEC_N_MAX (BR_FEC_K_MAX + BR_FEC_M_MAX)

static bool fec_dims_ok(uint8_t k, uint8_t m, uint16_t block_len)
{
    return k >= 1u && k <= BR_FEC_K_MAX && m >= 1u && m <= BR_FEC_M_MAX &&
           block_len >= 1u && block_len <= BR_FEC_MAX_BLOCK_LEN;
}

br_err_t br_fec_block_from_payload(const uint8_t *payload, uint8_t payload_len,
                                   uint16_t block_len, uint8_t *block_out)
{
    if (block_out == NULL || (payload == NULL && payload_len > 0u) ||
        block_len == 0u || block_len > BR_FEC_MAX_BLOCK_LEN) {
        return BR_ERR_ARG;
    }
    if ((unsigned)payload_len + 1u > (unsigned)block_len) {
        return BR_ERR_TOO_BIG;
    }
    block_out[0] = payload_len;
    if (payload_len > 0u) {
        memcpy(&block_out[1], payload, payload_len);
    }
    size_t pad = (size_t)block_len - 1u - payload_len;
    if (pad > 0u) {
        memset(&block_out[1u + payload_len], 0, pad);
    }
    return BR_OK;
}

br_err_t br_fec_payload_from_block(const uint8_t *block, uint16_t block_len,
                                   const uint8_t **payload_out, uint8_t *payload_len_out)
{
    if (block == NULL || payload_out == NULL || payload_len_out == NULL ||
        block_len == 0u || block_len > BR_FEC_MAX_BLOCK_LEN) {
        return BR_ERR_ARG;
    }
    uint8_t plen = block[0];
    if ((unsigned)plen + 1u > (unsigned)block_len) {
        return BR_ERR_DECODE;
    }
    uint8_t acc = 0u;
    for (size_t i = 1u + (size_t)plen; i < block_len; i++) {
        acc = (uint8_t)(acc | block[i]);
    }
    if (acc != 0u) {
        return BR_ERR_DECODE;
    }
    *payload_out = &block[1];
    *payload_len_out = plen;
    return BR_OK;
}

br_err_t br_fec_encode(const uint8_t *const data[], uint8_t k, uint8_t m,
                       uint16_t block_len, uint8_t *const parity_out[])
{
    if (data == NULL || parity_out == NULL || !fec_dims_ok(k, m, block_len)) {
        return BR_ERR_ARG;
    }
    for (unsigned i = 0u; i < k; i++) {
        if (data[i] == NULL) {
            return BR_ERR_ARG;
        }
    }
    for (unsigned j = 0u; j < m; j++) {
        if (parity_out[j] == NULL) {
            return BR_ERR_ARG;
        }
    }

    uint8_t col[BR_FEC_K_MAX];
    uint8_t par[BR_FEC_M_MAX];
    for (size_t p = 0u; p < block_len; p++) {
        for (unsigned i = 0u; i < k; i++) {
            col[i] = data[i][p];
        }
        br_err_t rc = br_rs_encode(col, k, m, par);
        if (rc != BR_OK) {
            return rc; /* unreachable: k + m <= 20 */
        }
        for (unsigned j = 0u; j < m; j++) {
            parity_out[j][p] = par[j];
        }
    }
    return BR_OK;
}

br_err_t br_fec_decode(uint8_t *const blocks[], const bool present[], uint8_t k, uint8_t m,
                       uint16_t block_len, uint8_t *n_recovered_out)
{
    if (blocks == NULL || present == NULL || !fec_dims_ok(k, m, block_len)) {
        return BR_ERR_ARG;
    }
    const unsigned n = (unsigned)k + (unsigned)m;
    for (unsigned i = 0u; i < n; i++) {
        if (blocks[i] == NULL) {
            return BR_ERR_ARG;
        }
    }

    uint8_t erase_pos[FEC_N_MAX];
    uint8_t n_erase = 0u;
    unsigned missing_data = 0u;
    for (unsigned i = 0u; i < n; i++) {
        if (!present[i]) {
            erase_pos[n_erase] = (uint8_t)i;
            n_erase++;
            if (i < k) {
                missing_data++;
            }
        }
    }
    if (n_erase > m) {
        return BR_ERR_UNCORRECTABLE; /* fewer than k of k + m present; nothing written */
    }
    if (missing_data == 0u) {
        if (n_recovered_out != NULL) {
            *n_recovered_out = 0u;
        }
        return BR_OK;
    }

    uint8_t col[FEC_N_MAX];
    for (size_t p = 0u; p < block_len; p++) {
        for (unsigned i = 0u; i < n; i++) {
            col[i] = present[i] ? blocks[i][p] : 0u;
        }
        br_err_t rc = br_rs_erasure_fill(col, n, m, erase_pos, n_erase);
        if (rc != BR_OK) {
            return rc; /* unreachable with distinct in-range positions */
        }
        for (unsigned i = 0u; i < k; i++) {
            if (!present[i]) {
                blocks[i][p] = col[i];
            }
        }
    }
    if (n_recovered_out != NULL) {
        *n_recovered_out = (uint8_t)missing_data;
    }
    return BR_OK;
}

br_err_t br_fec_parity_hdr_encode(const br_fec_parity_hdr_t *hdr, uint8_t *out, size_t out_cap)
{
    if (hdr == NULL || out == NULL ||
        hdr->k < 1u || hdr->k > BR_FEC_K_MAX ||
        hdr->m < 1u || hdr->m > BR_FEC_M_MAX ||
        hdr->idx >= hdr->m ||
        hdr->block_len < 1u || hdr->block_len > BR_FEC_MAX_BLOCK_LEN) {
        return BR_ERR_ARG;
    }
    if (out_cap < BR_FEC_PARITY_HDR_LEN) {
        return BR_ERR_TOO_BIG;
    }
    br_wr_le16(&out[0], hdr->first_seq);
    out[2] = hdr->k;
    out[3] = hdr->m;
    out[4] = hdr->idx;
    br_wr_le16(&out[5], hdr->block_len);
    out[7] = hdr->reserved;
    return BR_OK;
}

br_err_t br_fec_parity_hdr_decode(const uint8_t *payload, size_t len, br_fec_parity_hdr_t *hdr_out)
{
    if (payload == NULL || hdr_out == NULL) {
        return BR_ERR_ARG;
    }
    if (len < BR_FEC_PARITY_HDR_LEN) {
        return BR_ERR_DECODE;
    }
    uint16_t block_len = br_rd_le16(&payload[5]);
    if ((size_t)block_len != len - BR_FEC_PARITY_HDR_LEN) {
        return BR_ERR_DECODE;
    }
    hdr_out->first_seq = br_rd_le16(&payload[0]);
    hdr_out->k = payload[2];
    hdr_out->m = payload[3];
    hdr_out->idx = payload[4];
    hdr_out->block_len = block_len;
    hdr_out->reserved = payload[7];
    return BR_OK;
}
