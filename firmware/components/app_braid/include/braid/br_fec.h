// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_fec.h - group FEC: systematic RS erasure code ACROSS frames (spec 3.3).
 *
 * Model (3.3):
 * - A group has k data blocks (k = actual members, 1..fec_k <= 16) and m
 *   parity blocks (m = fec_m, 1..4). FEC runs on PLAINTEXT DATA payloads:
 *   below encryption at the sender, above decryption at the receiver.
 * - Each DATA frame maps to a block [len u8][payload][zero pad] of block_len
 *   bytes, block_len = longest payload in the group + 1.
 * - Column-wise code: for each byte position p, the k data bytes
 *   data[0][p] .. data[k-1][p] are RS-encoded with nsym = m using the
 *   br_rs.h conventions (prim 0x11D, fcr 0, alpha 2, parity appended);
 *   parity symbol j goes to parity[j][p].
 *   With m = 1 the parity block is the XOR of the data blocks.
 * - Erasure decoding: the per-column codeword is
 *   data[0] .. data[k-1], parity[0] .. parity[m-1], so data block i is
 *   codeword position i and parity block j is position k + j. Any k of the
 *   k + m blocks reconstruct the rest.
 *
 * Vectors (Appendix A.5):
 *   k 2 / m 1: 03 01 02 03 00, 04 10 20 30 40 -> parity 07 11 22 33 40
 *   k 4 / m 2: 02 aa bb 00, 03 11 22 33, 01 ff 00 00, 03 01 02 03
 *              -> parity 2d 01 2d 19, 2e 44 b6 29;
 *              erasing positions {1, 3} reproduces blocks 1 and 3.
 *
 * PARITY payload (3.3, line 226), little-endian:
 *   first_seq u16, k u8, m u8, idx u8 (0..m-1), block_len u16, reserved u8,
 *   parity[block_len]                       -> 8-byte header + block_len.
 *
 * No heap; reentrant.
 */
#ifndef BRAID_BR_FEC_H
#define BRAID_BR_FEC_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_FEC_PARITY_HDR_LEN   8u
/** Largest block: longest plaintext payload (BR_MAX_PAYLOAD_NOAUTH) + 1 length byte. */
#define BR_FEC_MAX_BLOCK_LEN   (BR_MAX_PAYLOAD_NOAUTH + 1u)

/** Decoded PARITY payload header (3.3). */
typedef struct {
    uint16_t first_seq;  /**< seq of the first data member; members are k consecutive seqs (mod 2^16). */
    uint8_t  k;          /**< Actual data members, 1..fec_k. */
    uint8_t  m;          /**< Parity frames in the group (== fec_m). */
    uint8_t  idx;        /**< This parity block's index, 0..m-1. */
    uint16_t block_len;  /**< Bytes per block. */
    uint8_t  reserved;   /**< 0 on send; ignored on decode (copied out as received). */
} br_fec_parity_hdr_t;

/**
 * Build a group block from a DATA plaintext payload: [len][payload][0 pad].
 *
 * @param payload      Plaintext DATA payload; NULL only if payload_len == 0.
 * @param payload_len  0..255; must be <= block_len - 1.
 * @param block_len    1..BR_FEC_MAX_BLOCK_LEN.
 * @param block_out    Receives block_len bytes.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or block_len out of range;
 *         BR_ERR_TOO_BIG if payload_len + 1 > block_len.
 * @spec 3.3
 */
br_err_t br_fec_block_from_payload(const uint8_t *payload, uint8_t payload_len,
                                   uint16_t block_len, uint8_t *block_out);

/**
 * Extract the DATA payload from a (possibly reconstructed) block.
 *
 * Returns a pointer INTO block (no copy): *payload_out = block + 1,
 * *payload_len_out = block[0].
 *
 * @param block            Block of block_len bytes.
 * @param block_len        1..BR_FEC_MAX_BLOCK_LEN.
 * @param payload_out      Receives block + 1.
 * @param payload_len_out  Receives block[0].
 * @return BR_OK; BR_ERR_ARG on NULL pointers or block_len out of range;
 *         BR_ERR_DECODE if block[0] + 1 > block_len, or a pad byte after the
 *         payload is non-zero (corrupt reconstruction).
 * @spec 3.3
 */
br_err_t br_fec_payload_from_block(const uint8_t *block, uint16_t block_len,
                                   const uint8_t **payload_out, uint8_t *payload_len_out);

/**
 * Encode the m parity blocks of a group.
 *
 * @param data        k pointers to data blocks of block_len bytes each.
 * @param k           1..BR_FEC_K_MAX.
 * @param m           1..BR_FEC_M_MAX.
 * @param block_len   1..BR_FEC_MAX_BLOCK_LEN.
 * @param parity_out  m pointers to output blocks of block_len bytes; must not
 *                    overlap any data block.
 * @return BR_OK; BR_ERR_ARG on NULL pointers (array or element) or k, m,
 *         block_len out of range.
 * @spec 3.3, A.5
 */
br_err_t br_fec_encode(const uint8_t *const data[], uint8_t k, uint8_t m,
                       uint16_t block_len, uint8_t *const parity_out[]);

/**
 * Reconstruct missing data blocks by erasure decoding.
 *
 * blocks[] has k + m entries in codeword order: data 0..k-1, then parity
 * 0..m-1. present[i] says whether blocks[i] holds a received block. Missing
 * data blocks are written in place (blocks[i] must point to block_len bytes of
 * writable storage even when present[i] is false). Missing parity blocks are
 * not regenerated. Present blocks are trusted (they passed CRC / CCM): this is
 * erasure-only decoding, no error search.
 *
 * @param blocks       k + m pointers (none NULL).
 * @param present      k + m flags.
 * @param k            1..BR_FEC_K_MAX.
 * @param m            1..BR_FEC_M_MAX.
 * @param block_len    1..BR_FEC_MAX_BLOCK_LEN.
 * @param n_recovered_out  Optional (may be NULL): number of data blocks
 *                     reconstructed (feeds fec_recovered).
 * @return BR_OK (all k data blocks now valid; also when none were missing);
 *         BR_ERR_ARG on NULL pointers or k, m, block_len out of range;
 *         BR_ERR_UNCORRECTABLE if fewer than k of the k + m blocks are
 *         present (nothing written).
 * @spec 3.3, A.5
 */
br_err_t br_fec_decode(uint8_t *const blocks[], const bool present[], uint8_t k, uint8_t m,
                       uint16_t block_len, uint8_t *n_recovered_out);

/**
 * Serialise a PARITY payload header (8 bytes, little-endian).
 *
 * Writes hdr->reserved as given (callers pass 0, 3.3).
 *
 * @param hdr      Header; requires 1 <= k <= BR_FEC_K_MAX, 1 <= m <= BR_FEC_M_MAX,
 *                 idx < m, 1 <= block_len <= BR_FEC_MAX_BLOCK_LEN.
 * @param out      Output buffer.
 * @param out_cap  >= BR_FEC_PARITY_HDR_LEN.
 * @return BR_OK; BR_ERR_ARG on NULL or out-of-range fields; BR_ERR_TOO_BIG if
 *         out_cap < 8.
 * @spec 3.3 (line 226)
 */
br_err_t br_fec_parity_hdr_encode(const br_fec_parity_hdr_t *hdr, uint8_t *out, size_t out_cap);

/**
 * Parse a PARITY payload header (syntax only).
 *
 * Range checks against the session (3.6 PARITY row: idx < m == fec_m,
 * k 1..fec_k, block_len <= max_payload - 8, first_seq inside the window)
 * need session state and are NOT done here, except that block_len must equal
 * len - 8 (parity[block_len] fills the rest of the payload).
 *
 * @param payload  PARITY plaintext payload.
 * @param len      Payload length; >= 8.
 * @param hdr_out  Receives the fields.
 * @return BR_OK; BR_ERR_ARG on NULL pointers; BR_ERR_DECODE if len < 8 or
 *         block_len != len - 8.
 * @spec 3.3, 3.6 (PARITY row)
 */
br_err_t br_fec_parity_hdr_decode(const uint8_t *payload, size_t len, br_fec_parity_hdr_t *hdr_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_FEC_H */
