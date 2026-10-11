// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_cobs.h - Consistent Overhead Byte Stuffing for the UART carrier (1.2, 3.2).
 *
 * Standard COBS (Cheshire and Baker): the encoded block contains no 0x00 byte;
 * a single 0x00 delimits frames on the wire. COBS bytes are outside max_frame
 * (1.2). Transmit order on UART: frame -> CRC -> RS parity -> COBS + 0x00.
 *
 * Wire convention used here (Appendix A.3): br_cobs_encode() WRITES the
 * trailing 0x00 delimiter. A 50-byte RS block (42-byte frame + 8 parity)
 * encodes to 52 bytes: 1 overhead code byte + 50 + 1 delimiter.
 */
#ifndef BRAID_BR_COBS_H
#define BRAID_BR_COBS_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_COBS_DELIM 0x00u

/**
 * Worst-case encoded size of n input bytes, INCLUDING the trailing delimiter:
 * n + n / 254 + 1 (code bytes) + 1 (delimiter).
 */
#define BR_COBS_MAX_ENCODED(n) ((size_t)(n) + ((size_t)(n) / 254u) + 2u)

/**
 * COBS-encode one block and append the 0x00 delimiter.
 *
 * @param src      Input bytes (frame incl. CRC and RS parity); NULL only if src_len == 0.
 * @param src_len  Input length, 0..BR_MAX_FRAME_MESH (larger inputs are accepted
 *                 if dst is big enough; the protocol never needs them).
 * @param dst      Output buffer. Must not overlap src.
 * @param dst_cap  Capacity of dst. BR_COBS_MAX_ENCODED(src_len) is always enough.
 * @param out_len  Receives the number of bytes written, delimiter included.
 *                 An empty input encodes to {0x01, 0x00}.
 * @return BR_OK; BR_ERR_ARG on NULL pointers; BR_ERR_TOO_BIG if dst_cap is too
 *         small (dst contents then unspecified, *out_len untouched).
 * @spec 1.2 (UART row), 3.2, A.3
 */
br_err_t br_cobs_encode(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len);

/**
 * COBS-decode one block.
 *
 * Input is the bytes of one frame as split from the byte stream. A single
 * trailing 0x00 delimiter, if present as the last byte, is ignored; any other
 * 0x00 in src is an error.
 *
 * @param src      Encoded bytes; NULL only if src_len == 0.
 * @param src_len  Encoded length (with or without the final delimiter).
 * @param dst      Output buffer. Must not overlap src.
 * @param dst_cap  Capacity of dst. src_len bytes is always enough.
 * @param out_len  Receives the decoded length.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or src_len == 0 (also: src is
 *         only a delimiter); BR_ERR_DECODE if src contains an embedded 0x00 or a
 *         code byte points past the end; BR_ERR_TOO_BIG if dst_cap is too small.
 * @spec 1.2, 3.2, A.3
 */
br_err_t br_cobs_decode(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_COBS_H */
