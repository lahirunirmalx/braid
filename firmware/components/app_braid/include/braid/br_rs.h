// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_rs.h - Reed-Solomon over GF(2^8) (spec 3.2; reused by group FEC, 3.3).
 *
 * Conventions (MUST match Python `reedsolo` with these arguments, which is
 * what tools/vectors.py uses for Appendix A):
 *
 *     reedsolo.RSCodec(nsym, fcr=0, prim=0x11d, generator=2, c_exp=8)
 *
 * - Field: GF(2^8), primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1).
 * - Generator element alpha = 2.
 * - First consecutive root fcr = 0: g(x) = prod_{i=0}^{nsym-1} (x - alpha^i).
 * - Systematic, parity APPENDED: codeword = message || parity, parity being
 *   the remainder of message(x) * x^nsym divided by g(x), highest-degree
 *   coefficient first (byte 0 of the message is the highest power).
 * - Codeword (message + parity) length <= 255.
 * - With nsym = 1 the single parity byte is the XOR of the message bytes
 *   (g(x) = x - 1), Appendix A.4: RS(1) of 12 34 56 78 9a = 92.
 * - Erasure positions are 0-based indices into the codeword counted from its
 *   first byte (reedsolo `erase_pos` convention); parity byte j of an
 *   L-byte message is at index L + j.
 *
 * Correction capacity: 2 * errors + erasures <= nsym.
 *
 * All functions are reentrant: tables are const, scratch is on the stack
 * (bounded by BR_RS_MAX_NSYM; under 1 KB). No heap.
 */
#ifndef BRAID_BR_RS_H
#define BRAID_BR_RS_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_RS_PRIM           0x11Du /**< Primitive polynomial. */
#define BR_RS_FCR            0u     /**< First consecutive root. */
#define BR_RS_GENERATOR      2u     /**< alpha. */
#define BR_RS_MAX_CODEWORD 255u     /**< message + parity. */
#define BR_RS_MAX_NSYM      32u     /**< Implementation bound (protocol uses <= 8). */

/**
 * Compute RS parity for a message.
 *
 * @param msg         Message bytes (NULL only if msg_len == 0).
 * @param msg_len     0..(255 - nsym).
 * @param nsym        Parity bytes, 1..BR_RS_MAX_NSYM.
 * @param parity_out  Receives nsym parity bytes, in the order they are
 *                    appended after msg. May not overlap msg.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or nsym out of range;
 *         BR_ERR_TOO_BIG if msg_len + nsym > 255.
 * @spec 3.2, A.3 (RS parity of the UART SEEK), A.4
 */
br_err_t br_rs_encode(const uint8_t *msg, size_t msg_len, uint8_t nsym, uint8_t *parity_out);

/**
 * Decode and correct a codeword in place, with errors AND erasures.
 *
 * On BR_OK the whole codeword (message and parity) is corrected in place and
 * re-encoding codeword[0 .. len-nsym-1] gives codeword[len-nsym .. len-1].
 * On any error the buffer is left unmodified.
 *
 * @param codeword        message || parity, modified in place.
 * @param len             Codeword length, nsym+1..255 (a message of at least 1 byte).
 * @param nsym            Parity bytes, 1..BR_RS_MAX_NSYM.
 * @param erase_pos       Known-bad positions (0-based codeword indices,
 *                        distinct, each < len); NULL only if n_erase == 0.
 * @param n_erase         Number of erasures, 0..nsym.
 * @param n_corrected_out Optional (may be NULL): receives the number of bytes
 *                        whose value changed (0 for an intact codeword).
 * @return BR_OK (codeword valid, possibly corrected);
 *         BR_ERR_ARG on NULL pointers, nsym/len out of range, duplicate or
 *         out-of-range erase_pos, or n_erase > nsym;
 *         BR_ERR_UNCORRECTABLE if 2 * errors + erasures > nsym was detected
 *         (decoder failure, locator degree mismatch, or the corrected word
 *         still has a non-zero syndrome). The frame is dropped (3.2) and the
 *         caller counts rs_fail.
 * @note Mis-correction beyond capacity is possible in theory; 3.2 requires
 *       the CRC to be checked after RS for that reason.
 * @spec 3.2, 3.3, A.4, A.5
 */
br_err_t br_rs_decode(uint8_t *codeword, size_t len, uint8_t nsym,
                      const uint8_t *erase_pos, uint8_t n_erase,
                      uint8_t *n_corrected_out);

/**
 * Compute the nsym syndromes of a codeword (diagnostic / test helper).
 *
 * S_i = codeword(alpha^(fcr + i)) for i = 0..nsym-1. All zero iff the
 * codeword is valid.
 *
 * @param codeword  message || parity.
 * @param len       1..255.
 * @param nsym      1..BR_RS_MAX_NSYM, nsym < len.
 * @param synd_out  Receives nsym bytes, S_0 first.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or out-of-range lengths.
 * @spec 3.2
 */
br_err_t br_rs_syndromes(const uint8_t *codeword, size_t len, uint8_t nsym, uint8_t *synd_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_RS_H */
