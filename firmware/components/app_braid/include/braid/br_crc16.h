// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_crc16.h - CRC-16/CCITT-FALSE (spec 3.1).
 *
 * Parameters: poly 0x1021, init 0xFFFF, no input/output reflection, xorout
 * 0x0000. Check value: CRC("123456789") = 0x29B1 (Appendix A.1).
 *
 * On the wire the CRC covers byte 0 .. end of hop_tag (or end of payload when
 * FLAG_AUTH is clear) and is stored little-endian (Appendix A.2: CRC 0xA5E9 is
 * sent as e9 a5). The same function gives the fallback unit ID from the base
 * MAC (section 2).
 */
#ifndef BRAID_BR_CRC16_H
#define BRAID_BR_CRC16_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_CRC16_INIT 0xFFFFu /**< Initial register value for br_crc16_update(). */

/**
 * One-shot CRC-16/CCITT-FALSE.
 *
 * @param data     Input bytes; may be NULL only if len == 0.
 * @param len      Number of bytes.
 * @param crc_out  Receives the CRC (0xFFFF for len == 0).
 * @return BR_OK; BR_ERR_ARG if crc_out is NULL or (data NULL and len > 0).
 * @spec 3.1, A.1
 */
br_err_t br_crc16(const uint8_t *data, size_t len, uint16_t *crc_out);

/**
 * Incremental CRC-16/CCITT-FALSE.
 *
 * Start with crc = BR_CRC16_INIT and feed chunks in order; the final value
 * equals br_crc16() over the concatenation (xorout is 0, so no finalisation).
 *
 * @param crc      Running CRC (BR_CRC16_INIT for the first chunk).
 * @param data     Chunk; may be NULL only if len == 0.
 * @param len      Chunk length.
 * @param crc_out  Receives the updated CRC. May alias nothing else.
 * @return BR_OK; BR_ERR_ARG as for br_crc16().
 * @spec 3.1
 */
br_err_t br_crc16_update(uint16_t crc, const uint8_t *data, size_t len, uint16_t *crc_out);

/**
 * Fallback unit ID from the 6-byte base MAC (section 2, line 121).
 *
 * id = CRC-16/CCITT-FALSE(mac[0..5]); if id < 0x0010 or id >= 0xFF00 then
 * id = (crc % 0xFEEF) + 0x0010. The result is always a unit ID.
 *
 * @param mac     6 bytes, in esp_read_mac() order.
 * @param id_out  Receives the fallback ID.
 * @return BR_OK; BR_ERR_ARG if a pointer is NULL.
 * @spec 2
 */
br_err_t br_fallback_unit_id(const uint8_t mac[6], uint16_t *id_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_CRC16_H */
