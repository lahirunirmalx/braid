// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_crc16.c - CRC-16/CCITT-FALSE (spec 3.1) and the fallback unit ID (section 2).
 *
 * poly 0x1021, init 0xFFFF, no reflection, xorout 0. Nibble-table
 * implementation: 16 x u16 of flash, two lookups per byte.
 */
#include "braid/br_crc16.h"

#include "br_internal.h"

/* s_crc_nib[i] = CRC register after shifting (i << 12) through 4 steps. */
static const uint16_t s_crc_nib[16] = {
    0x0000u, 0x1021u, 0x2042u, 0x3063u, 0x4084u, 0x50A5u, 0x60C6u, 0x70E7u,
    0x8108u, 0x9129u, 0xA14Au, 0xB16Bu, 0xC18Cu, 0xD1ADu, 0xE1CEu, 0xF1EFu
};

uint16_t br_crc16_raw(uint16_t crc, const uint8_t *data, size_t len)
{
    for (size_t i = 0u; i < len; i++) {
        unsigned b = data[i];
        unsigned r = crc;
        r = ((r << 4) & 0xFFFFu) ^ s_crc_nib[((r >> 12) ^ (b >> 4)) & 0x0Fu];
        r = ((r << 4) & 0xFFFFu) ^ s_crc_nib[((r >> 12) ^ b) & 0x0Fu];
        crc = (uint16_t)r;
    }
    return crc;
}

br_err_t br_crc16_update(uint16_t crc, const uint8_t *data, size_t len, uint16_t *crc_out)
{
    if (crc_out == NULL || (data == NULL && len > 0u)) {
        return BR_ERR_ARG;
    }
    *crc_out = (len == 0u) ? crc : br_crc16_raw(crc, data, len);
    return BR_OK;
}

br_err_t br_crc16(const uint8_t *data, size_t len, uint16_t *crc_out)
{
    return br_crc16_update((uint16_t)BR_CRC16_INIT, data, len, crc_out);
}

br_err_t br_fallback_unit_id(const uint8_t mac[6], uint16_t *id_out)
{
    if (mac == NULL || id_out == NULL) {
        return BR_ERR_ARG;
    }
    uint16_t crc = br_crc16_raw((uint16_t)BR_CRC16_INIT, mac, 6u);
    uint16_t id = crc;
    if (id < BR_ID_UNIT_FIRST || id >= BR_ID_GROUP_FIRST) {
        /* section 2: (crc % 0xFEEF) + 0x0010, always 0x0010..0xFEFE (a unit ID). */
        id = (uint16_t)((crc % 0xFEEFu) + BR_ID_UNIT_FIRST);
    }
    *id_out = id;
    return BR_OK;
}
