// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// disp_theme.c - see disp_theme.h. Dark theme, RGB565.

#include "disp_theme.h"

/* RGB888 -> RGB565 at compile time */
#define RGB565(r, g, b) (uint16_t)((((r) & 0xF8u) << 8) | (((g) & 0xFCu) << 3) | ((b) >> 3))

static const disp_palette_t k_dark = {
    RGB565(0x00, 0x00, 0x00),
    {
        [DISP_C_FG]     = RGB565(0xE0, 0xE0, 0xE0),
        [DISP_C_TITLE]  = RGB565(0x4F, 0xC3, 0xF7),
        [DISP_C_ACCENT] = RGB565(0xFF, 0xD5, 0x4F),
        [DISP_C_GOOD]   = RGB565(0x66, 0xBB, 0x6A),
        [DISP_C_WARN]   = RGB565(0xFF, 0xA7, 0x26),
        [DISP_C_BAD]    = RGB565(0xEF, 0x53, 0x50),
        [DISP_C_DIM]    = RGB565(0x90, 0x90, 0x90),
    },
};

const disp_palette_t *disp_theme_palette(void)
{
    return &k_dark;
}

disp_color_t disp_theme_rssi(int rssi_dbm)
{
    if (rssi_dbm >= -75) {
        return DISP_C_GOOD;
    }
    if (rssi_dbm >= -85) {
        return DISP_C_WARN;
    }
    return DISP_C_BAD;
}
