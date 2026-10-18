// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// disp_theme.h - colour roles of the status display and the palette that
// maps them to RGB565. The only place colours are defined: screens pick a
// role (disp_color_t), never a colour value. Monochrome panels ignore it.

#ifndef APP_NODE_DISP_THEME_H
#define APP_NODE_DISP_THEME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DISP_C_FG = 0,   /**< ordinary text */
    DISP_C_TITLE,    /**< role / id line */
    DISP_C_ACCENT,   /**< the large figure (hop count, frames forwarded) */
    DISP_C_GOOD,     /**< streaming, strong signal */
    DISP_C_WARN,     /**< seeking / listening, marginal signal */
    DISP_C_BAD,      /**< closed, weak signal, auth failures */
    DISP_C_DIM,      /**< counters, last event */
    DISP_C_COUNT
} disp_color_t;

typedef struct {
    uint16_t bg;                     /**< RGB565 background */
    uint16_t fg[DISP_C_COUNT];       /**< RGB565 per role */
} disp_palette_t;

/** The active palette. */
const disp_palette_t *disp_theme_palette(void);

/** Signal quality role for an RSSI in dBm (good >= -75, warn >= -85, else bad). */
disp_color_t disp_theme_rssi(int rssi_dbm);

#ifdef __cplusplus
}
#endif

#endif /* APP_NODE_DISP_THEME_H */
