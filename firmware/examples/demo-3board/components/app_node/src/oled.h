// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// oled.h - 128x64 monochrome status display (SSD1306, SH1106 with a column
// offset of 2), portable C11.
//
// No HAL or ESP-IDF header: bytes leave through the write callback (one I2C
// transaction per call, first byte the SSD1306 control byte 0x00 = commands
// or 0x40 = data). Host-tested by firmware/test/host/test_oled.c, which
// includes this .c directly.
//
// Frame updates use page addressing (0xB0 + page, column low / high nibble),
// which SSD1306 and SH1106 both support; horizontal addressing mode (0x20)
// is never used because SH1106 lacks it.
//
// Text: 5x7 font in 6x8 cells, 21 columns x 8 rows; printable ASCII
// 0x20..0x7E only, anything else renders blank. oled_text_x2 doubles the
// glyphs (12x16 cells, two text rows).

#ifndef APP_NODE_OLED_H
#define APP_NODE_OLED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OLED_W       128u
#define OLED_H       64u
#define OLED_PAGES   (OLED_H / 8u)
#define OLED_COLS    (OLED_W / 6u)  /**< 21 text columns */
#define OLED_ROWS    OLED_PAGES     /**< 8 text rows */
#define OLED_ADDR    0x3Cu          /**< usual 7-bit address (0x3D with SA0 high) */

#define OLED_CTRL_CMD   0x00u
#define OLED_CTRL_DATA  0x40u

/** One I2C write of @p len bytes; returns true when the device ACKed it. */
typedef bool (*oled_write_fn)(void *user, const uint8_t *buf, size_t len);

typedef struct {
    uint8_t       fb[OLED_PAGES][OLED_W];  /**< page-major, bit 0 = top row of the page */
    oled_write_fn write;
    void         *user;
    uint8_t       col_offset;              /**< 0 SSD1306, 2 SH1106 */
} oled_t;

/** Bind the transport; clears the frame buffer. Sends nothing. */
void oled_setup(oled_t *o, oled_write_fn write, void *user, uint8_t col_offset);

/** Send the power-on sequence (128x64, internal charge pump, display on). */
bool oled_init(oled_t *o);

/** Normal (false) or inverted (true) pixels, without touching the frame buffer. */
bool oled_invert(oled_t *o, bool on);

void oled_clear(oled_t *o);
void oled_pixel(oled_t *o, unsigned x, unsigned y, bool on);

/** 6x8 text at text row @p row (0..7), column @p col (0..20); clipped at the right edge. */
void oled_text(oled_t *o, unsigned row, unsigned col, const char *s);

/** 12x16 text: occupies rows @p row and @p row + 1, 10 columns of 12 px. */
void oled_text_x2(oled_t *o, unsigned row, unsigned col, const char *s);

/** Send the whole frame buffer (8 pages). */
bool oled_flush(oled_t *o);

/** The 5 column bytes of @p c (bit 0 = top); blank glyph outside 0x20..0x7E. */
const uint8_t *oled_glyph(char c);

#ifdef __cplusplus
}
#endif

#endif /* APP_NODE_OLED_H */
