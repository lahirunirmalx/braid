// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// st7789.h - ST7789 colour LCD (RGB565) for the status display, portable C11.
//
// No HAL or ESP-IDF header: commands, pixels and delays leave through the
// callbacks (on the device: hal_lcd.h). Text uses the 5x7 font of oled.c,
// scaled by an integer factor, drawn as whole strips (background included)
// so a redraw needs no clear and does not flicker. Host-tested by
// firmware/test/host/test_st7789.c.

#ifndef APP_NODE_ST7789_H
#define APP_NODE_ST7789_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ST7789_STRIP_BYTES 7680u  /**< 240 x 16 px RGB565: one text row at scale 2 */

#define ST7789_CASET   0x2Au
#define ST7789_RASET   0x2Bu
#define ST7789_RAMWR   0x2Cu
#define ST7789_INVOFF  0x20u
#define ST7789_INVON   0x21u

typedef bool (*st7789_cmd_fn)(void *user, uint8_t cmd, const uint8_t *params, size_t len);
typedef bool (*st7789_data_fn)(void *user, const uint8_t *data, size_t len);
typedef void (*st7789_delay_fn)(void *user, uint32_t ms);

typedef struct {
    st7789_cmd_fn   cmd;
    st7789_data_fn  data;
    st7789_delay_fn delay;
    void           *user;
    uint16_t        width;    /**< visible pixels after MADCTL rotation */
    uint16_t        height;
    uint16_t        x_off;    /**< panel RAM offset of the visible window */
    uint16_t        y_off;
    uint8_t         madctl;   /**< rotation / colour order (0x36 parameter) */
    bool            invert;   /**< IPS panels show correct colours with INVON */
    uint8_t         strip[ST7789_STRIP_BYTES];
} st7789_t;

/** Power-on sequence (after a hardware reset): sleep out, RGB565, MADCTL, inversion, display on. */
bool st7789_init(st7789_t *d);

/** Flip the panel inversion against its normal setting (true = flipped). */
bool st7789_flip(st7789_t *d, bool flipped);

/** Fill a rectangle with one colour (clipped to the panel). */
bool st7789_fill(st7789_t *d, unsigned x, unsigned y, unsigned w, unsigned h, uint16_t color);

/**
 * Text at pixel (x, y), cells of 6*scale x 8*scale, background drawn.
 * Exactly @p cols cells are drawn: shorter text is padded with spaces,
 * longer text cut, and cells past the right edge dropped.
 */
bool st7789_text(st7789_t *d, unsigned x, unsigned y, const char *s, unsigned cols, unsigned scale, uint16_t fg,
                 uint16_t bg);

#ifdef __cplusplus
}
#endif

#endif /* APP_NODE_ST7789_H */
