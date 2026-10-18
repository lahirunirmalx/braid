// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// st7789.c - see st7789.h.

#include "st7789.h"

#include "oled.h" /* oled_glyph(): the shared 5x7 font */

#define ST7789_SWRESET 0x01u
#define ST7789_SLPOUT  0x11u
#define ST7789_NORON   0x13u
#define ST7789_DISPON  0x29u
#define ST7789_COLMOD  0x3Au
#define ST7789_MADCTL  0x36u

static bool window(st7789_t *d, unsigned x, unsigned y, unsigned w, unsigned h)
{
    const unsigned x0 = x + d->x_off;
    const unsigned x1 = x0 + w - 1u;
    const unsigned y0 = y + d->y_off;
    const unsigned y1 = y0 + h - 1u;
    const uint8_t ca[4] = {(uint8_t)(x0 >> 8), (uint8_t)x0, (uint8_t)(x1 >> 8), (uint8_t)x1};
    const uint8_t ra[4] = {(uint8_t)(y0 >> 8), (uint8_t)y0, (uint8_t)(y1 >> 8), (uint8_t)y1};
    return d->cmd(d->user, ST7789_CASET, ca, sizeof ca) && d->cmd(d->user, ST7789_RASET, ra, sizeof ra) &&
           d->cmd(d->user, ST7789_RAMWR, NULL, 0u);
}

bool st7789_init(st7789_t *d)
{
    if (d->cmd == NULL || d->data == NULL || d->delay == NULL) {
        return false;
    }
    const uint8_t colmod = 0x55u; /* 16 bit / pixel */
    if (!d->cmd(d->user, ST7789_SWRESET, NULL, 0u)) {
        return false;
    }
    d->delay(d->user, 150u);
    if (!d->cmd(d->user, ST7789_SLPOUT, NULL, 0u)) {
        return false;
    }
    d->delay(d->user, 120u);
    if (!d->cmd(d->user, ST7789_COLMOD, &colmod, 1u) || !d->cmd(d->user, ST7789_MADCTL, &d->madctl, 1u) ||
        !d->cmd(d->user, d->invert ? ST7789_INVON : ST7789_INVOFF, NULL, 0u) ||
        !d->cmd(d->user, ST7789_NORON, NULL, 0u) || !d->cmd(d->user, ST7789_DISPON, NULL, 0u)) {
        return false;
    }
    d->delay(d->user, 20u);
    return true;
}

bool st7789_flip(st7789_t *d, bool flipped)
{
    const bool inv = d->invert != flipped;
    return d->cmd != NULL && d->cmd(d->user, inv ? ST7789_INVON : ST7789_INVOFF, NULL, 0u);
}

bool st7789_fill(st7789_t *d, unsigned x, unsigned y, unsigned w, unsigned h, uint16_t color)
{
    if (x >= d->width || y >= d->height || w == 0u || h == 0u) {
        return true;
    }
    if (w > d->width - x) {
        w = d->width - x;
    }
    if (h > d->height - y) {
        h = d->height - y;
    }
    size_t left = (size_t)w * h * 2u;
    const size_t chunk = left < sizeof d->strip ? left : sizeof d->strip;
    for (size_t i = 0; i + 1u < chunk; i += 2u) {
        d->strip[i] = (uint8_t)(color >> 8);
        d->strip[i + 1u] = (uint8_t)color;
    }
    if (!window(d, x, y, w, h)) {
        return false;
    }
    while (left > 0u) {
        const size_t n = left < chunk ? left : chunk;
        if (!d->data(d->user, d->strip, n)) {
            return false;
        }
        left -= n;
    }
    return true;
}

bool st7789_text(st7789_t *d, unsigned x, unsigned y, const char *s, unsigned cols, unsigned scale, uint16_t fg,
                 uint16_t bg)
{
    if (s == NULL || scale == 0u || x >= d->width || y >= d->height) {
        return true;
    }
    const unsigned cw = 6u * scale;
    const unsigned chh = 8u * scale;
    if (y + chh > d->height) {
        return true; /* a cut row would leave stale pixels below: skip it */
    }
    if (cols > (d->width - x) / cw) {
        cols = (d->width - x) / cw;
    }
    const unsigned per_chunk = (unsigned)(sizeof d->strip / ((size_t)cw * chh * 2u));
    if (per_chunk == 0u) {
        return false;
    }
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    for (unsigned c0 = 0; c0 < cols; c0 += per_chunk) {
        const unsigned n = cols - c0 < per_chunk ? cols - c0 : per_chunk;
        const unsigned w = n * cw;
        size_t k = 0;
        for (unsigned py = 0; py < chh; py++) {
            const unsigned gy = py / scale;
            for (unsigned px = 0; px < w; px++) {
                const unsigned cell = c0 + px / cw;
                const unsigned gx = (px % cw) / scale;
                const char ch = cell < len ? s[cell] : ' ';
                const uint8_t *g = oled_glyph(ch);
                const bool on = gx < 5u && ((g[gx] >> gy) & 1u) != 0u;
                const uint16_t c = on ? fg : bg;
                d->strip[k++] = (uint8_t)(c >> 8);
                d->strip[k++] = (uint8_t)c;
            }
        }
        if (!window(d, x + c0 * cw, y, w, chh) || !d->data(d->user, d->strip, k)) {
            return false;
        }
    }
    return true;
}
