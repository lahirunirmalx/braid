// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_st7789.c - host test of the colour status display driver
 * (examples/demo-3board/components/app_node/src/st7789.c, with oled.c for
 * the font and disp_theme.c), compiled into this executable.
 *
 * A fake panel interprets CASET / RASET / RAMWR and writes the pixel stream
 * into an emulated 320 x 240 RAM, so the checks are on pixels, not bytes.
 *
 * Part A  init: command order (SWRESET, SLPOUT, COLMOD 0x55, MADCTL as
 *         configured, INVON / INVOFF per invert, NORON, DISPON), delays.
 * Part B  fill: region and colour in RAM (offsets applied), clipping,
 *         chunking larger than one strip.
 * Part C  text: glyph pixels at scale 2 and 4, padding with background to
 *         the requested cell count, right-edge cut, a row that would cross
 *         the bottom is skipped, big-endian RGB565 on the wire.
 * Part D  flip and theme: inversion toggles against the panel setting,
 *         RSSI thresholds of disp_theme_rssi(), palette roles distinct.
 */

#include <stdio.h>
#include <string.h>

#include "braid/br_types.h"
#include "test_util.h"

#include "../../examples/demo-3board/components/app_node/src/oled.c"
#include "../../examples/demo-3board/components/app_node/src/st7789.c"
#include "../../examples/demo-3board/components/app_node/src/disp_theme.c"

#define RAM_W 320u
#define RAM_H 240u
#define LOG_MAX 64u

typedef struct {
    uint16_t ram[RAM_H][RAM_W];
    unsigned x0, x1, y0, y1, cx, cy;
    bool writing;
    uint8_t pending_hi;
    bool have_hi;
    uint8_t log[LOG_MAX];
    uint8_t log_param[LOG_MAX];
    unsigned n_log;
    unsigned delays_ms;
    unsigned fail_cmd_at; /* 1-based command index that fails, 0 = never */
    unsigned n_cmd;
} panel_t;

static bool fake_cmd(void *user, uint8_t cmd, const uint8_t *p, size_t n)
{
    panel_t *pn = user;
    pn->n_cmd++;
    if (pn->fail_cmd_at != 0u && pn->n_cmd == pn->fail_cmd_at) {
        return false;
    }
    if (pn->n_log < LOG_MAX) {
        pn->log[pn->n_log] = cmd;
        pn->log_param[pn->n_log] = n > 0u ? p[0] : 0u;
        pn->n_log++;
    }
    pn->writing = false;
    pn->have_hi = false;
    if (cmd == ST7789_CASET && n == 4u) {
        pn->x0 = (unsigned)p[0] << 8 | p[1];
        pn->x1 = (unsigned)p[2] << 8 | p[3];
    } else if (cmd == ST7789_RASET && n == 4u) {
        pn->y0 = (unsigned)p[0] << 8 | p[1];
        pn->y1 = (unsigned)p[2] << 8 | p[3];
    } else if (cmd == ST7789_RAMWR) {
        pn->writing = true;
        pn->cx = pn->x0;
        pn->cy = pn->y0;
    }
    return true;
}

static bool fake_data(void *user, const uint8_t *b, size_t n)
{
    panel_t *pn = user;
    if (!pn->writing) {
        return true;
    }
    for (size_t i = 0; i < n; i++) {
        if (!pn->have_hi) {
            pn->pending_hi = b[i];
            pn->have_hi = true;
            continue;
        }
        pn->have_hi = false;
        if (pn->cy <= pn->y1 && pn->cx < RAM_W && pn->cy < RAM_H) {
            pn->ram[pn->cy][pn->cx] = (uint16_t)(pn->pending_hi << 8 | b[i]);
        }
        if (++pn->cx > pn->x1) {
            pn->cx = pn->x0;
            pn->cy++;
        }
    }
    return true;
}

static void fake_delay(void *user, uint32_t ms)
{
    ((panel_t *)user)->delays_ms += ms;
}

static panel_t g_pn;
static st7789_t g_d;

static void setup(void)
{
    memset(&g_pn, 0, sizeof g_pn);
    memset(&g_d, 0, sizeof g_d);
    g_d.cmd = fake_cmd;
    g_d.data = fake_data;
    g_d.delay = fake_delay;
    g_d.user = &g_pn;
    g_d.width = 240u;
    g_d.height = 135u;
    g_d.x_off = 40u;
    g_d.y_off = 53u;
    g_d.madctl = 0x60u;
    g_d.invert = true;
}

static uint16_t px(unsigned x, unsigned y)
{
    return g_pn.ram[y + g_d.y_off][x + g_d.x_off];
}

static void part_a_init(void)
{
    tu_ctx("A init");
    setup();
    CHECK(st7789_init(&g_d));
    static const uint8_t order[] = {0x01, 0x11, 0x3A, 0x36, 0x21, 0x13, 0x29};
    CHECK_EQ_U32(g_pn.n_log, sizeof order);
    CHECK_MEM(order, g_pn.log, sizeof order);
    CHECK(g_pn.log_param[2] == 0x55u);
    CHECK(g_pn.log_param[3] == 0x60u);
    CHECK(g_pn.delays_ms >= 270u);

    setup();
    g_d.invert = false;
    CHECK(st7789_init(&g_d));
    CHECK(g_pn.log[4] == ST7789_INVOFF);

    setup();
    g_pn.fail_cmd_at = 3u;
    CHECK(!st7789_init(&g_d));
    setup();
    g_d.delay = NULL;
    CHECK(!st7789_init(&g_d));
}

static void part_b_fill(void)
{
    tu_ctx("B fill");
    setup();
    CHECK(st7789_fill(&g_d, 10u, 20u, 3u, 2u, 0xABCDu));
    CHECK(px(10u, 20u) == 0xABCDu && px(12u, 21u) == 0xABCDu);
    CHECK(px(9u, 20u) == 0u && px(13u, 20u) == 0u && px(10u, 22u) == 0u);
    CHECK(g_pn.x0 == 50u && g_pn.y0 == 73u); /* offsets applied */

    tu_ctx("B clip + chunks");
    setup();
    CHECK(st7789_fill(&g_d, 0u, 0u, 1000u, 1000u, 0x1234u)); /* whole panel, 64800 B > one strip */
    CHECK(px(0u, 0u) == 0x1234u && px(239u, 134u) == 0x1234u);
    CHECK(g_pn.ram[g_d.y_off + 135u][g_d.x_off] == 0u);       /* nothing below the window */
    CHECK(g_pn.ram[g_d.y_off][g_d.x_off + 240u] == 0u);
    CHECK(st7789_fill(&g_d, 240u, 0u, 5u, 5u, 0xFFFFu));      /* fully outside: no-op */
    CHECK(st7789_fill(&g_d, 0u, 0u, 0u, 5u, 0xFFFFu));
}

static void part_c_text(void)
{
    const uint16_t fg = 0xF800u;
    const uint16_t bg = 0x001Fu;

    tu_ctx("C text x2");
    setup();
    CHECK(st7789_text(&g_d, 0u, 16u, "A", 3u, 2u, fg, bg));
    /* 'A' column 0 = 0x7E: rows 1..6 on, row 0 off; scale 2 -> 2x2 blocks */
    CHECK(px(0u, 16u) == bg && px(1u, 17u) == bg);
    CHECK(px(0u, 18u) == fg && px(1u, 19u) == fg && px(0u, 29u) == fg);
    CHECK(px(0u, 30u) == bg);
    /* column 5 of each cell is the gap; cells 2 and 3 are padding */
    CHECK(px(10u, 18u) == bg && px(11u, 18u) == bg);
    CHECK(px(12u, 18u) == bg && px(35u, 31u) == bg);
    CHECK(px(36u, 18u) == 0u);                 /* exactly 3 cells drawn */

    tu_ctx("C text x4");
    setup();
    CHECK(st7789_text(&g_d, 0u, 32u, "1", 1u, 4u, fg, bg));
    /* '1' column 2 = 0x7F: rows 0..6 on -> x 8..11, y 32..59 */
    CHECK(px(8u, 32u) == fg && px(11u, 59u) == fg);
    CHECK(px(8u, 60u) == bg && px(7u, 40u) == bg);

    tu_ctx("C cut + skip");
    setup();
    CHECK(st7789_text(&g_d, 228u, 0u, "XYZ", 3u, 2u, fg, bg)); /* only one 12 px cell fits */
    CHECK(px(228u, 0u) == fg);                                   /* 'X' col 0 = 0x63: row 0 on */
    CHECK(g_pn.ram[g_d.y_off][g_d.x_off + 240u] == 0u);
    setup();
    CHECK(st7789_text(&g_d, 0u, 128u, "A", 1u, 2u, fg, bg));     /* 128 + 16 > 135: skipped */
    CHECK(px(1u, 130u) == 0u && g_pn.n_log == 0u);
    CHECK(st7789_text(&g_d, 0u, 0u, NULL, 1u, 2u, fg, bg));
    CHECK(st7789_text(&g_d, 0u, 0u, "A", 1u, 0u, fg, bg));

    tu_ctx("C long row");
    setup();
    CHECK(st7789_text(&g_d, 0u, 0u, "01234567890123456789", 20u, 2u, fg, bg));
    CHECK(px(239u, 15u) == bg);
    CHECK_EQ_U32(g_pn.n_log, 3u);              /* 20 cells x2 = one strip: one window */
}

static void part_d_flip_theme(void)
{
    tu_ctx("D flip");
    setup();
    CHECK(st7789_flip(&g_d, true) && g_pn.log[0] == ST7789_INVOFF);
    CHECK(st7789_flip(&g_d, false) && g_pn.log[1] == ST7789_INVON);
    g_d.invert = false;
    CHECK(st7789_flip(&g_d, true) && g_pn.log[2] == ST7789_INVON);

    tu_ctx("D theme");
    CHECK(disp_theme_rssi(-40) == DISP_C_GOOD && disp_theme_rssi(-75) == DISP_C_GOOD);
    CHECK(disp_theme_rssi(-76) == DISP_C_WARN && disp_theme_rssi(-85) == DISP_C_WARN);
    CHECK(disp_theme_rssi(-86) == DISP_C_BAD && disp_theme_rssi(-127) == DISP_C_BAD);
    const disp_palette_t *p = disp_theme_palette();
    CHECK(p != NULL);
    for (unsigned i = 0; i < DISP_C_COUNT; i++) {
        CHECK(p->fg[i] != p->bg);
    }
    CHECK(p->fg[DISP_C_GOOD] != p->fg[DISP_C_BAD] && p->fg[DISP_C_WARN] != p->fg[DISP_C_BAD]);
}

int main(void)
{
    part_a_init();
    part_b_fill();
    part_c_text();
    part_d_flip_theme();
    return tu_summary("test_st7789");
}
