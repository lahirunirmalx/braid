// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_oled.c - host test of the status display driver
 * (examples/demo-3board/components/app_node/src/oled.c), compiled into this executable.
 *
 * Part A  font: glyph table bounds, blank for non-printable bytes, a few
 *         glyphs pinned byte for byte (0, 1, A, x).
 * Part B  frame buffer: 6x8 text placement and right-edge clipping, the
 *         double-size renderer, pixel bounds.
 * Part C  bus traffic through a recording writer: init sequence framing,
 *         8 pages of (command 0xB0+p + column, data 0x40 + 128 bytes), the
 *         SH1106 column offset, invert, write failure stops the flush.
 *
 * With OLED_DUMP set in the environment the glyphs the status screens use
 * are printed as # / . art for a visual check.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "braid/br_types.h"
#include "test_util.h"

#include "../../examples/demo-3board/components/app_node/src/oled.c"

#define REC_MAX 64u

typedef struct {
    unsigned n;
    unsigned fail_at;   /* 1-based write index that fails, 0 = never */
    size_t len[REC_MAX];
    uint8_t buf[REC_MAX][1u + OLED_W];
} rec_t;

static bool rec_write(void *user, const uint8_t *buf, size_t len)
{
    rec_t *r = user;
    const unsigned i = r->n++;
    if (i < REC_MAX && len <= sizeof r->buf[0]) {
        r->len[i] = len;
        memcpy(r->buf[i], buf, len);
    }
    return r->fail_at == 0u || r->n != r->fail_at;
}

static void dump_glyphs(const char *s)
{
    for (unsigned row = 0; row < 7u; row++) {
        for (const char *p = s; *p != '\0'; p++) {
            const uint8_t *g = oled_glyph(*p);
            for (unsigned c = 0; c < 5u; c++) {
                putchar(((g[c] >> row) & 1u) != 0u ? '#' : '.');
            }
            putchar(' ');
        }
        putchar('\n');
    }
    putchar('\n');
}

static void part_a_font(void)
{
    tu_ctx("A font");
    static const uint8_t g0[5] = {0x3E, 0x51, 0x49, 0x45, 0x3E};
    static const uint8_t g1[5] = {0x00, 0x42, 0x7F, 0x40, 0x00};
    static const uint8_t gA[5] = {0x7E, 0x11, 0x11, 0x11, 0x7E};
    static const uint8_t gx[5] = {0x44, 0x28, 0x10, 0x28, 0x44};
    static const uint8_t blank[5] = {0, 0, 0, 0, 0};
    CHECK_MEM(g0, oled_glyph('0'), 5u);
    CHECK_MEM(g1, oled_glyph('1'), 5u);
    CHECK_MEM(gA, oled_glyph('A'), 5u);
    CHECK_MEM(gx, oled_glyph('x'), 5u);
    CHECK_MEM(blank, oled_glyph(' '), 5u);
    CHECK_MEM(blank, oled_glyph('\n'), 5u);
    CHECK_MEM(blank, oled_glyph((char)0x7F), 5u);
    CHECK_MEM(blank, oled_glyph((char)0xB0), 5u);
    CHECK(oled_glyph('~') == k_font[94]);
    /* every printable glyph but the space draws something, and fits 7 rows */
    for (char c = 0x21; c <= 0x7E; c++) {
        const uint8_t *g = oled_glyph(c);
        unsigned any = 0u;
        for (unsigned i = 0; i < 5u; i++) {
            any |= g[i];
            CHECK((g[i] & 0x80u) == 0u);
        }
        CHECK(any != 0u);
    }
}

static void part_b_framebuffer(void)
{
    static oled_t o;
    oled_setup(&o, NULL, NULL, 0u);

    tu_ctx("B text");
    oled_text(&o, 2u, 1u, "A1");
    CHECK_MEM(oled_glyph('A'), &o.fb[2][6], 5u);
    CHECK(o.fb[2][11] == 0u);
    CHECK_MEM(oled_glyph('1'), &o.fb[2][12], 5u);
    CHECK(o.fb[2][5] == 0u && o.fb[1][6] == 0u && o.fb[3][6] == 0u);

    tu_ctx("B clip");
    oled_clear(&o);
    oled_text(&o, 0u, 0u, "0123456789012345678901234"); /* 25 chars, 21 fit */
    CHECK_MEM(oled_glyph('0'), &o.fb[0][120], 5u);      /* col 20 = '0' of "20" */
    CHECK(o.fb[0][126] == 0u && o.fb[0][127] == 0u);
    CHECK(o.fb[1][0] == 0u);
    oled_text(&o, 8u, 0u, "X");                          /* row out of range: ignored */
    oled_text(&o, 0u, 21u, "X");                         /* column out of range: ignored */
    CHECK(o.fb[0][126] == 0u);

    tu_ctx("B pixel");
    oled_clear(&o);
    oled_pixel(&o, 127u, 63u, true);
    CHECK(o.fb[7][127] == 0x80u);
    oled_pixel(&o, 127u, 63u, false);
    CHECK(o.fb[7][127] == 0u);
    oled_pixel(&o, 128u, 0u, true);
    oled_pixel(&o, 0u, 64u, true);
    for (unsigned p = 0; p < OLED_PAGES; p++) {
        for (unsigned x = 0; x < OLED_W; x++) {
            CHECK(o.fb[p][x] == 0u);
        }
    }

    tu_ctx("B x2");
    oled_clear(&o);
    oled_text_x2(&o, 2u, 0u, "1");
    /* '1' column 2 is 0x7F: rows 0..6 set -> doubled to y 16..29 at x 4, 5 */
    CHECK(o.fb[2][4] == 0xFFu && o.fb[2][5] == 0xFFu);
    CHECK(o.fb[3][4] == 0x3Fu && o.fb[3][5] == 0x3Fu);
    CHECK(o.fb[2][0] == 0u && o.fb[1][4] == 0u && o.fb[4][4] == 0u);
    oled_text_x2(&o, 7u, 0u, "1");                       /* needs two rows: ignored */
    CHECK(o.fb[7][4] == 0u);
}

static void part_c_bus(void)
{
    static oled_t o;
    static rec_t r;

    tu_ctx("C init");
    memset(&r, 0, sizeof r);
    oled_setup(&o, rec_write, &r, 0u);
    CHECK(oled_init(&o));
    CHECK_EQ_U32(r.n, 1u);
    CHECK(r.buf[0][0] == OLED_CTRL_CMD);
    CHECK(r.buf[0][1] == 0xAEu);                  /* off first */
    CHECK(r.buf[0][r.len[0] - 1u] == 0xAFu);      /* on last */

    tu_ctx("C flush");
    memset(&r, 0, sizeof r);
    oled_text(&o, 3u, 0u, "A");
    CHECK(oled_flush(&o));
    CHECK_EQ_U32(r.n, 2u * OLED_PAGES);
    for (unsigned p = 0; p < OLED_PAGES; p++) {
        const unsigned c = 2u * p;
        const unsigned d = c + 1u;
        CHECK_EQ_U32(r.len[c], 4u);
        CHECK(r.buf[c][0] == OLED_CTRL_CMD && r.buf[c][1] == 0xB0u + p);
        CHECK(r.buf[c][2] == 0x00u && r.buf[c][3] == 0x10u);
        CHECK_EQ_U32(r.len[d], 1u + OLED_W);
        CHECK(r.buf[d][0] == OLED_CTRL_DATA);
        CHECK_MEM(o.fb[p], &r.buf[d][1], OLED_W);
    }
    CHECK_MEM(oled_glyph('A'), &r.buf[7][1], 5u);  /* page 3 data */

    tu_ctx("C sh1106");
    memset(&r, 0, sizeof r);
    o.col_offset = 2u;
    CHECK(oled_flush(&o));
    CHECK(r.buf[0][2] == 0x02u && r.buf[0][3] == 0x10u);
    o.col_offset = 0x12u;
    memset(&r, 0, sizeof r);
    CHECK(oled_flush(&o));
    CHECK(r.buf[0][2] == 0x02u && r.buf[0][3] == 0x11u);

    tu_ctx("C invert");
    memset(&r, 0, sizeof r);
    CHECK(oled_invert(&o, true));
    CHECK(oled_invert(&o, false));
    CHECK(r.len[0] == 2u && r.buf[0][1] == 0xA7u && r.buf[1][1] == 0xA6u);

    tu_ctx("C fail");
    memset(&r, 0, sizeof r);
    r.fail_at = 3u;                               /* page 1 command */
    CHECK(!oled_flush(&o));
    CHECK_EQ_U32(r.n, 3u);
    oled_setup(&o, NULL, NULL, 0u);
    CHECK(!oled_init(&o) && !oled_flush(&o) && !oled_invert(&o, true));
}

int main(void)
{
    if (getenv("OLED_DUMP") != NULL) {
        dump_glyphs("0123456789");
        dump_glyphs("ABCDEFGHIJKLM");
        dump_glyphs("NOPQRSTUVWXYZ");
        dump_glyphs("abcdefghijklm");
        dump_glyphs("nopqrstuvwxyz");
        dump_glyphs("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
    }
    part_a_font();
    part_b_framebuffer();
    part_c_bus();
    return tu_summary("test_oled");
}
