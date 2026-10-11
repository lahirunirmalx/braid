// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_nrf24_link.c - host test of the nRF24L01+ transport
 * (components/app_nrf24_link; spec 1.2 nRF24 row, 11.3, 11.6, 11.11, 12.4,
 * Appendix C.5; SPEC-NOTES N22).
 *
 * The three portable sources are compiled into this executable (as
 * test_uart_link.c does with uart_link.c); the radio below them is a fake.
 *
 * Part A  Segmentation (nrf24_seg.c) over a fake 32-byte pipe: header
 *         layout, round trip of every frame size 0..250 plus the A.3 and
 *         A.15 frames, drops / duplicates / reorder of every segment of a
 *         9-segment frame, two interleaved transmitters, a foreign tag,
 *         the reassembly timeout, buffer-full, malformed segments.
 * Part B  Register driver (nrf24_regs.c) against a register-model fake of
 *         the SPI bus: the init sequence (CONFIG, FEATURE, SETUP_RETR,
 *         SETUP_AW, RF_CH, RF_SETUP, EN_AA, EN_RXADDR, DYNPD, flushes,
 *         STATUS clear, PWR_UP), address byte order, ACTIVATE fallback,
 *         no-chip detection, payload FIFO, PRX / PTX switching, MAX_RT
 *         recovery (FLUSH_TX + flag clear).
 * Part C  Adapter (nrf24_link.c): transport fields and register(); MAX_RT
 *         -> br_node_tx_status(delivered = false); the 12.4 busy hook; then
 *         two real br_node instances (sender 0x0101, probe 0x0103, group
 *         0xFF10, bench key, AUTH on, fec_m 0, ARQ on) through two
 *         adapters on a fake ESB medium: clean; 5 % segment loss with ESB
 *         auto-ACK (ARC 15: every press arrives, no MAX_RT); 5 % loss with
 *         the ACK blind (an unacknowledged carrier: reassembly drops are
 *         counted, ARQ recovers); the allowlist excluding the peer.
 */
#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_sample.h"
#include "braid/br_session.h"
#include "braid/br_tables.h"
#include "test_util.h"
#include "vectors_generated.h"

#include "../../components/app_nrf24_link/src/nrf24_link.c"
#include "../../components/app_nrf24_link/src/nrf24_regs.c"
#include "../../components/app_nrf24_link/src/nrf24_seg.c"

/* ========================================================================= */
/* Part A: segmentation                                                       */
/* ========================================================================= */

#define PIPE_MAX 64u

typedef struct {
    uint8_t  pkt[PIPE_MAX][NRF24_SEG_PKT_MAX];
    uint8_t  len[PIPE_MAX];
    unsigned n;
    bool     refuse;
} pipe_t;

static bool pipe_send(void *ctx, void *tx_ctx, const uint8_t *pkt, uint8_t len)
{
    pipe_t *p = (pipe_t *)ctx;
    (void)tx_ctx;
    if (p->refuse || p->n >= PIPE_MAX) {
        return false;
    }
    memcpy(p->pkt[p->n], pkt, len);
    p->len[p->n] = len;
    p->n++;
    return true;
}

typedef struct {
    uint8_t  src[16];
    uint16_t len[16];
    uint8_t  data[16][NRF24_SEG_MAX_FRAME];
    unsigned n;
} frames_t;

static void frame_sink(void *ctx, uint8_t src, const uint8_t *frame, uint16_t len)
{
    frames_t *f = (frames_t *)ctx;
    if (f->n < 16u) {
        f->src[f->n] = src;
        f->len[f->n] = len;
        if (len > 0u) {
            memcpy(f->data[f->n], frame, len);
        }
    }
    f->n++;
}

static pipe_t    PIPE;
static frames_t  FR;
static nrf24_seg_t TX;
static nrf24_seg_t RX;

static void seg_fresh(uint8_t tx_src, uint8_t rx_slots)
{
    memset(&PIPE, 0, sizeof PIPE);
    memset(&FR, 0, sizeof FR);
    CHECK(nrf24_seg_init(&TX, tx_src, 0, 0, pipe_send, &PIPE, NULL, NULL) == NRF24_SEG_OK);
    CHECK(nrf24_seg_init(&RX, 0xEE, rx_slots, 0, NULL, NULL, frame_sink, &FR) == NRF24_SEG_OK);
}

static void feed_all(nrf24_seg_t *rx, const pipe_t *p, uint64_t now)
{
    for (unsigned i = 0; i < p->n; i++) {
        nrf24_seg_rx(rx, p->pkt[i], p->len[i], now);
    }
}

static void test_seg_layout(void)
{
    tu_ctx("segment header layout (C.5)");
    seg_fresh(0x01, 0);
    uint8_t frame[NRF24_SEG_MAX_FRAME];
    for (unsigned i = 0; i < sizeof frame; i++) {
        frame[i] = (uint8_t)i;
    }
    CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
    CHECK_EQ_U32(PIPE.n, 9u);
    CHECK_EQ_U32(nrf24_seg_count(250), 9u);
    CHECK_EQ_U32(nrf24_seg_count(0), 1u);
    CHECK_EQ_U32(nrf24_seg_count(29), 1u);
    CHECK_EQ_U32(nrf24_seg_count(30), 2u);
    for (unsigned k = 0; k < 9u && k < PIPE.n; k++) {
        CHECK_EQ_U32(PIPE.pkt[k][0], 0x01u);                                   /* src */
        CHECK_EQ_U32(PIPE.pkt[k][1], 0x00u);                                   /* tag of the first frame */
        CHECK_EQ_U32(PIPE.pkt[k][2] & NRF24_SEG_IDX_MASK, k);                  /* idx */
        CHECK_EQ_U32((PIPE.pkt[k][2] & NRF24_SEG_LAST) != 0u, k == 8u);        /* LAST on the 9th */
        CHECK_EQ_U32(PIPE.len[k], k == 8u ? 3u + 18u : 32u);
        if (PIPE.len[k] >= 4u) {
            CHECK_EQ_U32(PIPE.pkt[k][3], (uint8_t)(k * 29u));                  /* frame byte offset */
        }
    }
    /* second frame: tag 1 */
    CHECK(nrf24_seg_send(&TX, NULL, frame, 1) == NRF24_SEG_OK);
    CHECK_EQ_U32(PIPE.n, 10u);
    CHECK_EQ_U32(PIPE.pkt[9][1], 0x01u);
    CHECK_EQ_U32(PIPE.pkt[9][2], NRF24_SEG_LAST);
    CHECK_EQ_U32(PIPE.len[9], 4u);
    /* empty frame: one LAST segment, 3 bytes */
    CHECK(nrf24_seg_send(&TX, NULL, NULL, 0) == NRF24_SEG_OK);
    CHECK_EQ_U32(PIPE.n, 11u);
    CHECK_EQ_U32(PIPE.len[10], 3u);
    CHECK_EQ_U32(PIPE.pkt[10][2], NRF24_SEG_LAST);
    /* refusals */
    CHECK(nrf24_seg_send(&TX, NULL, frame, 251) == NRF24_SEG_ERR_TOO_BIG);
    CHECK(nrf24_seg_send(NULL, NULL, frame, 1) == NRF24_SEG_ERR_ARG);
    CHECK(nrf24_seg_send(&TX, NULL, NULL, 5) == NRF24_SEG_ERR_ARG);
    CHECK(nrf24_seg_init(&RX, 0, NRF24_SEG_SLOTS_MAX + 1u, 0, NULL, NULL, NULL, NULL) == NRF24_SEG_ERR_ARG);
    nrf24_seg_stats_t s;
    nrf24_seg_get_stats(&TX, &s);
    CHECK_EQ_U32(s.seg_tx, 11u);
    CHECK_EQ_U32(s.frames_tx, 3u);
    /* a refused pipe aborts the frame and counts it */
    PIPE.refuse = true;
    CHECK(nrf24_seg_send(&TX, NULL, frame, 100) == NRF24_SEG_ERR_SEND);
    nrf24_seg_get_stats(&TX, &s);
    CHECK_EQ_U32(s.tx_refused, 1u);
    CHECK_EQ_U32(s.frames_tx, 3u);
}

static void round_trip(const uint8_t *frame, uint16_t len, const char *what)
{
    seg_fresh(0x01, 0);
    tu_ctx(what);
    CHECK(nrf24_seg_send(&TX, NULL, frame, len) == NRF24_SEG_OK);
    CHECK_EQ_U32(PIPE.n, nrf24_seg_count(len));
    feed_all(&RX, &PIPE, 1000);
    CHECK_EQ_U32(FR.n, 1u);
    if (FR.n == 1u) {
        CHECK_EQ_U32(FR.src[0], 0x01u);
        CHECK_EQ_U32(FR.len[0], len);
        if (FR.len[0] == len && len > 0u) {
            CHECK_MEM(frame, FR.data[0], len);
        }
    }
    nrf24_seg_stats_t s;
    nrf24_seg_get_stats(&RX, &s);
    CHECK_EQ_U32(s.frames_rx, 1u);
    CHECK_EQ_U32(s.seg_rx, nrf24_seg_count(len));
    CHECK_EQ_U32(s.frames_dropped, 0u);
    CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
}

static void test_seg_round_trip_all_sizes(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0x5E6u);
    uint8_t frame[NRF24_SEG_MAX_FRAME];
    tu_rng_fill(&r, frame, sizeof frame);
    unsigned bad = 0;
    for (unsigned len = 0; len <= NRF24_SEG_MAX_FRAME; len++) {
        seg_fresh(0x42, 0);
        if (nrf24_seg_send(&TX, NULL, frame, (uint16_t)len) != NRF24_SEG_OK) {
            bad++;
            continue;
        }
        feed_all(&RX, &PIPE, 5000);
        if (FR.n != 1u || FR.len[0] != len || FR.src[0] != 0x42u ||
            (len > 0u && memcmp(FR.data[0], frame, len) != 0)) {
            bad++;
        }
    }
    tu_ctx("round trip of every size 0..250");
    CHECK_EQ_U32(bad, 0u);
    round_trip(BRV_A3_FRAME, BRV_A3_FRAME_LEN, "A.3 SEEK frame (42 bytes, 2 segments)");
    round_trip(BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, "A.15 SEEK frame (54 bytes)");
    round_trip(BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, "A.15 HELLO frame (61 bytes)");
}

static void test_seg_damage(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0xDA3Au);
    uint8_t frame[NRF24_SEG_MAX_FRAME];
    tu_rng_fill(&r, frame, sizeof frame);
    nrf24_seg_stats_t s;

    /* drop each of the 9 segments in turn: never delivered, counted once */
    for (unsigned drop = 0; drop < 9u; drop++) {
        seg_fresh(0x01, 0);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
        for (unsigned i = 0; i < PIPE.n; i++) {
            if (i != drop) {
                nrf24_seg_rx(&RX, PIPE.pkt[i], PIPE.len[i], 1000);
            }
        }
        tu_ctx("one segment dropped");
        CHECK_EQ_U32(FR.n, 0u);
        nrf24_seg_get_stats(&RX, &s);
        if (drop == 8u) {
            /* the LAST segment is missing: the frame stays open until the timeout */
            CHECK_EQ_U32(s.frames_dropped, 0u);
            CHECK_EQ_U32(nrf24_seg_open_count(&RX), 1u);
            CHECK(nrf24_seg_rx_active(&RX, 1000, 1500));
            CHECK_EQ_U32(nrf24_seg_next_deadline(&RX), 1000u + 50000u);
            nrf24_seg_tick(&RX, 1000 + 49999);
            CHECK_EQ_U32(nrf24_seg_open_count(&RX), 1u);
            nrf24_seg_tick(&RX, 1000 + 50000);
            CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
            nrf24_seg_get_stats(&RX, &s);
            CHECK_EQ_U32(s.timeouts, 1u);
            CHECK_EQ_U32(s.frames_dropped, 1u);
            CHECK(!nrf24_seg_rx_active(&RX, 1000 + 50000, 1500));
            CHECK_EQ_U32(nrf24_seg_next_deadline(&RX), UINT64_MAX);
        } else if (drop == 0u) {
            /* segment 0 lost: nothing ever opened, the other 8 are orphans */
            CHECK_EQ_U32(s.gaps, 0u);
            CHECK_EQ_U32(s.orphans, 8u);
            CHECK_EQ_U32(s.frames_dropped, 0u);
            CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
        } else {
            /* the open frame is dropped at the first out-of-order segment, the tail is orphans */
            CHECK_EQ_U32(s.gaps, 1u);
            CHECK_EQ_U32(s.orphans, 7u - drop);
            CHECK_EQ_U32(s.frames_dropped, 1u);
            CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
        }
        /* the next frame from the same src goes through */
        memset(&PIPE, 0, sizeof PIPE);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 77) == NRF24_SEG_OK);
        feed_all(&RX, &PIPE, 60000);
        CHECK_EQ_U32(FR.n, 1u);
        CHECK_EQ_U32(FR.len[0], 77u);
    }

    /* duplicate each segment: delivered once, dups counted */
    for (unsigned dup = 0; dup < 9u; dup++) {
        seg_fresh(0x01, 0);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
        for (unsigned i = 0; i < PIPE.n; i++) {
            nrf24_seg_rx(&RX, PIPE.pkt[i], PIPE.len[i], 1000);
            if (i == dup) {
                nrf24_seg_rx(&RX, PIPE.pkt[i], PIPE.len[i], 1000);
            }
        }
        tu_ctx("one segment duplicated");
        CHECK_EQ_U32(FR.n, 1u);
        CHECK_EQ_U32(FR.len[0], 250u);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.dups, 1u);
        CHECK_EQ_U32(s.frames_dropped, 0u);
        CHECK_EQ_U32(s.frames_rx, 1u);
    }

    /* whole frame repeated (every segment twice, in order): dups, no second delivery */
    seg_fresh(0x01, 0);
    CHECK(nrf24_seg_send(&TX, NULL, frame, 60) == NRF24_SEG_OK);
    feed_all(&RX, &PIPE, 1000);
    feed_all(&RX, &PIPE, 1000);
    tu_ctx("whole frame repeated");
    CHECK_EQ_U32(FR.n, 1u);
    nrf24_seg_get_stats(&RX, &s);
    CHECK_EQ_U32(s.dups, 3u);
    CHECK_EQ_U32(s.frames_dropped, 0u);

    /* swap each adjacent pair: out of order -> dropped (gap), nothing delivered */
    for (unsigned sw = 0; sw + 1u < 9u; sw++) {
        seg_fresh(0x01, 0);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
        for (unsigned i = 0; i < PIPE.n; i++) {
            unsigned j = i == sw ? sw + 1u : (i == sw + 1u ? sw : i);
            nrf24_seg_rx(&RX, PIPE.pkt[j], PIPE.len[j], 1000);
        }
        tu_ctx("adjacent segments swapped");
        CHECK_EQ_U32(FR.n, 0u);
        nrf24_seg_get_stats(&RX, &s);
        CHECK(s.gaps >= 1u);
        CHECK(s.frames_dropped >= 1u);
    }

    /* two transmitters with distinct src bytes interleaved segment by segment */
    {
        seg_fresh(0x01, 4);
        pipe_t pa;
        pipe_t pb;
        nrf24_seg_t txb;
        memset(&pa, 0, sizeof pa);
        memset(&pb, 0, sizeof pb);
        CHECK(nrf24_seg_init(&txb, 0x03, 0, 0, pipe_send, &pb, NULL, NULL) == NRF24_SEG_OK);
        TX.send_ctx = &pa;
        uint8_t fb[200];
        for (unsigned i = 0; i < sizeof fb; i++) {
            fb[i] = (uint8_t)(0xFF - i);
        }
        CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
        CHECK(nrf24_seg_send(&txb, NULL, fb, 200) == NRF24_SEG_OK);
        CHECK_EQ_U32(pa.n, 9u);
        CHECK_EQ_U32(pb.n, 7u);
        for (unsigned i = 0; i < 9u; i++) {
            nrf24_seg_rx(&RX, pa.pkt[i], pa.len[i], 2000 + i);
            if (i < pb.n) {
                nrf24_seg_rx(&RX, pb.pkt[i], pb.len[i], 2000 + i);
            }
        }
        tu_ctx("two interleaved transmitters");
        CHECK_EQ_U32(FR.n, 2u);
        if (FR.n == 2u) {
            CHECK_EQ_U32(FR.src[0], 0x03u); /* B's 7 segments complete first */
            CHECK_EQ_U32(FR.len[0], 200u);
            CHECK_MEM(fb, FR.data[0], 200);
            CHECK_EQ_U32(FR.src[1], 0x01u);
            CHECK_EQ_U32(FR.len[1], 250u);
            CHECK_MEM(frame, FR.data[1], 250);
        }
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.frames_dropped, 0u);
        CHECK_EQ_U32(s.frames_rx, 2u);
    }

    /* same src, a new tag before LAST: the open frame is dropped (foreign_tag), the new one delivered */
    {
        seg_fresh(0x01, 0);
        pipe_t p1;
        CHECK(nrf24_seg_send(&TX, NULL, frame, 250) == NRF24_SEG_OK);
        p1 = PIPE;
        memset(&PIPE, 0, sizeof PIPE);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 40) == NRF24_SEG_OK);
        for (unsigned i = 0; i < 5u; i++) {
            nrf24_seg_rx(&RX, p1.pkt[i], p1.len[i], 1000);
        }
        feed_all(&RX, &PIPE, 1001);
        for (unsigned i = 5; i < 9u; i++) {
            nrf24_seg_rx(&RX, p1.pkt[i], p1.len[i], 1002); /* the rest of the old frame: orphans */
        }
        tu_ctx("foreign tag before LAST");
        CHECK_EQ_U32(FR.n, 1u);
        CHECK_EQ_U32(FR.len[0], 40u);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.foreign_tag, 1u);
        CHECK_EQ_U32(s.orphans, 4u);
        CHECK_EQ_U32(s.gaps, 0u);
        CHECK_EQ_U32(s.frames_dropped, 1u);
    }

    /* timeout between two segments, the rest then counts as a gap */
    {
        seg_fresh(0x01, 0);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 100) == NRF24_SEG_OK); /* 4 segments */
        nrf24_seg_rx(&RX, PIPE.pkt[0], PIPE.len[0], 10000);
        nrf24_seg_rx(&RX, PIPE.pkt[1], PIPE.len[1], 10000 + 49999);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 1u);
        nrf24_seg_rx(&RX, PIPE.pkt[2], PIPE.len[2], 10000 + 49999 + 50000);
        tu_ctx("reassembly timeout mid-frame");
        CHECK_EQ_U32(FR.n, 0u);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.timeouts, 1u);
        CHECK_EQ_U32(s.orphans, 1u);
        CHECK_EQ_U32(s.frames_dropped, 1u);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
    }

    /* buffer full: 2 slots, three neighbours mid-frame */
    {
        seg_fresh(0x01, 2);
        nrf24_seg_t t2;
        nrf24_seg_t t3;
        pipe_t p2;
        pipe_t p3;
        memset(&p2, 0, sizeof p2);
        memset(&p3, 0, sizeof p3);
        CHECK(nrf24_seg_init(&t2, 0x02, 0, 0, pipe_send, &p2, NULL, NULL) == NRF24_SEG_OK);
        CHECK(nrf24_seg_init(&t3, 0x03, 0, 0, pipe_send, &p3, NULL, NULL) == NRF24_SEG_OK);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 60) == NRF24_SEG_OK);
        CHECK(nrf24_seg_send(&t2, NULL, frame, 60) == NRF24_SEG_OK);
        CHECK(nrf24_seg_send(&t3, NULL, frame, 60) == NRF24_SEG_OK);
        nrf24_seg_rx(&RX, PIPE.pkt[0], PIPE.len[0], 100);
        nrf24_seg_rx(&RX, p2.pkt[0], p2.len[0], 101);
        nrf24_seg_rx(&RX, p3.pkt[0], p3.len[0], 102); /* no buffer: dropped */
        tu_ctx("buffer full");
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.buffer_full, 1u);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 2u);
        nrf24_seg_rx(&RX, p3.pkt[1], p3.len[1], 103); /* rest of the refused frame: orphans */
        nrf24_seg_rx(&RX, p3.pkt[2], p3.len[2], 104);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.orphans, 2u);
        CHECK_EQ_U32(s.gaps, 0u);
        /* the two open frames complete */
        for (unsigned i = 1; i < 3u; i++) {
            nrf24_seg_rx(&RX, PIPE.pkt[i], PIPE.len[i], 110);
            nrf24_seg_rx(&RX, p2.pkt[i], p2.len[i], 111);
        }
        CHECK_EQ_U32(FR.n, 2u);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
        /* now src 3 gets the least recently used closed slot (src 1's) */
        memset(&p3, 0, sizeof p3);
        CHECK(nrf24_seg_send(&t3, NULL, frame, 10) == NRF24_SEG_OK);
        feed_all(&RX, &p3, 200);
        CHECK_EQ_U32(FR.n, 3u);
        CHECK_EQ_U32(FR.src[2], 0x03u);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.buffer_full, 1u);
        CHECK_EQ_U32(s.frames_rx, 3u);
        /* stale open buffers are reclaimed by the timeout, not by a newcomer */
        memset(&PIPE, 0, sizeof PIPE);
        memset(&p2, 0, sizeof p2);
        CHECK(nrf24_seg_send(&TX, NULL, frame, 60) == NRF24_SEG_OK);
        CHECK(nrf24_seg_send(&t2, NULL, frame, 60) == NRF24_SEG_OK);
        nrf24_seg_rx(&RX, PIPE.pkt[0], PIPE.len[0], 300);   /* src 1 reclaims src 3's idle slot */
        nrf24_seg_rx(&RX, p2.pkt[0], p2.len[0], 301);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 2u);
        memset(&p3, 0, sizeof p3);
        CHECK(nrf24_seg_send(&t3, NULL, frame, 60) == NRF24_SEG_OK);
        nrf24_seg_rx(&RX, p3.pkt[0], p3.len[0], 302);
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.buffer_full, 2u);
        nrf24_seg_rx(&RX, p3.pkt[0], p3.len[0], 302 + 50000); /* both stale ones expire first: slot free */
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.timeouts, 2u);
        CHECK_EQ_U32(s.buffer_full, 2u);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 1u);
    }

    /* malformed segments */
    {
        seg_fresh(0x01, 0);
        uint8_t bad[NRF24_SEG_PKT_MAX];
        memset(bad, 0, sizeof bad);
        nrf24_seg_rx(&RX, bad, 2, 1);                 /* too short */
        bad[2] = 9;                                   /* idx 9 */
        nrf24_seg_rx(&RX, bad, 32, 1);
        bad[2] = 0;                                   /* non-LAST with 10 payload bytes */
        nrf24_seg_rx(&RX, bad, 13, 1);
        nrf24_seg_rx(&RX, NULL, 13, 1);               /* tolerated */
        nrf24_seg_rx(NULL, bad, 13, 1);
        tu_ctx("malformed segments");
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.malformed, 3u);
        CHECK_EQ_U32(s.seg_rx, 0u);
        CHECK_EQ_U32(FR.n, 0u);
        /* oversize: 9 full segments then the chip hands a 10th (idx 8 was not LAST) */
        uint8_t full[NRF24_SEG_PKT_MAX];
        for (unsigned i = 0; i < 9u; i++) {
            memset(full, (int)i, sizeof full);
            full[0] = 0x01;
            full[1] = 0x07;
            full[2] = (uint8_t)i; /* never LAST */
            nrf24_seg_rx(&RX, full, 32, 1);
        }
        nrf24_seg_get_stats(&RX, &s);
        CHECK_EQ_U32(s.oversize, 1u);
        CHECK_EQ_U32(nrf24_seg_open_count(&RX), 0u);
    }
}

/* ========================================================================= */
/* Part B: register-model fake of the SPI bus                                 */
/* ========================================================================= */

#define FIFO_DEPTH 3u
#define LOG_MAX 256u

typedef struct {
    uint8_t  data[NRF24_PAYLOAD_MAX];
    uint8_t  len;
    bool     no_ack;
} fpayload_t;

typedef struct {
    bool       present;                 /* MISO answers (a chip is wired) */
    bool       fail_bus;                /* the SPI driver refuses every transfer */
    bool       feature_locked;          /* non-plus behaviour: FEATURE / DYNPD ignore writes until ACTIVATE */
    uint8_t    reg[NRF24_REG_COUNT];
    uint8_t    addr_p0[5];              /* raw bytes as received over SPI (LSByte first) */
    uint8_t    addr_p1[5];
    uint8_t    addr_tx[5];
    fpayload_t tx[FIFO_DEPTH];
    unsigned   tx_n;
    fpayload_t rx[FIFO_DEPTH];
    uint8_t    rx_pipe[FIFO_DEPTH];
    unsigned   rx_n;
    uint8_t    rx_width_override;       /* 0 = none; else R_RX_PL_WID answers this */
    bool       ce;
    unsigned   ce_pulses;
    uint32_t   delay_total_us;
    unsigned   flush_tx;
    unsigned   flush_rx;
    unsigned   activates;
    unsigned   writes;
    uint8_t    wlog_reg[LOG_MAX];
    uint8_t    wlog_val[LOG_MAX];
    unsigned   wlog_n;
    unsigned   transfers;
} fchip_t;

static void fchip_reset(fchip_t *c)
{
    memset(c, 0, sizeof *c);
    c->present = true;
    c->reg[NRF24_REG_CONFIG] = 0x08;
    c->reg[NRF24_REG_EN_AA] = 0x3F;
    c->reg[NRF24_REG_EN_RXADDR] = 0x03;
    c->reg[NRF24_REG_SETUP_AW] = 0x03;
    c->reg[NRF24_REG_SETUP_RETR] = 0x03;
    c->reg[NRF24_REG_RF_CH] = 0x02;
    c->reg[NRF24_REG_RF_SETUP] = 0x0E;
    c->reg[NRF24_REG_STATUS] = 0x0E;
    c->reg[NRF24_REG_FIFO_STATUS] = 0x11;
    memset(c->addr_p0, 0xE7, 5);
    memset(c->addr_p1, 0xC2, 5);
    memset(c->addr_tx, 0xE7, 5);
    for (unsigned p = 2; p < 6u; p++) {
        c->reg[NRF24_REG_RX_ADDR_P0 + p] = (uint8_t)(0xC1u + p);
    }
}

static uint8_t fchip_status(const fchip_t *c)
{
    uint8_t st = (uint8_t)(c->reg[NRF24_REG_STATUS] & 0x70u);
    st |= (uint8_t)((c->rx_n > 0u ? c->rx_pipe[0] : 7u) << 1);
    if (c->tx_n >= FIFO_DEPTH) {
        st |= 0x01u;
    }
    return st;
}

static void fchip_update_fifo_status(fchip_t *c)
{
    uint8_t f = 0;
    if (c->tx_n >= FIFO_DEPTH) {
        f |= NRF24_FIFO_TX_FULL;
    }
    if (c->tx_n == 0u) {
        f |= NRF24_FIFO_TX_EMPTY;
    }
    if (c->rx_n >= FIFO_DEPTH) {
        f |= NRF24_FIFO_RX_FULL;
    }
    if (c->rx_n == 0u) {
        f |= NRF24_FIFO_RX_EMPTY;
    }
    c->reg[NRF24_REG_FIFO_STATUS] = f;
}

static void fchip_rx_push(fchip_t *c, uint8_t pipe, const uint8_t *d, uint8_t len)
{
    if (c->rx_n < FIFO_DEPTH) {
        memcpy(c->rx[c->rx_n].data, d, len);
        c->rx[c->rx_n].len = len;
        c->rx_pipe[c->rx_n] = pipe;
        c->rx_n++;
        c->reg[NRF24_REG_STATUS] |= NRF24_ST_RX_DR;
        fchip_update_fifo_status(c);
    }
}

static bool fchip_transfer(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len)
{
    fchip_t *c = (fchip_t *)ctx;
    c->transfers++;
    if (c->fail_bus || len == 0u || len > 33u) {
        return false;
    }
    if (!c->present) {
        memset(rx, 0, len); /* MISO floating low */
        return true;
    }
    uint8_t cmd = tx[0];
    uint8_t n = (uint8_t)(len - 1u);
    rx[0] = fchip_status(c);
    memset(rx + 1, 0, n);
    if ((cmd & 0xE0u) == NRF24_CMD_R_REGISTER) {
        uint8_t reg = cmd & NRF24_CMD_REGISTER_MASK;
        if (reg == NRF24_REG_RX_ADDR_P0 || reg == NRF24_REG_RX_ADDR_P1 || reg == NRF24_REG_TX_ADDR) {
            const uint8_t *a = reg == NRF24_REG_RX_ADDR_P0 ? c->addr_p0 : (reg == NRF24_REG_RX_ADDR_P1 ? c->addr_p1 : c->addr_tx);
            for (uint8_t i = 0; i < n && i < 5u; i++) {
                rx[1 + i] = a[i];
            }
        } else if (reg < NRF24_REG_COUNT && n >= 1u) {
            rx[1] = reg == NRF24_REG_STATUS ? fchip_status(c) : c->reg[reg];
        }
        return true;
    }
    if ((cmd & 0xE0u) == NRF24_CMD_W_REGISTER) {
        uint8_t reg = cmd & NRF24_CMD_REGISTER_MASK;
        c->writes++;
        if (c->wlog_n < LOG_MAX) {
            c->wlog_reg[c->wlog_n] = reg;
            c->wlog_val[c->wlog_n] = n >= 1u ? tx[1] : 0u;
            c->wlog_n++;
        }
        if (reg == NRF24_REG_RX_ADDR_P0 || reg == NRF24_REG_RX_ADDR_P1 || reg == NRF24_REG_TX_ADDR) {
            uint8_t *a = reg == NRF24_REG_RX_ADDR_P0 ? c->addr_p0 : (reg == NRF24_REG_RX_ADDR_P1 ? c->addr_p1 : c->addr_tx);
            for (uint8_t i = 0; i < n && i < 5u; i++) {
                a[i] = tx[1 + i];
            }
        } else if (reg == NRF24_REG_STATUS) {
            c->reg[reg] &= (uint8_t)~(tx[1] & 0x70u); /* write 1 to clear */
        } else if ((reg == NRF24_REG_FEATURE || reg == NRF24_REG_DYNPD) && c->feature_locked) {
            /* ignored until ACTIVATE */
        } else if (reg < NRF24_REG_COUNT && n >= 1u) {
            c->reg[reg] = tx[1];
        }
        return true;
    }
    switch (cmd) {
    case NRF24_CMD_W_TX_PAYLOAD:
    case NRF24_CMD_W_TX_PAYLOAD_NO_ACK:
        if (c->tx_n < FIFO_DEPTH && n >= 1u) {
            memcpy(c->tx[c->tx_n].data, tx + 1, n);
            c->tx[c->tx_n].len = n;
            c->tx[c->tx_n].no_ack = cmd == NRF24_CMD_W_TX_PAYLOAD_NO_ACK;
            c->tx_n++;
            fchip_update_fifo_status(c);
        }
        return true;
    case NRF24_CMD_R_RX_PL_WID:
        if (n >= 1u) {
            rx[1] = c->rx_width_override != 0u ? c->rx_width_override : (c->rx_n > 0u ? c->rx[0].len : 0u);
        }
        return true;
    case NRF24_CMD_R_RX_PAYLOAD:
        if (c->rx_n > 0u) {
            for (uint8_t i = 0; i < n && i < c->rx[0].len; i++) {
                rx[1 + i] = c->rx[0].data[i];
            }
            memmove(&c->rx[0], &c->rx[1], (FIFO_DEPTH - 1u) * sizeof c->rx[0]);
            memmove(&c->rx_pipe[0], &c->rx_pipe[1], FIFO_DEPTH - 1u);
            c->rx_n--;
            fchip_update_fifo_status(c);
        }
        return true;
    case NRF24_CMD_FLUSH_TX:
        c->flush_tx++;
        c->tx_n = 0;
        fchip_update_fifo_status(c);
        return true;
    case NRF24_CMD_FLUSH_RX:
        c->flush_rx++;
        c->rx_n = 0;
        fchip_update_fifo_status(c);
        return true;
    case NRF24_CMD_ACTIVATE:
        if (n >= 1u && tx[1] == 0x73u) {
            c->activates++;
            c->feature_locked = false;
        }
        return true;
    case NRF24_CMD_NOP:
        return true;
    default:
        return false;
    }
}

static void fchip_ce(void *ctx, bool high)
{
    fchip_t *c = (fchip_t *)ctx;
    if (!c->ce && high) {
        c->ce_pulses++;
    }
    c->ce = high;
}

static void fchip_delay(void *ctx, uint32_t us)
{
    ((fchip_t *)ctx)->delay_total_us += us;
}

static fchip_t CHIP;
static nrf24_regs_t REGS;

static const nrf24_regs_io_t CHIP_IO = {&CHIP, fchip_transfer, fchip_ce, fchip_delay};

static nrf24_regs_cfg_t braid_regs_cfg(void)
{
    nrf24_regs_cfg_t c;
    memset(&c, 0, sizeof c);
    c.channel = 76;
    c.rate = NRF24_RATE_2M;
    c.pa = NRF24_PA_MAX;
    c.ard = 1;  /* 500 us */
    c.arc = 15;
    c.addr_width = 5;
    return c;
}

/* Index of the first write to reg in the log, or -1. */
static int first_write(const fchip_t *c, uint8_t reg)
{
    for (unsigned i = 0; i < c->wlog_n; i++) {
        if (c->wlog_reg[i] == reg) {
            return (int)i;
        }
    }
    return -1;
}

static void test_regs_init_sequence(void)
{
    tu_ctx("register init sequence (C.5 configuration)");
    fchip_reset(&CHIP);
    nrf24_regs_cfg_t cfg = braid_regs_cfg();
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_OK);
    CHECK(!CHIP.ce);                                                         /* CE low throughout */
    CHECK_EQ_U32(CHIP.ce_pulses, 0u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_CONFIG], 0x0Eu);                         /* EN_CRC | CRCO | PWR_UP, PTX */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_FEATURE], 0x05u);                        /* EN_DPL | EN_DYN_ACK */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_DYNPD], 0x03u);                          /* pipes 0, 1 */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_EN_AA], 0x03u);                          /* auto-ACK on both (DPL needs it) */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_EN_RXADDR], 0x03u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_SETUP_AW], 0x03u);                       /* 5 bytes */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_SETUP_RETR], 0x1Fu);                     /* ARD 500 us, ARC 15 */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_CH], 76u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_SETUP], 0x0Eu);                       /* 2 Mbps (RF_DR_HIGH), 0 dBm */
    for (unsigned p = 0; p < 6u; p++) {
        CHECK_EQ_U32(CHIP.reg[NRF24_REG_RX_PW_P0 + p], 32u);
    }
    CHECK_EQ_U32(CHIP.flush_tx, 1u);
    CHECK_EQ_U32(CHIP.flush_rx, 1u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_STATUS] & 0x70u, 0u);
    CHECK_EQ_U32(CHIP.activates, 0u);
    CHECK(CHIP.delay_total_us >= 2u * NRF24_PWR_UP_US);                      /* settle + power-up wait */
    /* order: CONFIG written powered-down first, PWR_UP as the last CONFIG write */
    int c0 = first_write(&CHIP, NRF24_REG_CONFIG);
    CHECK(c0 >= 0);
    if (c0 >= 0) {
        CHECK_EQ_U32(CHIP.wlog_val[c0], 0x0Cu);
    }
    unsigned last_cfg = 0;
    for (unsigned i = 0; i < CHIP.wlog_n; i++) {
        if (CHIP.wlog_reg[i] == NRF24_REG_CONFIG) {
            last_cfg = i;
        }
    }
    CHECK_EQ_U32(CHIP.wlog_val[last_cfg], 0x0Eu);
    int st = first_write(&CHIP, NRF24_REG_STATUS);
    CHECK(st >= 0 && (unsigned)st < last_cfg);                               /* STATUS cleared before PWR_UP */
    if (st >= 0) {
        CHECK_EQ_U32(CHIP.wlog_val[st], 0x70u);
    }
    nrf24_regs_stats_t rs;
    nrf24_regs_get_stats(&REGS, &rs);
    CHECK_EQ_U32(rs.spi_err, 0u);
    CHECK_EQ_U32(rs.activate_used, 0u);

    tu_ctx("other rates / PA");
    cfg.rate = NRF24_RATE_250K;
    cfg.pa = NRF24_PA_MIN;
    cfg.channel = 83;
    fchip_reset(&CHIP);
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_SETUP], 0x20u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_CH], 83u);
    cfg.rate = NRF24_RATE_1M;
    cfg.pa = NRF24_PA_HIGH;
    fchip_reset(&CHIP);
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_SETUP], 0x04u);

    tu_ctx("init argument checks");
    cfg = braid_regs_cfg();
    cfg.channel = 126;
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_ERR_ARG);
    cfg = braid_regs_cfg();
    cfg.addr_width = 2;
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_ERR_ARG);
    cfg = braid_regs_cfg();
    cfg.arc = 16;
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_ERR_ARG);
    cfg = braid_regs_cfg();
    CHECK(nrf24_regs_init(NULL, &CHIP_IO, &cfg) == NRF24_REGS_ERR_ARG);
    nrf24_regs_io_t bad = CHIP_IO;
    bad.ce_set = NULL;
    CHECK(nrf24_regs_init(&REGS, &bad, &cfg) == NRF24_REGS_ERR_ARG);

    tu_ctx("ACTIVATE fallback (non-plus chip / clone)");
    fchip_reset(&CHIP);
    CHIP.feature_locked = true;
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.activates, 1u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_FEATURE], 0x05u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_DYNPD], 0x03u);
    nrf24_regs_get_stats(&REGS, &rs);
    CHECK_EQ_U32(rs.activate_used, 1u);

    tu_ctx("no chip wired: NO_CHIP, nothing else touched");
    fchip_reset(&CHIP);
    CHIP.present = false;
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_ERR_NO_CHIP);
    CHECK(!REGS.inited);
    CHECK(nrf24_regs_status(&REGS) == NRF24_ST_INVALID);
    CHECK(nrf24_regs_start_listening(&REGS) == NRF24_REGS_ERR_ARG);
}

static void test_regs_addresses_and_payloads(void)
{
    fchip_reset(&CHIP);
    nrf24_regs_cfg_t cfg = braid_regs_cfg();
    CHECK(nrf24_regs_init(&REGS, &CHIP_IO, &cfg) == NRF24_REGS_OK);

    tu_ctx("address byte order: C.5 list order in, LSByte first on the bus");
    static const uint8_t own[5] = {0x50, 0x4C, 0x01, 0x03, 0xA5};
    static const uint8_t bcast[5] = {0x50, 0x4C, 0xFF, 0xFF, 0xA5};
    static const uint8_t own_wire[5] = {0xA5, 0x03, 0x01, 0x4C, 0x50};
    static const uint8_t bcast_wire[5] = {0xA5, 0xFF, 0xFF, 0x4C, 0x50};
    CHECK(nrf24_regs_set_rx_address(&REGS, 0, own, true) == NRF24_REGS_OK);
    CHECK(nrf24_regs_set_rx_address(&REGS, 1, bcast, true) == NRF24_REGS_OK);
    CHECK_MEM(own_wire, CHIP.addr_p0, 5);
    CHECK_MEM(bcast_wire, CHIP.addr_p1, 5);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_EN_RXADDR], 0x03u);
    CHECK(nrf24_regs_set_rx_address(&REGS, 2, own, true) == NRF24_REGS_OK);   /* LSByte only */
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RX_ADDR_P2], 0xA5u);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_EN_RXADDR], 0x07u);
    CHECK(nrf24_regs_set_rx_address(&REGS, 2, own, false) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_EN_RXADDR], 0x03u);
    CHECK(nrf24_regs_set_rx_address(&REGS, 6, own, true) == NRF24_REGS_ERR_ARG);

    tu_ctx("TX address programs TX_ADDR and pipe 0; listening restores pipe 0");
    static const uint8_t dst[5] = {0x50, 0x4C, 0x01, 0x01, 0xA5};
    static const uint8_t dst_wire[5] = {0xA5, 0x01, 0x01, 0x4C, 0x50};
    CHECK(nrf24_regs_set_tx_address(&REGS, dst) == NRF24_REGS_OK);
    CHECK_MEM(dst_wire, CHIP.addr_tx, 5);
    CHECK_MEM(dst_wire, CHIP.addr_p0, 5);
    CHECK(nrf24_regs_start_listening(&REGS) == NRF24_REGS_OK);
    CHECK_MEM(own_wire, CHIP.addr_p0, 5);
    CHECK(CHIP.ce);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_CONFIG], 0x0Fu);                          /* PRIM_RX | PWR_UP | CRC */
    CHECK(nrf24_regs_start_tx(&REGS) == NRF24_REGS_ERR_ARG);                  /* not while listening */
    CHECK(nrf24_regs_stop_listening(&REGS) == NRF24_REGS_OK);
    CHECK(!CHIP.ce);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_CONFIG], 0x0Eu);

    tu_ctx("payload writes: ACK / NO_ACK commands, FIFO full after 3");
    uint8_t pl[32];
    for (unsigned i = 0; i < 32u; i++) {
        pl[i] = (uint8_t)(0xA0 + i);
    }
    CHECK(nrf24_regs_write_payload(&REGS, pl, 32, false) == NRF24_REGS_OK);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 3, true) == NRF24_REGS_OK);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 10, false) == NRF24_REGS_OK);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 10, false) == NRF24_REGS_ERR_FULL);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 0, false) == NRF24_REGS_ERR_ARG);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 33, false) == NRF24_REGS_ERR_ARG);
    CHECK_EQ_U32(CHIP.tx_n, 3u);
    CHECK(!CHIP.tx[0].no_ack && CHIP.tx[1].no_ack && !CHIP.tx[2].no_ack);
    CHECK_EQ_U32(CHIP.tx[0].len, 32u);
    CHECK_MEM(pl, CHIP.tx[0].data, 32);
    CHECK_EQ_U32(CHIP.tx[1].len, 3u);
    CHECK((nrf24_regs_status(&REGS) & NRF24_ST_TX_FULL) != 0u);
    unsigned pulses = CHIP.ce_pulses;
    CHECK(nrf24_regs_start_tx(&REGS) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.ce_pulses, pulses + 1u);
    CHECK(!CHIP.ce);

    tu_ctx("MAX_RT recovery: FLUSH_TX and the flag cleared");
    CHIP.reg[NRF24_REG_STATUS] |= NRF24_ST_MAX_RT;
    CHECK((nrf24_regs_status(&REGS) & NRF24_ST_MAX_RT) != 0u);
    unsigned flushes = CHIP.flush_tx;
    CHECK(nrf24_regs_tx_abort(&REGS) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.flush_tx, flushes + 1u);
    CHECK_EQ_U32(CHIP.tx_n, 0u);
    CHECK_EQ_U32(nrf24_regs_status(&REGS) & NRF24_ST_MAX_RT, 0u);
    CHECK(!CHIP.ce);
    nrf24_regs_stats_t rs;
    nrf24_regs_get_stats(&REGS, &rs);
    CHECK_EQ_U32(rs.tx_aborts, 1u);

    tu_ctx("payload reads: pipe, width, order; width > 32 flushes");
    uint8_t p0[5] = {1, 2, 3, 4, 5};
    uint8_t p1[32];
    memset(p1, 0x5A, sizeof p1);
    fchip_rx_push(&CHIP, 1, p0, 5);
    fchip_rx_push(&CHIP, 0, p1, 32);
    uint8_t pipe = 9;
    uint8_t len = 0;
    uint8_t buf[32];
    CHECK((nrf24_regs_status(&REGS) & NRF24_ST_RX_DR) != 0u);
    CHECK_EQ_U32((nrf24_regs_status(&REGS) & NRF24_ST_RX_P_NO_MASK) >> 1, 1u);
    CHECK(nrf24_regs_read_payload(&REGS, &pipe, buf, &len) == NRF24_REGS_OK);
    CHECK_EQ_U32(pipe, 1u);
    CHECK_EQ_U32(len, 5u);
    CHECK_MEM(p0, buf, 5);
    CHECK(nrf24_regs_read_payload(&REGS, &pipe, buf, &len) == NRF24_REGS_OK);
    CHECK_EQ_U32(pipe, 0u);
    CHECK_EQ_U32(len, 32u);
    CHECK_MEM(p1, buf, 32);
    CHECK(nrf24_regs_read_payload(&REGS, &pipe, buf, &len) == NRF24_REGS_ERR_EMPTY);
    CHECK(nrf24_regs_clear_irq(&REGS, NRF24_ST_RX_DR) == NRF24_REGS_OK);
    CHECK_EQ_U32(nrf24_regs_status(&REGS) & NRF24_ST_RX_DR, 0u);
    fchip_rx_push(&CHIP, 0, p1, 32);
    CHIP.rx_width_override = 33;
    unsigned frx = CHIP.flush_rx;
    CHECK(nrf24_regs_read_payload(&REGS, &pipe, buf, &len) == NRF24_REGS_ERR_WIDTH);
    CHECK_EQ_U32(CHIP.flush_rx, frx + 1u);
    CHECK_EQ_U32(CHIP.rx_n, 0u);
    CHIP.rx_width_override = 0;
    nrf24_regs_get_stats(&REGS, &rs);
    CHECK_EQ_U32(rs.rx_bad_width, 1u);

    tu_ctx("channel change, power, raw register access");
    CHECK(nrf24_regs_set_channel(&REGS, 81) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_CH], 81u);
    CHECK(nrf24_regs_set_channel(&REGS, 126) == NRF24_REGS_ERR_ARG);
    CHECK(nrf24_regs_power(&REGS, false) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_CONFIG], 0x0Cu);
    uint32_t d = CHIP.delay_total_us;
    CHECK(nrf24_regs_power(&REGS, true) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_CONFIG], 0x0Eu);
    CHECK(CHIP.delay_total_us - d >= NRF24_PWR_UP_US);
    uint8_t v = 0;
    CHECK(nrf24_regs_read(&REGS, NRF24_REG_SETUP_RETR, &v) == NRF24_REGS_OK);
    CHECK_EQ_U32(v, 0x1Fu);
    CHECK(nrf24_regs_read(&REGS, 0x1E, &v) == NRF24_REGS_ERR_ARG);
    CHECK(nrf24_regs_write(&REGS, NRF24_REG_RF_CH, 77) == NRF24_REGS_OK);
    CHECK_EQ_U32(CHIP.reg[NRF24_REG_RF_CH], 77u);

    tu_ctx("bus failure surfaces as SPI error, status invalid");
    CHIP.fail_bus = true;
    CHECK(nrf24_regs_status(&REGS) == NRF24_ST_INVALID);
    CHECK(nrf24_regs_write(&REGS, NRF24_REG_RF_CH, 78) == NRF24_REGS_ERR_SPI);
    CHECK(nrf24_regs_read_payload(&REGS, &pipe, buf, &len) == NRF24_REGS_ERR_SPI);
    CHECK(nrf24_regs_write_payload(&REGS, pl, 4, false) == NRF24_REGS_ERR_SPI);
    CHIP.fail_bus = false;
    nrf24_regs_get_stats(&REGS, &rs);
    CHECK_EQ_U32(rs.spi_err, 4u);
    CHECK(nrf24_regs_status(&REGS) != NRF24_ST_INVALID);
}

/* ========================================================================= */
/* Part C: adapter over a fake ESB medium                                     */
/* ========================================================================= */

#define RXQ_DEPTH 32u   /* generous: the pump drains per segment anyway (hardware: 3) */

/* Virtual clock shared by the platform table, the pumps and the medium. */
static uint64_t g_now_us = 1000000u;

#define AIR_US  250u    /* 32-byte payload + ACK on the air at 2 Mbps, rounded up */
#define ARD_US  500u    /* C.5 auto retransmit delay */

typedef struct fmedium fmedium_t;

typedef struct {
    fmedium_t *med;
    uint8_t    pipe_addr[2][5];
    uint8_t    tx_addr[5];
    bool       listening;
    uint8_t    status;              /* IRQ bits only */
    fpayload_t tx;
    bool       tx_valid;
    bool       pending;             /* a transmit is on the air; resolved by fr_status() as time passes */
    unsigned   attempt;
    uint64_t   next_attempt_us;
    bool       delivered_once;      /* PID filter: a retransmit of a delivered payload is dropped by the PRX */
    fpayload_t rxq[RXQ_DEPTH];
    uint8_t    rxq_pipe[RXQ_DEPTH];
    unsigned   rxq_n;
    unsigned   aborts;
    unsigned   starts;
    unsigned   tx_attempts;
    unsigned   max_rt;
    unsigned   pkts_lost;
    unsigned   acks_lost;
    unsigned   bcast_sent;
    unsigned   seeks_sent;          /* broadcast first segments carrying a SEEK header */
    uint16_t   first_seek_path_mtu;
} fradio_t;

struct fmedium {
    fradio_t *r[2];
    tu_rng_t  rng;
    uint32_t  loss_pct;             /* per attempt, data packets */
    uint32_t  ack_loss_pct;         /* per delivered attempt, the ACK */
    uint8_t   arc;                  /* ESB retries */
    bool      ack_blind;            /* lose packets but always report TX_DS (unacknowledged carrier) */
    bool      armed;                /* loss enabled */
    unsigned  data_lost;
    unsigned  acks_lost;
    unsigned  dup_filtered;
    unsigned  delivered;
};

static void med_resolve(fmedium_t *m);

static bool fr_set_rx_address(void *radio, uint8_t pipe, const uint8_t *addr)
{
    fradio_t *r = (fradio_t *)radio;
    if (pipe > 1u) {
        return false;
    }
    memcpy(r->pipe_addr[pipe], addr, 5);
    return true;
}

static bool fr_set_tx_address(void *radio, const uint8_t *addr)
{
    fradio_t *r = (fradio_t *)radio;
    if (r->listening) {
        return false;
    }
    memcpy(r->tx_addr, addr, 5);
    return true;
}

static bool fr_write_payload(void *radio, const uint8_t *buf, uint8_t len, bool no_ack)
{
    fradio_t *r = (fradio_t *)radio;
    if (r->tx_valid || len == 0u || len > 32u) {
        return false;
    }
    memcpy(r->tx.data, buf, len);
    r->tx.len = len;
    r->tx.no_ack = no_ack;
    r->tx_valid = true;
    return true;
}

static void fr_rx_push(fradio_t *r, uint8_t pipe, const fpayload_t *p)
{
    if (r->rxq_n < RXQ_DEPTH) {
        r->rxq[r->rxq_n] = *p;
        r->rxq_pipe[r->rxq_n] = pipe;
        r->rxq_n++;
        r->status |= NRF24_ST_RX_DR;
    }
}

static bool lose(fmedium_t *m, uint32_t pct)
{
    return m->armed && pct > 0u && tu_rng_below(&m->rng, 100) < pct;
}

static bool fr_start_tx(void *radio)
{
    fradio_t *r = (fradio_t *)radio;
    med_resolve(r->med);
    if (r->listening || !r->tx_valid || r->pending) {
        return false;
    }
    r->starts++;
    const fpayload_t *p = &r->tx;
    /* observe SEEK floods (first segment, header type at frame offset 1) */
    if (p->no_ack && p->len >= 3u + BR_OFF_PATH_MTU + 2u && (p->data[2] & NRF24_SEG_IDX_MASK) == 0u &&
        p->data[3 + BR_OFF_TYPE] == BR_TYPE_SEEK) {
        if (r->seeks_sent == 0u) {
            r->first_seek_path_mtu = br_rd_le16(p->data + 3 + BR_OFF_PATH_MTU);
        }
        r->seeks_sent++;
    }
    if (p->no_ack) {
        r->bcast_sent++;
    }
    r->pending = true;
    r->attempt = 0;
    r->delivered_once = false;
    r->next_attempt_us = g_now_us + AIR_US;
    return true;
}

/*
 * One ESB attempt at the time it is due: the peer must be in PRX on an
 * address of ours right then (a radio in PTX hears nothing). Unicast with
 * auto-ACK: deliver once, every attempt that gets an ACK ends the transmit,
 * ARC + 1 failures give MAX_RT and the payload stays in the FIFO. NO_ACK and
 * ACK-blind: one attempt, TX_DS whatever happened on the air.
 */
static void fr_resolve_one(fradio_t *r)
{
    fmedium_t *m = r->med;
    if (r->pending && r->next_attempt_us <= g_now_us) {
        fradio_t *peer = m->r[0] == r ? m->r[1] : m->r[0];
        const fpayload_t *p = &r->tx;
        int pipe = -1;
        if (peer != NULL && peer->listening) {
            if (memcmp(peer->pipe_addr[0], r->tx_addr, 5) == 0) {
                pipe = 0;
            } else if (memcmp(peer->pipe_addr[1], r->tx_addr, 5) == 0) {
                pipe = 1;
            }
        }
        r->tx_attempts++;
        r->attempt++;
        bool got_through = false;
        if (pipe >= 0) {
            if (lose(m, m->loss_pct)) {
                m->data_lost++;
                r->pkts_lost++;
            } else {
                got_through = true;
                if (!r->delivered_once) {
                    fr_rx_push(peer, (uint8_t)pipe, p);
                    m->delivered++;
                    r->delivered_once = true;
                } else {
                    m->dup_filtered++;
                }
            }
        }
        if (p->no_ack || m->ack_blind) {
            r->status |= NRF24_ST_TX_DS;
            r->tx_valid = false;
            r->pending = false;
            return;
        }
        if (got_through && !lose(m, m->ack_loss_pct)) {
            r->status |= NRF24_ST_TX_DS;
            r->tx_valid = false; /* the chip removes an acknowledged payload */
            r->pending = false;
            return;
        }
        if (got_through) {
            m->acks_lost++;
            r->acks_lost++;
        }
        if (r->attempt > m->arc) {
            r->status |= NRF24_ST_MAX_RT;
            r->max_rt++;
            r->pending = false; /* payload stays until tx_abort */
            return;
        }
        r->next_attempt_us += ARD_US;
    }
}

/* Everything on the air that is due by now, earliest first, whichever radio sent it. */
static void med_resolve(fmedium_t *m)
{
    for (;;) {
        fradio_t *next = NULL;
        for (unsigned i = 0; i < 2u; i++) {
            fradio_t *r = m->r[i];
            if (r != NULL && r->pending && r->next_attempt_us <= g_now_us &&
                (next == NULL || r->next_attempt_us < next->next_attempt_us)) {
                next = r;
            }
        }
        if (next == NULL) {
            return;
        }
        fr_resolve_one(next);
    }
}

static bool fr_read_payload(void *radio, uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out)
{
    fradio_t *r = (fradio_t *)radio;
    med_resolve(r->med);
    if (r->rxq_n == 0u) {
        return false;
    }
    *pipe_out = r->rxq_pipe[0];
    *len_out = r->rxq[0].len;
    memcpy(buf, r->rxq[0].data, r->rxq[0].len);
    memmove(&r->rxq[0], &r->rxq[1], (RXQ_DEPTH - 1u) * sizeof r->rxq[0]);
    memmove(&r->rxq_pipe[0], &r->rxq_pipe[1], RXQ_DEPTH - 1u);
    r->rxq_n--;
    return true;
}

static uint8_t fr_status(void *radio)
{
    fradio_t *r = (fradio_t *)radio;
    med_resolve(r->med);
    uint8_t st = r->status;
    st |= (uint8_t)((r->rxq_n > 0u ? r->rxq_pipe[0] : 7u) << 1);
    if (r->tx_valid) {
        st |= NRF24_ST_TX_FULL; /* one-deep fake FIFO */
    }
    return st;
}

static bool fr_clear_irq(void *radio, uint8_t mask)
{
    fradio_t *r = (fradio_t *)radio;
    r->status &= (uint8_t)~(mask & NRF24_ST_IRQ_MASK);
    return true;
}

static bool fr_tx_abort(void *radio)
{
    fradio_t *r = (fradio_t *)radio;
    r->aborts++;
    r->tx_valid = false;
    r->pending = false;
    r->status &= (uint8_t)~(NRF24_ST_MAX_RT | NRF24_ST_TX_DS);
    return true;
}

static bool fr_start_listening(void *radio)
{
    ((fradio_t *)radio)->listening = true;
    return true;
}

static bool fr_stop_listening(void *radio)
{
    ((fradio_t *)radio)->listening = false;
    return true;
}

static nrf24_radio_ops_t fr_ops(fradio_t *r)
{
    nrf24_radio_ops_t o;
    o.radio = r;
    o.set_rx_address = fr_set_rx_address;
    o.set_tx_address = fr_set_tx_address;
    o.write_payload = fr_write_payload;
    o.start_tx = fr_start_tx;
    o.read_payload = fr_read_payload;
    o.status = fr_status;
    o.clear_irq = fr_clear_irq;
    o.tx_abort = fr_tx_abort;
    o.start_listening = fr_start_listening;
    o.stop_listening = fr_stop_listening;
    return o;
}

/* ---- host platform ------------------------------------------------------ */

static tu_rng_t g_plat_rng;

static uint64_t t_now(void *user)
{
    (void)user;
    return g_now_us;
}

static br_err_t t_random(void *user, uint8_t *buf, size_t len)
{
    (void)user;
    tu_rng_fill(&g_plat_rng, buf, len);
    return BR_OK;
}

static void t_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    (void)user;
    (void)level;
    (void)tag;
    (void)msg;
}

static br_stats_t node_stats(const br_node_t *n)
{
    br_stats_t s;
    memset(&s, 0, sizeof s);
    CHECK_ERR(br_node_get_stats(n, &s), BR_OK);
    return s;
}

/* ---- endpoints ------------------------------------------------------------ */

typedef struct {
    const char    *name;
    br_node_t      node;
    nrf24_link_t   link;
    fradio_t       radio;
    br_session_t   sess;
    bool           streaming;
    bool           bound;
    unsigned       acked;
    unsigned       ones;
    unsigned       zeros;
    unsigned       samples;
    unsigned       gaps;
    unsigned       gap_seqs;
    unsigned       closed;
    unsigned       link_fail;
} ep_t;

static fmedium_t MED;
static ep_t EA;
static ep_t EB;

static void cb_acked(void *user, br_session_t s, uint16_t seq)
{
    (void)s;
    (void)seq;
    ((ep_t *)user)->acked++;
}

static void cb_state(void *user, br_session_t s, uint8_t old_state, uint8_t new_state)
{
    ep_t *e = (ep_t *)user;
    (void)old_state;
    if ((s & BR_SESSION_PROBE) == 0u && new_state == BR_SND_STREAMING) {
        e->streaming = true;
    }
}

static void cb_bound(void *user, br_session_t s, uint16_t peer)
{
    (void)s;
    (void)peer;
    ((ep_t *)user)->bound = true;
}

static void cb_samples(void *user, const br_samples_meta_t *meta, const br_mode_t *mode, const uint8_t *samples,
                       size_t samples_len)
{
    ep_t *e = (ep_t *)user;
    size_t sz = 0;
    CHECK_ERR(br_sample_size(mode, &sz), BR_OK);
    CHECK_EQ_U32(meta->src_id, 0x0101u);
    CHECK_EQ_U32(meta->hops, 1u);
    for (uint8_t i = 0; i < meta->hdr.n_samples && sz > 0u; i++) {
        size_t off = (size_t)i * sz;
        if (off + sz > samples_len) {
            break;
        }
        br_value_t vals[BR_MAX_CHANNELS];
        if (br_sample_decode(mode, samples + off, sz, vals) == BR_OK) {
            e->samples++;
            if ((vals[0].lines & 1u) != 0u) {
                e->ones++;
            } else {
                e->zeros++;
            }
        }
    }
}

static void cb_gap(void *user, br_session_t s, uint16_t first, uint16_t count)
{
    ep_t *e = (ep_t *)user;
    (void)first;
    e->gaps++;
    if ((s & BR_SESSION_PROBE) == 0u) {
        e->gap_seqs += count;
    }
}

static void cb_closed(void *user, br_session_t s, uint8_t reason)
{
    (void)s;
    (void)reason;
    ((ep_t *)user)->closed++;
}

static void ep_init(ep_t *e, const char *name, uint16_t unit, bool probe, uint16_t allow_id)
{
    memset(e, 0, sizeof *e);
    e->name = name;
    e->sess = BR_SESSION_NONE;
    e->radio.med = &MED;

    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = unit;
    c.role = BR_ROLE_NODE;
    c.node_count = 2;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY; /* node_app kCapsBase */
    if (probe) {
        c.caps = (uint16_t)(c.caps | BR_CAP_MULTI);
        c.groups[0] = 0xFF10;
        c.n_groups = 1;
    }
    c.auth = true;
    c.cold_boot = false;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE; /* the bench key of node_app */
    c.net_key_len = BRV_A6_K_SITE_LEN;
    nrf24_link_cfg_t lc;
    memset(&lc, 0, sizeof lc);
    lc.unit_id = unit;
    nrf24_radio_ops_t ops = fr_ops(&e->radio);
    CHECK_ERR(nrf24_link_register(&e->link, &c, &lc, &ops), BR_OK);
    CHECK_EQ_U32(c.n_transports, 1u);
    CHECK_EQ_U32(e->link.link, 0u);
    c.transports[0].allowlist.enabled = allow_id != 0u;
    c.transports[0].allowlist.n = allow_id != 0u ? 1u : 0u;
    c.transports[0].allowlist.ids[0] = allow_id;
    c.app.user = e;
    c.app.on_bound = cb_bound;
    c.app.on_samples = cb_samples;
    c.app.on_gap = cb_gap;
    c.app.on_acked = cb_acked;
    c.app.on_closed = cb_closed;
    c.app.on_state = cb_state;
    c.txseq_start = 1;
    c.preseq_start = 1;
    CHECK_ERR(br_node_init(&e->node, sizeof e->node, &c), BR_OK);
    CHECK(nrf24_link_start(&e->link));
    CHECK(e->radio.listening);
}

static void step_ms(void)
{
    uint64_t nd = 0;
    g_now_us += 1000u;
    CHECK_ERR(br_node_tick(&EA.node, g_now_us, &nd), BR_OK);
    CHECK_ERR(br_node_tick(&EB.node, g_now_us, &nd), BR_OK);
    /* two pump rounds per ms: a reply within the same step still goes out */
    for (unsigned k = 0; k < 2u; k++) {
        uint64_t d = nrf24_link_pump(&EA.link, &EA.node, g_now_us);
        CHECK(d <= g_now_us + NRF24_LINK_POLL_US);
        d = nrf24_link_pump(&EB.link, &EB.node, g_now_us);
        CHECK(d <= g_now_us + NRF24_LINK_POLL_US);
    }
}

static bool run_until(bool (*cond)(void), uint32_t max_ms)
{
    for (uint32_t i = 0; i < max_ms; i++) {
        if (cond()) {
            return true;
        }
        step_ms();
    }
    return cond();
}

static unsigned g_want_acked;
static bool cond_streaming(void) { return EA.streaming; }
static bool cond_acked(void) { return EA.acked + EA.gap_seqs >= g_want_acked; }
static bool cond_quiet(void)
{
    return nrf24_link_tx_pending(&EA.link) == 0u && nrf24_link_tx_pending(&EB.link) == 0u &&
           EA.radio.rxq_n == 0u && EB.radio.rxq_n == 0u;
}

static uint64_t g_t0_us;

static void start_pair(uint32_t loss_pct, bool ack_blind, bool arm_now, uint16_t a_allow, uint16_t b_allow,
                       uint64_t seed)
{
    g_t0_us = g_now_us;
    memset(&MED, 0, sizeof MED);
    tu_rng_seed(&MED.rng, seed * 7u + 3u);
    MED.loss_pct = loss_pct;
    MED.ack_loss_pct = loss_pct;
    MED.arc = 15;
    MED.ack_blind = ack_blind;
    MED.armed = arm_now;
    tu_rng_seed(&g_plat_rng, seed ^ 0xA5A5A5A5u);
    ep_init(&EA, "A", 0x0101, false, a_allow);
    ep_init(&EB, "B", 0x0103, true, b_allow);
    MED.r[0] = &EA.radio;
    MED.r[1] = &EB.radio;
    CHECK_ERR(br_node_seek(&EA.node, 0xFF10, &EA.sess), BR_OK);
    br_mode_t m; /* node_app demo MODE */
    memset(&m, 0, sizeof m);
    m.config_id = 1;
    m.mode = BR_MODE_HIGH;
    m.ch_count = 1;
    m.period = 1;
    m.flags = BR_MODE_FLAG_PERIOD_MS;
    m.fec_k = 8;
    m.fec_m = 0;
    m.arq = 1;
    m.keepalive_ms = BR_KEEPALIVE_DEFAULT_MS;
    m.ch[0].kind = BR_CH_KIND_DIGITAL;
    m.ch[0].fmt = 1;
    CHECK_ERR(br_node_set_mode(&EA.node, EA.sess, &m), BR_OK);
}

/* One press = value 1 then value 0, both ACK_REQ (node_app sender_press). */
static bool press(unsigned i)
{
    br_value_t v;
    v.lines = 1;
    br_err_t r1 = br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true);
    v.lines = 0;
    br_err_t r0 = br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true);
    CHECK_ERR(r1, BR_OK);
    CHECK_ERR(r0, BR_OK);
    g_want_acked = 2u * (i + 1u);
    return run_until(cond_acked, 30000);
}

static void finish_pair(void)
{
    (void)run_until(cond_quiet, 2000);
    br_node_deinit(&EA.node);
    br_node_deinit(&EB.node);
}

#define PRESSES 20u

typedef struct {
    br_stats_t         a;
    br_stats_t         b;
    nrf24_link_stats_t la;
    nrf24_link_stats_t lb;
    nrf24_seg_stats_t  sa;
    nrf24_seg_stats_t  sb;
} pair_stats_t;

static void print_pair(const char *what, const pair_stats_t *ps)
{
    printf("  %-44s t=%5.1fs frames A->B %3u B->A %3u segs %4u/%4u lost %3u/%3u acks_lost %3u/%3u "
           "max_rt %u/%u reasm_drop %u/%u (gap %u/%u to %u/%u) retx %u gave_up %u bcast %u/%u\n",
           what, (double)(g_now_us - g_t0_us) / 1e6, ps->la.tx_frames, ps->lb.tx_frames, ps->la.tx_segments,
           ps->lb.tx_segments, EA.radio.pkts_lost, EB.radio.pkts_lost, EA.radio.acks_lost, EB.radio.acks_lost,
           ps->la.tx_max_rt, ps->lb.tx_max_rt, ps->sb.frames_dropped, ps->sa.frames_dropped, ps->sb.gaps,
           ps->sa.gaps, ps->sb.timeouts, ps->sa.timeouts, (unsigned)ps->a.f.arq_retx, EA.gap_seqs,
           ps->la.tx_bcast, ps->lb.tx_bcast);
}

/*
 * strict: every press delivered and acknowledged, no MAX_RT. Not strict
 * (ACK-blind carrier): ARQ may give a DATA seq up after ARQ_MAX_RETRIES;
 * every DATA must then be accounted for (acked or on_gap) and the session
 * must still be STREAMING.
 */
static pair_stats_t run_session(const char *what, uint32_t loss_pct, bool ack_blind, bool arm_now,
                                uint16_t a_allow, uint16_t b_allow, uint64_t seed, bool strict)
{
    pair_stats_t ps;
    tu_ctx(what);
    start_pair(loss_pct, ack_blind, arm_now, a_allow, b_allow, seed);
    bool up = run_until(cond_streaming, 60000);
    CHECK_MSG(up, "sender never reached STREAMING");
    CHECK(EB.bound);
    MED.armed = loss_pct > 0u;
    unsigned ok = 0;
    for (unsigned i = 0; up && i < PRESSES; i++) {
        if (press(i)) {
            ok++;
        }
        for (unsigned k = 0; k < 50u; k++) {
            step_ms();
        }
    }
    for (unsigned k = 0; k < 2000u; k++) {
        step_ms(); /* > REORDER_MS: the probe releases anything held behind a given-up seq */
    }
    CHECK_EQ_U32(ok, PRESSES);
    CHECK_EQ_U32(EA.acked + EA.gap_seqs, 2u * PRESSES);
    if (strict) {
        CHECK_EQ_U32(EA.acked, 2u * PRESSES);
        CHECK_EQ_U32(EA.gap_seqs, 0u);
        CHECK_EQ_U32(EB.ones, PRESSES);
        CHECK_EQ_U32(EB.zeros, PRESSES);
    } else {
        CHECK(EB.ones + EB.zeros + EA.gap_seqs >= 2u * PRESSES);
        CHECK(EA.acked >= PRESSES);
    }
    uint8_t st = 0;
    CHECK_ERR(br_node_session_state(&EA.node, EA.sess, &st), BR_OK);
    CHECK_EQ_U32(st, BR_SND_STREAMING);
    CHECK_EQ_U32(EA.closed, 0u);
    CHECK_EQ_U32(EB.closed, 0u);
    (void)run_until(cond_quiet, 2000);
    ps.a = node_stats(&EA.node);
    ps.b = node_stats(&EB.node);
    nrf24_link_get_stats(&EA.link, &ps.la);
    nrf24_link_get_stats(&EB.link, &ps.lb);
    nrf24_link_get_seg_stats(&EA.link, &ps.sa);
    nrf24_link_get_seg_stats(&EB.link, &ps.sb);

    /* every unicast frame got exactly one verdict; nothing refused or stuck */
    CHECK_EQ_U32(ps.la.tx_status_ok + ps.la.tx_status_fail, ps.la.tx_unicast + ps.la.tx_max_rt);
    CHECK_EQ_U32(ps.lb.tx_status_ok + ps.lb.tx_status_fail, ps.lb.tx_unicast + ps.lb.tx_max_rt);
    CHECK_EQ_U32(ps.la.tx_refused + ps.lb.tx_refused, 0u);
    CHECK_EQ_U32(ps.la.tx_stuck + ps.lb.tx_stuck, 0u);
    CHECK_EQ_U32(ps.la.tx_radio_err + ps.lb.tx_radio_err, 0u);
    CHECK_EQ_U32(ps.la.rx_bad_pipe + ps.lb.rx_bad_pipe, 0u);
    CHECK_EQ_U32(ps.la.rx_src_mismatch + ps.lb.rx_src_mismatch, 0u);
    /* 11.3: the SEEK leaves with path_mtu 250, the adapter never shows 32 */
    CHECK(EA.radio.seeks_sent > 0u);
    CHECK_EQ_U32(EA.radio.first_seek_path_mtu, 250u);
    /* floods went out NO_ACK on the broadcast address, everything else unicast */
    CHECK(ps.la.tx_bcast > 0u);
    CHECK(EA.radio.bcast_sent >= ps.la.tx_bcast);          /* one or more NO_ACK segments per flood frame */
    CHECK(ps.la.tx_unicast > 0u && ps.lb.tx_unicast > 0u);
    /* both ends are back in PRX */
    CHECK(EA.radio.listening && EB.radio.listening);
    CHECK_EQ_U32(EA.link.tx_state == NRF24_TX_SENDING, 0u);
    /* the probe learnt the sender's derived address (C.5), not a MAC */
    {
        const br_tables_t *tb = NULL;
        CHECK_ERR(br_node_get_tables(&EB.node, &tb), BR_OK);
        br_link_entry_t *le = NULL;
        br_link_table_t lt = tb->link;
        CHECK_ERR(br_link_find(&lt, 0x0101, 0, &le), BR_OK);
        CHECK(le != NULL);
        if (le != NULL) {
            uint8_t want[5];
            nrf24_link_unit_addr(0x0101, want);
            CHECK_EQ_U32(le->addr_len, 5u);
            CHECK_MEM(want, le->addr, 5);
            CHECK_EQ_U32((uint32_t)(int32_t)le->rssi_ewma, (uint32_t)(int32_t)BR_RSSI_UNKNOWN);
        }
    }
    print_pair(what, &ps);
    return ps;
}

static void test_loopback_clean(void)
{
    pair_stats_t ps = run_session("loopback clean", 0, false, false, 0, 0, 11, true);
    CHECK_EQ_U32(ps.a.f.crc_fail + ps.b.f.crc_fail, 0u);
    CHECK_EQ_U32(ps.a.f.arq_retx, 0u);
    CHECK_EQ_U32(ps.la.tx_max_rt + ps.lb.tx_max_rt, 0u);
    CHECK_EQ_U32(ps.la.tx_status_fail + ps.lb.tx_status_fail, 0u);
    CHECK_EQ_U32(ps.sa.frames_dropped + ps.sb.frames_dropped, 0u);
    CHECK_EQ_U32(ps.sa.dups + ps.sb.dups, 0u);
    CHECK_EQ_U32(ps.sb.frames_rx, ps.la.tx_frames);           /* every frame A sent, B reassembled */
    CHECK_EQ_U32(ps.sa.frames_rx, ps.lb.tx_frames);
    CHECK_EQ_U32(ps.lb.rx_frames, ps.la.tx_frames);
    CHECK_EQ_U32(ps.a.f.rx_frames, ps.la.rx_frames);
    CHECK_EQ_U32(ps.b.f.rx_frames, ps.lb.rx_frames);
    CHECK_EQ_U32(ps.la.tx_segments, ps.sb.seg_rx);
    CHECK_EQ_U32(ps.lb.tx_segments, ps.sa.seg_rx);
    CHECK_EQ_U32(EA.gaps + EB.gaps, 0u);
    CHECK_EQ_U32(ps.a.f.link_fail_drops + ps.b.f.link_fail_drops, 0u);
    finish_pair();
}

#define SEEDS 6u

static void test_loopback_esb_loss(uint64_t seed)
{
    /* 5 % per attempt on data and ACKs, ESB retries on (ARC 15), loss from the first frame */
    pair_stats_t ps = run_session("loopback, 5% segment loss, ESB auto-ACK", 5, false, true, 0x0103, 0x0101,
                                  seed, true);
    CHECK(EA.radio.pkts_lost + EB.radio.pkts_lost > 0u);
    /*
     * Pure loss never exhausts ARC 15 (0.05^16). The residual MAX_RT path is
     * the head-on collision after a lost ACK on a LAST segment (both radios
     * in PTX, both deaf): the post-RX hold (rx_hold_us) removes most of it;
     * what remains must be rare and reported, and must never reach the 11.6
     * link deletion (3 consecutive).
     */
    CHECK(ps.la.tx_max_rt + ps.lb.tx_max_rt <= 2u);
    CHECK_EQ_U32(ps.la.tx_status_fail, ps.la.tx_max_rt);
    CHECK_EQ_U32(ps.lb.tx_status_fail, ps.lb.tx_max_rt);
    CHECK_EQ_U32(ps.a.f.link_fail_drops + ps.b.f.link_fail_drops, 0u);
    /* every unicast frame that completed was reassembled; a MAX_RT frame may still have arrived whole */
    CHECK(ps.sb.frames_rx >= ps.la.tx_unicast);
    CHECK(ps.sb.frames_rx <= ps.la.tx_frames + ps.la.tx_max_rt);
    CHECK(ps.sa.frames_rx >= ps.lb.tx_unicast);
    CHECK(ps.sa.frames_rx <= ps.lb.tx_frames + ps.lb.tx_max_rt);
    CHECK_EQ_U32(ps.la.rx_admit_drop + ps.lb.rx_admit_drop, 0u);
    finish_pair();
}

static void test_loopback_ack_blind(uint64_t seed)
{
    /* 5 % segment loss the ESB cannot see (armed once STREAMING, like the UART test's lossy modes) */
    pair_stats_t ps = run_session("loopback, 5% segment loss, ACK-blind carrier", 5, true, false, 0, 0, seed,
                                  false);
    CHECK(EA.radio.pkts_lost + EB.radio.pkts_lost > 0u);
    /* reassembly drops counted: a dropped frame, an orphaned tail, or a frame that never opened */
    CHECK(ps.sa.frames_dropped + ps.sb.frames_dropped + ps.sa.orphans + ps.sb.orphans > 0u);
    /* B cannot account for more frames than A sent (segment-0 losses leave no frame record, only orphans) */
    CHECK(ps.sb.frames_rx + ps.sb.frames_dropped + nrf24_seg_open_count(&EB.link.seg) <= ps.la.tx_frames);
    CHECK_EQ_U32(ps.sa.frames_dropped, ps.sa.gaps + ps.sa.timeouts + ps.sa.foreign_tag + ps.sa.oversize +
                                           ps.sa.buffer_full);
    CHECK(ps.a.f.arq_retx > 0u);                                                   /* ARQ carried the session */
    CHECK_EQ_U32(ps.la.tx_max_rt + ps.lb.tx_max_rt, 0u);                           /* the carrier never says no */
    finish_pair();
}

static void test_loopback_allowlist_excludes(void)
{
    tu_ctx("loopback, probe allowlist excludes the sender");
    start_pair(0, false, false, 0x0103, 0x0102, 77);
    bool up = run_until(cond_streaming, 10000);
    CHECK(!up);
    CHECK(!EB.bound);
    br_stats_t b = node_stats(&EB.node);
    CHECK_EQ_U32(b.f.rx_frames, 0u); /* the core saw nothing (N22) */
    nrf24_link_stats_t lb;
    nrf24_link_get_stats(&EB.link, &lb);
    CHECK(lb.rx_admit_drop > 0u);
    CHECK_EQ_U32(lb.rx_frames, 0u);
    finish_pair();
}

/* ---- adapter unit checks ---------------------------------------------------- */

static void test_adapter_fields_and_register(void)
{
    tu_ctx("transport fields (1.2 nRF24 row) and register()");
    fradio_t r;
    memset(&r, 0, sizeof r);
    r.med = &MED;
    memset(&MED, 0, sizeof MED);
    nrf24_radio_ops_t ops = fr_ops(&r);
    nrf24_link_cfg_t lc;
    memset(&lc, 0, sizeof lc);
    lc.unit_id = 0x0101;
    static nrf24_link_t l;
    CHECK(nrf24_link_init(&l, &lc, &ops));
    CHECK_EQ_U32(l.cfg.txq_frames, NRF24_LINK_TXQ_DEFAULT);
    CHECK_EQ_U32(l.cfg.guard_us, NRF24_LINK_GUARD_US);
    CHECK_EQ_U32(l.seg.n_slots, NRF24_SEG_SLOTS_DEFAULT);
    CHECK_EQ_U32(l.seg.src, 0x01u);
    static const uint8_t want[5] = {0x50, 0x4C, 0x01, 0x01, 0xA5};
    CHECK_MEM(want, l.own_addr, 5);
    static const uint8_t bc[5] = {0x50, 0x4C, 0xFF, 0xFF, 0xA5};
    CHECK_MEM(bc, NRF24_LINK_BCAST_ADDR, 5);
    br_transport_t tr;
    memset(&tr, 0, sizeof tr);
    tr.allowlist.enabled = true;
    tr.allowlist.n = 1;
    tr.allowlist.ids[0] = 0x0102;
    nrf24_link_fill_transport(&l, &tr);
    CHECK(strcmp(tr.name, "nrf24") == 0);
    CHECK(tr.link_class == BR_LINK_PACKET);
    CHECK_EQ_U32(tr.max_frame, 250u);
    CHECK_EQ_U32(tr.rs_nsym, 0u);
    CHECK(tr.can_broadcast);
    CHECK(tr.mac_retry);
    CHECK(!tr.edge_only);
    CHECK_EQ_U32(tr.link_cost, 2u);
    CHECK_EQ_U32(tr.addr_len, 5u);
    CHECK(tr.send == nrf24_link_send);
    CHECK(tr.user == &l);
    CHECK(tr.allowlist.enabled && tr.allowlist.n == 1u && tr.allowlist.ids[0] == 0x0102u); /* untouched */
    /* init refusals */
    lc.unit_id = 0x0001; /* a manager ID is not a unit */
    CHECK(!nrf24_link_init(&l, &lc, &ops));
    lc.unit_id = 0x0101;
    lc.txq_frames = NRF24_LINK_TXQ_MAX + 1u;
    CHECK(!nrf24_link_init(&l, &lc, &ops));
    lc.txq_frames = 0;
    nrf24_radio_ops_t bad = ops;
    bad.start_tx = NULL;
    CHECK(!nrf24_link_init(&l, &lc, &bad));
    CHECK(!nrf24_link_init(NULL, &lc, &ops));
    /* register fills slots until BR_NODE_MAX_TRANSPORTS */
    br_node_config_t nc;
    memset(&nc, 0, sizeof nc);
    static nrf24_link_t l2[BR_NODE_MAX_TRANSPORTS + 1u];
    for (unsigned i = 0; i < BR_NODE_MAX_TRANSPORTS; i++) {
        CHECK_ERR(nrf24_link_register(&l2[i], &nc, &lc, &ops), BR_OK);
        CHECK_EQ_U32(l2[i].link, i);
        CHECK_EQ_U32(nc.n_transports, i + 1u);
        CHECK(nc.transports[i].user == &l2[i]);
    }
    CHECK_ERR(nrf24_link_register(&l2[BR_NODE_MAX_TRANSPORTS], &nc, &lc, &ops), BR_ERR_TOO_BIG);
    CHECK_ERR(nrf24_link_register(NULL, &nc, &lc, &ops), BR_ERR_ARG);
    /* send before start, bad lengths */
    uint8_t f[260];
    memset(f, 0x11, sizeof f);
    CHECK_ERR(nrf24_link_send(&l, NULL, f, 10), BR_ERR_STATE);
    CHECK_ERR(nrf24_link_send(&l, NULL, f, 0), BR_ERR_ARG);
    CHECK_ERR(nrf24_link_send(&l, NULL, NULL, 5), BR_ERR_ARG);
    CHECK_ERR(nrf24_link_send(&l, NULL, f, 251), BR_ERR_TOO_BIG);
    CHECK_ERR(nrf24_link_send(NULL, NULL, f, 5), BR_ERR_ARG);
    nrf24_link_stats_t s;
    nrf24_link_get_stats(&l, &s);
    CHECK_EQ_U32(s.tx_bad_len, 3u);
    CHECK_EQ_U32(nrf24_link_pump(&l, NULL, 5), UINT64_MAX); /* not started */
    CHECK(!nrf24_link_radio_busy(&l, 5));
}

/* Pump the lone endpoint every 500 us (the IRQ / poll cadence) until cond or max passes. */
static ep_t *g_lone;
static bool pump_until(bool (*cond)(void), unsigned max_passes)
{
    for (unsigned i = 0; i < max_passes; i++) {
        if (cond()) {
            return true;
        }
        g_now_us += 500u;
        (void)nrf24_link_pump(&g_lone->link, &g_lone->node, g_now_us);
    }
    return cond();
}

static bool lone_cond_fail1(void)
{
    nrf24_link_stats_t s;
    nrf24_link_get_stats(&g_lone->link, &s);
    return s.tx_status_fail >= 1u;
}

static bool lone_cond_idle(void)
{
    return nrf24_link_tx_pending(&g_lone->link) == 0u && g_lone->link.tx_state == NRF24_TX_IDLE;
}

static void test_adapter_max_rt_and_busy(void)
{
    tu_ctx("MAX_RT -> br_node_tx_status(delivered = false); queue; busy hook");
    /* a lone node with the adapter; the peer radio exists but never listens */
    memset(&MED, 0, sizeof MED);
    MED.arc = 15;
    MED.armed = false;
    tu_rng_seed(&MED.rng, 1);
    static ep_t lone;
    static fradio_t deaf;
    memset(&deaf, 0, sizeof deaf);
    deaf.med = &MED;
    ep_init(&lone, "L", 0x0101, false, 0);
    g_lone = &lone;
    MED.r[0] = &lone.radio;
    MED.r[1] = &deaf;
    uint8_t dst[5];
    nrf24_link_unit_addr(0x0102, dst);
    uint8_t frame[250];
    for (unsigned i = 0; i < sizeof frame; i++) {
        frame[i] = (uint8_t)(i * 7u);
    }
    CHECK_ERR(nrf24_link_send(&lone.link, dst, frame, 250), BR_OK);
    CHECK_EQ_U32(nrf24_link_tx_pending(&lone.link), 1u);
    CHECK(!nrf24_link_radio_busy(&lone.link, g_now_us));
    uint64_t d = nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    CHECK(lone.link.tx_state == NRF24_TX_SENDING);
    CHECK_EQ_U32(lone.radio.starts, 1u);
    CHECK(nrf24_link_radio_busy(&lone.link, g_now_us));
    CHECK(!lone.radio.listening);
    CHECK(d <= g_now_us + NRF24_LINK_TX_POLL_US);
    uint64_t t0 = g_now_us;
    CHECK(pump_until(lone_cond_fail1, 100));
    /* 16 attempts, 500 us apart, then MAX_RT: about 8 ms */
    CHECK_EQ_U32(lone.radio.tx_attempts, 16u);
    CHECK_EQ_U32(lone.radio.max_rt, 1u);
    CHECK(g_now_us - t0 >= 15u * ARD_US && g_now_us - t0 <= 15u * ARD_US + 2000u);
    nrf24_link_stats_t s;
    nrf24_link_get_stats(&lone.link, &s);
    CHECK_EQ_U32(s.tx_max_rt, 1u);
    CHECK_EQ_U32(s.tx_status_fail, 1u);
    CHECK_EQ_U32(s.tx_status_ok, 0u);
    CHECK_EQ_U32(s.tx_frames, 0u);
    CHECK_EQ_U32(s.tx_segments, 1u);               /* the frame was abandoned at its first segment */
    CHECK_EQ_U32(lone.radio.aborts, 1u);            /* FLUSH_TX + flags cleared */
    CHECK(!lone.radio.tx_valid);
    CHECK(lone.radio.listening);                   /* back to PRX */
    CHECK(lone.link.tx_state == NRF24_TX_GUARD);
    CHECK_EQ_U32(nrf24_link_tx_pending(&lone.link), 0u);
    CHECK(!nrf24_link_radio_busy(&lone.link, g_now_us));
    /* the node took the failure for an unknown link: no crash, no deletion */
    br_stats_t ns = node_stats(&lone.node);
    CHECK_EQ_U32(ns.f.link_fail_drops, 0u);

    /* guard: nothing starts before guard_until, then a broadcast frame goes (2 segments, no verdict) */
    uint64_t guard_end = lone.link.guard_until_us;
    CHECK_ERR(nrf24_link_send(&lone.link, NULL, frame, 40), BR_OK);
    d = nrf24_link_pump(&lone.link, &lone.node, guard_end - 1u);
    CHECK(lone.link.tx_state == NRF24_TX_GUARD);
    CHECK_EQ_U32(lone.radio.starts, 1u);
    CHECK_EQ_U32(d, guard_end);
    g_now_us = guard_end;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    CHECK(lone.link.tx_state == NRF24_TX_SENDING);
    CHECK_EQ_U32(lone.radio.starts, 2u);
    CHECK(pump_until(lone_cond_idle, 40));
    nrf24_link_get_stats(&lone.link, &s);
    CHECK_EQ_U32(s.tx_frames, 1u);
    CHECK_EQ_U32(s.tx_bcast, 1u);
    CHECK_EQ_U32(s.tx_segments, 3u);
    CHECK_EQ_U32(lone.radio.bcast_sent, 2u);
    CHECK_EQ_U32(lone.radio.tx_attempts, 18u);      /* NO_ACK: one attempt per segment, nobody listening */
    CHECK_EQ_U32(s.tx_status_ok + s.tx_status_fail, 1u); /* broadcasts report nothing */
    CHECK(lone.radio.listening);

    /* queue full: txq_frames (4) frames queued, the 5th refused; all four then go out */
    for (unsigned i = 0; i < NRF24_LINK_TXQ_DEFAULT; i++) {
        CHECK_ERR(nrf24_link_send(&lone.link, NULL, frame, 29), BR_OK);
    }
    CHECK_ERR(nrf24_link_send(&lone.link, NULL, frame, 29), BR_ERR_QUEUE_FULL);
    nrf24_link_get_stats(&lone.link, &s);
    CHECK_EQ_U32(s.tx_refused, 1u);
    CHECK_EQ_U32(nrf24_link_tx_pending(&lone.link), 4u);
    CHECK(pump_until(lone_cond_idle, 200));
    nrf24_link_get_stats(&lone.link, &s);
    CHECK_EQ_U32(s.tx_frames, 5u);
    CHECK_EQ_U32(s.tx_segments, 7u);

    /* 12.4 hook: a neighbour mid-frame to us makes the radio busy and defers our transmit */
    uint8_t seg0[32];
    memset(seg0, 0x33, sizeof seg0);
    seg0[0] = 0x02;  /* src */
    seg0[1] = 0x00;  /* tag */
    seg0[2] = 0x00;  /* idx 0, not LAST */
    fpayload_t p;
    memcpy(p.data, seg0, 32);
    p.len = 32;
    p.no_ack = false;
    fr_rx_push(&lone.radio, 0, &p);
    g_now_us += 1000u;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    uint64_t seen = g_now_us;
    CHECK(nrf24_link_radio_busy(&lone.link, seen));
    CHECK(nrf24_link_radio_busy(&lone.link, seen + NRF24_LINK_RX_HOLD_US - 1u));
    CHECK(!nrf24_link_radio_busy(&lone.link, seen + NRF24_LINK_RX_HOLD_US));
    CHECK_ERR(nrf24_link_send(&lone.link, NULL, frame, 10), BR_OK);
    unsigned starts = lone.radio.starts;
    g_now_us = seen + 100u;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    CHECK_EQ_U32(lone.radio.starts, starts);        /* deferred */
    nrf24_link_get_stats(&lone.link, &s);
    CHECK(s.tx_deferred > 0u);
    g_now_us = seen + NRF24_LINK_RX_HOLD_US;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    CHECK_EQ_U32(lone.radio.starts, starts + 1u);   /* window over: sent */
    /* the half frame times out and is counted */
    g_now_us = seen + 60000u;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    nrf24_seg_stats_t ss;
    nrf24_link_get_seg_stats(&lone.link, &ss);
    CHECK_EQ_U32(ss.timeouts, 1u);
    br_node_deinit(&lone.node);
}

static void test_adapter_stuck_radio(void)
{
    tu_ctx("no TX_DS / MAX_RT within tx_timeout: frame abandoned, radio recovered");
    memset(&MED, 0, sizeof MED);
    MED.arc = 15;
    static ep_t lone;
    static fradio_t other;
    memset(&other, 0, sizeof other);
    other.med = &MED;
    ep_init(&lone, "S", 0x0101, false, 0);
    MED.r[0] = &lone.radio;
    MED.r[1] = &other;
    uint8_t frame[30];
    memset(frame, 0x44, sizeof frame);
    CHECK_ERR(nrf24_link_send(&lone.link, NULL, frame, 30), BR_OK);
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    CHECK(lone.link.tx_state == NRF24_TX_SENDING);
    lone.radio.pending = false; /* the chip never completes (broken CE wire) */
    lone.radio.status = 0;
    uint64_t t0 = g_now_us;
    (void)nrf24_link_pump(&lone.link, &lone.node, t0 + NRF24_LINK_TX_TIMEOUT_US - 1u);
    CHECK(lone.link.tx_state == NRF24_TX_SENDING);
    g_now_us = t0 + NRF24_LINK_TX_TIMEOUT_US;
    (void)nrf24_link_pump(&lone.link, &lone.node, g_now_us);
    nrf24_link_stats_t s;
    nrf24_link_get_stats(&lone.link, &s);
    CHECK_EQ_U32(s.tx_stuck, 1u);
    CHECK_EQ_U32(lone.radio.aborts, 1u);
    CHECK(lone.radio.listening);
    CHECK_EQ_U32(nrf24_link_tx_pending(&lone.link), 0u);
    br_node_deinit(&lone.node);
}

/* ========================================================================= */

int main(void)
{
    const br_platform_t plat = {t_now, t_random, t_log, NULL};
    tu_rng_seed(&g_plat_rng, 1);
    CHECK_ERR(br_platform_set(&plat), BR_OK);

    /* Part A */
    test_seg_layout();
    test_seg_round_trip_all_sizes();
    test_seg_damage();
    /* Part B */
    test_regs_init_sequence();
    test_regs_addresses_and_payloads();
    /* Part C */
    test_adapter_fields_and_register();
    test_adapter_max_rt_and_busy();
    test_adapter_stuck_radio();
    test_loopback_clean();
    for (uint64_t seed = 0; seed < SEEDS; seed++) {
        test_loopback_esb_loss(seed);
    }
    for (uint64_t seed = 0; seed < SEEDS; seed++) {
        test_loopback_ack_blind(seed);
    }
    test_loopback_allowlist_excludes();
    return tu_summary("test_nrf24_link");
}
