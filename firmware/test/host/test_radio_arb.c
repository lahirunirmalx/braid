// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_radio_arb.c - host test of the 12.4 bridge radio arbitration
 * (components/app_node/src/radio_arb.c, espnow_link.c and the nRF24 pump's
 * transmit gate in components/app_nrf24_link/src/nrf24_link.c;
 * firmware/RADIO-ARB.txt; PROTOCOL.md v0.8 12.4, C.5; SPEC-NOTES N60).
 *
 * The portable sources are compiled into this executable (as
 * test_nrf24_link.c does); both radios below them are fakes. The host clock
 * is installed through br_platform (espnow_link reads it).
 *
 * Part A  radio_arb alone: hold / release, counters once per held frame,
 *         the cap and the stale-signal rule, custom cap, both directions
 *         independent, single-radio and uninitialised arbiters are no-ops.
 * Part B  espnow_link deferral FIFO: pass-through (no arbiter, single
 *         radio: the raw send runs inside send(), nothing queued), enqueue
 *         while the nRF24 radio is busy, drain order (unicast / broadcast
 *         addresses kept), order kept when the radio frees up, FIFO full,
 *         drain refusal, bad lengths, cap on a held FIFO.
 * Part C  nRF24 transmit gate: a lone adapter holds its frame while
 *         ESP-NOW TX is in flight, starts on release, starts after the cap;
 *         a single-radio arbiter starts on the same pump pass as no gate.
 * Part D  End to end: sender A (nRF24 only) -> bridge B (nRF24 + ESP-NOW,
 *         relay) -> probe C (ESP-NOW only), real br_node instances, a fake
 *         ESB medium (A <-> B) and a fake ESP-NOW medium (B <-> C) whose
 *         in-flight count has the hal_radio_tx_inflight() semantics (raised
 *         by the send, lowered when the frame's air time ends, broadcasts
 *         included). Instrumented at B: every ESP-NOW start is checked
 *         against nrf24_link_radio_busy() and every nRF24 frame start
 *         (segment 0) against the ESP-NOW in-flight count. Every press is
 *         delivered (hops 2) and the overlap count never exceeds arb_timeout
 *         (which is 0 in these runs). A control run with the arbitration
 *         switched off shows the instrument does detect overlaps.
 */
#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_sample.h"
#include "braid/br_session.h"
#include "braid/br_tables.h"
#include "test_util.h"
#include "vectors_generated.h"

#include "../../components/app_node/src/espnow_link.c"
#include "../../components/app_node/src/radio_arb.c"
#include "../../components/app_nrf24_link/src/nrf24_link.c"
#include "../../components/app_nrf24_link/src/nrf24_seg.c"

/* Virtual clock shared by the platform table, the pumps and both media. */
static uint64_t g_now_us = 1000000u;

static uint64_t t_now(void *user)
{
    (void)user;
    return g_now_us;
}

static tu_rng_t g_plat_rng;

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

/* ========================================================================= */
/* Part A: radio_arb                                                          */
/* ========================================================================= */

typedef struct {
    bool     busy;
    unsigned calls;
} fsig_t;

static bool fsig_busy(void *ctx, uint64_t now_us)
{
    fsig_t *s = (fsig_t *)ctx;
    (void)now_us;
    s->calls++;
    return s->busy;
}

static fsig_t SIG_NRF;
static fsig_t SIG_ESP;

static void arb_bridge(radio_arb_t *a, uint32_t cap_us)
{
    memset(&SIG_NRF, 0, sizeof SIG_NRF);
    memset(&SIG_ESP, 0, sizeof SIG_ESP);
    radio_arb_cfg_t c;
    radio_arb_default_cfg(&c);
    CHECK_EQ_U32(c.cap_us, RADIO_ARB_CAP_US_DEFAULT);
    CHECK(c.nrf_busy == NULL && c.espnow_busy == NULL);
    c.nrf_busy = fsig_busy;
    c.nrf_ctx = &SIG_NRF;
    c.espnow_busy = fsig_busy;
    c.espnow_ctx = &SIG_ESP;
    c.cap_us = cap_us;
    CHECK(radio_arb_init(a, &c));
    CHECK(radio_arb_is_bridge(a));
}

static radio_arb_stats_t arb_stats(const radio_arb_t *a)
{
    radio_arb_stats_t s;
    radio_arb_get_stats(a, &s);
    return s;
}

static void test_arb_args_and_noop(void)
{
    radio_arb_t a;
    radio_arb_cfg_t c;
    radio_arb_stats_t s;

    tu_ctx("arb: NULL arguments");
    radio_arb_default_cfg(&c);
    radio_arb_default_cfg(NULL);
    CHECK(!radio_arb_init(NULL, &c));
    CHECK(!radio_arb_init(&a, NULL));
    CHECK(radio_arb_espnow_may_start(NULL, 0));
    CHECK(radio_arb_nrf_may_start(NULL, 0));
    CHECK(!radio_arb_is_bridge(NULL));
    radio_arb_get_stats(NULL, &s);
    CHECK_EQ_U32(s.hold_espnow + s.hold_nrf + s.timeout, 0u);
    radio_arb_get_stats(&a, NULL);

    tu_ctx("arb: all-zero (never initialised) arbiter allows everything");
    memset(&a, 0, sizeof a);
    CHECK(!radio_arb_is_bridge(&a));
    CHECK(radio_arb_espnow_may_start(&a, 5));
    CHECK(radio_arb_nrf_may_start(&a, 5));

    tu_ctx("arb: no radios after init, cap 0 = default");
    c.cap_us = 0;
    CHECK(radio_arb_init(&a, &c));
    CHECK_EQ_U32(a.cfg.cap_us, RADIO_ARB_CAP_US_DEFAULT);
    CHECK(radio_arb_espnow_may_start(&a, 5));
    CHECK(radio_arb_nrf_may_start(&a, 5));

    tu_ctx("arb: single radio nRF24 (busy) - no-op, query never asked, nothing counted");
    memset(&SIG_NRF, 0, sizeof SIG_NRF);
    SIG_NRF.busy = true;
    radio_arb_default_cfg(&c);
    c.nrf_busy = fsig_busy;
    c.nrf_ctx = &SIG_NRF;
    CHECK(radio_arb_init(&a, &c));
    CHECK(!radio_arb_is_bridge(&a));
    for (uint64_t t = 0; t < 100000u; t += 1000u) {
        CHECK(radio_arb_espnow_may_start(&a, t));
        CHECK(radio_arb_nrf_may_start(&a, t));
    }
    CHECK_EQ_U32(SIG_NRF.calls, 0u);
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow + s.hold_nrf + s.timeout, 0u);

    tu_ctx("arb: single radio ESP-NOW (busy) - no-op");
    memset(&SIG_ESP, 0, sizeof SIG_ESP);
    SIG_ESP.busy = true;
    radio_arb_default_cfg(&c);
    c.espnow_busy = fsig_busy;
    c.espnow_ctx = &SIG_ESP;
    CHECK(radio_arb_init(&a, &c));
    CHECK(!radio_arb_is_bridge(&a));
    for (uint64_t t = 0; t < 100000u; t += 1000u) {
        CHECK(radio_arb_espnow_may_start(&a, t));
        CHECK(radio_arb_nrf_may_start(&a, t));
    }
    CHECK_EQ_U32(SIG_ESP.calls, 0u);
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow + s.hold_nrf + s.timeout, 0u);
}

static void test_arb_hold_release(void)
{
    radio_arb_t a;
    radio_arb_stats_t s;

    tu_ctx("arb: idle radios - every start goes, nothing counted");
    arb_bridge(&a, 0);
    CHECK(radio_arb_espnow_may_start(&a, 1000));
    CHECK(radio_arb_nrf_may_start(&a, 1000));
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow + s.hold_nrf + s.timeout, 0u);

    tu_ctx("arb: ESP-NOW held while nRF24 busy, counted once per held frame");
    SIG_NRF.busy = true;
    CHECK(!radio_arb_espnow_may_start(&a, 2000));
    CHECK(!radio_arb_espnow_may_start(&a, 2500));
    CHECK(!radio_arb_espnow_may_start(&a, 2000 + RADIO_ARB_CAP_US_DEFAULT - 1u));
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow, 1u);
    CHECK_EQ_U32(s.timeout, 0u);
    CHECK(radio_arb_nrf_may_start(&a, 3000)); /* ESP-NOW idle: the nRF24 side is not held */
    CHECK_EQ_U32(arb_stats(&a).hold_nrf, 0u);

    tu_ctx("arb: release when the nRF24 radio reads idle");
    SIG_NRF.busy = false;
    CHECK(radio_arb_espnow_may_start(&a, 4000));
    SIG_NRF.busy = true;
    CHECK(!radio_arb_espnow_may_start(&a, 5000)); /* a new hold, a new count, a new cap window */
    CHECK_EQ_U32(arb_stats(&a).hold_espnow, 2u);
    CHECK(!radio_arb_espnow_may_start(&a, 5000 + RADIO_ARB_CAP_US_DEFAULT - 1u));
    SIG_NRF.busy = false;
    CHECK(radio_arb_espnow_may_start(&a, 5000 + RADIO_ARB_CAP_US_DEFAULT));
    CHECK_EQ_U32(arb_stats(&a).timeout, 0u);

    tu_ctx("arb: nRF24 held while ESP-NOW TX in flight (symmetric)");
    SIG_ESP.busy = true;
    CHECK(!radio_arb_nrf_may_start(&a, 50000));
    CHECK(!radio_arb_nrf_may_start(&a, 50500));
    CHECK(radio_arb_espnow_may_start(&a, 50600)); /* the ESP-NOW side itself is free (its own radio) */
    SIG_ESP.busy = false;
    CHECK(radio_arb_nrf_may_start(&a, 51000));
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_nrf, 1u);
    CHECK_EQ_U32(s.hold_espnow, 2u);
    CHECK_EQ_U32(s.timeout, 0u);

    tu_ctx("arb: both directions keep separate hold state");
    SIG_NRF.busy = true;
    SIG_ESP.busy = true;
    CHECK(!radio_arb_espnow_may_start(&a, 60000));
    CHECK(!radio_arb_nrf_may_start(&a, 61000));
    SIG_ESP.busy = false;
    CHECK(radio_arb_nrf_may_start(&a, 62000));
    CHECK(!radio_arb_espnow_may_start(&a, 62000)); /* still held, its window started at 60000 */
    CHECK(radio_arb_espnow_may_start(&a, 60000 + RADIO_ARB_CAP_US_DEFAULT)); /* cap from 60000, not 61000 */
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow, 3u);
    CHECK_EQ_U32(s.hold_nrf, 2u);
    CHECK_EQ_U32(s.timeout, 1u);
}

static void test_arb_cap_and_stale(void)
{
    radio_arb_t a;
    radio_arb_stats_t s;

    tu_ctx("arb: cap - the held start goes after cap_us and counts arb_timeout");
    arb_bridge(&a, 0);
    SIG_ESP.busy = true; /* wedged: e.g. a send callback that never ran */
    uint64_t t0 = 100000;
    CHECK(!radio_arb_nrf_may_start(&a, t0));
    for (uint64_t t = t0; t < t0 + RADIO_ARB_CAP_US_DEFAULT; t += RADIO_ARB_RECHECK_US) {
        CHECK(!radio_arb_nrf_may_start(&a, t));
    }
    CHECK(radio_arb_nrf_may_start(&a, t0 + RADIO_ARB_CAP_US_DEFAULT));
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_nrf, 1u);
    CHECK_EQ_U32(s.timeout, 1u);

    tu_ctx("arb: stale signal - later starts go at once, each counted, until it reads idle");
    for (unsigned i = 1; i <= 5u; i++) {
        CHECK(radio_arb_nrf_may_start(&a, t0 + RADIO_ARB_CAP_US_DEFAULT + i * 100u));
    }
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_nrf, 1u);   /* no new hold windows while stale */
    CHECK_EQ_U32(s.timeout, 6u);    /* = starts made while ESP-NOW read busy */
    SIG_ESP.busy = false;
    CHECK(radio_arb_nrf_may_start(&a, t0 + 30000u)); /* idle read clears the stale state, not counted */
    CHECK_EQ_U32(arb_stats(&a).timeout, 6u);
    SIG_ESP.busy = true;
    CHECK(!radio_arb_nrf_may_start(&a, t0 + 31000u)); /* held again: the signal is trusted again */
    CHECK_EQ_U32(arb_stats(&a).hold_nrf, 2u);

    tu_ctx("arb: stale state is not expired by time (a wedged signal costs one cap in total)");
    for (uint64_t t = t0 + 31000u; t <= t0 + 31000u + RADIO_ARB_CAP_US_DEFAULT; t += RADIO_ARB_RECHECK_US) {
        (void)radio_arb_nrf_may_start(&a, t);
    }
    CHECK(radio_arb_nrf_may_start(&a, t0 + 31000u + RADIO_ARB_CAP_US_DEFAULT + 100u)); /* stale now */
    CHECK(radio_arb_nrf_may_start(&a, t0 + 31000u + 10u * RADIO_ARB_CAP_US_DEFAULT));  /* still stale after a quiet gap */
    s = arb_stats(&a);
    CHECK_EQ_U32(s.timeout, 9u);
    CHECK_EQ_U32(s.hold_nrf, 2u);

    tu_ctx("arb: custom cap (5 ms) on the ESP-NOW side");
    arb_bridge(&a, 5000);
    CHECK_EQ_U32(a.cfg.cap_us, 5000u);
    SIG_NRF.busy = true;
    CHECK(!radio_arb_espnow_may_start(&a, 10000));
    CHECK(!radio_arb_espnow_may_start(&a, 14999));
    CHECK(radio_arb_espnow_may_start(&a, 15000));
    CHECK(radio_arb_espnow_may_start(&a, 15001)); /* stale */
    s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow, 1u);
    CHECK_EQ_U32(s.timeout, 2u);
    CHECK_EQ_U32(s.hold_nrf, 0u);
}

/* ========================================================================= */
/* Part B: espnow_link deferral FIFO                                          */
/* ========================================================================= */

#define RAW_MAX 32u

typedef struct {
    unsigned n;
    bool     bcast[RAW_MAX];
    uint8_t  addr[RAW_MAX][6];
    uint16_t len[RAW_MAX];
    uint8_t  tag[RAW_MAX];       /* first frame byte */
    uint64_t at[RAW_MAX];
    br_err_t result;             /* what the raw send returns */
} fraw_t;

static br_err_t fraw_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    fraw_t *r = (fraw_t *)user;
    if (r->n < RAW_MAX) {
        r->bcast[r->n] = addr == NULL;
        if (addr != NULL) {
            memcpy(r->addr[r->n], addr, 6);
        }
        r->len[r->n] = len;
        r->tag[r->n] = frame[0];
        r->at[r->n] = g_now_us;
    }
    r->n++;
    return r->result;
}

static const uint8_t MAC_X[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t MAC_Y[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

static uint8_t g_frame[ESPNOW_LINK_MAX_FRAME + 1u];

static br_err_t esend(espnow_link_t *l, const uint8_t *addr, uint8_t tag, uint16_t len)
{
    memset(g_frame, 0x5A, sizeof g_frame);
    g_frame[0] = tag;
    return espnow_link_send(l, addr, g_frame, len);
}

static espnow_link_stats_t el_stats(const espnow_link_t *l)
{
    espnow_link_stats_t s;
    espnow_link_get_stats(l, &s);
    return s;
}

static void test_espnow_passthrough(void)
{
    espnow_link_t l;
    fraw_t raw;
    radio_arb_t a;
    espnow_link_stats_t s;

    tu_ctx("espnow_link: init arguments");
    CHECK(!espnow_link_init(NULL, fraw_send, NULL, NULL));
    CHECK(!espnow_link_init(&l, NULL, NULL, NULL));
    CHECK_ERR(espnow_link_send(NULL, NULL, g_frame, 10), BR_ERR_ARG);
    CHECK(espnow_link_pump(NULL, 0) == UINT64_MAX);
    CHECK_EQ_U32(espnow_link_pending(NULL), 0u);
    espnow_link_get_stats(NULL, &s);
    CHECK_EQ_U32(s.direct + s.deferred, 0u);

    tu_ctx("espnow_link: no arbiter - pure pass-through, raw result returned unchanged");
    memset(&raw, 0, sizeof raw);
    raw.result = BR_OK;
    CHECK(espnow_link_init(&l, fraw_send, &raw, NULL));
    CHECK_ERR(esend(&l, MAC_X, 1, 100), BR_OK);
    CHECK_ERR(esend(&l, NULL, 2, 250), BR_OK);
    raw.result = BR_ERR_QUEUE_FULL; /* tr_send's code for HAL_ERR_BUSY */
    CHECK_ERR(esend(&l, MAC_X, 3, 50), BR_ERR_QUEUE_FULL);
    raw.result = BR_ERR_BUSY;
    CHECK_ERR(esend(&l, MAC_X, 4, 50), BR_ERR_BUSY);
    CHECK_EQ_U32(raw.n, 4u);
    CHECK(!raw.bcast[0] && raw.bcast[1]);
    CHECK_MEM(MAC_X, raw.addr[0], 6);
    CHECK_EQ_U32(raw.len[1], 250u);
    s = el_stats(&l);
    CHECK_EQ_U32(s.direct, 4u);
    CHECK_EQ_U32(s.deferred + s.qfull + s.drain_err, 0u);
    CHECK_EQ_U32(espnow_link_pending(&l), 0u);
    CHECK(espnow_link_pump(&l, g_now_us) == UINT64_MAX);

    tu_ctx("espnow_link: bad lengths never reach the raw send");
    raw.n = 0;
    CHECK_ERR(espnow_link_send(&l, MAC_X, NULL, 10), BR_ERR_ARG);
    CHECK_ERR(esend(&l, MAC_X, 1, 0), BR_ERR_ARG);
    CHECK_ERR(esend(&l, MAC_X, 1, ESPNOW_LINK_MAX_FRAME + 1u), BR_ERR_TOO_BIG);
    CHECK_EQ_U32(raw.n, 0u);
    CHECK_EQ_U32(el_stats(&l).bad_len, 3u);

    tu_ctx("espnow_link: single-radio arbiter (ESP-NOW only, TX in flight) - zero added latency");
    memset(&SIG_ESP, 0, sizeof SIG_ESP);
    SIG_ESP.busy = true;
    radio_arb_cfg_t c;
    radio_arb_default_cfg(&c);
    c.espnow_busy = fsig_busy;
    c.espnow_ctx = &SIG_ESP;
    CHECK(radio_arb_init(&a, &c));
    memset(&raw, 0, sizeof raw);
    CHECK(espnow_link_init(&l, fraw_send, &raw, &a));
    for (unsigned i = 0; i < 10u; i++) {
        uint64_t before = g_now_us;
        CHECK_ERR(esend(&l, (i & 1u) ? NULL : MAC_Y, (uint8_t)i, 60), BR_OK);
        CHECK_EQ_U32(raw.n, i + 1u);          /* sent inside send(), not later */
        CHECK(raw.at[i] == before);
        CHECK_EQ_U32(espnow_link_pending(&l), 0u);
        g_now_us += 300u;
    }
    s = el_stats(&l);
    CHECK_EQ_U32(s.direct, 10u);
    CHECK_EQ_U32(s.deferred, 0u);
    CHECK_EQ_U32(arb_stats(&a).hold_espnow + arb_stats(&a).timeout, 0u);

    tu_ctx("espnow_link: initialised before its (zeroed) arbiter - pass-through");
    memset(&a, 0, sizeof a);
    memset(&raw, 0, sizeof raw);
    CHECK(espnow_link_init(&l, fraw_send, &raw, &a));
    CHECK_ERR(esend(&l, MAC_X, 7, 40), BR_OK);
    CHECK_EQ_U32(raw.n, 1u);
}

static void test_espnow_defer_and_drain(void)
{
    espnow_link_t l;
    fraw_t raw;
    radio_arb_t a;
    espnow_link_stats_t s;

    tu_ctx("espnow_link: frames held while the nRF24 radio is busy");
    arb_bridge(&a, 0);
    memset(&raw, 0, sizeof raw);
    CHECK(espnow_link_init(&l, fraw_send, &raw, &a));
    SIG_NRF.busy = true;
    uint64_t t0 = g_now_us;
    CHECK_ERR(esend(&l, MAC_X, 0x11, 100), BR_OK);
    CHECK_ERR(esend(&l, NULL, 0x12, 30), BR_OK);
    CHECK_ERR(esend(&l, MAC_Y, 0x13, 250), BR_OK);
    CHECK_EQ_U32(raw.n, 0u);
    CHECK_EQ_U32(espnow_link_pending(&l), 3u);
    s = el_stats(&l);
    CHECK_EQ_U32(s.deferred, 3u);
    CHECK_EQ_U32(s.direct, 0u);
    CHECK_EQ_U32(arb_stats(&a).hold_espnow, 1u); /* one held head frame; the others queue behind it */

    tu_ctx("espnow_link: pump while still held - nothing sent, recheck deadline");
    g_now_us += 700u;
    CHECK(espnow_link_pump(&l, g_now_us) == g_now_us + RADIO_ARB_RECHECK_US);
    CHECK_EQ_U32(raw.n, 0u);

    tu_ctx("espnow_link: release - drained in order, addresses kept");
    SIG_NRF.busy = false;
    g_now_us += 300u;
    CHECK(espnow_link_pump(&l, g_now_us) == UINT64_MAX);
    CHECK_EQ_U32(raw.n, 3u);
    CHECK_EQ_U32(raw.tag[0], 0x11u);
    CHECK_EQ_U32(raw.tag[1], 0x12u);
    CHECK_EQ_U32(raw.tag[2], 0x13u);
    CHECK(!raw.bcast[0] && raw.bcast[1] && !raw.bcast[2]);
    CHECK_MEM(MAC_X, raw.addr[0], 6);
    CHECK_MEM(MAC_Y, raw.addr[2], 6);
    CHECK_EQ_U32(raw.len[0], 100u);
    CHECK_EQ_U32(raw.len[1], 30u);
    CHECK_EQ_U32(raw.len[2], 250u);
    CHECK(raw.at[0] == t0 + 1000u);
    s = el_stats(&l);
    CHECK_EQ_U32(s.drained, 3u);
    CHECK_EQ_U32(espnow_link_pending(&l), 0u);
    CHECK_EQ_U32(arb_stats(&a).timeout, 0u);

    tu_ctx("espnow_link: a new frame after release goes behind the queued ones (order kept)");
    SIG_NRF.busy = true;
    raw.n = 0;
    CHECK_ERR(esend(&l, MAC_X, 0x21, 20), BR_OK);
    CHECK_EQ_U32(raw.n, 0u);
    SIG_NRF.busy = false;
    CHECK_ERR(esend(&l, MAC_Y, 0x22, 20), BR_OK); /* drains 0x21 first, then sends 0x22 at once */
    CHECK_EQ_U32(raw.n, 2u);
    CHECK_EQ_U32(raw.tag[0], 0x21u);
    CHECK_EQ_U32(raw.tag[1], 0x22u);
    CHECK_EQ_U32(espnow_link_pending(&l), 0u);
    s = el_stats(&l);
    CHECK_EQ_U32(s.direct, 1u);
    CHECK_EQ_U32(s.drained, 4u);

    tu_ctx("espnow_link: FIFO full -> BR_ERR_QUEUE_FULL, counted, nothing sent");
    SIG_NRF.busy = true;
    raw.n = 0;
    for (unsigned i = 0; i < ESPNOW_LINK_TXQ; i++) {
        CHECK_ERR(esend(&l, MAC_X, (uint8_t)(0x30u + i), 40), BR_OK);
    }
    CHECK_ERR(esend(&l, MAC_X, 0x3F, 40), BR_ERR_QUEUE_FULL);
    CHECK_ERR(esend(&l, NULL, 0x3F, 40), BR_ERR_QUEUE_FULL);
    CHECK_EQ_U32(raw.n, 0u);
    CHECK_EQ_U32(espnow_link_pending(&l), ESPNOW_LINK_TXQ);
    CHECK_EQ_U32(el_stats(&l).qfull, 2u);

    tu_ctx("espnow_link: a queued frame the raw send refuses is dropped and counted, the rest go");
    SIG_NRF.busy = false;
    raw.result = BR_ERR_QUEUE_FULL;
    g_now_us += 1000u;
    (void)espnow_link_pump(&l, g_now_us);
    CHECK_EQ_U32(raw.n, ESPNOW_LINK_TXQ);
    CHECK_EQ_U32(el_stats(&l).drain_err, ESPNOW_LINK_TXQ);
    CHECK_EQ_U32(espnow_link_pending(&l), 0u);
    raw.result = BR_OK;
    for (unsigned i = 0; i < ESPNOW_LINK_TXQ; i++) {
        CHECK_EQ_U32(raw.tag[i], 0x30u + i);
    }
}

static void test_espnow_cap(void)
{
    espnow_link_t l;
    fraw_t raw;
    radio_arb_t a;

    tu_ctx("espnow_link: nRF24 busy for longer than the cap - held FIFO goes after cap_us");
    arb_bridge(&a, 0);
    memset(&raw, 0, sizeof raw);
    CHECK(espnow_link_init(&l, fraw_send, &raw, &a));
    SIG_NRF.busy = true;
    uint64_t t0 = g_now_us;
    CHECK_ERR(esend(&l, MAC_X, 0x41, 40), BR_OK);
    CHECK_ERR(esend(&l, MAC_X, 0x42, 40), BR_OK);
    uint64_t sent_at = 0;
    for (uint64_t t = t0; t <= t0 + 2u * RADIO_ARB_CAP_US_DEFAULT; t += RADIO_ARB_RECHECK_US) {
        g_now_us = t;
        (void)espnow_link_pump(&l, t);
        if (raw.n > 0u && sent_at == 0u) {
            sent_at = t;
        }
    }
    CHECK(sent_at == t0 + RADIO_ARB_CAP_US_DEFAULT);
    CHECK_EQ_U32(raw.n, 2u);
    radio_arb_stats_t s = arb_stats(&a);
    CHECK_EQ_U32(s.hold_espnow, 1u);
    CHECK_EQ_U32(s.timeout, 2u); /* both frames started while the nRF24 radio read busy */

    tu_ctx("espnow_link: while the busy signal is stale new frames go at once (each counted)");
    CHECK_ERR(esend(&l, MAC_X, 0x43, 40), BR_OK);
    CHECK_EQ_U32(raw.n, 3u);
    CHECK_EQ_U32(arb_stats(&a).timeout, 3u);
    SIG_NRF.busy = false;
    CHECK_ERR(esend(&l, MAC_X, 0x44, 40), BR_OK);
    SIG_NRF.busy = true;
    CHECK_ERR(esend(&l, MAC_X, 0x45, 40), BR_OK); /* signal trusted again after an idle read: held */
    CHECK_EQ_U32(raw.n, 4u);
    CHECK_EQ_U32(espnow_link_pending(&l), 1u);
    CHECK_EQ_U32(arb_stats(&a).hold_espnow, 2u);
}

/* ========================================================================= */
/* Fake ESB medium (two radios), after test_nrf24_link.c                     */
/* ========================================================================= */

#define RXQ_DEPTH 32u
#define AIR_US    250u   /* 32-byte payload + ACK at 2 Mbps, rounded up */
#define ARD_US    500u   /* C.5 auto retransmit delay */

typedef struct {
    uint8_t data[32];
    uint8_t len;
    bool    no_ack;
} fpayload_t;

typedef struct fmedium fmedium_t;
typedef struct fesp fesp_t;

typedef struct {
    fmedium_t *med;
    uint8_t    pipe_addr[2][5];
    uint8_t    tx_addr[5];
    bool       listening;
    uint8_t    status;
    fpayload_t tx;
    bool       tx_valid;
    bool       pending;
    unsigned   attempt;
    uint64_t   next_attempt_us;
    bool       delivered_once;
    fpayload_t rxq[RXQ_DEPTH];
    uint8_t    rxq_pipe[RXQ_DEPTH];
    unsigned   rxq_n;
    unsigned   starts;
    unsigned   frame_starts;        /* segment 0 starts */
    const fesp_t *colocated;        /* bridge: the ESP-NOW radio on the same board (instrument) */
    unsigned   overlap_starts;      /* segment 0 started while that ESP-NOW radio had TX in flight */
} fradio_t;

struct fmedium {
    fradio_t *r[2];
    tu_rng_t  rng;
    uint32_t  loss_pct;
    uint8_t   arc;
    bool      armed;
    unsigned  lost;                 /* packets or ACKs lost on the air */
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
    if (m->armed && pct > 0u && tu_rng_below(&m->rng, 100) < pct) {
        m->lost++;
        return true;
    }
    return false;
}

static uint32_t fesp_inflight(const fesp_t *e);

static bool fr_start_tx(void *radio)
{
    fradio_t *r = (fradio_t *)radio;
    med_resolve(r->med);
    if (r->listening || !r->tx_valid || r->pending) {
        return false;
    }
    r->starts++;
    if ((r->tx.data[2] & NRF24_SEG_IDX_MASK) == 0u) {
        r->frame_starts++;
        if (r->colocated != NULL && fesp_inflight(r->colocated) > 0u) {
            r->overlap_starts++;
        }
    }
    r->pending = true;
    r->attempt = 0;
    r->delivered_once = false;
    r->next_attempt_us = g_now_us + AIR_US;
    return true;
}

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
        r->attempt++;
        bool got_through = false;
        if (pipe >= 0 && !lose(m, m->loss_pct)) {
            got_through = true;
            if (!r->delivered_once) {
                fr_rx_push(peer, (uint8_t)pipe, p);
                r->delivered_once = true;
            }
        }
        if (p->no_ack || (got_through && !lose(m, m->loss_pct))) {
            r->status |= NRF24_ST_TX_DS;
            r->tx_valid = false;
            r->pending = false;
            return;
        }
        if (r->attempt > m->arc) {
            r->status |= NRF24_ST_MAX_RT;
            r->pending = false;
            return;
        }
        r->next_attempt_us += ARD_US;
    }
}

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
        st |= NRF24_ST_TX_FULL;
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

/* ========================================================================= */
/* Fake ESP-NOW medium (two radios)                                           */
/* ========================================================================= */

#define ESP_AIRQ   16u   /* driver buffers: more in flight -> BR_ERR_QUEUE_FULL (HAL_ERR_BUSY) */
#define ESP_EVQ    64u

typedef struct {
    uint8_t  dst[6];
    bool     bcast;
    uint16_t len;
    uint8_t  data[ESPNOW_LINK_MAX_FRAME];
    uint64_t end_us;
} fesp_frame_t;

typedef struct {
    uint8_t  kind;               /* 1 rx, 2 tx status */
    uint8_t  addr[6];
    bool     ok;
    uint16_t len;
    uint8_t  data[ESPNOW_LINK_MAX_FRAME];
} fesp_evt_t;

struct fesp {
    uint8_t       mac[6];
    fesp_t       *peer;
    fesp_frame_t  air[ESP_AIRQ];  /* accepted, in transmission order */
    unsigned      n_air;
    uint64_t      air_free_us;    /* when the last accepted frame leaves the air */
    fesp_evt_t    evq[ESP_EVQ];   /* the protocol task's queue (node_app g_q) */
    unsigned      ev_n;
    const fradio_t *colocated;    /* bridge: the nRF24 radio on the same board (instrument) */
    const nrf24_link_t *colocated_link;
    unsigned      starts;
    unsigned      overlap_starts; /* started while the colocated nRF24 radio read busy */
    unsigned      refused;
    uint32_t      phantom;        /* frames whose send callback never runs (wedged signal) */
};

/* hal_radio_tx_inflight() semantics: accepted, send callback not yet run */
static uint32_t fesp_inflight(const fesp_t *e)
{
    return e->n_air + e->phantom;
}

static bool fesp_busy(void *ctx, uint64_t now_us)
{
    (void)now_us;
    return fesp_inflight((const fesp_t *)ctx) > 0u;
}

static uint32_t esp_air_us(uint16_t len, bool bcast)
{
    /* 1 Mbps: preamble + MAC/vendor overhead + payload, plus the MAC ACK on unicast */
    return 200u + ((uint32_t)len + 40u) * 8u + (bcast ? 0u : 300u);
}

/* tr_send equivalent over the fake driver (node_app: hal_radio_send). */
static br_err_t fesp_raw_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    fesp_t *e = (fesp_t *)user;
    if (e->n_air >= ESP_AIRQ) {
        e->refused++;
        return BR_ERR_QUEUE_FULL;
    }
    e->starts++;
    if (e->colocated_link != NULL && nrf24_link_radio_busy(e->colocated_link, g_now_us)) {
        e->overlap_starts++;
    }
    fesp_frame_t *f = &e->air[e->n_air++];
    f->bcast = addr == NULL;
    memset(f->dst, 0xFF, 6);
    if (addr != NULL) {
        memcpy(f->dst, addr, 6);
    }
    f->len = len;
    memcpy(f->data, frame, len);
    uint64_t start = e->air_free_us > g_now_us ? e->air_free_us : g_now_us;
    f->end_us = start + esp_air_us(len, f->bcast);
    e->air_free_us = f->end_us;
    return BR_OK;
}

static void fesp_post(fesp_t *e, const fesp_evt_t *ev)
{
    if (e->ev_n < ESP_EVQ) {
        e->evq[e->ev_n++] = *ev;
    }
}

/* Frames whose air time ended: deliver, run the "send callback". */
static void fesp_resolve(fesp_t *e)
{
    while (e->n_air > 0u && e->air[0].end_us <= g_now_us) {
        const fesp_frame_t *f = &e->air[0];
        bool to_peer = e->peer != NULL && (f->bcast || memcmp(f->dst, e->peer->mac, 6) == 0);
        if (to_peer) {
            fesp_evt_t ev;
            ev.kind = 1;
            memcpy(ev.addr, e->mac, 6);
            ev.ok = true;
            ev.len = f->len;
            memcpy(ev.data, f->data, f->len);
            fesp_post(e->peer, &ev);
        }
        if (!f->bcast) {
            fesp_evt_t ev;
            ev.kind = 2;
            memcpy(ev.addr, f->dst, 6);
            ev.ok = to_peer;
            ev.len = 0;
            fesp_post(e, &ev);
        }
        memmove(&e->air[0], &e->air[1], (ESP_AIRQ - 1u) * sizeof e->air[0]);
        e->n_air--;
    }
}

/* ========================================================================= */
/* Part C: the nRF24 transmit gate on a lone adapter                          */
/* ========================================================================= */

static fmedium_t MED;

typedef struct {
    br_node_t    node;
    nrf24_link_t link;
    fradio_t     radio;
} lone_t;

static lone_t LONE;

static void lone_init(void)
{
    memset(&LONE, 0, sizeof LONE);
    memset(&MED, 0, sizeof MED);
    MED.arc = 15;
    MED.r[0] = &LONE.radio;
    LONE.radio.med = &MED;
    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = 0x0102;
    c.role = BR_ROLE_NODE;
    c.node_count = 2;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY;
    c.auth = true;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE;
    c.net_key_len = BRV_A6_K_SITE_LEN;
    c.txseq_start = 1;
    c.preseq_start = 1;
    nrf24_link_cfg_t lc;
    memset(&lc, 0, sizeof lc);
    lc.unit_id = 0x0102;
    nrf24_radio_ops_t ops = fr_ops(&LONE.radio);
    CHECK_ERR(nrf24_link_register(&LONE.link, &c, &lc, &ops), BR_OK);
    CHECK_ERR(br_node_init(&LONE.node, sizeof LONE.node, &c), BR_OK);
    CHECK(nrf24_link_start(&LONE.link));
}

static void lone_queue_bcast(void)
{
    uint8_t f[60];
    memset(f, 0x33, sizeof f);
    CHECK_ERR(nrf24_link_send(&LONE.link, NULL, f, sizeof f), BR_OK);
}

static void test_nrf_gate(void)
{
    radio_arb_t a;

    tu_ctx("nrf gate: setter arguments; init clears the gate");
    nrf24_link_set_tx_gate(NULL, radio_arb_nrf_may_start, &a);
    lone_init();
    CHECK(LONE.link.tx_gate == NULL);
    nrf24_link_set_tx_gate(&LONE.link, NULL, &a);
    CHECK(LONE.link.tx_gate_ctx == NULL);

    tu_ctx("nrf gate: no gate - frame starts on the first pump pass");
    lone_queue_bcast();
    (void)nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
    CHECK_EQ_U32(LONE.radio.frame_starts, 1u);
    unsigned base_starts = LONE.radio.starts;
    br_node_deinit(&LONE.node);

    tu_ctx("nrf gate: single-radio arbiter (nRF24 only) - same pump pass, nothing counted");
    lone_init();
    memset(&SIG_NRF, 0, sizeof SIG_NRF);
    radio_arb_cfg_t c;
    radio_arb_default_cfg(&c);
    c.nrf_busy = fsig_busy;
    c.nrf_ctx = &SIG_NRF;
    CHECK(radio_arb_init(&a, &c));
    nrf24_link_set_tx_gate(&LONE.link, radio_arb_nrf_may_start, &a);
    lone_queue_bcast();
    (void)nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
    CHECK_EQ_U32(LONE.radio.frame_starts, 1u);
    CHECK_EQ_U32(LONE.radio.starts, base_starts);
    CHECK_EQ_U32(arb_stats(&a).hold_nrf + arb_stats(&a).timeout, 0u);
    br_node_deinit(&LONE.node);

    tu_ctx("nrf gate: bridge, ESP-NOW TX in flight - frame held, deadline <= tx_poll_us, starts on release");
    lone_init();
    arb_bridge(&a, 0);
    nrf24_link_set_tx_gate(&LONE.link, radio_arb_nrf_may_start, &a);
    CHECK(LONE.link.tx_gate_ctx == &a);
    SIG_ESP.busy = true;
    lone_queue_bcast();
    for (unsigned i = 0; i < 6u; i++) {
        uint64_t d = nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
        CHECK(d <= g_now_us + NRF24_LINK_TX_POLL_US);
        CHECK(!nrf24_link_radio_busy(&LONE.link, g_now_us)); /* held frames do not make the nRF24 side busy */
        g_now_us += NRF24_LINK_TX_POLL_US;
    }
    CHECK_EQ_U32(LONE.radio.frame_starts, 0u);
    CHECK_EQ_U32(nrf24_link_tx_pending(&LONE.link), 1u);
    CHECK(LONE.radio.listening);
    CHECK_EQ_U32(arb_stats(&a).hold_nrf, 1u);
    SIG_ESP.busy = false;
    (void)nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
    CHECK_EQ_U32(LONE.radio.frame_starts, 1u);
    CHECK(nrf24_link_radio_busy(&LONE.link, g_now_us));
    CHECK_EQ_U32(arb_stats(&a).timeout, 0u);

    tu_ctx("nrf gate: a frame already being sent is never gated between segments");
    SIG_ESP.busy = true;
    for (unsigned i = 0; i < 40u && nrf24_link_tx_pending(&LONE.link) > 0u; i++) {
        g_now_us += NRF24_LINK_TX_POLL_US;
        (void)nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
    }
    CHECK_EQ_U32(nrf24_link_tx_pending(&LONE.link), 0u);
    CHECK_EQ_U32(LONE.radio.starts, 3u); /* 60 bytes = 3 segments, all sent */
    CHECK_EQ_U32(arb_stats(&a).hold_nrf, 1u);

    tu_ctx("nrf gate: ESP-NOW busy past the cap - starts after cap_us, arb_timeout counted");
    g_now_us += 10000u; /* past the guard */
    lone_queue_bcast();
    uint64_t t0 = g_now_us;
    uint64_t started = 0;
    for (unsigned i = 0; i < 200u && started == 0u; i++) {
        (void)nrf24_link_pump(&LONE.link, &LONE.node, g_now_us);
        if (LONE.radio.frame_starts == 2u) {
            started = g_now_us;
        }
        g_now_us += NRF24_LINK_TX_POLL_US;
    }
    CHECK(started == t0 + RADIO_ARB_CAP_US_DEFAULT);
    CHECK_EQ_U32(arb_stats(&a).hold_nrf, 2u);
    CHECK_EQ_U32(arb_stats(&a).timeout, 1u);
    br_node_deinit(&LONE.node);
    nrf24_link_set_tx_gate(&LONE.link, NULL, NULL);
}

/* ========================================================================= */
/* Part D: end to end A (nRF24) -> B (bridge) -> C (ESP-NOW)                  */
/* ========================================================================= */

#define SENDER_ID 0x0101u
#define BRIDGE_ID 0x0102u
#define PROBE_ID  0x0103u
#define GROUP_ID  0xFF10u
#define PRESSES   20u
#define STEP_US   250u

typedef struct {
    const char   *name;
    br_node_t     node;
    bool          has_nrf;
    bool          has_esp;
    uint8_t       l_nrf;
    uint8_t       l_esp;
    nrf24_link_t  nlink;
    fradio_t      radio;
    espnow_link_t elink;
    fesp_t        esp;
    radio_arb_t   arb;
    br_session_t  sess;
    bool          streaming;
    bool          bound;
    unsigned      acked;
    unsigned      ones;
    unsigned      zeros;
    unsigned      gap_seqs;
    unsigned      closed;
    unsigned      bad_hops;
} ep_t;

static ep_t EA;
static ep_t EB;
static ep_t EC;

static void cb_acked(void *user, br_session_t s, uint16_t seq)
{
    (void)s;
    (void)seq;
    ((ep_t *)user)->acked++;
}

static void cb_state(void *user, br_session_t s, uint8_t old_state, uint8_t new_state)
{
    (void)old_state;
    if ((s & BR_SESSION_PROBE) == 0u && new_state == BR_SND_STREAMING) {
        ((ep_t *)user)->streaming = true;
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
    CHECK_EQ_U32(meta->src_id, SENDER_ID);
    if (meta->hops != 2u) {
        e->bad_hops++; /* A -> B -> C is two links (N25) */
    }
    for (uint8_t i = 0; i < meta->hdr.n_samples && sz > 0u; i++) {
        size_t off = (size_t)i * sz;
        if (off + sz > samples_len) {
            break;
        }
        br_value_t vals[BR_MAX_CHANNELS];
        if (br_sample_decode(mode, samples + off, sz, vals) == BR_OK) {
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
    (void)first;
    if ((s & BR_SESSION_PROBE) == 0u) {
        ((ep_t *)user)->gap_seqs += count;
    }
}

static void cb_closed(void *user, br_session_t s, uint8_t reason)
{
    (void)s;
    (void)reason;
    ((ep_t *)user)->closed++;
}

/* radio_arb_hal_nrf24_busy() equivalent */
static bool nrf_busy_q(void *ctx, uint64_t now_us)
{
    return nrf24_link_radio_busy((const nrf24_link_t *)ctx, now_us);
}

static void esp_fill_transport(ep_t *e, br_transport_t *tr)
{
    /* node_app node_init_from() "espnow" block, with the deferral wrapper as send */
    tr->name = "espnow";
    tr->link_class = BR_LINK_PACKET;
    tr->max_frame = BR_MAX_FRAME_MESH;
    tr->rs_nsym = BR_RS_NSYM_PACKET;
    tr->can_broadcast = true;
    tr->mac_retry = true;
    tr->edge_only = false;
    tr->link_cost = 1;
    tr->addr_len = ESPNOW_LINK_ADDR_LEN;
    tr->send = espnow_link_send;
    tr->user = &e->elink;
}

/*
 * arbitrate false: the bridge's ESP-NOW wrapper gets no arbiter and the
 * nRF24 pump no gate (the control run of the instrument).
 */
static void ep_init(ep_t *e, const char *name, uint16_t unit, bool nrf, bool esp, bool probe, bool arbitrate)
{
    memset(e, 0, sizeof *e);
    e->name = name;
    e->sess = BR_SESSION_NONE;
    e->has_nrf = nrf;
    e->has_esp = esp;
    e->radio.med = &MED;
    e->esp.mac[0] = 0x02;
    e->esp.mac[4] = (uint8_t)(unit >> 8);
    e->esp.mac[5] = (uint8_t)(unit & 0xFFu);

    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = unit;
    c.role = BR_ROLE_NODE;
    c.node_count = 3;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY; /* node_app kCapsBase */
    if (probe) {
        c.caps = (uint16_t)(c.caps | BR_CAP_MULTI);
        c.groups[0] = GROUP_ID;
        c.n_groups = 1;
    }
    c.auth = true;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE;
    c.net_key_len = BRV_A6_K_SITE_LEN;
    c.txseq_start = 1;
    c.preseq_start = 1;
    c.app.user = e;
    c.app.on_bound = cb_bound;
    c.app.on_samples = cb_samples;
    c.app.on_gap = cb_gap;
    c.app.on_acked = cb_acked;
    c.app.on_closed = cb_closed;
    c.app.on_state = cb_state;
    /* registration order as node_app: espnow first, then nrf24 */
    if (esp) {
        e->l_esp = c.n_transports++;
        esp_fill_transport(e, &c.transports[e->l_esp]);
        CHECK(espnow_link_init(&e->elink, fesp_raw_send, &e->esp, arbitrate ? &e->arb : NULL));
    }
    if (nrf) {
        nrf24_link_cfg_t lc;
        memset(&lc, 0, sizeof lc);
        lc.unit_id = unit;
        nrf24_radio_ops_t ops = fr_ops(&e->radio);
        CHECK_ERR(nrf24_link_register(&e->nlink, &c, &lc, &ops), BR_OK);
        e->l_nrf = e->nlink.link;
    }
    /* radio_arb_setup_board() equivalent with the fakes */
    radio_arb_cfg_t ac;
    radio_arb_default_cfg(&ac);
    if (esp) {
        ac.espnow_busy = fesp_busy;
        ac.espnow_ctx = &e->esp;
    }
    if (nrf) {
        ac.nrf_busy = nrf_busy_q;
        ac.nrf_ctx = &e->nlink;
    }
    CHECK(radio_arb_init(&e->arb, &ac));
    CHECK_ERR(br_node_init(&e->node, sizeof e->node, &c), BR_OK);
    if (nrf) {
        CHECK(nrf24_link_start(&e->nlink));
    }
}

/* Bridge wiring (after ep_init): both busy queries, the gate, the instruments. */
static void bridge_wire(ep_t *e, bool arbitrate)
{
    radio_arb_cfg_t ac;
    radio_arb_default_cfg(&ac);
    ac.espnow_busy = fesp_busy;
    ac.espnow_ctx = &e->esp;
    ac.nrf_busy = nrf_busy_q;
    ac.nrf_ctx = &e->nlink;
    CHECK(radio_arb_init(&e->arb, &ac));
    CHECK(radio_arb_is_bridge(&e->arb));
    if (arbitrate) {
        nrf24_link_set_tx_gate(&e->nlink, radio_arb_nrf_may_start, &e->arb);
    }
    e->radio.colocated = &e->esp;
    e->esp.colocated = &e->radio;
    e->esp.colocated_link = &e->nlink;
}

/* One protocol-task pass, in node_app br_task order. */
static void ep_pass(ep_t *e)
{
    /* drain the event queue (kEvtRx / kEvtTxStatus) */
    unsigned n = e->esp.ev_n;
    for (unsigned i = 0; i < n; i++) {
        const fesp_evt_t *ev = &e->esp.evq[i];
        if (ev->kind == 1u) {
            const br_transport_t *tr = &e->node.cfg.transports[e->l_esp];
            if (br_transport_admit(tr, ev->data, ev->len)) {
                br_rx_meta_t m;
                memset(&m, 0, sizeof m);
                memcpy(m.addr, ev->addr, 6);
                m.addr_len = 6;
                m.rssi = -50;
                (void)br_node_rx(&e->node, ev->data, ev->len, e->l_esp, &m, NULL);
            }
        } else {
            (void)br_node_tx_status(&e->node, e->l_esp, ev->addr, 6, ev->ok);
        }
    }
    memmove(&e->esp.evq[0], &e->esp.evq[n], (e->esp.ev_n - n) * sizeof e->esp.evq[0]);
    e->esp.ev_n -= n;
    if (e->has_nrf) {
        (void)nrf24_link_pump(&e->nlink, &e->node, g_now_us);
    }
    if (e->has_esp) {
        (void)espnow_link_pump(&e->elink, g_now_us);
    }
    uint64_t nd = 0;
    CHECK_ERR(br_node_tick(&e->node, g_now_us, &nd), BR_OK);
    if (e->has_nrf) {
        (void)nrf24_link_pump(&e->nlink, &e->node, g_now_us);
    }
    if (e->has_esp) {
        (void)espnow_link_pump(&e->elink, g_now_us);
    }
}

static void step(void)
{
    g_now_us += STEP_US;
    med_resolve(&MED);
    fesp_resolve(&EB.esp);
    fesp_resolve(&EC.esp);
    ep_pass(&EA);
    ep_pass(&EB);
    ep_pass(&EC);
}

static bool run_until(bool (*cond)(void), uint32_t max_steps)
{
    for (uint32_t i = 0; i < max_steps; i++) {
        if (cond()) {
            return true;
        }
        step();
    }
    return cond();
}

static unsigned g_want_acked;
static bool cond_streaming(void) { return EA.streaming; }
static bool cond_acked(void) { return EA.acked + EA.gap_seqs >= g_want_acked; }

typedef struct {
    radio_arb_stats_t   arb;
    espnow_link_stats_t eb;
    espnow_link_stats_t ec;
    nrf24_link_stats_t  na;
    nrf24_link_stats_t  nb;
    unsigned            overlap_e;   /* ESP-NOW starts at B while the nRF24 radio read busy */
    unsigned            overlap_n;   /* nRF24 frame starts at B while ESP-NOW TX was in flight */
} e2e_t;

static e2e_t run_e2e(const char *what, bool arbitrate, uint32_t nrf_loss_pct, uint64_t seed, bool wedge)
{
    e2e_t r;
    memset(&r, 0, sizeof r);
    tu_ctx(what);
    memset(&MED, 0, sizeof MED);
    tu_rng_seed(&MED.rng, seed * 7u + 3u);
    MED.arc = 15;
    MED.loss_pct = nrf_loss_pct;
    tu_rng_seed(&g_plat_rng, seed ^ 0xA5A5A5A5u);
    ep_init(&EA, "A", SENDER_ID, true, false, false, arbitrate);
    ep_init(&EB, "B", BRIDGE_ID, true, true, false, arbitrate);
    ep_init(&EC, "C", PROBE_ID, false, true, true, arbitrate);
    bridge_wire(&EB, arbitrate);
    EB.esp.phantom = wedge ? 1u : 0u;
    /* A: nRF24-only board with the gate installed on a single-radio arbiter (a no-op) */
    nrf24_link_set_tx_gate(&EA.nlink, radio_arb_nrf_may_start, &EA.arb);
    CHECK(!radio_arb_is_bridge(&EA.arb));
    CHECK(!radio_arb_is_bridge(&EC.arb));
    MED.r[0] = &EA.radio;
    MED.r[1] = &EB.radio;
    EB.esp.peer = &EC.esp;
    EC.esp.peer = &EB.esp;
    MED.armed = nrf_loss_pct > 0u;

    CHECK_ERR(br_node_seek(&EA.node, GROUP_ID, &EA.sess), BR_OK);
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

    bool up = run_until(cond_streaming, 240000);
    CHECK_MSG(up, "sender never reached STREAMING through the bridge");
    CHECK(EC.bound);
    unsigned ok = 0;
    for (unsigned i = 0; up && i < PRESSES; i++) {
        br_value_t v;
        v.lines = 1;
        CHECK_ERR(br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true), BR_OK);
        v.lines = 0;
        CHECK_ERR(br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true), BR_OK);
        g_want_acked = 2u * (i + 1u);
        if (run_until(cond_acked, 120000)) {
            ok++;
        }
        for (unsigned k = 0; k < 200u; k++) {
            step(); /* 50 ms between presses */
        }
    }
    for (unsigned k = 0; k < 8000u; k++) {
        step(); /* 2 s: > REORDER_MS, queues quiet */
    }
    CHECK_EQ_U32(ok, PRESSES);
    CHECK_EQ_U32(EA.acked, 2u * PRESSES);
    CHECK_EQ_U32(EA.gap_seqs, 0u);
    CHECK_EQ_U32(EC.ones, PRESSES);
    CHECK_EQ_U32(EC.zeros, PRESSES);
    CHECK_EQ_U32(EC.bad_hops, 0u);
    CHECK_EQ_U32(EA.closed + EC.closed, 0u);
    uint8_t st = 0;
    CHECK_ERR(br_node_session_state(&EA.node, EA.sess, &st), BR_OK);
    CHECK_EQ_U32(st, BR_SND_STREAMING);
    CHECK_EQ_U32(espnow_link_pending(&EB.elink), 0u);
    CHECK_EQ_U32(nrf24_link_tx_pending(&EB.nlink), 0u);

    radio_arb_get_stats(&EB.arb, &r.arb);
    espnow_link_get_stats(&EB.elink, &r.eb);
    espnow_link_get_stats(&EC.elink, &r.ec);
    nrf24_link_get_stats(&EA.nlink, &r.na);
    nrf24_link_get_stats(&EB.nlink, &r.nb);
    r.overlap_e = EB.esp.overlap_starts;
    r.overlap_n = EB.radio.overlap_starts;

    /* single-radio boards: zero added latency, nothing counted */
    radio_arb_stats_t sa;
    radio_arb_stats_t sc;
    radio_arb_get_stats(&EA.arb, &sa);
    radio_arb_get_stats(&EC.arb, &sc);
    CHECK_EQ_U32(sa.hold_espnow + sa.hold_nrf + sa.timeout, 0u);
    CHECK_EQ_U32(sc.hold_espnow + sc.hold_nrf + sc.timeout, 0u);
    CHECK_EQ_U32(r.ec.deferred + r.ec.qfull + r.ec.drain_err, 0u);
    CHECK_EQ_U32(r.ec.direct, EC.esp.starts + EC.esp.refused);
    CHECK(r.ec.direct > 0u);

    printf("  %-46s t=%5.1fs B: esp starts %4u nrf frame starts %4u overlap e/n %u/%u "
           "arb_hold_e %3u arb_hold_n %3u arb_to %u arb_defer %3u qfull %u derr %u | nrf lost %u maxrt %u\n",
           what, (double)g_now_us / 1e6, EB.esp.starts, EB.radio.frame_starts, r.overlap_e, r.overlap_n,
           r.arb.hold_espnow, r.arb.hold_nrf, r.arb.timeout, r.eb.deferred, r.eb.qfull, r.eb.drain_err,
           MED.lost, r.na.tx_max_rt + r.nb.tx_max_rt);
    br_node_deinit(&EA.node);
    br_node_deinit(&EB.node);
    br_node_deinit(&EC.node);
    return r;
}

static void test_e2e_bridge(void)
{
    e2e_t r = run_e2e("e2e bridge, arbitration on, clean", true, 0, 1, false);
    CHECK_EQ_U32(r.arb.timeout, 0u);
    CHECK_EQ_U32(r.overlap_e + r.overlap_n, 0u);      /* never two TX windows at once (no cap hit) */
    CHECK(r.overlap_e + r.overlap_n <= r.arb.timeout);
    CHECK(r.arb.hold_espnow > 0u);                     /* the nRF24 -> ESP-NOW forward is held */
    CHECK(r.arb.hold_nrf > 0u);                        /* and the other direction was exercised */
    CHECK(r.eb.deferred > 0u);
    CHECK_EQ_U32(r.eb.qfull + r.eb.drain_err, 0u);
    CHECK_EQ_U32(EB.esp.refused, 0u);

    for (uint64_t seed = 2; seed < 5u; seed++) {
        char what[64];
        snprintf(what, sizeof what, "e2e bridge, arbitration on, nRF24 5%% loss s%u", (unsigned)seed);
        r = run_e2e(what, true, 5, seed, false);
        CHECK(MED.lost > 0u); /* the loss did happen (ESB retries hide it from the frame counters) */
        CHECK(r.overlap_e + r.overlap_n <= r.arb.timeout);
        CHECK_EQ_U32(r.arb.timeout, 0u);
        CHECK_EQ_U32(r.eb.qfull + r.eb.drain_err, 0u);
    }
}

static void test_e2e_control(void)
{
    e2e_t r = run_e2e("e2e bridge, arbitration OFF (instrument check)", false, 0, 1, false);
    CHECK(r.overlap_e + r.overlap_n > 0u); /* the instrument sees overlaps when nothing prevents them */
    CHECK_EQ_U32(r.eb.deferred, 0u);
    CHECK_EQ_U32(r.arb.hold_nrf, 0u);
}

/*
 * A send callback that never runs (dropped by a wedged driver) pins the
 * ESP-NOW in-flight count at >= 1 for the whole run: the first nRF24 frame
 * waits one cap, then the signal is stale and later frames go at once, each
 * counted in arb_timeout. Delivery is unaffected.
 */
static void test_e2e_wedged_signal(void)
{
    e2e_t r = run_e2e("e2e bridge, ESP-NOW signal wedged busy", true, 0, 1, true);
    CHECK(r.arb.timeout > 0u);
    CHECK(r.overlap_e + r.overlap_n <= r.arb.timeout);
    CHECK_EQ_U32(r.overlap_e, 0u);                /* the ESP-NOW side still waits for the nRF24 radio */
    CHECK_EQ_U32(r.overlap_n, r.arb.timeout);     /* every nRF24 start counted */
    CHECK_EQ_U32(r.arb.hold_nrf, 1u);             /* one cap paid, not one per frame */
    CHECK_EQ_U32(r.eb.qfull + r.eb.drain_err, 0u);
}

/* ========================================================================= */

int main(void)
{
    const br_platform_t plat = {t_now, t_random, t_log, NULL};
    tu_rng_seed(&g_plat_rng, 1);
    CHECK_ERR(br_platform_set(&plat), BR_OK);

    /* Part A */
    test_arb_args_and_noop();
    test_arb_hold_release();
    test_arb_cap_and_stale();
    /* Part B */
    test_espnow_passthrough();
    test_espnow_defer_and_drain();
    test_espnow_cap();
    /* Part C */
    test_nrf_gate();
    /* Part D */
    test_e2e_bridge();
    test_e2e_wedged_signal();
    test_e2e_control();
    return tu_summary("test_radio_arb");
}
