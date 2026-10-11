// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_sim_self.c - self-test of the brsim medium, clock and trace.
 *
 * br_node is still stubs in phase 1b step 1, so every medium check below
 * runs with test-double endpoints (brsim_add_endpoint). The last section
 * only checks the stub contract the simulator relies on.
 *
 * Checks:
 *  1. loss rate within tolerance over 10k frames (binomial 4 sigma);
 *  2. identical traces for identical seeds, different for another seed;
 *  3. connectivity matrix enforced (A-B, B-C: nothing ever reaches A<->C);
 *  4. bench allowlist (SPEC-NOTES N22) applied before the endpoint;
 *  5. no-reorder links keep order, reorder links do reorder;
 *  6. endpoint timers fire at the requested virtual times;
 *  7. unicast delivery reports (ESP-NOW style tx_status);
 *  8. br_node stub contract and the br_session.h timer formulas.
 */

#include "brsim/brsim.h"
#include "test_util.h"

static brsim_t g_sim; /* ~1.2 MB: static */

/* ------------------------------------------------------------------------- */
/* Test-double endpoint                                                       */
/* ------------------------------------------------------------------------- */

#define EP_MAX_TICKS 16u

typedef struct {
    uint32_t rx_total;
    uint32_t rx_from[BRSIM_MAX_NODES];  /* by sender node index (carrier address) */
    uint32_t inversions;                /* seq lower than the previous one seen */
    uint32_t last_seq;
    bool     have_seq;
    uint32_t status_ok, status_fail;
    uint64_t tick_at[EP_MAX_TICKS];     /* requested deadlines (0 = none) */
    uint32_t n_tick_req;
    uint32_t tick_next_i;
    uint64_t tick_seen[EP_MAX_TICKS];
    uint32_t n_tick_seen;
} ep_t;

static void ep_rx(brsim_t *sim, uint8_t node, void *user, const uint8_t *frame, size_t len,
                  const br_rx_meta_t *meta, char *verdict, size_t verdict_cap)
{
    (void)node;
    ep_t *ep = (ep_t *)user;
    ep->rx_total++;
    uint16_t from_id = (uint16_t)((meta->addr[4] << 8) | meta->addr[5]);
    uint8_t from = brsim_find(sim, from_id);
    if (from < BRSIM_MAX_NODES) {
        ep->rx_from[from]++;
    }
    if (len >= BR_HDR_LEN) {
        uint32_t seq = tu_get16(frame + BR_OFF_SEQ);
        if (ep->have_seq && seq < ep->last_seq) {
            ep->inversions++;
        }
        ep->last_seq = seq;
        ep->have_seq = true;
    }
    snprintf(verdict, verdict_cap, "rx");
}

static uint64_t ep_tick(brsim_t *sim, uint8_t node, void *user, uint64_t now_us)
{
    (void)sim;
    (void)node;
    ep_t *ep = (ep_t *)user;
    while (ep->tick_next_i < ep->n_tick_req && ep->tick_at[ep->tick_next_i] <= now_us) {
        if (ep->n_tick_seen < EP_MAX_TICKS) {
            ep->tick_seen[ep->n_tick_seen++] = now_us;
        }
        ep->tick_next_i++;
    }
    return ep->tick_next_i < ep->n_tick_req ? ep->tick_at[ep->tick_next_i] : BRSIM_NEVER;
}

static void ep_status(brsim_t *sim, uint8_t node, void *user, const uint8_t *addr, uint8_t addr_len,
                      bool delivered)
{
    (void)sim;
    (void)node;
    (void)addr;
    (void)addr_len;
    ep_t *ep = (ep_t *)user;
    if (delivered) {
        ep->status_ok++;
    } else {
        ep->status_fail++;
    }
}

static const brsim_endpoint_ops_t k_ops = { ep_rx, ep_tick, ep_status };

/* Build a 21-byte header-only frame: DATA, src, dst FF10, prev_hop, seq. */
static size_t mk_frame(uint8_t *buf, uint16_t src, uint16_t prev_hop, uint16_t seq)
{
    br_hdr_t h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    h.type = BR_TYPE_DATA;
    h.src_id = src;
    h.dst_id = 0xFF10u;
    h.prev_hop = prev_hop;
    h.next_hop = BR_ID_FLOOD;
    h.ttl = 4;
    h.hop_seq = seq;
    h.session_id = 1;
    h.seq = seq;
    size_t w = 0;
    if (br_hdr_encode(&h, buf, 64, &w) != BR_OK) {
        return 0;
    }
    buf[w] = 0xAA;
    buf[w + 1u] = 0x55;
    return w + 2u;
}

/* Periodic sender driven by brsim_schedule. */
typedef struct {
    uint8_t  from;
    uint16_t prev_hop;           /* written into the frame header */
    const uint8_t *addr;         /* NULL = broadcast */
    uint32_t left;
    uint32_t sent;
    uint32_t period_us;
} pump_t;

static void pump_fn(brsim_t *sim, void *arg)
{
    pump_t *p = (pump_t *)arg;
    uint8_t f[64];
    size_t n = mk_frame(f, sim->nodes[p->from].unit_id, p->prev_hop, (uint16_t)p->sent);
    CHECK_ERR(brsim_send(sim, p->from, p->addr, f, n), BR_OK);
    p->sent++;
    if (--p->left > 0) {
        CHECK_ERR(brsim_schedule(sim, brsim_now(sim) + p->period_us, pump_fn, p), BR_OK);
    }
}

static void start_pump(pump_t *p, uint8_t from, uint16_t prev_hop, const uint8_t *addr,
                       uint32_t count, uint32_t period_us)
{
    memset(p, 0, sizeof *p);
    p->from = from;
    p->prev_hop = prev_hop;
    p->addr = addr;
    p->left = count;
    p->period_us = period_us;
    CHECK_ERR(brsim_schedule(&g_sim, brsim_now(&g_sim), pump_fn, p), BR_OK);
}

static uint8_t add_ep(uint16_t unit, ep_t *ep)
{
    uint8_t idx = BRSIM_NO_NODE;
    memset(ep, 0, sizeof *ep);
    CHECK_ERR(brsim_add_endpoint(&g_sim, unit, &k_ops, ep, &idx), BR_OK);
    return idx;
}

static brsim_link_t mk_link(uint32_t loss_ppm, uint32_t dmin, uint32_t dmax, bool reorder)
{
    brsim_link_t l;
    memset(&l, 0, sizeof l);
    l.connected = true;
    l.loss_ppm = loss_ppm;
    l.delay_min_us = dmin;
    l.delay_max_us = dmax;
    l.reorder = reorder;
    return l;
}

/* ------------------------------------------------------------------------- */
/* 1. Loss rate                                                               */
/* ------------------------------------------------------------------------- */

static void test_loss_rate(void)
{
    tu_ctx("loss_rate");
    static ep_t a, b;
    static pump_t pump;
    CHECK_ERR(brsim_init(&g_sim, 0x5EED0001u), BR_OK);
    uint8_t ia = add_ep(0x0101u, &a);
    uint8_t ib = add_ep(0x0102u, &b);
    brsim_link_t l = mk_link(100000u, 1000u, 3000u, true); /* 10 % */
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    const uint32_t n = 10000u;
    start_pump(&pump, ia, 0x0101u, NULL, n, 100u);
    CHECK_ERR(brsim_run_for(&g_sim, 5000000u), BR_OK);

    brsim_link_stats_t st;
    CHECK_ERR(brsim_link_stats(&g_sim, ia, ib, &st), BR_OK);
    CHECK_EQ_U32(pump.sent, n);
    CHECK_EQ_U32(st.sent, n);
    CHECK_EQ_U32(st.lost + st.delivered, n);
    CHECK_EQ_U32(b.rx_total, st.delivered);
    /* Binomial: mean 1000 lost, sigma = sqrt(10000 x 0.1 x 0.9) = 30; 4 sigma = 120. */
    CHECK_MSG(st.lost >= 880u && st.lost <= 1120u, "loss outside 10 % +/- 4 sigma");
    CHECK_EQ_U32(a.rx_total, 0u); /* B -> A has no link */
    printf("loss_rate: %" PRIu32 " of %" PRIu32 " lost (expected 1000 +/- 120)\n", st.lost, n);

    /* 0 % and 100 % edges. */
    CHECK_ERR(brsim_init(&g_sim, 7u), BR_OK);
    ia = add_ep(0x0101u, &a);
    ib = add_ep(0x0102u, &b);
    l = mk_link(0u, 10u, 10u, false);
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    start_pump(&pump, ia, 0x0101u, NULL, 500u, 50u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(b.rx_total, 500u);
    l.loss_ppm = 1000000u;
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    start_pump(&pump, ia, 0x0101u, NULL, 500u, 50u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(b.rx_total, 500u);
}

/* ------------------------------------------------------------------------- */
/* 2. Determinism                                                             */
/* ------------------------------------------------------------------------- */

static uint64_t run_seeded(uint64_t seed, uint32_t *lines_out, uint32_t *rx_out)
{
    static ep_t e[3];
    static pump_t p0, p1, p2;
    static uint8_t addr_c[BRSIM_ADDR_LEN];
    CHECK_ERR(brsim_init(&g_sim, seed), BR_OK);
    uint8_t i0 = add_ep(0x0101u, &e[0]);
    uint8_t i1 = add_ep(0x0102u, &e[1]);
    uint8_t i2 = add_ep(0x0103u, &e[2]);
    brsim_link_t l = mk_link(200000u, 100u, 5000u, true);
    CHECK_ERR(brsim_set_link_sym(&g_sim, i0, i1, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, i1, i2, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, i0, i2, &l), BR_OK);
    CHECK_ERR(brsim_addr(&g_sim, i2, addr_c), BR_OK);
    CHECK_ERR(brsim_set_mac_attempts(&g_sim, 2u), BR_OK);
    start_pump(&p0, i0, 0x0101u, NULL, 300u, 700u);
    start_pump(&p1, i1, 0x0102u, NULL, 300u, 900u);
    start_pump(&p2, i0, 0x0101u, addr_c, 300u, 1100u);
    CHECK_ERR(brsim_run_for(&g_sim, 2000000u), BR_OK);
    *rx_out = e[0].rx_total + e[1].rx_total + e[2].rx_total;
    return brsim_trace_hash(&g_sim, lines_out);
}

static void test_determinism(void)
{
    tu_ctx("determinism");
    uint32_t l1 = 0, l2 = 0, l3 = 0, r1 = 0, r2 = 0, r3 = 0;
    uint64_t h1 = run_seeded(42u, &l1, &r1);
    uint64_t h2 = run_seeded(42u, &l2, &r2);
    uint64_t h3 = run_seeded(43u, &l3, &r3);
    CHECK(h1 == h2);
    CHECK_EQ_U32(l1, l2);
    CHECK_EQ_U32(r1, r2);
    CHECK(l1 > 1000u);
    CHECK_MSG(h1 != h3, "different seed should give a different trace");
    printf("determinism: seed 42 -> %" PRIu32 " lines, hash %016" PRIx64 " (twice); seed 43 -> %016" PRIx64 "\n",
           l1, h1, h3);
}

/* ------------------------------------------------------------------------- */
/* 3. Connectivity matrix                                                     */
/* ------------------------------------------------------------------------- */

static void test_connectivity(void)
{
    tu_ctx("connectivity");
    static ep_t a, b, c;
    static pump_t pa, pc, pu;
    static uint8_t addr_c[BRSIM_ADDR_LEN];
    CHECK_ERR(brsim_init(&g_sim, 99u), BR_OK);
    uint8_t ia = add_ep(0x0101u, &a);
    uint8_t ib = add_ep(0x0102u, &b);
    uint8_t ic = add_ep(0x0103u, &c);
    brsim_link_t l = mk_link(0u, 500u, 1500u, true);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ia, ib, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ib, ic, &l), BR_OK);
    CHECK_ERR(brsim_addr(&g_sim, ic, addr_c), BR_OK);

    start_pump(&pa, ia, 0x0101u, NULL, 10000u, 100u);
    start_pump(&pc, ic, 0x0103u, NULL, 1000u, 1000u);
    start_pump(&pu, ia, 0x0101u, addr_c, 100u, 1000u); /* unicast A -> C: no link */
    CHECK_ERR(brsim_run_for(&g_sim, 3000000u), BR_OK);

    CHECK_EQ_U32(c.rx_from[ia], 0u);
    CHECK_EQ_U32(a.rx_from[ic], 0u);
    CHECK_EQ_U32(b.rx_from[ia], 10000u);
    CHECK_EQ_U32(b.rx_from[ic], 1000u);
    CHECK_EQ_U32(c.rx_total, 0u);
    CHECK_EQ_U32(a.rx_total, 0u);
    CHECK_EQ_U32(a.status_fail, 100u);
    CHECK_EQ_U32(a.status_ok, 0u);
    brsim_link_stats_t st;
    CHECK_ERR(brsim_link_stats(&g_sim, ia, ic, &st), BR_OK);
    CHECK_EQ_U32(st.sent, 0u);
    CHECK_EQ_U32(st.delivered, 0u);
}

/* ------------------------------------------------------------------------- */
/* 4. Bench allowlist (N22)                                                   */
/* ------------------------------------------------------------------------- */

static void test_allowlist(void)
{
    tu_ctx("allowlist");
#ifndef BR_FIELD_BUILD
    /* Direct unit checks of the adapter filter. */
    uint8_t f[64];
    size_t n = mk_frame(f, 0x0101u, 0x0101u, 1u);
    br_bench_allowlist_t al;
    memset(&al, 0, sizeof al);
    CHECK(br_bench_allowlist_admit(NULL, f, n));
    CHECK(br_bench_allowlist_admit(&al, f, n));           /* disabled */
    al.enabled = true;
    CHECK(!br_bench_allowlist_admit(&al, f, n));          /* enabled, empty */
    al.ids[0] = 0x0102u;
    al.n = 1;
    CHECK(!br_bench_allowlist_admit(&al, f, n));
    al.ids[1] = 0x0101u;
    al.n = 2;
    CHECK(br_bench_allowlist_admit(&al, f, n));
    CHECK(!br_bench_allowlist_admit(&al, f, 7u));         /* too short for prev_hop */
    CHECK(br_bench_allowlist_admit(&al, f, 8u));
    CHECK(!br_bench_allowlist_admit(&al, NULL, 0u));

    /* Through the medium: full connectivity, C admits only B. */
    static ep_t a, b, c;
    static pump_t pa, pb, pforge;
    CHECK_ERR(brsim_init(&g_sim, 5u), BR_OK);
    uint8_t ia = add_ep(0x0101u, &a);
    uint8_t ib = add_ep(0x0102u, &b);
    uint8_t ic = add_ep(0x0103u, &c);
    brsim_link_t l = mk_link(0u, 100u, 200u, false);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ia, ib, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ib, ic, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ia, ic, &l), BR_OK);
    const uint16_t only_b = 0x0102u;
    CHECK_ERR(brsim_set_allowlist(&g_sim, ic, true, &only_b, 1u), BR_OK);
    CHECK_ERR(brsim_set_allowlist(&g_sim, ia, true, &only_b, 1u), BR_OK);

    start_pump(&pa, ia, 0x0101u, NULL, 200u, 1000u);
    start_pump(&pb, ib, 0x0102u, NULL, 50u, 1000u);
    /* A frame from A whose header claims prev_hop B passes: the filter is
     * header-based topology shaping, not authentication. */
    start_pump(&pforge, ia, 0x0102u, NULL, 3u, 1000u);
    CHECK_ERR(brsim_run_for(&g_sim, 1000000u), BR_OK);

    brsim_link_stats_t st;
    CHECK_ERR(brsim_link_stats(&g_sim, ia, ic, &st), BR_OK);
    CHECK_EQ_U32(st.delivered, 203u);
    CHECK_EQ_U32(st.allowlist_drop, 200u);
    CHECK_EQ_U32(c.rx_from[ia], 3u);
    CHECK_EQ_U32(c.rx_from[ib], 50u);
    CHECK_EQ_U32(b.rx_from[ia], 203u);
    CHECK_EQ_U32(a.rx_from[ib], 50u);
    CHECK_EQ_U32(a.rx_from[ic], 0u);
    /* Disable again: everything admitted. */
    CHECK_ERR(brsim_set_allowlist(&g_sim, ic, false, NULL, 0u), BR_OK);
    start_pump(&pa, ia, 0x0101u, NULL, 10u, 1000u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(c.rx_from[ia], 13u);
#else
    TU_SKIP("allowlist", "compiled out by BR_FIELD_BUILD");
#endif
}

/* ------------------------------------------------------------------------- */
/* 5. Ordering                                                                */
/* ------------------------------------------------------------------------- */

static void test_ordering(void)
{
    tu_ctx("ordering");
    static ep_t a, b;
    static pump_t p;
    CHECK_ERR(brsim_init(&g_sim, 11u), BR_OK);
    uint8_t ia = add_ep(0x0101u, &a);
    uint8_t ib = add_ep(0x0102u, &b);
    brsim_link_t l = mk_link(0u, 0u, 5000u, false);
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    start_pump(&p, ia, 0x0101u, NULL, 1000u, 10u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(b.rx_total, 1000u);
    CHECK_EQ_U32(b.inversions, 0u);

    CHECK_ERR(brsim_init(&g_sim, 11u), BR_OK);
    ia = add_ep(0x0101u, &a);
    ib = add_ep(0x0102u, &b);
    l.reorder = true;
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    start_pump(&p, ia, 0x0101u, NULL, 1000u, 10u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(b.rx_total, 1000u);
    CHECK_MSG(b.inversions > 100u, "reorder link should reorder");
}

/* ------------------------------------------------------------------------- */
/* 6. Timers                                                                  */
/* ------------------------------------------------------------------------- */

static void test_timers(void)
{
    tu_ctx("timers");
    static ep_t a;
    CHECK_ERR(brsim_init(&g_sim, 3u), BR_OK);
    memset(&a, 0, sizeof a);
    a.tick_at[0] = 1000u;
    a.tick_at[1] = 2500u;
    a.tick_at[2] = 2500u;
    a.tick_at[3] = 10000u;
    a.n_tick_req = 4;
    uint8_t idx = BRSIM_NO_NODE;
    CHECK_ERR(brsim_add_endpoint(&g_sim, 0x0101u, &k_ops, &a, &idx), BR_OK);
    CHECK_ERR(brsim_run_until(&g_sim, 9999u), BR_OK);
    CHECK_EQ_U32(a.n_tick_seen, 3u);
    CHECK_EQ_U32((uint32_t)a.tick_seen[0], 1000u);
    CHECK_EQ_U32((uint32_t)a.tick_seen[1], 2500u);
    CHECK_EQ_U32((uint32_t)a.tick_seen[2], 2500u);
    CHECK_EQ_U32((uint32_t)brsim_now(&g_sim), 9999u);
    CHECK_ERR(brsim_run_until(&g_sim, 20000u), BR_OK);
    CHECK_EQ_U32(a.n_tick_seen, 4u);
    CHECK_EQ_U32((uint32_t)a.tick_seen[3], 10000u);
    CHECK_EQ_U32(g_sim.n_events, 0u); /* BRSIM_NEVER after the last one */
    CHECK_ERR(brsim_run_until(&g_sim, 100u), BR_ERR_ARG); /* time never goes back */
}

/* ------------------------------------------------------------------------- */
/* 7. Unicast delivery reports                                                */
/* ------------------------------------------------------------------------- */

static void test_unicast_status(void)
{
    tu_ctx("unicast_status");
    static ep_t a, b, c;
    static pump_t p;
    static uint8_t addr_b[BRSIM_ADDR_LEN];
    CHECK_ERR(brsim_init(&g_sim, 21u), BR_OK);
    uint8_t ia = add_ep(0x0101u, &a);
    uint8_t ib = add_ep(0x0102u, &b);
    uint8_t ic = add_ep(0x0103u, &c);
    brsim_link_t l = mk_link(0u, 100u, 100u, false);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ia, ib, &l), BR_OK);
    CHECK_ERR(brsim_set_link_sym(&g_sim, ia, ic, &l), BR_OK);
    CHECK_ERR(brsim_addr(&g_sim, ib, addr_b), BR_OK);
    start_pump(&p, ia, 0x0101u, addr_b, 100u, 500u);
    CHECK_ERR(brsim_run_for(&g_sim, 100000u), BR_OK);
    CHECK_EQ_U32(b.rx_total, 100u);
    CHECK_EQ_U32(c.rx_total, 0u);   /* MAC filter: no overhearing */
    CHECK_EQ_U32(a.status_ok, 100u);
    CHECK_EQ_U32(a.status_fail, 0u);

    /* 50 % per attempt, 3 attempts: P(delivered) = 1 - 0.125 = 0.875. */
    l.loss_ppm = 500000u;
    CHECK_ERR(brsim_set_link(&g_sim, ia, ib, &l), BR_OK);
    CHECK_ERR(brsim_set_mac_attempts(&g_sim, 3u), BR_OK);
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    start_pump(&p, ia, 0x0101u, addr_b, 4000u, 100u);
    CHECK_ERR(brsim_run_for(&g_sim, 1000000u), BR_OK);
    CHECK_EQ_U32(a.status_ok + a.status_fail, 4000u);
    CHECK_EQ_U32(b.rx_total, a.status_ok);
    /* mean 3500, sigma = sqrt(4000 x 0.875 x 0.125) = 20.9; 4 sigma = 84. */
    CHECK_MSG(a.status_ok >= 3416u && a.status_ok <= 3584u, "MAC retry delivery rate");
    CHECK_ERR(brsim_set_mac_attempts(&g_sim, 0u), BR_ERR_ARG);
}

/* ------------------------------------------------------------------------- */
/* 8. br_node stub contract and timer formulas                                */
/* ------------------------------------------------------------------------- */

static void test_stub_contract(void)
{
    tu_ctx("stub_contract");
    static br_node_t node;
    static br_node_config_t cfg;
    CHECK_ERR(brsim_init(&g_sim, 1u), BR_OK);
    memset(&cfg, 0, sizeof cfg);
    cfg.unit_id = 0x0101u;
    cfg.n_transports = 1;
    uint8_t idx = BRSIM_NO_NODE;
    br_err_t rc = brsim_add_br_node(&g_sim, &node, &cfg, &idx);
    if (rc == BR_ERR_NOT_IMPLEMENTED) {
        CHECK_EQ_U32(g_sim.n_nodes, 0u);
        CHECK(brsim_find(&g_sim, 0x0101u) == BRSIM_NO_NODE);
    } else {
        TU_SKIP("stub contract", "br_node_init is implemented now; scenarios take over");
    }
    uint64_t next = 0;
    (void)br_node_tick(&node, 0u, &next);
    CHECK(next == BR_NEVER_US || rc != BR_ERR_NOT_IMPLEMENTED);

    /* br_session.h timer formulas against the 4.1.10 table and section 9. */
    CHECK_EQ_U32(br_bind_retry_ms(1), 60u);
    CHECK_EQ_U32(br_bind_retry_ms(2), 120u);
    CHECK_EQ_U32(br_bind_timeout_ms(1), 470u);
    CHECK_EQ_U32(br_bind_timeout_ms(2), 890u);
    CHECK_EQ_U32(br_bind_timeout_ms(4), 1730u);
    CHECK_EQ_U32(br_bind_timeout_ms(8), 3410u);
    CHECK_EQ_U32(br_seek_base_ms(4), 530u);
    CHECK_EQ_U32(br_seek_jitter_max_ms(0), 600u);
    CHECK_EQ_U32(br_seek_jitter_max_ms(6), 38400u);
    CHECK_EQ_U32(br_seek_jitter_max_ms(7), 60000u);
    br_rtt_t r = { 0u, false };
    CHECK_EQ_U32(br_rto_ms(&r), 100u);
    CHECK_EQ_U32(br_reorder_ms(&r), 500u);
    CHECK_EQ_U32(br_session_timeout_ms(5000u, &r), 20000u);
    br_rtt_sample(&r, 80u);
    CHECK_EQ_U32(br_rto_ms(&r), 160u);
    br_rtt_sample(&r, 160u);
    CHECK_EQ_U32(r.srtt_ms, 90u);
    CHECK_EQ_U32(br_session_timeout_ms(1000u, &r), 4000u);
}

int main(void)
{
    test_loss_rate();
    test_determinism();
    test_connectivity();
    test_allowlist();
    test_ordering();
    test_timers();
    test_unicast_status();
    test_stub_contract();
    return tu_summary("test_sim_self");
}
