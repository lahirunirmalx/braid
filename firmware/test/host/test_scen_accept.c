// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_scen_accept.c - phase 1b acceptance scenarios (README-SCENARIOS.txt section A).
 *
 *   three_node_relay           PROTOCOL.md 4 (line 313 flow), 4.1, 7, 11.4 (lines 1110-1152), 11.6
 *   bench_allowlist_topology   SPEC-NOTES N22; PROTOCOL.md 11.4 steps 5-9
 *   three_node_relay_lossy     PROTOCOL.md 7 (lines 707-741)
 *
 * A = 0x0101 sender, B = 0x0102 relay, C = 0x0103 probe (group 0xFF10). Bench
 * test keys (Appendix A K_site), AUTH on, FEC off, ARQ on. A seeks 0xFF10; the
 * default MODE is queued right behind the seek (it is sent on BIND_ACK; the plan
 * text "set MODE once STREAMING" is inverted: STREAMING needs the MODE_ACK).
 * For each of N presses A sends digital 1 then 0 with ack_req. C's app log must
 * show each 0->1 edge exactly once with hops == 2 (SPEC-NOTES N25).
 */
#include "scen_common.h"

#define S_ID 0x0101u
#define R_ID 0x0102u
#define P_ID 0x0103u

enum { K_RELAY = 0, K_ALLOWLIST = 1, K_LOSSY = 2 };

#define LOSSY_LOSS_PPM 100000u /* 10 % per link per attempt (task text; the plan text says 20 %) */
#define LOSSY_PRESSES 50u
#define LOSSY_DELIVERY_BOUND_MS 3000u

static unsigned app_records_of(uint16_t id)
{
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    unsigned c = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return 0;
    }
    uint8_t idx = sc_ix(id);
    for (uint32_t i = 0; i < n; i++) {
        if (r[i].node == idx) {
            c++;
        }
    }
    return c;
}

static void accept_body(uint64_t seed, int kind)
{
    const unsigned n_press = kind == K_LOSSY ? LOSSY_PRESSES : 5u;

    if (!sc_topo3(seed)) {
        return;
    }
    if (kind == K_ALLOWLIST) {
        sc_link2(S_ID, P_ID); /* everybody hears everybody */
        static const uint16_t al_s[] = { R_ID };
        static const uint16_t al_r[] = { S_ID, P_ID };
        static const uint16_t al_p[] = { R_ID };
        sc_base_allow(S_ID, al_s, 1);
        sc_base_allow(R_ID, al_r, 2);
        sc_base_allow(P_ID, al_p, 1);
    }
    if (kind == K_LOSSY) {
        sc.reorder_default = true; /* plan default: links may reorder; ARQ reorder buffer is exercised */
        sc_link2_loss(S_ID, R_ID, LOSSY_LOSS_PPM);
        sc_link2_loss(R_ID, P_ID, LOSSY_LOSS_PPM);
        /* Two MAC tries per unicast (ESP-NOW hardware retries): with one try the chance of three
         * consecutive failures on a link (LINK_FAIL_MAX, 11.6) is about 50 % over 150 frames. */
        CHECK_ERR(brsim_set_mac_attempts(&sc.sim, 2), BR_OK);
    }

    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool streaming = sc_wait_snd_state(S_ID, BR_SND_STREAMING, kind == K_LOSSY ? 60000u : 5000u);
    CHECK_MSG(streaming, "sender never reached STREAMING");
    if (!streaming) {
        return;
    }
    sc_run_ms(200);

    uint64_t t_send[2 * LOSSY_PRESSES];
    unsigned n_sent = 0;
    for (unsigned i = 0; i < n_press; i++) {
        t_send[n_sent++] = brsim_now(&sc.sim);
        br_err_t r1 = sc_send(S_ID, 1, true);
        CHECK_ERR(r1, BR_OK);
        sc_run_ms(200);
        t_send[n_sent++] = brsim_now(&sc.sim);
        br_err_t r0 = sc_send(S_ID, 0, true);
        CHECK_ERR(r0, BR_OK);
        sc_run_ms(100);
    }
    sc_run_ms(kind == K_LOSSY ? 8000u : 2000u);

    /* --- samples at C: each edge exactly once, hops == 2, in seq order --- */
    sc_smp_t smp[2 * LOSSY_PRESSES + 4];
    unsigned ns = sc_samples(P_ID, smp, sizeof smp / sizeof smp[0]);
    unsigned ones = 0, zeros = 0;
    bool in_order = true, alternating = true, src_ok = true, hops_ok = true, bound_ok = true;
    for (unsigned i = 0; i < ns; i++) {
        ones += smp[i].b0 == 1u;
        zeros += smp[i].b0 == 0u;
        src_ok = src_ok && smp[i].src == S_ID;
        hops_ok = hops_ok && smp[i].hops == 2u;
        if (i > 0) {
            in_order = in_order && (int16_t)(uint16_t)(smp[i].seq - smp[i - 1].seq) > 0;
        }
        alternating = alternating && smp[i].b0 == (uint8_t)((i % 2u) == 0u ? 1u : 0u);
        if (kind == K_LOSSY && i < n_sent) {
            bound_ok = bound_ok && smp[i].t >= t_send[i] &&
                       smp[i].t - t_send[i] <= SC_US(LOSSY_DELIVERY_BOUND_MS);
        }
    }
    CHECK_EQ_U32(ns, 2u * n_press);
    CHECK_EQ_U32(ones, n_press);   /* each 0 -> 1 edge exactly once */
    CHECK_EQ_U32(zeros, n_press);
    CHECK_MSG(src_ok, "src_id of every sample must be 0x0101");
    CHECK_MSG(hops_ok, "meta.hops must be 2 for A -> B -> C (SPEC-NOTES N25)");
    CHECK_MSG(in_order, "samples must arrive in seq order, no duplicates");
    CHECK_MSG(alternating, "samples must alternate 1,0,1,0 as pressed");
    CHECK_MSG(bound_ok, "every sample delivered within the stated bound of its send");

    /* --- ACKs reached A, no gaps, no retransmission on a clean link --- */
    bool all_acked = true;
    for (unsigned i = 0; i < ns; i++) {
        all_acked = all_acked && sc_acked_has(S_ID, smp[i].seq);
    }
    CHECK_MSG(all_acked, "A must see an on_acked for every DATA seq");
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, -1, -1, -1, -1), 0);
    br_stats_t sa = sc_stats(S_ID), sb = sc_stats(R_ID), sp = sc_stats(P_ID);
    if (kind == K_LOSSY) {
        CHECK_MSG(sa.f.arq_retx > 0, "10 % loss must cause at least one ARQ retransmission");
        CHECK_EQ_U32(sp.f.replay_dropped, 0); /* duplicates are dropped by ARQ before the replay window */
    } else {
        CHECK_EQ_U32(sa.f.arq_retx, 0);
    }

    /* --- states --- */
    uint8_t seq_s[32], seq_p[32];
    unsigned ks = sc_state_seq(S_ID, seq_s, 32), kp = sc_state_seq(P_ID, seq_p, 32);
    static const uint8_t want_s[] = { BR_SND_SEEKING, BR_SND_BINDING, BR_SND_CONFIGURING, BR_SND_STREAMING };
    static const uint8_t want_p[] = { BR_PRB_BOUND, BR_PRB_STREAMING };
    CHECK_MSG(sc_subseq(seq_s, ks, want_s, 4), "A: IDLE->SEEKING->BINDING->CONFIGURING->STREAMING");
    CHECK_MSG(sc_subseq(seq_p, kp, want_p, 2), "C: LISTENING->BOUND->STREAMING");
    if (kind != K_LOSSY) {
        CHECK_EQ_U32(ks, 4);
        CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    }

    /* --- routes (11.4 table) --- */
    br_route_entry_t e;
    CHECK(sc_route(R_ID, S_ID, &e));
    CHECK_EQ_U32(e.next_hop, S_ID);
    CHECK_EQ_U32(e.hops, 1);
    CHECK(sc_route(R_ID, P_ID, &e));
    CHECK_EQ_U32(e.next_hop, P_ID);
    CHECK_EQ_U32(e.hops, 1);
    CHECK(sc_route(S_ID, P_ID, &e));
    CHECK_EQ_U32(e.next_hop, R_ID);
    CHECK_EQ_U32(e.hops, 2);
    CHECK(sc_route(P_ID, S_ID, &e));
    CHECK_EQ_U32(e.next_hop, R_ID);
    CHECK_EQ_U32(e.hops, 2);

    /* --- relay did its job, delivered nothing locally --- */
    CHECK_MSG(sb.f.relay_fwd >= 10u, "B forwards BIND, BIND_ACK, MODE, MODE_ACK, DATA and ACKs");
    CHECK_EQ_U32(app_records_of(R_ID), 0);

    /* --- A and C never talked directly --- */
    brsim_link_stats_t l_sp, l_ps;
    CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(S_ID), sc_ix(P_ID), &l_sp), BR_OK);
    CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(P_ID), sc_ix(S_ID), &l_ps), BR_OK);
    if (kind == K_ALLOWLIST) {
        /* Full connectivity: the carrier delivered, the bench allowlist (N22) dropped before br_node_rx. */
        CHECK_MSG(l_sp.allowlist_drop > 0, "S->P frames must be dropped by P's allowlist");
        CHECK_MSG(l_ps.allowlist_drop > 0, "P->S frames must be dropped by S's allowlist");
        CHECK_EQ_U32(l_sp.allowlist_drop, l_sp.delivered);
        CHECK_EQ_U32(l_ps.allowlist_drop, l_ps.delivered);
        /* Every trace line between A and C shows the allowlist verdict, never a pipeline verdict. */
        sc_q_t q = sc_q(NULL, S_ID, P_ID, -1);
        unsigned all_sp = sc_q_count(&q);
        q.verdict = "allowlist";
        CHECK_EQ_U32(sc_q_count(&q), all_sp);
        q = sc_q(NULL, P_ID, S_ID, -1);
        unsigned all_ps = sc_q_count(&q);
        q.verdict = "allowlist";
        CHECK_EQ_U32(sc_q_count(&q), all_ps);
        /* The core never saw the dropped frames: its rx_frames is bounded by what the adapters passed on. */
        brsim_link_stats_t l_rp, l_sr, l_pr, l_rs;
        CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(R_ID), sc_ix(P_ID), &l_rp), BR_OK);
        CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(S_ID), sc_ix(R_ID), &l_sr), BR_OK);
        CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(P_ID), sc_ix(R_ID), &l_pr), BR_OK);
        CHECK_ERR(brsim_link_stats(&sc.sim, sc_ix(R_ID), sc_ix(S_ID), &l_rs), BR_OK);
        CHECK(sp.f.rx_frames <= l_rp.delivered - l_rp.allowlist_drop);
        CHECK(sa.f.rx_frames <= l_rs.delivered - l_rs.allowlist_drop);
        CHECK_EQ_U32(l_rp.allowlist_drop, 0);
        CHECK_EQ_U32(l_sr.allowlist_drop, 0);
        CHECK_EQ_U32(l_pr.allowlist_drop, 0);
        CHECK_EQ_U32(l_rs.allowlist_drop, 0);
    } else {
        CHECK_EQ_U32(l_sp.sent, 0);
        CHECK_EQ_U32(l_sp.delivered, 0);
        CHECK_EQ_U32(l_ps.sent, 0);
        CHECK_EQ_U32(l_ps.delivered, 0);
        CHECK_EQ_U32(sc_pair_lines(S_ID, P_ID), 0);
    }

    /* --- end-of-scenario counters --- */
    sc_check_clean(kind == K_LOSSY ? SC_STAT_BIT(BR_STAT_HOP_REPLAY) : 0u);
}

static void scen_three_node_relay(uint64_t seed)
{
    accept_body(seed, K_RELAY);
}

static void scen_bench_allowlist_topology(uint64_t seed)
{
    accept_body(seed, K_ALLOWLIST);
}

static void scen_three_node_relay_lossy(uint64_t seed)
{
    accept_body(seed, K_LOSSY);
}

int main(int argc, char **argv)
{
    sc_args(argc, argv);
    sc_run("three_node_relay", "PROTOCOL.md 4 line 313, 4.1, 7, 11.4 lines 1110-1152, 11.6", scen_three_node_relay,
           false);
#ifdef BR_FIELD_BUILD
    sc_skip("bench_allowlist_topology", "SPEC-NOTES N22", "bench allowlist is compiled out with BR_FIELD_BUILD");
#else
    sc_run("bench_allowlist_topology", "SPEC-NOTES N22, PROTOCOL.md 11.4 steps 5-9", scen_bench_allowlist_topology,
           false);
#endif
    sc_run("three_node_relay_lossy", "PROTOCOL.md 7 lines 707-741", scen_three_node_relay_lossy, false);
    return tu_summary("test_scen_accept");
}
