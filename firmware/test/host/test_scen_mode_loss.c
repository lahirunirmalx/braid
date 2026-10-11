// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_scen_mode_loss.c - control-frame loss inside the ARQ seq space
 * (PROTOCOL.md 3.5 lines 255-283, 4.1 lines 338-456, 6.1 lines 598-651,
 * 7 lines 707-741; SPEC-NOTES N23, N24, N35, N46).
 *
 *   first_mode_lost          the first MODE (session seq 0) never reaches the probe
 *   first_mode_lost_twice    seq 0 and the retry at seq 1 are both lost
 *   mode_change_lost         MODE change mid-stream lost once, old-config DATA in flight
 *   ping_lost                a keepalive PING is lost mid-stream
 *   baseline_clean_hash      no loss: prints the brsim trace hash of the clean run
 *
 * A = 0x0101 sender, B = 0x0102 relay, C = 0x0103 probe (group 0xFF10),
 * bench keys, AUTH on, FEC off, ARQ on; the default MODE is queued behind
 * the SEEK (sent on BIND_ACK, SPEC-NOTES N23: session seq 0).
 *
 * The defect these scenarios pin down: control retries take new seqs (3.5),
 * so a lost MODE leaves a permanent hole in the probe's seq space. Before
 * SPEC-NOTES N46 the probe's reorder buffer waited REORDER_MS for seq 0,
 * held every later DATA, stopped acking once its 4 slots were full and the
 * sender exhausted its ARQ retries. N46: holes below a MODE that can only
 * have been preceded by control frames (the session's first config) are
 * given up at once as informational on_gap; every other hole (MODE change
 * mid-stream, PING) is indistinguishable from lost DATA and keeps the
 * section 7 REORDER_MS wait (N35), with ACKs flowing meanwhile.
 *
 * Drop injection: scen_common.h rules (bench allowlist at the receiver, so
 * no 11.6 accounting is triggered). A rule armed before the handshake would
 * also drop BIND, so the first-MODE rules arm on the "BIND delivered at C"
 * trace line.
 */
#include "scen_common.h"

#define S_ID 0x0101u
#define R_ID 0x0102u
#define P_ID 0x0103u

#define N_PRESS           5u
#define HOLD_MS         200u
#define GAP_MS          100u
#define ACK_BOUND_MS    200u   /* on_acked after a DATA send on a clean 2-hop path */
#define DELIVER_BOUND_MS 100u  /* on_samples after a DATA send with no hole open */
#define REORDER_SLACK_MS 150u  /* REORDER_MS (500 at the sim SRTT) + tick / link slack */

/* ------------------------------------------------------------------------- */
/* Shared checks                                                              */
/* ------------------------------------------------------------------------- */

/* Press N_PRESS times (1 then 0, both ack_req); t_send receives the 2 x N send times. */
static void presses(uint64_t *t_send, unsigned *n_sent)
{
    for (unsigned i = 0; i < N_PRESS; i++) {
        t_send[(*n_sent)++] = brsim_now(&sc.sim);
        CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
        sc_run_ms(HOLD_MS);
        t_send[(*n_sent)++] = brsim_now(&sc.sim);
        CHECK_ERR(sc_send(S_ID, 0, true), BR_OK);
        sc_run_ms(GAP_MS);
    }
}

/* Samples at C: count, order, alternation, source; every seq acked at A. */
static unsigned check_samples(sc_smp_t *smp, unsigned max, unsigned want, bool alternate)
{
    unsigned ns = sc_samples(P_ID, smp, max);
    bool in_order = true, alternating = true, src_ok = true, all_acked = true;
    for (unsigned i = 0; i < ns; i++) {
        src_ok = src_ok && smp[i].src == S_ID;
        if (i > 0) {
            in_order = in_order && (int16_t)(uint16_t)(smp[i].seq - smp[i - 1].seq) > 0;
        }
        alternating = alternating && smp[i].b0 == (uint8_t)((i % 2u) == 0u ? 1u : 0u);
        all_acked = all_acked && sc_acked_has(S_ID, smp[i].seq);
    }
    CHECK_EQ_U32(ns, want);
    CHECK_MSG(src_ok, "src_id of every sample must be 0x0101");
    CHECK_MSG(in_order, "samples must arrive in seq order, no duplicates");
    if (alternate) {
        CHECK_MSG(alternating, "samples must alternate 1,0,1,0 as pressed");
    }
    CHECK_MSG(all_acked, "A must see an on_acked for every delivered DATA seq");
    return ns;
}

/* Time of the first on_acked record for a DATA seq at A, or UINT64_MAX. */
static uint64_t acked_time(uint16_t seq)
{
    const brsim_app_rec_t *r = sc_app_nth(BRSIM_APP_ACKED, S_ID, -1, -1, seq, 0);
    return r != NULL ? r->t_us : UINT64_MAX;
}

/* Sample i (delivered at smp[i].t) was sent at t_send[i]: both bounds in ms. */
static void check_latency(const sc_smp_t *smp, unsigned ns, const uint64_t *t_send, unsigned n_sent,
                          uint32_t deliver_bound_ms, uint32_t ack_bound_ms)
{
    bool deliver_ok = true, ack_ok = true;
    for (unsigned i = 0; i < ns && i < n_sent; i++) {
        deliver_ok = deliver_ok && smp[i].t >= t_send[i] && smp[i].t - t_send[i] <= SC_US(deliver_bound_ms);
        uint64_t ta = acked_time(smp[i].seq);
        ack_ok = ack_ok && ta != UINT64_MAX && ta >= t_send[i] && ta - t_send[i] <= SC_US(ack_bound_ms);
    }
    CHECK_MSG(deliver_ok, "every sample delivered within the stated bound of its send");
    CHECK_MSG(ack_ok, "every DATA acked within the stated bound of its send (no ACK stall)");
}

static void check_session_alive(void)
{
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
}

/* ------------------------------------------------------------------------- */
/* 1 / 2: the first MODE is lost once or twice                                */
/* ------------------------------------------------------------------------- */

static void first_mode_body(uint64_t seed, int n_lost)
{
    if (!sc_topo3(seed)) {
        return;
    }
    /* arm once the BIND has been delivered at C: nothing but MODE then travels B -> C */
    sc_rule_t *ru = sc_rule_on("BIND", (int)R_ID, (int)P_ID, "deliver", (int)P_ID, (int)R_ID, (int)S_ID, "MODE",
                               n_lost);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool streaming = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(streaming, "sender never reached STREAMING");
    if (!streaming) {
        return;
    }
    CHECK(ru != NULL && ru->done && ru->dropped == (uint32_t)n_lost);
    sc_q_t qm = sc_q("MODE", (int)S_ID, (int)R_ID, (int)S_ID);
    CHECK_MSG(sc_q_count(&qm) == (unsigned)n_lost + 1u, "MODE sent once per RTO until MODE_ACK (6.1)");
    /* the accepted MODE took a new seq (3.5): seq n_lost */
    const sc_tl_t *mk = sc_q_nth(&qm, (unsigned)n_lost);
    CHECK(mk != NULL && mk->seq == (uint16_t)n_lost);
    /* N46: the probe reports the control hole(s) below the accepted MODE at once, before any DATA */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, (int)P_ID, -1, n_lost, 0), 1);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, -1, -1, -1, -1), 1);
    CHECK_EQ_U32(sc_stats(P_ID).f.gaps, 1);
    sc_run_ms(200);

    uint64_t t_send[2 * N_PRESS];
    unsigned n_sent = 0;
    presses(t_send, &n_sent);
    sc_run_ms(2000);

    sc_smp_t smp[2 * N_PRESS + 4];
    unsigned ns = check_samples(smp, sizeof smp / sizeof smp[0], 2u * N_PRESS, true);
    check_latency(smp, ns, t_send, n_sent, DELIVER_BOUND_MS, ACK_BOUND_MS);
    CHECK_EQ_U32(smp[0].seq, (uint16_t)(n_lost + 1)); /* first DATA right behind the accepted MODE */

    br_stats_t sa = sc_stats(S_ID), sp = sc_stats(P_ID);
    CHECK_EQ_U32(sa.f.arq_retx, 0);   /* a control retry is not an ARQ retransmission */
    CHECK_EQ_U32(sa.f.gaps, 0);       /* the sender gave nothing up */
    CHECK_EQ_U32(sp.f.gaps, 1);       /* exactly the one control gap, nothing from the reorder timer */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, -1, -1, -1, -1), 1);
    CHECK_EQ_U32(sp.f.replay_dropped, 0);
    check_session_alive();

    uint8_t seq_s[32], seq_p[32];
    unsigned ks = sc_state_seq(S_ID, seq_s, 32), kp = sc_state_seq(P_ID, seq_p, 32);
    static const uint8_t want_s[] = { BR_SND_SEEKING, BR_SND_BINDING, BR_SND_CONFIGURING, BR_SND_STREAMING };
    static const uint8_t want_p[] = { BR_PRB_BOUND, BR_PRB_STREAMING };
    CHECK_MSG(sc_subseq(seq_s, ks, want_s, 4), "A: IDLE->SEEKING->BINDING->CONFIGURING->STREAMING");
    CHECK_MSG(sc_subseq(seq_p, kp, want_p, 2), "C: LISTENING->BOUND->STREAMING");
    CHECK_EQ_U32(ks, 4);
    sc_check_clean(0);
}

static void scen_first_mode_lost(uint64_t seed)
{
    first_mode_body(seed, 1);
}

static void scen_first_mode_lost_twice(uint64_t seed)
{
    first_mode_body(seed, 2);
}

/* ------------------------------------------------------------------------- */
/* 3: MODE change mid-stream, new MODE lost once, old-config DATA in flight    */
/* ------------------------------------------------------------------------- */

static void scen_mode_change_lost(uint64_t seed)
{
    if (!sc_up3(seed, 0)) {
        return;
    }
    sc_run_ms(200);
    /* one HIGH press so the stream exists and the sender is streaming the old config */
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(HOLD_MS);
    CHECK_ERR(sc_send(S_ID, 0, true), BR_OK);
    sc_run_ms(GAP_MS);
    sc_smp_t smp[2 * N_PRESS + 6];
    unsigned n0 = sc_samples(P_ID, smp, sizeof smp / sizeof smp[0]);
    CHECK_EQ_U32(n0, 2);
    const uint8_t cfg_high = n0 > 0 ? smp[0].cfg : 0u;

    /* old-config DATA on the air, then the MODE; the rule drops everything B -> C until
     * the MODE is dropped, so that DATA is lost too and must come back by ARQ, not be
     * skipped as a control hole (N46 applies to the first config only) */
    const uint64_t t_press = brsim_now(&sc.sim);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_rule_t *ru = sc_rule_now((int)P_ID, (int)R_ID, (int)S_ID, "MODE", 1);
    br_mode_t lo;
    sc_mode(&lo, BR_MODE_LOW);
    const uint64_t t_set = brsim_now(&sc.sim);
    CHECK_ERR(br_node_set_mode(sc_pl(S_ID), sc_n(S_ID)->sess, &lo), BR_OK);
    sc_kick();
    sc_run_ms(20);
    CHECK(ru != NULL && ru->done && ru->dropped == 1);
    CHECK_ERR(sc_send(S_ID, 0, true), BR_OK); /* still the old config_id (6.1) */
    const uint64_t t_release = brsim_now(&sc.sim);
    /* wait for the MODE retry (RTO) and its MODE_ACK, then press under the new config */
    bool mode_ok = false;
    for (unsigned i = 0; i < 100 && !mode_ok; i++) {
        sc_run_ms(5);
        mode_ok = sc_app_count(BRSIM_APP_MODE, (int)S_ID, -1, -1, -1) >= 2;
    }
    CHECK_MSG(mode_ok, "the MODE retry must be acknowledged (6.1 MODE_RETRY)");
    sc_q_t qm = sc_q("MODE", (int)S_ID, (int)R_ID, (int)S_ID);
    qm.t0 = t_set;
    CHECK_EQ_U32(sc_q_count(&qm), 2);
    const sc_tl_t *m_lost = sc_q_nth(&qm, 0);
    const uint16_t mode_seq = m_lost != NULL ? m_lost->seq : 0u;
    sc_run_ms(100);
    uint64_t t_low[2 * N_PRESS];
    unsigned n_low = 0;
    presses(t_low, &n_low);
    sc_run_ms(2000);

    /* every sample delivered, in order, each acked: 2 HIGH + 2 HIGH (one recovered by ARQ) + 10 LOW */
    unsigned ns = check_samples(smp, sizeof smp / sizeof smp[0], 4u + 2u * N_PRESS, true);
    bool cfg_ok = ns == 4u + 2u * N_PRESS;
    for (unsigned i = 0; cfg_ok && i < ns; i++) {
        bool high = i < 4u;
        cfg_ok = high ? (smp[i].cfg == cfg_high && smp[i].n_bytes == 4u)
                      : (smp[i].cfg != cfg_high && smp[i].n_bytes == 1u);
    }
    CHECK_MSG(cfg_ok, "DATA keeps the old config_id until MODE_ACK, then the new one (6.1)");
    if (ns == 4u + 2u * N_PRESS) {
        /* the lost DATA came back by retransmission within a few RTOs */
        CHECK(smp[2].t >= t_press && smp[2].t - t_press <= SC_US(4u * BR_ARQ_RTO_MS + DELIVER_BOUND_MS));
        /* the release behind the control hole waited at most REORDER_MS (N35), not longer */
        CHECK(smp[3].t >= t_release && smp[3].t - t_release <= SC_US(BR_REORDER_MS_MIN + REORDER_SLACK_MS));
        /* once the hole expired the new-config presses flow and are acked promptly */
        bool late_ok = true, ack_ok = true;
        for (unsigned i = 0; i < n_low; i++) {
            const sc_smp_t *s = &smp[4u + i];
            late_ok = late_ok && s->t >= t_low[i] && s->t - t_low[i] <= SC_US(BR_REORDER_MS_MIN + REORDER_SLACK_MS);
            uint64_t ta = acked_time(s->seq);
            ack_ok = ack_ok && ta != UINT64_MAX && ta - t_low[i] <= SC_US(ACK_BOUND_MS);
        }
        CHECK_MSG(late_ok, "new-config samples delivered within REORDER_MS of their send");
        CHECK_MSG(ack_ok, "new-config DATA acked promptly while the hole is open (ACKs never stop)");
    }
    br_stats_t sa = sc_stats(S_ID), sp = sc_stats(P_ID);
    CHECK_MSG(sa.f.arq_retx >= 1, "the dropped old-config DATA must be retransmitted");
    CHECK_EQ_U32(sa.f.gaps, 0);                      /* nothing lost at the sender */
    CHECK_EQ_U32(sp.f.gaps, 1);                      /* the lost MODE seq, after REORDER_MS (N35) */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, (int)P_ID, -1, 1, (int)mode_seq), 1);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_MODE, (int)P_ID, -1, -1, -1), 2);
    check_session_alive();
    sc_check_clean(0);
}

/* ------------------------------------------------------------------------- */
/* 4: a keepalive PING is lost mid-stream                                     */
/* ------------------------------------------------------------------------- */

static void scen_ping_lost(uint64_t seed)
{
    if (!sc_topo3(seed)) {
        return;
    }
    br_mode_t m;
    sc_mode(&m, BR_MODE_HIGH);
    m.keepalive_ms = 1000; /* shortest keepalive (6.1): PING after 1 s without an ACK */
    if (!sc_start(S_ID, 0xFF10, &m)) {
        return;
    }
    bool streaming = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(streaming, "sender never reached STREAMING");
    if (!streaming) {
        return;
    }
    sc_run_ms(200);
    uint64_t t_send[2 * N_PRESS + 2];
    unsigned n_sent = 0;
    t_send[n_sent++] = brsim_now(&sc.sim);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(HOLD_MS);
    t_send[n_sent++] = brsim_now(&sc.sim);
    CHECK_ERR(sc_send(S_ID, 0, true), BR_OK);
    sc_run_ms(300); /* ACKs are home */

    sc_rule_t *ru = sc_rule_now((int)P_ID, (int)R_ID, (int)S_ID, "PING", 1);
    const uint64_t t_arm = brsim_now(&sc.sim);
    bool dropped = false;
    for (unsigned i = 0; i < 400 && !dropped; i++) {
        sc_run_ms(5);
        dropped = ru != NULL && ru->done;
    }
    CHECK_MSG(dropped, "a PING must be sent after keepalive_ms without an ACK (4.2)");
    sc_q_t qp = sc_q("PING", (int)S_ID, (int)R_ID, (int)S_ID);
    qp.t0 = t_arm;
    const sc_tl_t *ping = sc_q_nth(&qp, 0);
    CHECK(ping != NULL);
    const uint16_t ping_seq = ping != NULL ? ping->seq : 0u;
    sc_q_t qpong = sc_q("PONG", (int)P_ID, (int)R_ID, (int)P_ID);
    CHECK_EQ_U32(sc_q_count(&qpong), 0);

    /* press right behind the lost PING: its seq is the hole */
    uint64_t t_after[2 * N_PRESS];
    unsigned n_after = 0;
    presses(t_after, &n_after);
    sc_run_ms(2000);

    sc_smp_t smp[2 * N_PRESS + 6];
    unsigned ns = check_samples(smp, sizeof smp / sizeof smp[0], 2u + 2u * N_PRESS, true);
    check_latency(smp, 2, t_send, n_sent, DELIVER_BOUND_MS, ACK_BOUND_MS);
    if (ns == 2u + 2u * N_PRESS) {
        CHECK_EQ_U32(smp[2].seq, (uint16_t)(ping_seq + 1u));
        bool late_ok = true, ack_ok = true;
        for (unsigned i = 0; i < n_after; i++) {
            const sc_smp_t *s = &smp[2u + i];
            /* the hole expires REORDER_MS after the first DATA behind it; later ones wait less */
            late_ok = late_ok && s->t >= t_after[i] && s->t - t_after[i] <= SC_US(BR_REORDER_MS_MIN + REORDER_SLACK_MS);
            uint64_t ta = acked_time(s->seq);
            ack_ok = ack_ok && ta != UINT64_MAX && ta - t_after[i] <= SC_US(ACK_BOUND_MS);
        }
        CHECK_MSG(late_ok, "samples behind the lost PING delivered within REORDER_MS (N35)");
        CHECK_MSG(ack_ok, "DATA behind the lost PING acked promptly (bitmap ACKs, no stall)");
    }
    br_stats_t sa = sc_stats(S_ID), sp = sc_stats(P_ID);
    CHECK_EQ_U32(sa.f.arq_retx, 0);  /* no slot overflow at the probe: nothing had to be resent */
    CHECK_EQ_U32(sa.f.gaps, 0);
    CHECK_EQ_U32(sp.f.gaps, 1);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, (int)P_ID, -1, 1, (int)ping_seq), 1);
    check_session_alive();
    sc_check_clean(0);
}

/* ------------------------------------------------------------------------- */
/* 5: clean run, trace hash printed for the before / after comparison         */
/* ------------------------------------------------------------------------- */

static void scen_baseline_clean_hash(uint64_t seed)
{
    if (!sc_up3(seed, 0)) {
        return;
    }
    sc_run_ms(200);
    uint64_t t_send[2 * N_PRESS];
    unsigned n_sent = 0;
    presses(t_send, &n_sent);
    sc_run_ms(2000);
    sc_smp_t smp[2 * N_PRESS + 4];
    unsigned ns = check_samples(smp, sizeof smp / sizeof smp[0], 2u * N_PRESS, true);
    check_latency(smp, ns, t_send, n_sent, DELIVER_BOUND_MS, ACK_BOUND_MS);
    br_stats_t sa = sc_stats(S_ID), sp = sc_stats(P_ID);
    CHECK_EQ_U32(sa.f.arq_retx, 0);
    CHECK_EQ_U32(sa.f.gaps, 0);
    CHECK_EQ_U32(sp.f.gaps, 0);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_GAP, -1, -1, -1, -1), 0);
    check_session_alive();
    uint32_t lines = 0;
    uint64_t h = brsim_trace_hash(&sc.sim, &lines);
    printf("  baseline_clean_hash seed=%012llx trace_hash=%016llx lines=%u\n", (unsigned long long)seed,
           (unsigned long long)h, (unsigned)lines);
    sc_check_clean(0);
}

int main(int argc, char **argv)
{
    sc_args(argc, argv);
    sc_run("first_mode_lost", "PROTOCOL.md 3.5, 4.1 (DATA only in STREAMING), 6.1, 7; SPEC-NOTES N46",
           scen_first_mode_lost, false);
    sc_run("first_mode_lost_twice", "PROTOCOL.md 3.5, 6.1 MODE_RETRY; SPEC-NOTES N46", scen_first_mode_lost_twice,
           false);
    sc_run("mode_change_lost", "PROTOCOL.md 6.1 (two configs, DATA keeps the old config_id), 7; SPEC-NOTES N35, N46",
           scen_mode_change_lost, false);
    sc_run("ping_lost", "PROTOCOL.md 4.2 PING, 7 REORDER_MS; SPEC-NOTES N35", scen_ping_lost, false);
    sc_run("baseline_clean_hash", "PROTOCOL.md 4 line 313 flow (no loss)", scen_baseline_clean_hash, false);
    return tu_summary("test_scen_mode_loss");
}
