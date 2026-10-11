// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_scen_races.c - one scenario per PROTOCOL.md 4.3 race catalogue row
 * (README-SCENARIOS.txt section C), in the order of the table (lines 483-494).
 *
 * Injection tools and their limits are described in scen_common.h: drops are
 * applied at the receiver's adapter (the sender's MAC reports success), the tap
 * can record and replay BROADCAST frames only. Everything that needs the bytes
 * of a unicast frame, or a forged frame, is reported as SKIP with the hook name.
 */
#include "scen_common.h"

#define S_ID  0x0101u
#define R_ID  0x0102u
#define P_ID  0x0103u
#define X_ID  0x0104u

static unsigned count_type(const char *type, int from, int to, int src)
{
    sc_q_t q = sc_q(type, from, to, src);
    return sc_q_count(&q);
}

static const sc_tl_t *first_line(const char *type, int from, int to, int src, const char *verdict)
{
    sc_q_t q = sc_q(type, from, to, src);
    q.verdict = verdict;
    return sc_q_nth(&q, 0);
}

/* ========================================================================= */
/* row 483: two probes answer the same SEEK (4.1.5, 4.1.7)                   */
/* ========================================================================= */

static void scen_race_two_probes_one_seek(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 4;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE) || !sc_add(X_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    sc_link2(R_ID, X_ID);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    sc_run_ms(2500); /* past BIND_TIMEOUT of the losing offer */

    CHECK_MSG(count_type("HELLO", P_ID, R_ID, P_ID) >= 1 && count_type("HELLO", X_ID, R_ID, X_ID) >= 1,
              "both probes answer the SEEK");
    unsigned bp = sc_q_count(&(sc_q_t){ "BIND", S_ID, R_ID, S_ID, P_ID, NULL, 0, UINT64_MAX });
    unsigned bx = sc_q_count(&(sc_q_t){ "BIND", S_ID, R_ID, S_ID, X_ID, NULL, 0, UINT64_MAX });
    CHECK_MSG((bp > 0) != (bx > 0), "BIND is unicast to exactly one probe");
    const uint16_t win = bp > 0 ? P_ID : X_ID, lose = bp > 0 ? X_ID : P_ID;
    CHECK_EQ_U32(sc_prb_live(win, NULL), 1);
    CHECK_EQ_U32(sc_prb_live(lose, NULL), 0);             /* the other probe's offer timed out, no session */
    CHECK_EQ_U32(count_type("BIND_ACK", -1, -1, lose), 0);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_SEEK_RESULT, S_ID, -1, -1, win), 1);
    const brsim_app_rec_t *sr = sc_app_nth(BRSIM_APP_SEEK_RESULT, S_ID, -1, -1, win, 0);
    CHECK(sr != NULL && sr->err == BR_OK);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    sc_smp_t smp[4];
    CHECK_EQ_U32(sc_samples(win, smp, 4), 1);
    CHECK_EQ_U32(sc_samples(lose, smp, 4), 0);
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 484: two senders SEEK one group at once (4.1.2, 4.1.6)                */
/* ========================================================================= */

static void scen_race_two_senders_one_group(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 4;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(X_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(X_ID, R_ID);
    sc_link2(R_ID, P_ID);
    if (!sc_start(S_ID, 0xFF10, NULL) || !sc_start(X_ID, 0xFF10, NULL)) { /* same simulated instant */
        return;
    }
    bool up1 = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 10000);
    bool up2 = sc_wait_snd_state(X_ID, BR_SND_STREAMING, 10000);
    CHECK_MSG(up1 && up2, "a multi-session probe must serve both senders");
    if (!up1 || !up2) {
        return;
    }
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 2);
    CHECK_EQ_U32(count_type("BIND_NAK", -1, -1, -1), 0);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    CHECK_ERR(sc_send(X_ID, 1, true), BR_OK);
    sc_run_ms(500);
    sc_smp_t smp[8];
    unsigned n = sc_samples(P_ID, smp, 8);
    unsigned from_s = 0, from_x = 0;
    for (unsigned i = 0; i < n; i++) {
        from_s += smp[i].src == S_ID;
        from_x += smp[i].src == X_ID;
    }
    CHECK_EQ_U32(from_s, 1);
    CHECK_EQ_U32(from_x, 1);
    sc_skip("race_two_senders_one_group/records_1_variant", "PROTOCOL.md 4.3 line 484, 4.1.2, 4.1.6",
            "BR_RX_RECORDS is a compile-time constant (4): the 'second sender gets status 1 / BIND_NAK with one record' "
            "variant cannot be built at run time; the full-table / no-stream behaviour is covered by "
            "r02b_offers_and_full, r06 and r12");
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 485: bound probe hears a SEEK from its own sender (4.1.3)             */
/* ========================================================================= */

static void scen_race_bound_probe_hears_own_sender_seek(uint64_t seed)
{
    if (!sc_up3(seed, SC_TAP_HEAR_S | SC_TAP_SPEAK_R | SC_TAP_SPEAK_P)) {
        return;
    }
    sc_run_ms(1000);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    const sc_cap_t *seek0 = sc_cap_find(BR_TYPE_SEEK, S_ID, 0);
    CHECK(seek0 != NULL);

    /* (a) an old SEEK replayed where both the relay and the probe hear it */
    br_route_entry_t pr0, pr1;
    CHECK(sc_route(P_ID, S_ID, &pr0));
    unsigned p_records = sc_app_records_of(P_ID);
    sc_tap_replay(seek0);
    sc_run_ms(500);
    sc_q_t qr = sc_q("SEEK", SC_TAP_ID, -1, S_ID);
    CHECK_EQ_U32(sc_q_count(&qr), 2); /* one line per receiver: R and P */
    for (unsigned i = 0; i < 2; i++) {
        const sc_tl_t *t = sc_q_nth(&qr, i);
        CHECK(t != NULL && sc_str_prefix(t->verdict, "drop:"));
    }
    CHECK_EQ_U32(sc_app_records_of(P_ID), p_records);
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    CHECK(sc_route(P_ID, S_ID, &pr1));
    CHECK_EQ_U32(pr1.next_hop, pr0.next_hop);
    CHECK_EQ_U32(pr1.hops, pr0.hops);

    /* (b) S reboots and seeks: the old session is replaced only by the BIND that decrypts under the new Ke_hs */
    if (!sc_reboot(S_ID) || !sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool binding = false;
    for (unsigned i = 0; i < 100000 && !binding; i++) { /* 100 us steps up to 10 s */
        (void)brsim_run_for(&sc.sim, 100);
        binding = sc_snd_state(S_ID) == BR_SND_BINDING;
    }
    CHECK_MSG(binding, "rebooted sender never got a HELLO");
    if (!binding) {
        return;
    }
    /* the BIND is still at least two link delays away from P: nothing may have changed at P yet */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_BOUND, P_ID, -1, -1, -1), 1);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 8000);
    CHECK_MSG(up, "rebooted sender never re-bound");
    sc_run_ms(500);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_BOUND, P_ID, -1, -1, -1), 2);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1); /* replaced, not duplicated */
    sc_smp_t smp[4];
    unsigned n0 = sc_samples(P_ID, smp, 4);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    CHECK_EQ_U32(sc_samples(P_ID, smp, 4), n0 + 1u);
    sc_check_clean(SC_STAT_BIT(BR_STAT_HOP_REPLAY));
}

/* ========================================================================= */
/* row 486: BIND or BIND_ACK lost (4.1.9, 4.1.10)                            */
/* ========================================================================= */

static void race_bind_lost_run(uint64_t seed, unsigned hops, bool lose_bind_ack)
{
    if (!sc_topo_chain(seed, hops - 1u, hops > 4u ? 8u : 4u)) {
        return;
    }
    const uint16_t s_side = hops == 1 ? P_ID : sc_relay_id(0);               /* S's neighbour */
    const uint16_t p_side = hops == 1 ? S_ID : sc_relay_id(hops - 2u);       /* P's neighbour */
    sc_rule_t *ru;
    if (!lose_bind_ack) {
        ru = sc_rule_on("HELLO", s_side, S_ID, "deliver", P_ID, p_side, S_ID, "BIND", 1);
    } else {
        ru = sc_rule_on("BIND", p_side, P_ID, "deliver", S_ID, s_side, P_ID, "BIND_ACK", 1);
    }
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 20000);
    CHECK_MSG(up, "session not established after a lost BIND / BIND_ACK");
    sc_run_ms(500);
    CHECK(ru != NULL && ru->dropped == 1);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1); /* no duplicate record */
    const sc_tl_t *h = first_line("HELLO", s_side, S_ID, P_ID, "deliver");
    uint64_t t_conf = sc_state_time(S_ID, BR_SND_CONFIGURING);
    CHECK(h != NULL && t_conf != UINT64_MAX);
    if (h != NULL && t_conf != UINT64_MAX) {
        CHECK_MSG(t_conf - h->t <= SC_US(br_bind_timeout_ms((uint8_t)hops)),
                  "session must start inside BIND_TIMEOUT(hops) of the HELLO");
    }
    if (lose_bind_ack) {
        /* idempotent: the repeated BIND is answered again, one record only */
        CHECK(count_type("BIND_ACK", P_ID, p_side, P_ID) >= 2);
    }
    sc_check_clean(0);
}

static void scen_race_bind_or_bind_ack_lost(uint64_t seed)
{
    static const unsigned hop_counts[3] = { 1, 2, 4 };
    for (unsigned i = 0; i < 3; i++) {
        race_bind_lost_run(seed, hop_counts[i], false);
        race_bind_lost_run(seed, hop_counts[i], true);
    }
}

/* ========================================================================= */
/* row 487: HELLO lost, SEEK retried (4.1.5, 4.1.8)                          */
/* ========================================================================= */

static void scen_race_hello_lost_seek_retried(uint64_t seed)
{
    if (!sc_topo3(seed) || !sc_tap_add()) {
        return;
    }
    sc_tap_hear(S_ID);
    sc_rule_t *ru = sc_rule_now(S_ID, R_ID, P_ID, "HELLO", 1);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 10000);
    CHECK_MSG(up, "SEEK retry did not lead to a session");
    sc_run_ms(500);
    CHECK(ru != NULL && ru->dropped == 1);
    sc_round_t rd[8];
    unsigned n = sc_seek_rounds(S_ID, rd, 8);
    CHECK_MSG(n >= 2, "S must retry the SEEK after the lost HELLO");
    for (unsigned k = 1; k < n; k++) {
        CHECK_EQ_U32(rd[k].nonce_s, rd[0].nonce_s); /* same nonce_s ... */
        CHECK(rd[k].pre_ctr > rd[k - 1].pre_ctr);   /* ... newer pre_ctr */
    }
    CHECK_MSG(count_type("HELLO", P_ID, R_ID, P_ID) >= 2, "P must answer again");
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    sc_smp_t smp[4];
    unsigned n0 = sc_samples(P_ID, smp, 4);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK); /* both ends derived the same keys (one transcript) */
    sc_run_ms(500);
    CHECK_EQ_U32(sc_samples(P_ID, smp, 4), n0 + 1u);
    CHECK_EQ_U32(sc_stats(P_ID).f.auth_fail, 0);
    sc_skip("race_hello_lost_seek_retried/nonce_p_and_seek_ctr", "PROTOCOL.md 4.3 line 487, 4.1.8",
            "decrypting the unicast HELLO: 'same nonce_p, new seek_ctr' is not observable (P may also have timed out "
            "and made a fresh offer); the end result, one session with matching keys, is asserted");
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 488: seq wraps at 65535 (3.5, 8)                                      */
/* ========================================================================= */

typedef struct {
    uint64_t delivered;
    uint16_t prev_seq;
    uint32_t prev_roc;
    bool     have_prev;
    uint64_t bad_order, wraps, bad_roc;
    uint32_t max_roc;
} wrap_ctx_t;

static wrap_ctx_t g_wrap;

static void wrap_on_samples(void *user, const br_samples_meta_t *meta, const br_mode_t *mode, const uint8_t *samples,
                            size_t samples_len)
{
    (void)user;
    (void)mode;
    (void)samples;
    (void)samples_len;
    wrap_ctx_t *w = &g_wrap;
    w->delivered++;
    if (w->have_prev) {
        if ((int16_t)(uint16_t)(meta->seq - w->prev_seq) <= 0) {
            w->bad_order++;
        }
        bool wrapped = meta->seq < w->prev_seq;
        w->wraps += wrapped;
        uint32_t want_roc = w->prev_roc + (wrapped ? 1u : 0u);
        if (meta->roc != want_roc) {
            w->bad_roc++;
        }
    }
    w->have_prev = true;
    w->prev_seq = meta->seq;
    w->prev_roc = meta->roc;
    if (meta->roc > w->max_roc) {
        w->max_roc = meta->roc;
    }
}

static void scen_race_seq_wrap(uint64_t seed)
{
    sc_reset(seed);
    sc.store_on = false;        /* 66000 frames: no trace store, no app-log reliance */
    sc.allow_overflow = true;
    brsim_set_trace(&sc.sim, NULL, NULL); /* the hash is kept; no per-line parsing for 500k lines */
    memset(&g_wrap, 0, sizeof g_wrap);
    br_node_config_t cp;
    sc_cfg(&cp, P_ID, SC_PROBE);
    cp.app.on_samples = wrap_on_samples;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add_cfg(&cp)) {
        return;
    }
    /* no reordering on the links: 1 ms spacing against 0.3 .. 1.5 ms jitter would make hop_seq go backwards (8.4) */
    brsim_link_t l = sc_link_default();
    l.reorder = false;
    sc_link_set(S_ID, R_ID, &l);
    sc_link_set(R_ID, S_ID, &l);
    sc_link_set(R_ID, P_ID, &l);
    sc_link_set(P_ID, R_ID, &l);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    if (!up) {
        return;
    }
    const unsigned total = 66000; /* one seq per frame of any type: crosses 65535 */
    unsigned errors = 0;
    for (unsigned i = 0; i < total; i++) {
        if (sc_send(S_ID, i & 1u, (i % 8u) == 7u) != BR_OK) {
            errors++;
        }
        sc_run_ms(1);
    }
    sc_run_ms(3000);
    CHECK_EQ_U32(errors, 0);
    CHECK_EQ_U32(g_wrap.delivered, total);
    CHECK_EQ_U32(g_wrap.bad_order, 0);   /* serial arithmetic keeps the order across 65535 -> 0 */
    CHECK_EQ_U32(g_wrap.wraps, 1);
    CHECK_EQ_U32(g_wrap.bad_roc, 0);     /* ROC estimate follows the wrap (A.10) */
    CHECK_EQ_U32(g_wrap.max_roc, 1);
    br_stats_t sp = sc_stats(P_ID), ss = sc_stats(S_ID);
    CHECK_EQ_U32(sp.f.auth_fail, 0);
    CHECK_EQ_U32(sp.f.replay_dropped, 0);
    CHECK_EQ_U32(sp.f.gaps, 0);
    CHECK_EQ_U32(ss.f.gaps, 0);
    sc_skip("race_seq_wrap/reorder_across_wrap_and_pre_wrap_replay", "PROTOCOL.md 4.3 line 488, 3.5, 8, A.10",
            "capture of a UNICAST DATA frame (replay of a pre-wrap frame must fail CCM under the new ROC) and a way to "
            "reorder exactly across the wrap; the wrap itself is driven by 66000 real frames");
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 489: replayed SEEK / HELLO / BIND (8.4)                               */
/* ========================================================================= */

static void scen_race_replayed_presession_frames(uint64_t seed)
{
    if (!sc_up3(seed, SC_TAP_HEAR_S | SC_TAP_SPEAK_R | SC_TAP_SPEAK_P)) {
        return;
    }
    sc_run_ms(1000);
    const sc_cap_t *seek0 = sc_cap_find(BR_TYPE_SEEK, S_ID, 0);
    CHECK(seek0 != NULL);
    br_route_entry_t rr0, pr0, rr1, pr1;
    CHECK(sc_route(R_ID, S_ID, &rr0));
    CHECK(sc_route(P_ID, S_ID, &pr0));
    const unsigned p_records = sc_app_records_of(P_ID);
    const unsigned hello_before = count_type("HELLO", P_ID, -1, P_ID);

    for (unsigned round = 0; round < 2; round++) {
        /* round 0: inside DEDUP_TTL_MS; round 1: after the dedup entries expired (hop_seq / ORIGIN must still hold) */
        sc_tap_replay(seek0);
        sc_run_ms(round == 0 ? 8000u : 1000u);
    }
    sc_q_t qr = sc_q("SEEK", SC_TAP_ID, -1, S_ID);
    CHECK_EQ_U32(sc_q_count(&qr), 4); /* 2 replays x (R, P) */
    for (unsigned i = 0; i < 4; i++) {
        const sc_tl_t *t = sc_q_nth(&qr, i);
        CHECK_MSG(t != NULL && sc_str_prefix(t->verdict, "drop:"), "a replayed SEEK must be dropped, never flooded on");
    }
    sc_q_t qrr = sc_q("SEEK", SC_TAP_ID, R_ID, S_ID);
    for (unsigned i = 0; i < sc_q_count(&qrr); i++) {
        const sc_tl_t *t = sc_q_nth(&qrr, i);
        CHECK_MSG(t != NULL && strcmp(t->verdict, "drop:hop_replay") == 0, "relay drops it as hop_replay (hop_seq not newer)");
    }
    CHECK(sc_stats(R_ID).f.hop_replay >= 2u);
    /* nothing replied, no table change, session untouched */
    CHECK_EQ_U32(count_type("HELLO", P_ID, -1, P_ID), hello_before);
    CHECK_EQ_U32(sc_app_records_of(P_ID), p_records);
    CHECK(sc_route(R_ID, S_ID, &rr1));
    CHECK(sc_route(P_ID, S_ID, &pr1));
    CHECK_EQ_U32(rr1.next_hop, rr0.next_hop);
    CHECK_EQ_U32(rr1.hops, rr0.hops);
    CHECK_EQ_U32(pr1.next_hop, pr0.next_hop);
    CHECK_EQ_U32(pr1.hops, pr0.hops);
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    sc_smp_t smp[4];
    unsigned n0 = sc_samples(P_ID, smp, 4);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    CHECK_EQ_U32(sc_samples(P_ID, smp, 4), n0 + 1u);
    sc_skip("race_replayed_presession_frames/hello_bind_replay", "PROTOCOL.md 4.3 line 489, 8.4",
            "capture of UNICAST HELLO / BIND bytes: the tap can only record broadcasts (the medium delivers a unicast "
            "to its owner only), so replay of those two types cannot be driven; MGMT_RESP is out of scope in phase 1b");
    sc_check_clean(SC_STAT_BIT(BR_STAT_HOP_REPLAY));
}

/* ========================================================================= */
/* row 490: many nodes reboot together (4.1.1, 4.1.8, 4.2)                   */
/* ========================================================================= */

static void scen_race_mass_reboot(uint64_t seed)
{
    static const uint16_t snd[6] = { 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116 };
    static const uint16_t rel[4] = { 0x0121, 0x0122, 0x0123, 0x0124 };
    static const uint16_t prb[2] = { 0x0131, 0x0132 };
    sc_reset(seed);
    sc.node_count_default = 12;
    sc.seek_ttl_default = 6;
    for (unsigned i = 0; i < 6; i++) {
        br_node_config_t c;
        sc_cfg(&c, snd[i], SC_SENDER);
        c.caps = (uint16_t)(c.caps & ~BR_CAP_ARQ); /* records only, see r12b for the stream question */
        c.cold_boot = true; /* every node cold boots at t = 0 */
        if (!sc_add_cfg(&c)) {
            return;
        }
    }
    for (unsigned i = 0; i < 4; i++) {
        if (!sc_add(rel[i], SC_RELAY)) {
            return;
        }
    }
    for (unsigned i = 0; i < 2; i++) {
        if (!sc_add(prb[i], SC_PROBE)) {
            return;
        }
    }
    for (unsigned i = 0; i + 1 < 4; i++) {
        sc_link2(rel[i], rel[i + 1]);
    }
    for (unsigned i = 0; i < 6; i++) {
        sc_link2(snd[i], rel[i / 2u < 3u ? i / 2u : 2u]);
    }
    sc_link2(prb[0], rel[3]);
    sc_link2(prb[1], rel[3]);
    br_mode_t mn;
    sc_mode_noarq(&mn);
    for (unsigned i = 0; i < 6; i++) {
        if (!sc_start(snd[i], 0xFF10, &mn)) {
            return;
        }
    }
    unsigned all_up_ms = 0;
    for (unsigned t = 0; t < 30000; t += 100) {
        sc_run_ms(100);
        unsigned up = 0;
        for (unsigned i = 0; i < 6; i++) {
            up += sc_snd_state(snd[i]) == BR_SND_STREAMING;
        }
        if (up == 6 && all_up_ms == 0) {
            all_up_ms = t + 100;
            break;
        }
    }
    CHECK_MSG(all_up_ms != 0, "not every sender bound within 30 s");
    /* first SEEKs spread over rand(0..BOOT_SPREAD_MS = 600 x 12 ms) */
    uint64_t t_min = UINT64_MAX, t_max = 0;
    for (unsigned i = 0; i < 6; i++) {
        sc_q_t q = sc_q("SEEK", snd[i], -1, snd[i]);
        const sc_tl_t *t = sc_q_nth(&q, 0);
        CHECK(t != NULL);
        if (t != NULL) {
            t_min = t->t < t_min ? t->t : t_min;
            t_max = t->t > t_max ? t->t : t_max;
            CHECK_MSG(t->t <= SC_US(600u * 12u) + 2000u, "first SEEK later than BOOT_SPREAD_MS");
        }
    }
    CHECK_MSG(t_max - t_min >= SC_US(50), "first SEEKs must be spread, not simultaneous");
    CHECK_EQ_U32(sc_prb_live(prb[0], NULL) + sc_prb_live(prb[1], NULL), 6);
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 491: relay on the session path dies (4.2, 11.6)                       */
/* ========================================================================= */

static void scen_race_relay_dies(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 4;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(X_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    /* the second path is dearer and 60 ms per link slower: the first session deterministically goes through R */
    sc_link2_slow(S_ID, X_ID, -80, 60000, 65000);
    sc_link2_slow(X_ID, P_ID, -80, 60000, 65000);
    br_mode_t m;
    sc_mode(&m, BR_MODE_HIGH);
    m.keepalive_ms = 1000; /* SESSION_TIMEOUT 4 s */
    if (!sc_start(S_ID, 0xFF10, &m)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    if (!up) {
        return;
    }
    br_route_entry_t e;
    CHECK(sc_route(S_ID, P_ID, &e));
    CHECK_EQ_U32(e.next_hop, R_ID);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(300);

    /* the relay dies: every link of R goes away */
    const uint64_t t_cut = brsim_now(&sc.sim);
    sc_unlink(S_ID, R_ID);
    sc_unlink(R_ID, P_ID);
    for (unsigned i = 0; i < 200; i++) { /* the button keeps being pressed for 60 s */
        (void)sc_send(S_ID, 1, true);
        sc_run_ms(300);
    }
    /* send failures to R reach LINK_FAIL_MAX: link and routes via R deleted, BR_EVT_LINK_FAIL */
    unsigned lf = sc_app_count(BRSIM_APP_EVENT, S_ID, -1, -1, BR_EVT_LINK_FAIL);
    CHECK_MSG(lf >= 1, "BR_EVT_LINK_FAIL expected after LINK_FAIL_MAX failed unicasts");
    const brsim_app_rec_t *ev = sc_app_nth(BRSIM_APP_EVENT, S_ID, -1, -1, BR_EVT_LINK_FAIL, 0);
    if (ev != NULL) {
        CHECK_EQ_U32(ev->arg & 0xFFFFu, R_ID);
        CHECK_MSG(ev->t_us >= t_cut && ev->t_us <= t_cut + SC_US(10000), "link failure detected within 10 s");
    }
    /* SESSION_TIMEOUT -> re-SEEK -> new session through the second relay */
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK(sc_route(S_ID, P_ID, &e));
    CHECK_EQ_U32(e.next_hop, X_ID);
    CHECK_MSG(count_type("DATA", S_ID, X_ID, S_ID) >= 1, "DATA must flow through the surviving relay");
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    static sc_smp_t smp[256];
    unsigned n = sc_samples(P_ID, smp, 256);
    bool after = false;
    for (unsigned i = 0; i < n; i++) {
        after = after || (smp[i].t > t_cut + SC_US(5000) && smp[i].hops == 2u);
    }
    CHECK_MSG(after, "no sample delivered through the new session");
    sc_skip("race_relay_dies/penalty_list", "PROTOCOL.md 4.3 line 491, 4.2",
            "penalty-list accessor: 'a later HELLO via R ranks last' is not observable");
    sc.allow_overflow = true;
    sc_check_clean(0);
}

/* ========================================================================= */
/* row 493: every probe is FULL (4.1.4)                                      */
/* ========================================================================= */

static void scen_race_every_probe_full(uint64_t seed)
{
    const unsigned n_fill = 2u * BR_RX_RECORDS;
    CHECK_MSG(n_fill <= 8u, "scenario needs 2 x BR_RX_RECORDS filler senders (<= 8 with the demo sizes)");
    if (n_fill > 8u) {
        return;
    }
    sc_reset(seed);
    sc.node_count_default = (uint8_t)(n_fill + 4u);
    if (!sc_add_noarq(S_ID) || !sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE) || !sc_add(X_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    sc_link2(R_ID, X_ID);
    br_mode_t mn;
    sc_mode_noarq(&mn);
    for (unsigned k = 0; k < n_fill; k++) {
        uint16_t id = (uint16_t)(0x0111u + k);
        if (!sc_add_noarq(id)) { /* records only: every probe is FULL for lack of a record */
            return;
        }
        sc_link2(id, R_ID);
    }
    if (!sc_tap_add()) {
        return;
    }
    sc_tap_hear(S_ID);
    /* fill both probes one sender at a time */
    for (unsigned k = 0; k < n_fill; k++) {
        uint16_t id = (uint16_t)(0x0111u + k);
        if (!sc_start(id, 0xFF10, &mn)) {
            return;
        }
        bool up = sc_wait_snd_state(id, BR_SND_STREAMING, 20000);
        CHECK_MSG(up, "filler sender did not bind");
        if (!up) {
            return;
        }
    }
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), BR_RX_RECORDS);
    CHECK_EQ_U32(sc_prb_live(X_ID, NULL), BR_RX_RECORDS);

    const uint64_t t0 = brsim_now(&sc.sim);
    if (!sc_start(S_ID, 0xFF10, &mn)) {
        return;
    }
    sc_run_ms(900000); /* 15 minutes */
    CHECK_MSG(sc_snd_state(S_ID) != BR_SND_STREAMING, "no probe has room: S must not get a session");
    CHECK_EQ_U32(count_type("BIND", S_ID, -1, S_ID), 0);
    sc_round_t rd[64];
    unsigned n = sc_seek_rounds(S_ID, rd, 64);
    CHECK_MSG(n >= 2, "S keeps seeking (about once a minute at most), it does not give up");
    for (unsigned k = 1; k < n; k++) {
        /* FULL backoff rand(0, min(3600, 60 x 2^n)) s, n growing per all-FULL round (n counted from 0 or 1) */
        uint32_t shift = k + 1u < 6u ? k + 1u : 6u;
        uint64_t cap_s = 60u << shift;
        if (cap_s > 3600u) {
            cap_s = 3600u;
        }
        uint64_t gap = rd[k].t - rd[k - 1].t;
        if (gap > SC_US(cap_s * 1000u) + SC_US(5000)) {
            CHECK_MSG(false, "gap between SEEKs exceeds the FULL backoff cap");
            fprintf(stderr, "  round %u gap %llu us, cap %llu s\n", k, (unsigned long long)gap, (unsigned long long)cap_s);
        }
    }
    CHECK(rd[0].t >= t0);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL) + sc_prb_live(X_ID, NULL), n_fill);
    sc_check_clean(0);
}

/* ========================================================================= */

int main(int argc, char **argv)
{
    sc_args(argc, argv);
    sc_run("race_two_probes_one_seek", "PROTOCOL.md 4.3 line 483 (4.1.5, 4.1.7)", scen_race_two_probes_one_seek, false);
    sc_run("race_two_senders_one_group", "PROTOCOL.md 4.3 line 484 (4.1.2, 4.1.6)", scen_race_two_senders_one_group,
           false);
    sc_run("race_bound_probe_hears_own_sender_seek", "PROTOCOL.md 4.3 line 485 (4.1.3)",
           scen_race_bound_probe_hears_own_sender_seek, false);
    sc_run("race_bind_or_bind_ack_lost", "PROTOCOL.md 4.3 line 486 (4.1.9, 4.1.10)", scen_race_bind_or_bind_ack_lost,
           false);
    sc_run("race_hello_lost_seek_retried", "PROTOCOL.md 4.3 line 487 (4.1.5, 4.1.8)", scen_race_hello_lost_seek_retried,
           false);
    sc_run("race_seq_wrap", "PROTOCOL.md 4.3 line 488 (3.5, 8)", scen_race_seq_wrap, true); /* 66000 frames: one run */
    sc_run("race_replayed_presession_frames", "PROTOCOL.md 4.3 line 489 (8.4)", scen_race_replayed_presession_frames,
           false);
    sc_run("race_mass_reboot", "PROTOCOL.md 4.3 line 490 (4.1.1, 4.1.8, 4.2)", scen_race_mass_reboot, false);
    sc_run("race_relay_dies", "PROTOCOL.md 4.3 line 491 (4.2, 11.6)", scen_race_relay_dies, false);
    sc_skip_oos("race_management_relay_dies", "PROTOCOL.md 4.3 line 492 (11.6, 11.10), MGMT");
    sc_run("race_every_probe_full", "PROTOCOL.md 4.3 line 493 (4.1.4)", scen_race_every_probe_full, false);
    sc_skip_oos("race_retired_epoch_rejoin", "PROTOCOL.md 4.3 line 494 (8.5), key rotation / MGMT");
    return tu_summary("test_scen_races");
}
