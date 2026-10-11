// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_scen_rules.c - phase 1b scenarios for the PROTOCOL.md 4.1 rules and
 * 4.2 liveness (README-SCENARIOS.txt section B). One scenario per rule.
 *
 * Unit IDs: S 0x0101 sender, R 0x0102 relay, P 0x0103 probe (group 0xFF10),
 * extra nodes 0x0104.. as the scenario needs. Bench keys, AUTH, FEC off, ARQ on.
 *
 * Injection: sc_rule_*() drops frames at the receiver's bench allowlist (the
 * sender's MAC still reports success, so no 11.6 link-failure accounting is
 * triggered by the injection), the tap records / replays broadcast frames
 * (SEEK floods), sc_reboot() cycles a node. Anything that needs the bytes of a
 * UNICAST frame (HELLO, BIND, ...) or a forged frame is reported as SKIP.
 */
#include "scen_common.h"

#define S_ID  0x0101u
#define R_ID  0x0102u
#define P_ID  0x0103u
#define X_ID  0x0104u /* second relay / second probe / second sender, per scenario */

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
/* r01  SEEK flood (4.1.1, 11.4 steps 9a-9f, 11.5)                           */
/* ========================================================================= */

static void scen_r01_seek_flood(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 4;
    sc.seek_ttl_default = 4;
    br_node_config_t c;
    sc_cfg(&c, S_ID, SC_SENDER);
    c.cold_boot = true;
    if (!sc_add_cfg(&c) || !sc_add(R_ID, SC_RELAY) || !sc_add(X_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, X_ID);
    sc_link2(X_ID, P_ID);
    if (!sc_tap_add()) {
        return;
    }
    sc_tap_hear(S_ID);
    sc_tap_hear(R_ID);
    sc_tap_hear(X_ID);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 10000);
    CHECK_MSG(up, "sender never reached STREAMING across 3 hops");
    sc_run_ms(500);

    /* first SEEK not later than BOOT_SPREAD_MS = 600 x node_count (the lower bound is random and unobservable) */
    const sc_tl_t *t0 = first_line("SEEK", S_ID, R_ID, S_ID, NULL);
    CHECK(t0 != NULL);
    if (t0 != NULL) {
        CHECK_MSG(t0->t <= SC_US(600u * 4u) + 2000u, "first SEEK after BOOT_SPREAD_MS");
    }

    /* the SEEK as it leaves S (frame bytes from the tap) */
    const sc_cap_t *cs = sc_cap_find(BR_TYPE_SEEK, S_ID, 0);
    CHECK(cs != NULL);
    if (cs != NULL) {
        tu_ref_hdr_t h;
        tu_ref_parse(cs->b, &h);
        CHECK_EQ_U32(h.src, S_ID);
        CHECK_EQ_U32(h.dst, 0xFF10);
        CHECK_EQ_U32(h.next, 0xFFFF);
        CHECK_EQ_U32(h.prev, S_ID);
        CHECK_EQ_U32(h.ttl, 4);
        CHECK_EQ_U32(h.hops, 0);
        CHECK_EQ_U32(h.path_cost, 0);
        CHECK_EQ_U32(h.path_mtu, 250);
        CHECK_EQ_U32(h.flags & BR_FLAG_AUTH, BR_FLAG_AUTH);

        /* each relay rebroadcasts after <= RELAY_JITTER_MS with ttl - 1, hops + 1, prev_hop = itself, new hop_seq */
        static const struct {
            uint16_t id;
            uint8_t ttl, hops, cost;
        } relays[2] = { { R_ID, 3, 1, 1 }, { X_ID, 2, 2, 2 } };
        for (unsigned i = 0; i < 2; i++) {
            const sc_cap_t *cr = sc_cap_find(BR_TYPE_SEEK, relays[i].id, 0);
            CHECK(cr != NULL);
            if (cr == NULL) {
                continue;
            }
            tu_ref_hdr_t hr;
            tu_ref_parse(cr->b, &hr);
            CHECK_EQ_U32(hr.src, S_ID);
            CHECK_EQ_U32(hr.prev, relays[i].id);
            CHECK_EQ_U32(hr.next, 0xFFFF);
            CHECK_EQ_U32(hr.ttl, relays[i].ttl);
            CHECK_EQ_U32(hr.hops, relays[i].hops);
            CHECK_EQ_U32(hr.path_cost, relays[i].cost);
            CHECK(hr.path_mtu <= 250u);
            CHECK(hr.hop_seq != h.hop_seq);
            CHECK_EQ_U32(sc_cap_pre_ctr(cr), sc_cap_pre_ctr(cs)); /* same flood, same pre_ctr */
            unsigned copies = 0;
            for (unsigned k = 0; k < sc.n_cap; k++) {
                copies += sc.cap[k].len >= 2 && sc.cap[k].b[1] == BR_TYPE_SEEK && sc.cap[k].from_id == relays[i].id &&
                          sc_cap_pre_ctr(&sc.cap[k]) == sc_cap_pre_ctr(cs);
            }
            CHECK_MSG(copies >= 1 && copies <= BR_FLOOD_REPEAT, "relay rebroadcasts once (FLOOD_REPEAT copies at most)");
        }
        /* jitter: rebroadcast within RELAY_JITTER_MS of the first copy received (+ the tap link delay) */
        const sc_tl_t *rx = first_line("SEEK", S_ID, R_ID, S_ID, "flood");
        const sc_cap_t *cr1 = sc_cap_find(BR_TYPE_SEEK, R_ID, 0);
        CHECK(rx != NULL && cr1 != NULL);
        if (rx != NULL && cr1 != NULL) {
            CHECK(cr1->t >= rx->t);
            CHECK_MSG(cr1->t - rx->t <= SC_US(BR_RELAY_JITTER_MS) + 1600u, "relay jitter above RELAY_JITTER_MS");
        }
    }

    /* the second FLOOD_REPEAT copy / the neighbour's rebroadcast is dropped as a duplicate */
    CHECK(sc_stats(R_ID).f.relay_drop_dedup >= 1u);

    /* S's own echo is dropped silently (9a): no counter, no collision alarm */
    unsigned echoes = count_type("SEEK", R_ID, S_ID, S_ID);
    CHECK(echoes >= 1u);
    sc_q_t qe = sc_q("SEEK", R_ID, S_ID, S_ID);
    qe.verdict = "drop:silent";
    CHECK_EQ_U32(sc_q_count(&qe), echoes);
    CHECK_EQ_U32(sc_stats(S_ID).f.id_collisions, 0);
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_EVENT, S_ID, -1, -1, BR_EVT_ID_COLLISION), 0);

    /* every node installed a reverse route to the origin */
    br_route_entry_t e;
    CHECK(sc_route(R_ID, S_ID, &e));
    CHECK_EQ_U32(e.next_hop, S_ID);
    CHECK_EQ_U32(e.hops, 1);
    CHECK(sc_route(X_ID, S_ID, &e));
    CHECK_EQ_U32(e.next_hop, R_ID);
    CHECK_EQ_U32(e.hops, 2);
    CHECK(sc_route(P_ID, S_ID, &e));
    CHECK_EQ_U32(e.next_hop, X_ID);
    CHECK_EQ_U32(e.hops, 3);
    sc_check_clean(0);
}

/* ========================================================================= */
/* r02  HELLO offer (4.1.2)                                                  */
/* ========================================================================= */

static void scen_r02_hello_offer(uint64_t seed)
{
    sc_reset(seed);
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(X_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    /* The second path is dearer (rssi -80: cost 3 per link) AND slower (60 ms per link = HOP_DELAY_MS), so its copy
     * reaches P at least 120 ms after the send while the cheap copy needs at most 50 ms relay jitter: the first copy
     * and the HELLO window (<= 50 ms) are then independent of the seed, and the HELLO must go via R. */
    sc_link2_slow(S_ID, X_ID, -80, 60000, 65000);
    sc_link2_slow(X_ID, P_ID, -80, 60000, 65000);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    sc_run_ms(500);

    /* P answers once, along the lowest-cost copy (via R), inside rand(0..HELLO_WINDOW_MS) of the first SEEK */
    CHECK_EQ_U32(count_type("HELLO", P_ID, R_ID, P_ID), 1);
    CHECK_EQ_U32(count_type("HELLO", P_ID, X_ID, P_ID), 0);
    const sc_tl_t *seek_at_p = first_line("SEEK", -1, P_ID, S_ID, NULL);
    const sc_tl_t *hello = first_line("HELLO", P_ID, R_ID, P_ID, NULL);
    CHECK(seek_at_p != NULL && hello != NULL);
    if (seek_at_p != NULL && hello != NULL) {
        CHECK(hello->t >= seek_at_p->t);
        CHECK_MSG(hello->t - seek_at_p->t <= SC_US(BR_HELLO_WINDOW_MS) + 1600u, "HELLO later than HELLO_WINDOW_MS");
    }
    /* BIND is unicast along the HELLO route: nothing goes to the dear relay */
    CHECK_EQ_U32(count_type("BIND", S_ID, X_ID, S_ID), 0);
    CHECK_EQ_U32(count_type("BIND_ACK", -1, X_ID, P_ID), 0);
    br_route_entry_t e;
    CHECK(sc_route(S_ID, P_ID, &e));
    CHECK_EQ_U32(e.next_hop, R_ID);
    CHECK_EQ_U32(e.hops, 2);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    sc_skip("r02_hello_offer/hello_max_frame_and_offer_expiry", "PROTOCOL.md 4.1.2 line 349",
            "decrypting the unicast HELLO (max_frame) and an OFFERED-table accessor (expiry BIND_TIMEOUT); expiry is "
            "covered indirectly by r07_offer_timeout");
    sc_check_clean(0);
}

/* 5 senders SEEK at once: PROBE_OFFERS_MAX and a full record table (4.1.2) */
static void scen_r02b_offers_and_full(uint64_t seed)
{
    const unsigned n_send = BR_RX_RECORDS + 1u;
    sc_reset(seed);
    sc.node_count_default = (uint8_t)(n_send + 2u);
    if (!sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(R_ID, P_ID);
    for (unsigned k = 0; k < n_send; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (!sc_add_noarq(id)) { /* records only: independent of when a stream is taken (see r12b) */
            return;
        }
        sc_link2(id, R_ID);
    }
    br_mode_t m;
    sc_mode_noarq(&m);
    for (unsigned k = 0; k < n_send; k++) {
        if (!sc_start((uint16_t)(0x0110u + k), 0xFF10, &m)) {
            return;
        }
    }
    sc_run_ms(30000);
    unsigned streaming = 0, loser = 0;
    uint16_t loser_id = 0;
    for (unsigned k = 0; k < n_send; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (sc_snd_state(id) == BR_SND_STREAMING) {
            streaming++;
        } else {
            loser++;
            loser_id = id;
        }
    }
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), BR_RX_RECORDS); /* the table is full ... */
    CHECK_EQ_U32(streaming, BR_RX_RECORDS);               /* ... and exactly that many senders got a session */
    CHECK_EQ_U32(loser, 1);
    CHECK_EQ_U32(count_type("BIND_ACK", R_ID, loser_id, P_ID), 0); /* the sender without a session never got a BIND_ACK */
    sc_skip("r02b_offers_and_full/oldest_offer_replaced", "PROTOCOL.md 4.1.2 line 349",
            "OFFERED-table accessor (br_offer_t) or a hook to hold a BIND so the replaced oldest offer can be seen");
    sc_check_clean(0);
}

/* ========================================================================= */
/* r03  bound probe, new SEEK (4.1.3)                                        */
/* ========================================================================= */

static struct {
    unsigned live, streaming;
    unsigned bound_records;
    bool fired;
} g_r03;

static void r03_hook(void *u)
{
    (void)u;
    unsigned counts[5];
    g_r03.live = sc_prb_live(P_ID, counts);
    g_r03.streaming = counts[BR_PRB_STREAMING];
    g_r03.bound_records = sc_app_count(BRSIM_APP_BOUND, P_ID, -1, -1, -1);
    g_r03.fired = true;
}

static void scen_r03_bound_probe_new_seek(uint64_t seed)
{
    if (!sc_up3(seed, SC_TAP_HEAR_S | SC_TAP_SPEAK_R)) {
        return;
    }
    sc_run_ms(1000);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);

    /* (a) replay S's first SEEK bytes at the relay */
    const sc_cap_t *seek0 = sc_cap_find(BR_TYPE_SEEK, S_ID, 0);
    CHECK(seek0 != NULL);
    unsigned p_records = sc_app_records_of(P_ID);
    unsigned hello_before = count_type("HELLO", P_ID, -1, P_ID);
    br_stats_t r0 = sc_stats(R_ID);
    sc_tap_replay(seek0);
    sc_run_ms(500);
    br_stats_t r1 = sc_stats(R_ID);
    CHECK_MSG(r1.f.hop_replay + r1.f.relay_drop_dedup + r1.f.relay_drop_stale >
                  r0.f.hop_replay + r0.f.relay_drop_dedup + r0.f.relay_drop_stale,
              "a replayed SEEK must be dropped by the relay (hop_replay / dedup / stale)");
    const sc_tl_t *rep = first_line("SEEK", SC_TAP_ID, R_ID, S_ID, NULL);
    CHECK(rep != NULL);
    if (rep != NULL) {
        CHECK_MSG(sc_str_prefix(rep->verdict, "drop:"), "replayed SEEK must not be flooded on");
    }
    CHECK_EQ_U32(sc_app_records_of(P_ID), p_records);
    CHECK_EQ_U32(count_type("HELLO", P_ID, -1, P_ID), hello_before);
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);

    /* (b) S reboots and seeks again; the first BIND is lost on R -> P */
    memset(&g_r03, 0, sizeof g_r03);
    sc_rule_t *ru = sc_rule_on("HELLO", R_ID, S_ID, "deliver", P_ID, R_ID, S_ID, "BIND", 1);
    if (ru != NULL) {
        ru->hook = r03_hook;
    }
    if (!sc_reboot(S_ID) || !sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 8000);
    CHECK_MSG(up, "rebooted sender never re-bound");
    sc_run_ms(500);
    CHECK(ru != NULL && ru->dropped == 1);
    CHECK_MSG(g_r03.fired, "BIND drop hook did not run");
    CHECK_MSG(g_r03.live == 1 && g_r03.streaming == 1, "old session must stay STREAMING while the new BIND is lost");
    CHECK_EQ_U32(g_r03.bound_records, 1);
    CHECK_MSG(count_type("HELLO", P_ID, -1, P_ID) > hello_before, "P answers the new SEEK with a HELLO");
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);              /* one record: the new session replaced the old */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_BOUND, P_ID, -1, -1, -1), 2);
    CHECK_MSG(count_type("BIND", S_ID, R_ID, S_ID) >= 3, "first session BIND + the lost BIND + its retry");
    sc_smp_t before[8];
    unsigned nb = sc_samples(P_ID, before, 8);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    CHECK_EQ_U32(sc_samples(P_ID, before, 8), nb + 1u);
    sc_skip("r03_bound_probe_new_seek/new_session_id_and_keys", "PROTOCOL.md 4.1.3 line 361",
            "session_id / key accessor (the new session_id and 'old keys unchanged' are not observable; the BIND "
            "replacing the record is seen through on_bound and the record count)");
    sc_check_clean(SC_STAT_BIT(BR_STAT_HOP_REPLAY));
}

/* ========================================================================= */
/* r04  first HELLO wins (4.1.4)                                             */
/* ========================================================================= */

static void scen_r04_first_hello_wins(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 4;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE) || !sc_add(X_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    sc_link2(R_ID, X_ID);
    sc_link2_delay(R_ID, X_ID, 3000, 6000); /* the second probe's links are slower */
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    sc_run_ms(1500);

    CHECK_MSG(count_type("HELLO", R_ID, S_ID, -1) >= 2, "both probes answer");
    const sc_tl_t *h1 = first_line("HELLO", R_ID, S_ID, -1, NULL);
    const sc_tl_t *b1 = first_line("BIND", S_ID, R_ID, S_ID, NULL);
    CHECK(h1 != NULL && b1 != NULL);
    if (h1 != NULL && b1 != NULL) {
        CHECK_EQ_U32(b1->dst, h1->src);   /* BIND goes to the probe whose HELLO came first */
        CHECK(b1->t >= h1->t);
        CHECK_MSG(b1->t - h1->t <= 1600u, "BIND must follow the first status-0 HELLO at once");
        uint16_t other = h1->src == P_ID ? X_ID : P_ID;
        CHECK_EQ_U32(sc_q_count(&(sc_q_t){ "BIND", -1, -1, S_ID, other, NULL, 0, UINT64_MAX }), 0);
        CHECK_EQ_U32(sc_prb_live(h1->src, NULL), 1);
        CHECK_EQ_U32(sc_prb_live(other, NULL), 0); /* the loser's offer expired, no session */
    }
    sc_skip("r04_first_hello_wins/candidates_penalty_and_full", "PROTOCOL.md 4.1.4 line 365",
            "penalty-list accessor (candidate ranking); the all-FULL backoff variant is run by "
            "race_every_probe_full, BIND_NAK fallback by r06");
    sc_check_clean(0);
}

/* ========================================================================= */
/* r05  BIND unicast (4.1.5, 8.2)                                            */
/* ========================================================================= */

static void scen_r05_bind_unicast(uint64_t seed)
{
    if (!sc_up3(seed, SC_TAP_HEAR_S)) {
        return;
    }
    sc_run_ms(300);
    CHECK_MSG(count_type("BIND", S_ID, R_ID, S_ID) >= 1 && count_type("BIND", R_ID, P_ID, S_ID) >= 1,
              "BIND travels S -> R -> P");
    CHECK_MSG(count_type("BIND_ACK", P_ID, R_ID, P_ID) >= 1 && count_type("BIND_ACK", R_ID, S_ID, P_ID) >= 1,
              "BIND_ACK travels P -> R -> S");
    CHECK_EQ_U32(count_type("BIND", S_ID, -1, S_ID), count_type("BIND", S_ID, R_ID, S_ID)); /* only toward the next hop */
    CHECK_MSG(sc_cap_find(BR_TYPE_BIND, -1, 0) == NULL, "BIND must not be broadcast");
    uint8_t seq_p[16];
    unsigned kp = sc_state_seq(P_ID, seq_p, 16);
    static const uint8_t want[] = { BR_PRB_BOUND };
    CHECK(sc_subseq(seq_p, kp, want, 1));
    /* both ends hold identical Ke_s2p / Ke_p2s: a DATA decrypts at P and its ACK decrypts at S */
    sc_smp_t smp[4];
    unsigned n0 = sc_samples(P_ID, smp, 4);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    CHECK_EQ_U32(sc_samples(P_ID, smp, 4), n0 + 1u);
    CHECK_EQ_U32(smp[n0].b0, 1);
    CHECK_EQ_U32(sc_stats(P_ID).f.auth_fail, 0);
    CHECK_EQ_U32(sc_stats(S_ID).f.auth_fail, 0);
    CHECK(sc_acked_has(S_ID, smp[n0].seq));
    sc_check_clean(0);
}

/* ========================================================================= */
/* r06  BIND mismatch and NAK (4.1.6)                                        */
/* ========================================================================= */

static void scen_r06_bind_nak_when_streams_taken(uint64_t seed)
{
    const uint16_t s3 = 0x0105u, s4 = 0x0106u, r3 = 0x0107u; /* S3 reaches P through its own relay R3 */
    const unsigned n_fill = BR_RX_STREAMS - 1u;
    CHECK_MSG(BR_RX_STREAMS >= 2u && BR_RX_RECORDS > BR_RX_STREAMS, "scenario needs 2+ streams and a spare record");
    if (BR_RX_STREAMS < 2u || BR_RX_RECORDS <= BR_RX_STREAMS) {
        return;
    }
    sc_reset(seed);
    sc.node_count_default = (uint8_t)(n_fill + 5u);
    if (!sc_add(R_ID, SC_RELAY) || !sc_add(r3, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(R_ID, P_ID);
    sc_link2(r3, P_ID);
    for (unsigned k = 0; k < n_fill; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (!sc_add(id, SC_SENDER)) {
            return;
        }
        sc_link2(id, R_ID);
    }
    if (!sc_add(s3, SC_SENDER) || !sc_add(s4, SC_SENDER)) {
        return;
    }
    sc_link2(s3, r3);
    sc_link2(s4, R_ID);
    /* all but one stream are taken: those fillers bind AND send their first DATA */
    for (unsigned k = 0; k < n_fill; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (!sc_start(id, 0xFF10, NULL)) {
            return;
        }
        bool up = sc_wait_snd_state(id, BR_SND_STREAMING, 5000);
        CHECK_MSG(up, "filler sender never reached STREAMING");
        if (!up) {
            return;
        }
        CHECK_ERR(sc_send(id, 1, true), BR_OK);
        sc_run_ms(300);
    }
    /* S3 gets its HELLO (one stream is free), its first two BINDs are lost on R3 -> P (S4 is not affected) ... */
    sc_rule_t *ru = sc_rule_on("HELLO", r3, s3, "deliver", P_ID, r3, s3, "BIND", 2);
    if (ru == NULL || !sc_start(s3, 0xFF10, NULL)) {
        return;
    }
    for (unsigned i = 0; i < 4000 && ru->dropped == 0; i++) {
        sc_run_ms(1);
    }
    CHECK_MSG(ru->dropped >= 1, "the first BIND of S3 was never dropped (S3 got no status-0 HELLO)");
    /* ... meanwhile S4 takes the last stream: it binds and sends its first DATA (BIND_RETRY(2) = 120 ms) */
    if (!sc_start(s4, 0xFF10, NULL)) {
        return;
    }
    bool up4 = sc_wait_snd_state(s4, BR_SND_STREAMING, 3000);
    CHECK_MSG(up4, "S4 never reached STREAMING");
    CHECK_ERR(sc_send(s4, 1, true), BR_OK);
    sc_run_ms(5000);
    CHECK_EQ_U32(ru->dropped, 2);
    /* the retried BIND of S3 finds the stream gone: BIND_NAK (busy) to S3, which restarts SEEK */
    CHECK_MSG(count_type("BIND_NAK", r3, s3, P_ID) >= 1, "P must answer the late BIND with BIND_NAK");
    CHECK_MSG(sc_snd_state(s3) != BR_SND_STREAMING, "S3 must not get a session");
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), BR_RX_STREAMS); /* fillers + S4 */
    sc_smp_t smp[8];
    unsigned n = sc_samples(P_ID, smp, 8);
    unsigned from4 = 0;
    for (unsigned i = 0; i < n; i++) {
        from4 += smp[i].src == s4;
    }
    CHECK_EQ_U32(from4, 1);
    sc_skip("r06_bind_mismatch/wrong_nonces_and_corrupt_ciphertext", "PROTOCOL.md 4.1.6 line 381",
            "a way to capture a UNICAST BIND and rebuild hop_tag / CRC (or a frame forge helper with the session keys) "
            "to inject a BIND with wrong nonces or a corrupted ciphertext byte; the BIND_NAK reason byte (1 busy) is not "
            "visible either (only the BIND_NAK type in the trace)");
    sc_check_clean(0);
}

/* ========================================================================= */
/* r07  offer timeout (4.1.7)                                                */
/* ========================================================================= */

static void r07_run(uint64_t seed, uint32_t bind_path_delay_us, bool expect_bound)
{
    sc_reset(seed);
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_link2(R_ID, P_ID);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    /* Step finely until the HELLO reaches S; the BIND leaves S in the same instant, so R -> P is slowed down
     * before R forwards it (>= 300 us later). SEEK / HELLO were fast, the BIND and its retries are slow. */
    bool got_hello = false;
    for (unsigned i = 0; i < 100000 && !got_hello; i++) {
        (void)brsim_run_for(&sc.sim, 50);
        got_hello = count_type("HELLO", R_ID, S_ID, P_ID) > 0;
    }
    CHECK_MSG(got_hello, "no HELLO reached the sender");
    if (!got_hello) {
        return;
    }
    const uint64_t t_hello = brsim_now(&sc.sim);
    sc_link_dir_delay(R_ID, P_ID, bind_path_delay_us, bind_path_delay_us);
    if (expect_bound) {
        bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 6000);
        CHECK_MSG(up, "BIND inside BIND_TIMEOUT(2) must be accepted");
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
        CHECK(count_type("BIND_ACK", P_ID, R_ID, P_ID) >= 1);
    } else {
        /* the BIND and all its retries reach P between 1.0 and 1.4 s after its HELLO, BIND_TIMEOUT(2) is 890 ms */
        (void)brsim_run_until(&sc.sim, t_hello + SC_US(1500));
        CHECK_MSG(count_type("BIND", R_ID, P_ID, S_ID) >= 1, "the late BIND does reach P");
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 0);
        CHECK_EQ_U32(count_type("BIND_ACK", P_ID, -1, P_ID), 0); /* an expired offer / LISTENING ignores a BIND naming it */
        CHECK(sc_snd_state(S_ID) != BR_SND_STREAMING);
    }
    sc_check_clean(0);
}

static void scen_r07_offer_timeout(uint64_t seed)
{
    CHECK_EQ_U32(br_bind_timeout_ms(2), 890);
    r07_run(seed, 1000000u, false);
}

static void scen_r07b_bind_within_timeout(uint64_t seed)
{
    r07_run(seed, 400000u, true);
}

/* ========================================================================= */
/* r08  SEEK retry backoff (4.1.8)                                           */
/* ========================================================================= */

static void scen_r08_seek_retry_backoff(uint64_t seed)
{
    sc_reset(seed);
    sc.node_count_default = 2;
    if (!sc_add(S_ID, SC_SENDER) || !sc_add(R_ID, SC_RELAY) || !sc_tap_add()) {
        return;
    }
    sc_link2(S_ID, R_ID);
    sc_tap_hear(S_ID);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    sc_run_ms(120000);
    sc_round_t rd[32];
    unsigned n = sc_seek_rounds(S_ID, rd, 32);
    CHECK_MSG(n >= 6, "a SEEK sender never gives up: at least 6 floods in 120 s");
    if (n < 6) {
        return;
    }
    for (unsigned k = 1; k < n; k++) {
        CHECK_EQ_U32(rd[k].nonce_s, rd[0].nonce_s); /* same nonce_s ... */
        CHECK(rd[k].pre_ctr > rd[k - 1].pre_ctr);   /* ... new pre_ctr */
        uint64_t gap = rd[k].t - rd[k - 1].t;
        uint64_t lo = SC_US(br_seek_base_ms(BR_SEEK_TTL_DEFAULT)) - 3000u;
        /* n is 0 or 1 for the first retry depending on how the spec's "n" is counted: allow either */
        uint64_t hi = SC_US(br_seek_base_ms(BR_SEEK_TTL_DEFAULT) + br_seek_jitter_max_ms((uint8_t)(k + 1u))) + 3000u;
        if (gap < lo || gap > hi) {
            CHECK_MSG(false, "SEEK retry gap outside [SEEK_BASE_MS, SEEK_BASE_MS + min(60000, 600 x 2^n)]");
            fprintf(stderr, "  round %u gap %llu us, allowed [%llu, %llu]\n", k, (unsigned long long)gap,
                    (unsigned long long)lo, (unsigned long long)hi);
        }
    }
    CHECK_MSG(rd[n - 1].t + SC_US(62000) >= brsim_now(&sc.sim), "still flooding at the end of the run (cap about 1 / min)");
    const brsim_app_rec_t *ev = sc_app_nth(BRSIM_APP_EVENT, S_ID, -1, -1, BR_EVT_NO_PROBE, 0);
    CHECK(ev != NULL);
    if (ev != NULL) {
        CHECK_EQ_U32(ev->arg, 0xFF10);
        CHECK_MSG(ev->t_us + 3000u >= rd[4].t, "BR_EVT_NO_PROBE is raised after the 5th attempt");
    }
    sc_skip("r08_seek_retry_backoff/offered_probe_resends_hello", "PROTOCOL.md 4.1.8 line 387",
            "decrypting the unicast HELLO (same nonce_p, new seek_ctr); the lost-HELLO retry is run end to end by "
            "race_hello_lost_seek_retried");
    sc_check_clean(0);
}

/* ========================================================================= */
/* r09  BIND retry, idempotent BIND_ACK (4.1.9)                              */
/* ========================================================================= */

static void scen_r09_bind_retry_idempotent(uint64_t seed)
{
    if (!sc_topo3(seed)) {
        return;
    }
    sc_rule_t *ru = sc_rule_on("HELLO", R_ID, S_ID, "deliver", S_ID, R_ID, P_ID, "BIND_ACK", 2);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING after losing two BIND_ACKs");
    sc_run_ms(300);
    CHECK(ru != NULL && ru->dropped == 2);
    sc_q_t qb = sc_q("BIND", S_ID, R_ID, S_ID);
    CHECK_EQ_U32(sc_q_count(&qb), 3); /* the BIND and two retries */
    const sc_tl_t *b0 = sc_q_nth(&qb, 0), *b1 = sc_q_nth(&qb, 1), *b2 = sc_q_nth(&qb, 2);
    if (b0 != NULL && b1 != NULL && b2 != NULL) {
        uint64_t want = SC_US(br_bind_retry_ms(2)); /* hops 2: 120 ms */
        CHECK_MSG(b1->t - b0->t + 4000u >= want && b1->t - b0->t <= want + 4000u, "BIND_RETRY(2) = 120 ms");
        CHECK_MSG(b2->t - b1->t + 4000u >= want && b2->t - b1->t <= want + 4000u, "BIND_RETRY(2) = 120 ms");
    }
    CHECK_EQ_U32(count_type("BIND_ACK", P_ID, R_ID, P_ID), count_type("BIND", R_ID, P_ID, S_ID)); /* each answered */
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);              /* no second record */
    uint8_t seq_s[16];
    unsigned ks = sc_state_seq(S_ID, seq_s, 16);
    CHECK_EQ_U32(ks, 4);                                   /* the session started once, on the first BIND_ACK that arrived */
    sc_skip("r09_bind_retry_idempotent/srtt_seeded", "PROTOCOL.md 4.1.9 line 400, 7", "SRTT accessor");
    sc_check_clean(0);
}

/* ========================================================================= */
/* r10  BIND_TIMEOUT margin (4.1.10)                                         */
/* ========================================================================= */

static void scen_r10_bind_timeout_margin(uint64_t seed)
{
    static const struct {
        unsigned hops;
        uint32_t retry, timeout, needed;
    } tab[4] = { { 1, 60, 470, 350 }, { 2, 120, 890, 650 }, { 4, 240, 1730, 1250 }, { 8, 480, 3410, 2450 } };
    for (unsigned i = 0; i < 4; i++) {
        const unsigned hops = tab[i].hops;
        CHECK_EQ_U32(br_bind_retry_ms((uint8_t)hops), tab[i].retry);
        CHECK_EQ_U32(br_bind_timeout_ms((uint8_t)hops), tab[i].timeout);
        CHECK(br_bind_timeout_ms((uint8_t)hops) > tab[i].needed);

        if (!sc_topo_chain(seed, hops - 1u, hops > 4u ? 8u : 4u)) {
            return;
        }
        const uint16_t upstream = hops == 1 ? S_ID : sc_relay_id(hops - 2u);
        const uint16_t first_hop = hops == 1 ? P_ID : sc_relay_id(0);
        /* all BIND retries but the last are lost at the probe's door (silent: no 11.6 failure accounting) */
        sc_rule_t *ru = sc_rule_on("HELLO", first_hop, S_ID, "deliver", P_ID, upstream, S_ID, "BIND", 3);
        if (!sc_start(S_ID, 0xFF10, NULL)) {
            return;
        }
        bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 20000);
        CHECK_MSG(up, "BIND delivered on the last retry must still start the session");
        sc_run_ms(500);
        CHECK(ru != NULL && ru->dropped == 3);
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1); /* P was still OFFERED when the last BIND arrived */
        const sc_tl_t *h = first_line("HELLO", first_hop, S_ID, P_ID, "deliver");
        uint64_t t_conf = sc_state_time(S_ID, BR_SND_CONFIGURING);
        CHECK(h != NULL && t_conf != UINT64_MAX);
        if (h != NULL && t_conf != UINT64_MAX) {
            uint64_t dt = t_conf - h->t;
            CHECK_MSG(dt <= SC_US(tab[i].timeout), "session started later than BIND_TIMEOUT(hops) after the HELLO");
            CHECK_MSG(dt + 8000u >= SC_US(3u * tab[i].retry), "three BIND retries are spaced by BIND_RETRY(hops)");
        }
        sc_check_clean(0);
    }
}

/* ========================================================================= */
/* r11  session_id (4.1.11)                                                  */
/* ========================================================================= */

static void scen_r11_session_cycles(uint64_t seed)
{
    if (!sc_up3(seed, 0)) {
        return;
    }
    for (unsigned cycle = 1; cycle < 20; cycle++) {
        br_err_t rc = br_node_close(sc_pl(S_ID), sc_n(S_ID)->sess, BR_CLOSE_NORMAL);
        CHECK_ERR(rc, BR_OK);
        sc_kick();
        sc_run_ms(300);
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 0); /* CLOSE frees the probe record */
        if (!sc_start(S_ID, 0xFF10, NULL)) {
            return;
        }
        bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 8000);
        CHECK_MSG(up, "re-seek after CLOSE did not reach STREAMING");
        if (!up) {
            return;
        }
        CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    }
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_BOUND, P_ID, -1, -1, S_ID), 20);
    sc_check_clean(0);
}

/* ========================================================================= */
/* r12  capacity (4.1.12)                                                    */
/* ========================================================================= */

static void scen_r12_capacity_full(uint64_t seed)
{
    CHECK_MSG(BR_RX_RECORDS == 4u && BR_RX_STREAMS == 2u, "scenario is written for the demo sizes (4 records, 2 streams)");
    if (BR_RX_RECORDS != 4u || BR_RX_STREAMS != 2u) {
        return;
    }
    const uint16_t a1 = 0x0101, a2 = 0x0104, a3 = 0x0105; /* ARQ senders */
    const uint16_t n1 = 0x0106, n2 = 0x0107, n3 = 0x0108; /* senders without ARQ */
    sc_reset(seed);
    sc.node_count_default = 8;
    if (!sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(R_ID, P_ID);
    static const uint16_t ids[6] = { 0x0101, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108 };
    for (unsigned k = 0; k < 6; k++) {
        br_node_config_t c;
        sc_cfg(&c, ids[k], SC_SENDER);
        if (k >= 3) {
            c.caps = (uint16_t)(c.caps & ~BR_CAP_ARQ);
        }
        if (!sc_add_cfg(&c)) {
            return;
        }
        sc_link2(ids[k], R_ID);
    }
    br_mode_t m_arq, m_noarq;
    sc_mode(&m_arq, BR_MODE_HIGH);
    sc_mode(&m_noarq, BR_MODE_HIGH);
    m_noarq.arq = 0;

    /* two ARQ senders take both streams at their first DATA */
    for (unsigned k = 0; k < 2; k++) {
        if (!sc_start(ids[k], 0xFF10, &m_arq)) {
            return;
        }
        bool up = sc_wait_snd_state(ids[k], BR_SND_STREAMING, 5000);
        CHECK_MSG(up, "ARQ sender never reached STREAMING");
        if (!up) {
            return;
        }
        CHECK_ERR(sc_send(ids[k], 1, true), BR_OK);
        sc_run_ms(300);
    }
    /* a third ARQ sender: HELLO status 1 (no free stream): no BIND ever sent */
    if (!sc_start(a3, 0xFF10, &m_arq)) {
        return;
    }
    sc_run_ms(8000);
    CHECK_EQ_U32(count_type("BIND", a3, R_ID, a3), 0);
    CHECK(sc_snd_state(a3) != BR_SND_STREAMING);
    /* senders without ARQ / FEC need a record but no stream */
    for (unsigned k = 3; k < 5; k++) {
        if (!sc_start(ids[k], 0xFF10, &m_noarq)) {
            return;
        }
        bool up = sc_wait_snd_state(ids[k], BR_SND_STREAMING, 8000);
        CHECK_MSG(up, "sender without ARQ must get a session while a record is free");
        CHECK_ERR(sc_send(ids[k], 1, false), BR_OK);
        sc_run_ms(300);
    }
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 4);
    /* a fifth sender (any caps): HELLO status 1 (no record) */
    if (!sc_start(n3, 0xFF10, &m_noarq)) {
        return;
    }
    sc_run_ms(8000);
    CHECK_EQ_U32(count_type("BIND", n3, R_ID, n3), 0);
    CHECK(sc_snd_state(n3) != BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 4);

    /* streams and records are held until CLOSE: close one ARQ sender and one other, the waiters get in */
    CHECK_ERR(br_node_close(sc_pl(a1), sc_n(a1)->sess, BR_CLOSE_NORMAL), BR_OK);
    CHECK_ERR(br_node_close(sc_pl(n1), sc_n(n1)->sess, BR_CLOSE_NORMAL), BR_OK);
    sc_kick();
    sc_run_ms(500);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 2);
    bool got_a3 = false, got_n3 = false;
    for (unsigned t = 0; t < 6000 && !(got_a3 && got_n3); t++) { /* FULL backoff is up to 60 x 2^n s */
        sc_run_ms(100);
        got_a3 = sc_snd_state(a3) == BR_SND_STREAMING;
        got_n3 = sc_snd_state(n3) == BR_SND_STREAMING;
    }
    CHECK_MSG(got_a3, "the waiting ARQ sender never got the freed stream");
    CHECK_MSG(got_n3, "the waiting sender never got the freed record");
    if (got_a3) {
        sc_smp_t smp[16];
        unsigned n0 = sc_samples(P_ID, smp, 16);
        CHECK_ERR(sc_send(a3, 1, true), BR_OK);
        sc_run_ms(500);
        CHECK_EQ_U32(sc_samples(P_ID, smp, 16), n0 + 1u);
    }
    (void)a2;
    (void)n2;
    sc.allow_overflow = true; /* long run: the app log may fill */
    sc_check_clean(0);
}

/* 4.1.12 literal reading: a stream is taken at the FIRST DATA, not at bind time */
static void scen_r12b_stream_taken_at_first_data(uint64_t seed)
{
    const unsigned n = BR_RX_STREAMS + 1u; /* ARQ senders, one more than there are streams */
    CHECK_MSG(n + 2u <= SC_MAX_NODES, "too many nodes");
    sc_reset(seed);
    sc.node_count_default = (uint8_t)(n + 2u);
    if (!sc_add(R_ID, SC_RELAY) || !sc_add(P_ID, SC_PROBE)) {
        return;
    }
    sc_link2(R_ID, P_ID);
    for (unsigned k = 0; k < n; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (!sc_add(id, SC_SENDER)) {
            return;
        }
        sc_link2(id, R_ID);
    }
    /* "Full is decided once, at HELLO: no free record, or no free stream" and streams are taken at the first
     * DATA (4.1.12), so ARQ senders that have not sent DATA yet hold no stream: all of them bind. */
    for (unsigned k = 0; k < n; k++) {
        uint16_t id = (uint16_t)(0x0110u + k);
        if (!sc_start(id, 0xFF10, NULL)) {
            return;
        }
        bool up = sc_wait_snd_state(id, BR_SND_STREAMING, 5000);
        CHECK_MSG(up, "4.1.12: a stream is taken at the first DATA; an ARQ sender that has not sent DATA must still bind");
        if (!up) {
            return;
        }
    }
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), n);
    /* the first BR_RX_STREAMS senders send DATA and take the streams; the last one finds none */
    for (unsigned k = 0; k < BR_RX_STREAMS; k++) {
        CHECK_ERR(sc_send((uint16_t)(0x0110u + k), 1, true), BR_OK);
    }
    sc_run_ms(1000);
    sc_smp_t smp[8];
    CHECK_EQ_U32(sc_samples(P_ID, smp, 8), BR_RX_STREAMS);
    sc_check_clean(0);
}

/* ========================================================================= */
/* r13  unknown session (4.1.13)                                             */
/* ========================================================================= */

static void scen_r13_unknown_session(uint64_t seed)
{
    if (!sc_up3(seed, 0)) {
        return;
    }
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(300);
    CHECK_ERR(sc_send(S_ID, 0, true), BR_OK);
    sc_run_ms(300);
    if (!sc_reboot(P_ID)) { /* records lost */
        return;
    }
    const uint64_t t_reboot = brsim_now(&sc.sim);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 0);
    bool left_streaming = false;
    for (unsigned i = 0; i < 100; i++) { /* S keeps pressing for 30 s */
        (void)sc_send(S_ID, 1, true);
        sc_run_ms(300);
    }
    /* a state record with old state STREAMING proves the sender left STREAMING (the dip can be shorter than the poll) */
    left_streaming = sc_app_count(BRSIM_APP_STATE, S_ID, -1, BR_SND_STREAMING, -1) >= 1u;
    CHECK_MSG(sc_stats(P_ID).f.unknown_session >= 1u, "P must count DATA for an unknown (src_id, session_id) (N27)");
    /* bench profile: CLOSE(2) at most once per second per peer */
    sc_q_t qc = sc_q("CLOSE", P_ID, R_ID, P_ID);
    qc.t0 = t_reboot;
    unsigned nc = sc_q_count(&qc);
    for (unsigned i = 1; i < nc; i++) {
        const sc_tl_t *a = sc_q_nth(&qc, i - 1), *b = sc_q_nth(&qc, i);
        CHECK_MSG(a != NULL && b != NULL && b->t - a->t + 4000u >= SC_US(BR_CLOSE_UNKNOWN_GAP_MS),
                  "CLOSE(2) more often than once per second per peer");
    }
    /* the sender notices (CLOSE(2) or ARQ_MAX_RETRIES unanswered ACK_REQ), closes and re-SEEKs */
    CHECK_MSG(left_streaming, "sender kept streaming into a probe that lost its session");
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    sc_smp_t smp[8];
    unsigned n = sc_samples(P_ID, smp, 8);
    bool after = false;
    for (unsigned i = 0; i < n; i++) {
        after = after || smp[i].t > t_reboot;
    }
    CHECK_MSG(after, "no sample delivered through the re-established session");
    /* a CLOSE(2) from a probe that lost its keys cannot be authenticated by the sender: allow auth_fail at S only */
    sc.allow_overflow = true;
    sc_check_clean(SC_STAT_BIT(BR_STAT_AUTH_FAIL));
}

/* ========================================================================= */
/* r14  nonce uniqueness (4.1.14)                                            */
/* ========================================================================= */

static uint32_t r14_first_nonce(uint64_t seed, uint32_t tx, uint32_t pre, uint32_t *first_pre)
{
    sc_reset(seed);
    sc.node_count_default = 2;
    br_node_config_t c;
    sc_cfg(&c, S_ID, SC_SENDER);
    c.txseq_start = tx;
    c.preseq_start = pre;
    if (!sc_add_cfg(&c) || !sc_add(R_ID, SC_RELAY) || !sc_tap_add()) {
        return 0;
    }
    sc_link2(S_ID, R_ID);
    sc_tap_hear(S_ID);
    if (!sc_start(S_ID, 0xFF10, NULL)) {
        return 0;
    }
    sc_run_ms(1200);
    sc_round_t rd[4];
    unsigned n = sc_seek_rounds(S_ID, rd, 4);
    CHECK(n >= 1);
    if (n == 0) {
        return 0;
    }
    if (first_pre != NULL) {
        *first_pre = rd[0].pre_ctr;
    }
    return rd[0].nonce_s;
}

static void scen_r14_nonce_uniqueness(uint64_t seed)
{
    uint32_t pre1 = 0;
    uint32_t a1 = r14_first_nonce(seed, 5000, 500, &pre1);
    uint32_t a2 = r14_first_nonce(seed, 5000, 500, NULL);
    uint32_t b = r14_first_nonce(seed, 9000, 900, NULL);   /* same PRNG stream, other txseq / preseq (a reboot) */
    uint32_t c = r14_first_nonce(seed + 1, 5000, 500, NULL); /* other PRNG stream */
    CHECK_MSG(a1 != 0, "no SEEK captured");
    CHECK_EQ_U32(a1, a2);                                   /* identical inputs give identical nonce_s (determinism) */
    CHECK_MSG(a1 != b, "nonce_s must depend on preseq / txseq (4.1.14)");
    CHECK_MSG(a1 != c, "nonce_s must depend on the random source (4.1.14)");
    CHECK_EQ_U32(pre1, 500);                                /* first pre_ctr used = preseq_start (br_node_config_t) */
    sc_skip("r14_nonce_uniqueness/nonce_p_and_keys", "PROTOCOL.md 4.1.14 line 444",
            "nonce_p and the derived keys are inside the encrypted unicast HELLO / BIND (no capture hook, no key "
            "accessor); a reboot with an IDENTICAL PRNG state cannot be built (the sim PRNG stream cannot be reseeded "
            "per node), so txseq / preseq dependence is shown by changing only those two inputs");
}

/* ========================================================================= */
/* 4.2  liveness                                                             */
/* ========================================================================= */

static void scen_r_liveness_keepalive(uint64_t seed)
{
    if (!sc_topo3(seed)) {
        return;
    }
    br_mode_t m;
    sc_mode(&m, BR_MODE_HIGH);
    m.keepalive_ms = 1000;
    if (!sc_start(S_ID, 0xFF10, &m)) {
        return;
    }
    bool up = sc_wait_snd_state(S_ID, BR_SND_STREAMING, 5000);
    CHECK_MSG(up, "sender never reached STREAMING");
    if (!up) {
        return;
    }
    sc_run_ms(500);
    const uint64_t t_idle0 = brsim_now(&sc.sim);
    sc_run_ms(10000);
    const uint64_t t_cut = brsim_now(&sc.sim);

    sc_q_t qp = sc_q("PING", S_ID, R_ID, S_ID);
    qp.t0 = t_idle0;
    qp.t1 = t_cut;
    sc_q_t qo = sc_q("PONG", P_ID, R_ID, P_ID);
    qo.t0 = t_idle0;
    qo.t1 = t_cut;
    sc_q_t qa = sc_q("ACK", P_ID, R_ID, P_ID);
    qa.t0 = t_idle0;
    qa.t1 = t_cut;
    unsigned pings = sc_q_count(&qp), pongs = sc_q_count(&qo), acks = sc_q_count(&qa);
    CHECK_MSG(pings >= 5, "sender PINGs when no ACK arrived for keepalive_ms (about 1 per second)");
    CHECK_MSG(pongs + 1u >= pings, "every PING is answered with a PONG");
    CHECK_MSG(pongs + acks >= 8, "the probe shows life about once per keepalive_ms");
    CHECK_EQ_U32(sc_snd_state(S_ID), BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);
    CHECK_EQ_U32(count_type("CLOSE", -1, -1, -1), 0);

    /* cut the R - P link */
    sc_unlink(R_ID, P_ID);
    sc_run_ms(2000);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 1);            /* P's own SESSION_TIMEOUT has not run out yet */
    sc_run_ms(6000);
    sc_q_t qc = sc_q("CLOSE", S_ID, R_ID, S_ID);
    qc.t0 = t_cut;
    CHECK_EQ_U32(sc_q_count(&qc), 2);                    /* CLOSE twice */
    const sc_tl_t *c0 = sc_q_nth(&qc, 0);
    if (c0 != NULL) {
        /* SESSION_TIMEOUT = max(4 x 1000, 8 x SRTT) = 4 s after the last ACK / PONG (which was <= 1 s before the cut) */
        CHECK_MSG(c0->t >= t_cut + SC_US(2900) && c0->t <= t_cut + SC_US(4300), "S closes after SESSION_TIMEOUT");
        sc_q_t qs = sc_q("SEEK", S_ID, R_ID, S_ID);
        qs.t0 = c0->t;
        const sc_tl_t *s0 = sc_q_nth(&qs, 0);
        CHECK(s0 != NULL);
        if (s0 != NULL) {
            CHECK_MSG(s0->t <= c0->t + SC_US(BR_RESEEK_JITTER_MS) + 100000u, "re-SEEK within RESEEK_JITTER_MS of the CLOSE");
        }
    }
    CHECK(sc_snd_state(S_ID) != BR_SND_STREAMING);
    CHECK_EQ_U32(sc_prb_live(P_ID, NULL), 0);            /* P freed the record after its own SESSION_TIMEOUT */
    sc_skip("r_liveness_keepalive/penalty_list", "PROTOCOL.md 4.2", "penalty-list accessor (first hop 0x0102 recorded)");
    sc_check_clean(0);
}

/* ========================================================================= */
/* 6.1  MODE change                                                          */
/* ========================================================================= */

static void scen_r_mode_change(uint64_t seed)
{
    if (!sc_up3(seed, 0)) {
        return;
    }
    sc_smp_t smp[16];
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(300);
    CHECK_ERR(sc_send(S_ID, 0, true), BR_OK);
    sc_run_ms(300);
    unsigned n0 = sc_samples(P_ID, smp, 16);
    CHECK_EQ_U32(n0, 2);
    CHECK_EQ_U32(smp[0].n_bytes, 4); /* HIGH digital sample: 4 bytes */
    const uint8_t cfg_high = smp[0].cfg;
    sc_q_t qd = sc_q("DATA", S_ID, R_ID, S_ID);
    const sc_tl_t *d0 = sc_q_nth(&qd, 0);
    CHECK(d0 != NULL);
    const uint16_t len_high = d0 != NULL ? d0->len : 0u;

    /* HIGH -> LOW; the first MODE is lost */
    br_mode_t lo;
    sc_mode(&lo, BR_MODE_LOW);
    sc_rule_t *ru = sc_rule_now(P_ID, R_ID, S_ID, "MODE", 1);
    const uint64_t t_set = brsim_now(&sc.sim);
    CHECK_ERR(br_node_set_mode(sc_pl(S_ID), sc_n(S_ID)->sess, &lo), BR_OK);
    sc_kick();
    sc_run_ms(20);
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK); /* sent while the MODE is unacknowledged: still the old config_id */
    sc_run_ms(1500);
    CHECK(ru != NULL && ru->dropped == 1);
    sc_q_t qm = sc_q("MODE", S_ID, R_ID, S_ID);
    qm.t0 = t_set;
    CHECK_MSG(sc_q_count(&qm) >= 2, "MODE must be resent when unacknowledged");
    const sc_tl_t *m0 = sc_q_nth(&qm, 0), *m1 = sc_q_nth(&qm, 1);
    if (m0 != NULL && m1 != NULL) {
        CHECK_MSG(m1->t - m0->t + 4000u >= SC_US(BR_ARQ_RTO_MS) && m1->t - m0->t <= SC_US(400), "MODE_RETRY = RTO");
    }
    unsigned n1 = sc_samples(P_ID, smp, 16);
    CHECK_EQ_U32(n1, n0 + 1u);
    CHECK_MSG(smp[n0].cfg == cfg_high && smp[n0].n_bytes == 4, "DATA keeps the old config_id until MODE_ACK");
    sc_q_t qd2 = sc_q("DATA", S_ID, R_ID, S_ID);
    qd2.t0 = t_set;
    const sc_tl_t *dp = sc_q_nth(&qd2, 0);
    CHECK(dp != NULL && dp->len == len_high);
    const unsigned modes_after_low = sc_app_count(BRSIM_APP_MODE, S_ID, -1, -1, -1);
    CHECK_EQ_U32(modes_after_low, 2);                         /* initial + LOW, both acknowledged */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_MODE, P_ID, -1, -1, -1), 2);
    const brsim_app_rec_t *ml = sc_app_nth(BRSIM_APP_MODE, S_ID, -1, -1, -1, 1);
    CHECK(ml != NULL && ml->c != cfg_high);
    /* after MODE_ACK the LOW digital sample is 1 byte under the new config_id */
    CHECK_ERR(sc_send(S_ID, 1, true), BR_OK);
    sc_run_ms(500);
    unsigned n2 = sc_samples(P_ID, smp, 16);
    CHECK_EQ_U32(n2, n1 + 1u);
    CHECK_MSG(smp[n1].n_bytes == 1 && smp[n1].b0 == 1, "LOW digital sample is 1 byte");
    CHECK(ml != NULL && smp[n1].cfg == ml->c);
    sc_q_t qd3 = sc_q("DATA", S_ID, R_ID, S_ID);
    qd3.t0 = brsim_now(&sc.sim) - SC_US(500);
    const sc_tl_t *dl = sc_q_nth(&qd3, 0);
    CHECK(dl != NULL && dl->len + 3u == len_high);

    /* LOW -> HIGH; the first MODE_ACK is lost: MODE is resent, the probe re-acks without side effects */
    br_mode_t hi;
    sc_mode(&hi, BR_MODE_HIGH);
    sc_rule_t *ru2 = sc_rule_now(S_ID, R_ID, P_ID, "MODE_ACK", 1);
    sc_q_t qm2 = sc_q("MODE", S_ID, R_ID, S_ID);
    qm2.t0 = brsim_now(&sc.sim);
    sc_q_t qa2 = sc_q("MODE_ACK", P_ID, R_ID, P_ID);
    qa2.t0 = brsim_now(&sc.sim);
    CHECK_ERR(br_node_set_mode(sc_pl(S_ID), sc_n(S_ID)->sess, &hi), BR_OK);
    sc_kick();
    sc_run_ms(1500);
    CHECK(ru2 != NULL && ru2->dropped == 1);
    CHECK_MSG(sc_q_count(&qm2) >= 2, "MODE resent after a lost MODE_ACK");
    CHECK_MSG(sc_q_count(&qa2) >= 2, "MODE_ACK sent again for the already active config_id");
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_MODE, P_ID, -1, -1, -1), 3); /* no second on_mode for the repeat */
    CHECK_EQ_U32(sc_app_count(BRSIM_APP_MODE, S_ID, -1, -1, -1), 3);

    /* a descriptor with ch_count 0 never reaches the air from the public API; nothing counts as bad_frame (N7) */
    br_mode_t bad;
    sc_mode(&bad, BR_MODE_HIGH);
    bad.ch_count = 0;
    CHECK_ERR(br_node_set_mode(sc_pl(S_ID), sc_n(S_ID)->sess, &bad), BR_ERR_ARG);
    sc_kick();
    sc_run_ms(500);
    CHECK_EQ_U32(sc_stats(P_ID).f.bad_frame, 0);
    CHECK_EQ_U32(sc_stats(R_ID).f.bad_frame, 0);
    sc_skip("r_mode_change/bad_and_too_big_MODE_on_the_air", "PROTOCOL.md 6.1, 3.6 line 302, SPEC-NOTES N7",
            "a frame forge helper (session keys + hop_tag + CRC) to put a MODE with ch_count 0 or an oversized sample on "
            "the air; br_node_set_mode() refuses them at the sender, and a too-big sample cannot be built on a "
            "217-byte path at all (max 16 channels x 4 bytes + 7); the status mapping is unit-tested in test_sample");
    sc_check_clean(0);
}

/* ========================================================================= */

int main(int argc, char **argv)
{
    sc_args(argc, argv);
    sc_run("r01_seek_flood", "PROTOCOL.md 4.1.1 line 341, 11.4 steps 9a-9f, 11.5 line 1157", scen_r01_seek_flood, false);
    sc_run("r02_hello_offer", "PROTOCOL.md 4.1.2 line 349", scen_r02_hello_offer, false);
    sc_run("r02b_offers_and_full", "PROTOCOL.md 4.1.2 line 349 (PROBE_OFFERS_MAX, status 1)", scen_r02b_offers_and_full,
           false);
    sc_run("r03_bound_probe_new_seek", "PROTOCOL.md 4.1.3 line 361", scen_r03_bound_probe_new_seek, false);
    sc_run("r04_first_hello_wins", "PROTOCOL.md 4.1.4 line 365", scen_r04_first_hello_wins, false);
    sc_run("r05_bind_unicast", "PROTOCOL.md 4.1.5 line 374, 8.2 lines 778-783", scen_r05_bind_unicast, false);
    sc_run("r06_bind_nak_when_streams_taken", "PROTOCOL.md 4.1.6 line 381", scen_r06_bind_nak_when_streams_taken, false);
    sc_run("r07_offer_timeout", "PROTOCOL.md 4.1.7 line 385", scen_r07_offer_timeout, false);
    sc_run("r07b_bind_within_timeout", "PROTOCOL.md 4.1.7 line 385, 4.1.10 (control)", scen_r07b_bind_within_timeout,
           false);
    sc_run("r08_seek_retry_backoff", "PROTOCOL.md 4.1.8 line 387", scen_r08_seek_retry_backoff, false);
    sc_run("r09_bind_retry_idempotent", "PROTOCOL.md 4.1.9 line 400", scen_r09_bind_retry_idempotent, false);
    sc_run("r10_bind_timeout_margin", "PROTOCOL.md 4.1.10 line 404 table", scen_r10_bind_timeout_margin, false);
    sc_run("r11_session_cycles", "PROTOCOL.md 4.1.11 line 419 (20 close / re-seek cycles)", scen_r11_session_cycles,
           false);
    sc_skip("r11_session_id_values", "PROTOCOL.md 4.1.11 line 419",
            "session_id accessor / UNICAST frame capture: the id (1..255, never 0, not in the last 8) is neither in the "
            "trace nor in any accessor, and a forced PRNG repeat cannot be injected per node");
    sc_run("r12_capacity_full", "PROTOCOL.md 4.1.12 line 423", scen_r12_capacity_full, false);
    sc_run("r12b_stream_taken_at_first_data", "PROTOCOL.md 4.1.12 line 423 (streams taken at the first DATA)",
           scen_r12b_stream_taken_at_first_data, false);
    sc_run("r13_unknown_session", "PROTOCOL.md 4.1.13 line 439, SPEC-NOTES N27", scen_r13_unknown_session, false);
    sc_run("r14_nonce_uniqueness", "PROTOCOL.md 4.1.14 line 444", scen_r14_nonce_uniqueness, true);
    sc_skip_oos("r15_half_duplex_guard", "PROTOCOL.md 4.1.15 line 450, IR / nRF24 carriers");
    sc_run("r_liveness_keepalive", "PROTOCOL.md 4.2 lines 459-477", scen_r_liveness_keepalive, false);
    sc_run("r_mode_change", "PROTOCOL.md 6.1 lines 600-630, 4.2 MODE_RETRY, SPEC-NOTES N7", scen_r_mode_change, false);
    return tu_summary("test_scen_rules");
}
