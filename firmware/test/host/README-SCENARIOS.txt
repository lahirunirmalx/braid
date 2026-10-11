Braid phase 1b/1c - host scenario tests (skeleton, to be implemented)
=========================================================================

Each scenario below becomes one function in a scenario test file under
firmware/sim/test/ (e.g. test_scn_handshake.c, test_scn_races.c,
test_scn_relay.c), linked against brsim (firmware/sim/include/brsim/brsim.h)
and registered in CTest by the existing glob in firmware/host/CMakeLists.txt.
Every scenario runs real br_node_t instances on the simulated medium; none
of them may reach into br_node internals except through br_node_get_*,
br_node_route, br_node_session_state, brsim_app_log, brsim_link_stats and
the trace hash.

Spec line numbers refer to PROTOCOL.md v0.8 (frozen copy PROTOCOL.v0.8.md).
SPEC-NOTES.md decides any reading conflict.

Common setup (unless a scenario says otherwise)
-----------------------------------------------
- Bench profile, Appendix A test keys: net_key = BRV_A6_K_SITE (stands in
  for K_site, 8.2 line 808), key_epoch 1. FLAG_AUTH on every frame
  (AES-CCM + hop_tag). FEC off (fec_m 0). ARQ on (arq 1).
- Unit IDs: S1 0x0101 (sender), R1 0x0102 (relay), P1 0x0103 (probe,
  group 0xFF10); extra nodes 0x0104.. as needed.
- Default link: connected, loss 0, delay 300..1500 us, reorder true,
  rssi -60 (cost 1). seek_ttl 4. mac_attempts 1.
- Default MODE: HIGH, 1 channel digital, 1 line, period 1 ms
  (flags bit0 = 1, period 1), arq 1, fec_m 0, keepalive_ms 5000.
- "Press" = br_node_send_sample(S1, s, {.lines = 1}, 1, t, 0, ack_req=1)
  followed by a release {.lines = 0} 200 ms later.
- Every scenario runs twice with the same seed and asserts identical
  brsim_trace_hash (determinism guard), and once with a second seed.
- Every scenario ends by asserting, on every node: no BR_ERR_* returned by
  any br_node_* call except the ones the scenario expects; bad_frame,
  crc_fail, hop_tag_fail, hop_replay, auth_fail are 0 unless injected.

Injection helpers the scenario file will need (write them in the test,
not in brsim): drop the next frame of type T on link X->Y (a CALL that
sets loss 1e6 for one frame window, or a test-double relay that filters),
duplicate / replay a recorded frame (capture via a test-double endpoint
added on the same medium, then brsim_send of the stored bytes), and
"reboot" a node (br_node_deinit + br_node_init with txseq/preseq_start
taken from the persisted reserve).

=========================================================================
A. Acceptance
=========================================================================

three_node_relay
  Spec:     4 (line 313 flow), 4.1, 7, 11.4 (lines 1094-1152), 11.6
  Setup:    S1, R1, P1. Links S1<->R1 and R1<->P1 only (connectivity
            matrix). No S1<->P1 link. S1 seeks 0xFF10, sets the default
            MODE once STREAMING. Run 2 s, press once, run 3 s.
  Inject:   nothing.
  Expect:   - P1 on_samples exactly one record with lines == 1 and one with
              lines == 0, src_id 0x0101, meta.hops == 2 (header hops 1 at
              arrival + 1); in seq order.
            - S1 on_acked for both DATA seqs (the ACK returned to A);
              S1 arq_retx == 0 with loss 0.
            - R1 route table: entry dst 0x0101 next_hop 0x0101 hops 1 and
              entry dst 0x0103 next_hop 0x0103 hops 1; both live.
            - S1 route to 0x0103 via 0x0102 hops 2; P1 route to 0x0101 via
              0x0102 hops 2.
            - brsim_link_stats(S1, P1) and (P1, S1): sent == 0,
              delivered == 0 (no frame ever went A<->C directly), and no
              trace line has from/to = 0101/0103 or 0103/0101.
            - R1 relay_fwd >= 10 (BIND, BIND_ACK, MODE, MODE_ACK, 2 DATA,
              ACKs); R1 never delivers locally (no on_* records for R1).
            - State sequences: S1 IDLE->SEEKING->BINDING->CONFIGURING->
              STREAMING; P1 record LISTENING->BOUND->STREAMING.
  Note:     "no A<->C" is enforced here by the matrix; the allowlist is
            tested separately (bench_allowlist_topology).

bench_allowlist_topology
  Spec:     none (SPEC-NOTES N22); 11.4 steps 5-9
  Setup:    as three_node_relay but FULL connectivity S1<->R1<->P1<->S1;
            allowlists S1 {0x0102}, R1 {0x0101, 0x0103}, P1 {0x0102}.
  Inject:   nothing.
  Expect:   same outcome as three_node_relay (hops == 2 at P1, routes via
            R1); brsim_link_stats(S1, P1).allowlist_drop > 0 and
            (P1, S1).allowlist_drop > 0; no br_node counter moved for
            those dropped frames (they never reached br_node_rx).
            Repeat with -DBR_FIELD_BUILD build: scenario is skipped.

three_node_relay_lossy
  Spec:     7 (lines 707-741)
  Setup:    as three_node_relay, every link loss 20 %, 50 presses 300 ms
            apart.
  Inject:   loss only.
  Expect:   all 100 samples delivered at P1 exactly once, in seq order,
            no on_gap; S1 arq_retx > 0; P1 rx duplicates dropped by ARQ
            before the replay window (replay_dropped == 0).

=========================================================================
B. Section 4.1 rules (one scenario per rule)
=========================================================================

r01_seek_flood
  Spec:     4.1.1 (line 341), 11.4 steps 9a-9f, 11.5 (line 1157)
  Setup:    line S1 - R1 - R2 - P1 (P1 in 0xFF10), seek_ttl 4,
            cold_boot true, node_count 4.
  Inject:   nothing.
  Expect:   first SEEK not before rand(0..600 x 4 ms) after init; SEEK
            leaves S1 with next_hop FFFF, ttl 4, hops 0, path_cost 0,
            path_mtu 250; each relay rebroadcasts once after <= 50 ms
            jitter with ttl - 1, hops + 1, prev_hop = itself, new hop_seq;
            FLOOD_REPEAT second copies are dropped as relay_drop_dedup;
            S1's own echo dropped silently (9a, no counter, no
            BR_EVT_ID_COLLISION); every node installs a reverse route to
            0x0101; S1 keeps the payloads of its last 5 SEEKs.

r02_hello_offer
  Spec:     4.1.2 (line 349), 11.4 row "Unicast HELLO"
  Setup:    S1 - R1 - P1 plus a second path S1 - R2 - P1 with R2 links at
            rssi -80 (cost 3).
  Inject:   nothing.
  Expect:   P1 answers HELLO once, after rand(0..50 ms), along the
            lowest-cost copy (via R1); HELLO max_frame = min(own 250,
            path_mtu); P1 has one OFFERED entry for 0x0101 with expiry
            BIND_TIMEOUT(2) = 890 ms; S1 installs forward route to 0x0103
            via R1. Then 5 different senders SEEK P1 at once: the 5th
            offer replaces the oldest (PROBE_OFFERS_MAX 4); with
            BR_RX_RECORDS records full P1 answers status 1 and keeps no state.

r03_bound_probe_new_seek
  Spec:     4.1.3 (line 361)
  Setup:    three_node_relay up to STREAMING.
  Inject:   (a) replay the recorded bytes of S1's first SEEK; (b) reboot S1
            (deinit + init, counters from the persisted reserve) and seek
            0xFF10 again, dropping the new BIND on R1 -> P1 once.
  Expect:   (a) changes nothing (dropped at R1 by dedup / ORIGIN:
            relay_drop_dedup or relay_drop_stale, or hop_replay).
            (b) P1 answers the new SEEK with HELLO while its record for
            0x0101 stays STREAMING with the old keys (state and keys
            unchanged while the BIND is lost); the retried BIND that
            decrypts under the new Ke_hs replaces the old session (one
            record, new session_id).

r04_first_hello_wins
  Spec:     4.1.4 (line 365)
  Setup:    S1 - R1, R1 - P1, R1 - P2 (both in 0xFF10), P2 links slower.
  Inject:   nothing; then a variant with every probe FULL.
  Expect:   BIND goes to the first HELLO with status 0 at once; up to 4
            more kept as candidates; a candidate whose first hop is on the
            penalty list ranks last. All FULL: S1 backs off
            rand(0, min(3600, 60 x 2^n)) s before the next SEEK; n resets
            on success.

r05_bind_unicast
  Spec:     4.1.5 (line 374), 8.2 (lines 778-783)
  Setup:    three_node_relay.
  Inject:   nothing.
  Expect:   BIND unicast along the HELLO route; P1 derives Ke_hs from the
            SEEK copy named by seek_ctr and the HELLO named by hello_ctr;
            both ends hold identical Ke_s2p / Ke_p2s (check by decrypting
            a DATA at P1); BIND_ACK under Ke_hs; P1 record BOUND.

r06_bind_mismatch_and_nak
  Spec:     4.1.6 (line 381)
  Setup:    S1 - R1 - P1, P1 with BR_RX_STREAMS streams already taken
            between HELLO and BIND (bind other senders first).
  Inject:   (a) a BIND with wrong nonces; (b) a BIND with a corrupted
            ciphertext byte; (c) the real BIND after the streams filled.
  Expect:   (a), (b) dropped silently (auth_fail for (b)); (c) BIND_NAK
            reason 1; S1 tries the next candidate, none left -> SEEK again.

r07_offer_timeout
  Spec:     4.1.7 (line 385)
  Setup:    S1 - R1 - P1.
  Inject:   drop every BIND on R1 -> P1.
  Expect:   P1 OFFERED entry gone after BIND_TIMEOUT(2) = 890 ms; a BIND
            arriving later is ignored (P1 LISTENING ignores BIND naming it).

r08_seek_retry_backoff
  Spec:     4.1.8 (line 387)
  Setup:    S1 - R1, no probe in 0xFF10.
  Inject:   nothing; variant: HELLO dropped once.
  Expect:   resend at SEEK_BASE_MS(4) = 530 + rand(0, min(60000,
            600 x 2^n)) ms, same nonce_s, new pre_ctr; never gives up;
            BR_EVT_NO_PROBE after the 5th attempt. Variant: P1 in OFFERED
            that sees the same nonce_s with a newer pre_ctr resends HELLO
            with the same nonce_p and a new seek_ctr. (MGMT_REQ trigger is
            out of scope in phase 1b.)

r09_bind_retry_idempotent
  Spec:     4.1.9 (line 400)
  Setup:    three_node_relay.
  Inject:   drop the first two BIND_ACKs on R1 -> S1.
  Expect:   S1 resends BIND every BIND_RETRY(2) = 120 ms (max 3); P1
            answers each repeat with BIND_ACK again, no second record; the
            session starts on the first BIND_ACK that arrives; SRTT seeded
            from that round trip.

r10_bind_timeout_margin
  Spec:     4.1.10 (line 404, table)
  Setup:    lines of 1, 2, 4 and 8 hops (seek_ttl 8 for the last).
  Inject:   drop BIND 3 times (all retries), deliver the last.
  Expect:   P1 still OFFERED when the last BIND arrives at every hop count
            (BIND_TIMEOUT 470 / 890 / 1730 / 3410 ms vs needed 350 / 650 /
            1250 / 2450 ms with link delays at HOP_DELAY_MS 60).

r11_session_id
  Spec:     4.1.11 (line 419)
  Setup:    S1 - R1 - P1; 20 consecutive sessions (close, re-seek).
  Inject:   PRNG stream forced to repeat (seed chosen to hit a repeat).
  Expect:   session_id in 1..255, never 0, never equal to any of the last
            8; frames matched on (src_id, session_id).

r12_capacity_full
  Spec:     4.1.12 (line 423)
  Setup:    P1 with BR_RX_RECORDS 4 and BR_RX_STREAMS 2; 5 senders.
  Inject:   nothing.
  Expect:   2 ARQ senders take streams at their first DATA; a 3rd ARQ
            sender gets HELLO status 1 (no free stream); a 5th sender gets
            status 1 (no record); streams held until CLOSE or
            SESSION_TIMEOUT, then reusable.

r13_unknown_session
  Spec:     4.1.13 (line 439)
  Setup:    three_node_relay up to STREAMING, then reboot P1 (deinit +
            init, records lost).
  Inject:   S1 keeps pressing.
  Expect:   P1 drops DATA for the unknown (0x0101, session_id) and counts
            it (counter: see open question Q3 in the phase 1b report);
            bench profile replies CLOSE(2) at most once per second per
            peer; S1 closes after ARQ_MAX_RETRIES unanswered ACK_REQ and
            re-SEEKs.

r14_nonce_uniqueness
  Spec:     4.1.14 (line 444)
  Setup:    two runs, same seed vs different seeds; reboot S1 mid-run.
  Inject:   nothing.
  Expect:   nonce_s / nonce_p differ across sessions and across a reboot
            with the same PRNG state (preseq / txseq enter the hash);
            keys differ because both pre_ctr values enter T.

r15_half_duplex_guard
  Spec:     4.1.15 (line 450)
  Status:   OUT OF SCOPE in phase 1b (IR / nRF24 carriers). Keep the name;
            the scenario is a TODO marker that asserts nothing.

r_liveness_keepalive
  Spec:     4.2 (lines 459-477)
  Setup:    three_node_relay, keepalive_ms 1000, no presses for 10 s.
  Inject:   then cut R1 <-> P1 (link connected = false).
  Expect:   while idle: P1 ACKs on keepalive, S1 PINGs when no ACK for
            keepalive_ms, PONG returns, session stays STREAMING.
            After the cut: S1 SESSION_TIMEOUT = max(4 x 1000, 8 x SRTT),
            sends CLOSE twice, records first hop 0x0102 on the penalty
            list, re-SEEKs after rand(0..1000 ms); P1 frees the record
            after its own SESSION_TIMEOUT.

r_mode_change
  Spec:     6.1 (lines 600-630), 4.2 (MODE_RETRY), SPEC-NOTES N7
  Setup:    three_node_relay STREAMING in HIGH.
  Inject:   switch to LOW; drop the first MODE; then send a MODE with
            ch_count 0 (bad arg) and one whose sample cannot fit (too big).
  Expect:   MODE resent after RTO; DATA keeps the old config_id until
            MODE_ACK; P1 re-acks an active config_id without side effects
            and keeps the last two; bad MODEs answered MODE_ACK 3 / 2 and
            NOT counted as bad_frame; LOW digital sample is 1 byte.

=========================================================================
C. Section 4.3 race catalogue (one scenario per row)
=========================================================================

race_two_probes_one_seek
  Spec:     4.3 row line 483 (4.1.5, 4.1.7)
  Setup:    S1 - R1, R1 - P1, R1 - P2, both in 0xFF10.
  Inject:   nothing.
  Expect:   both answer HELLO; BIND unicast to one; the other's OFFERED
            entry expires at BIND_TIMEOUT; exactly one session.

race_two_senders_one_group
  Spec:     4.3 row line 484 (4.1.2, 4.1.6)
  Setup:    S1 and S2 both seek 0xFF10 at the same instant; P1 with MULTI.
  Inject:   variant with P1 records = 1.
  Expect:   both bound (two records); variant: second gets status 1 or
            BIND_NAK and backs off.

race_bound_probe_hears_own_sender_seek
  Spec:     4.3 row line 485 (4.1.3)
  Setup:    three_node_relay STREAMING.
  Inject:   (a) replay of S1's old SEEK bytes; (b) S1 reboots and seeks.
  Expect:   (a) no state change at P1 (dropped at relays by dedup /
            ORIGIN, or answered HELLO with no session change);
            (b) old session replaced only when the new BIND decrypts under
            the new Ke_hs.

race_bind_or_bind_ack_lost
  Spec:     4.3 row line 486 (4.1.9, 4.1.10)
  Setup:    lines of 1, 2, 4 hops.
  Inject:   drop the first BIND; separately drop the first BIND_ACK.
  Expect:   session established at every hop count within BIND_TIMEOUT;
            idempotent BIND_ACK; no duplicate record.

race_hello_lost_seek_retried
  Spec:     4.3 row line 487 (4.1.5, 4.1.8)
  Setup:    three_node_relay.
  Inject:   drop the first HELLO on R1 -> S1.
  Expect:   S1 retries SEEK (same nonce_s, newer pre_ctr); P1 resends
            HELLO (same nonce_p, new seek_ctr); BIND's hello_ctr picks one
            transcript; both ends derive the same keys.

race_seq_wrap
  Spec:     4.3 row line 488 (3.5, 8)
  Setup:    three_node_relay STREAMING; send 70000 DATA frames (period
            1 ms; long run) or start the index near 0xFFF0 via a test hook
            if one is added to br_session (decide in phase 1c).
  Inject:   reorder across the wrap; replay a frame from before the wrap
            after it.
  Expect:   ordering by serial arithmetic across 65535 -> 0; ROC estimate
            correct (A.10 cases); the pre-wrap replay fails CCM (different
            ROC) -> auth_fail, never delivered.

race_replayed_presession_frames
  Spec:     4.3 row line 489 (8.4)
  Setup:    three_node_relay; a recording test-double on the medium.
  Inject:   replay recorded SEEK, HELLO and BIND bytes later (MGMT_RESP
            out of scope).
  Expect:   relays drop replayed floods (dedup / ORIGIN stale); hop_seq
            replay dropped (hop_replay) on every link before any table
            change; endpoints drop HELLO / BIND that match no outstanding
            SEEK / OFFERED entry; nothing replied.

race_mass_reboot
  Spec:     4.3 row line 490 (4.1.1, 4.1.8, 4.2)
  Setup:    12 nodes (brsim max 16), 6 senders, node_count 12, cold boot
            at t = 0 for all.
  Inject:   nothing.
  Expect:   first SEEKs spread over rand(0..600 x 12 ms); no flood dropped
            for relay_drop_rate beyond the budget; all sessions bound
            within 30 s.

race_relay_dies
  Spec:     4.3 row line 491 (4.2, 11.6)
  Setup:    S1 - R1 - P1 and S1 - R2 - P1 (R2 cost higher).
  Inject:   after STREAMING via R1, remove R1 (all its links off).
  Expect:   unicast failures on S1 -> R1 (mac_retry) reach LINK_FAIL_MAX
            3 -> link and routes via R1 deleted, BR_EVT_LINK_FAIL;
            SESSION_TIMEOUT -> re-SEEK -> new session via R2; R1 on the
            penalty list so a later HELLO via R1 ranks last.

race_management_relay_dies
  Spec:     4.3 row line 492 (11.6, 11.10)
  Status:   OUT OF SCOPE (MGMT). TODO marker.

race_every_probe_full
  Spec:     4.3 row line 493 (4.1.4)
  Setup:    two probes in 0xFF10, both with records full.
  Inject:   nothing.
  Expect:   all HELLOs status 1; S1 backoff rand(0, min(3600, 60 x 2^n)) s,
            n growing per all-FULL round, capped at 1 h; never a flood per
            minute.

race_retired_epoch_rejoin
  Spec:     4.3 row line 494 (8.5)
  Status:   OUT OF SCOPE (key rotation, MGMT). TODO marker.
