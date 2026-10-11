# ROAST-2: ProbeLink v0.4 vs field deployment

Target: PROTOCOL.md, DRAFT v0.4 (wire version 1, minor 0), about 2350 lines.
Deployment assumed: one implementer, ESP-IDF on ESP32 / ESP32-C3 / ESP32-S3,
5-50 nodes, building or outdoor site, unattended for months. Carriers
ESP-NOW, BLE (optional), WiFi UDP, IR, UART, nRF24L01+. Mesh mandatory.
Reviewer stance: hostile, round 2. Numbers marked "(estimate)" are reviewer
estimates, not measurements.

Sanity check done first: every Appendix A vector (A.1-A.10) was recomputed
independently: CRC-16, the A.3 RS parity and the 44-byte COBS wire image,
A.4 RS, K_mesh, K_pair, PRK, K_hs, K_s2p, K_p2s, Ke_s2p, the A.6/A.8 auth and
hop tags and CRCs, the A.8 keyed SEEK on both hops, the A.9 HELLO, inner tag
and BIND, the A.10 ROC cases and the AES-CCM ciphertext, tag, hop_tag and
CRC. All match byte for byte. The frame layouts in sections 3, 5 and 6 (SEEK
14, HELLO 21, BIND 19, MODE 13 fixed, DATA 7, PARITY 8) agree with the
vectors, the 6.3 table and the 4.1.10 timer table. The bit level is clean.
The problems are in the state machines, the timers and the operations
around them.

---

## 1. Round-1 fix verification

Verdicts: SOUND = specified and consistent; PARTIAL = specified but with a
gap or new contradiction; ASSERTED = Appendix D says fixed, the normative
text does not deliver it; REGRESSED = the fix broke something else.

| R1 ID | Sev | Verdict | Evidence / covering finding |
|---|---|---|---|
| F1 | CRIT | ASSERTED | 4.4 says RESUME_ACK installs forward routes; the 11.4 pipeline never does (G6). Parked leaves hold full session slots (G9). Leaves can never receive KEY_UPDATE and go deaf after the first epoch activation (G1, G10). Wake budget omits Secure Boot validation (G19). |
| F2 / S1 | CRIT | PARTIAL (keys half SOUND, rotation and revocation half ASSERTED) | Pairwise keys from K_site are specified and the A.6 vectors check out. Rotation strands every laggard (G1); revocation does not revoke K_mesh for a full epoch, and the key server needs K_site, which 8.2 says nobody in the field holds (G8). |
| F4 | CRIT | PARTIAL | The dedicated channel, no STA and two-chip gateway rule is clear and sound as a rule. It contradicts BLE bridges (G13) and puts two 2.4 GHz transmitters in one box (G12). |
| F17 / S7 | CRIT | PARTIAL | The session ROC is sound (A.10 cases verified). Pre-session frames keep ROC 0 under the long-lived K_mesh, so the F17 attack comes back for floods (G3). |
| F3 | HIGH | SOUND | Manifest, pl/unit_mac and pl/groups are specified. (With flash encryption in release mode a flash clone cannot boot anyway, so the check is bench-only.) |
| F5 | HIGH | PARTIAL | Roles, allowlist and magic are sound. WIFI_PS_NONE is mandatory on mesh nodes but IDF requires modem sleep with BT up (G13). |
| F6 | HIGH | ASSERTED | Best-copy routing cannot be reached for SEEK/BIND: step 9b drops the second copy before step 9c can compare cost, so routing is still first-copy, as in v0.3 (G5). |
| F9 | HIGH | ASSERTED | "Multi-session MUST, >= 4" is specified. "v2 single-session or arq_window 8" caps a sender buffer that no message negotiates. Parked leaves consume slots. No capacity rule exists (G9). |
| F10 | HIGH | PARTIAL | Holdoff, full jitter, no give-up and table sizes are sound. SEEK_TIMEOUT(n) is undefined, and BOOT_SPREAD ignores FLOOD_REPEAT (G15). |
| F11 | HIGH | SOUND | Bucket depth 6 refill 2/s, free BIND retries, and BIND_RETRY(hops) with the inequality table all recomputed correctly. Minor: the nonce memory for "free retry" is not in the RAM table (G28). |
| F12 | HIGH | PARTIAL | Key, TTL, eviction and the replacement rule are specified. "Learn only after hop_tag" does not stop replays (G4). |
| F13 | HIGH | ASSERTED | UPDATE_WINDOW needs maintenance WiFi at every node. "By cable" is impossible once 12.1 burns UART download disable (G11). |
| F14 | HIGH | SOUND | Frozen prefix, forwarders forward unknown versions, proto_minor, N/N-1. BIND_NAK reason 4 is still unreachable (G27). |
| F15 | HIGH | PARTIAL | DIAG is specified, but the fixed part plus pl_stats_t is about 156 bytes: nothing fits IR or BLE-64, and at most 7 links fit ESP-NOW (G17). Leaves are invisible (G10). |
| F16 | HIGH | PARTIAL | TIME/PONG utc_us/UNSYNCED are specified. The stratum chain cannot be verified, and TIME_REQ has no nonce although 8.4 says it does (G20). |
| F18 / S11 | HIGH | SOUND | The 3.6 table exists and is mostly consistent. Small gaps in G27. |
| F22 / S4 / S5 / S6 | HIGH / CRIT | PARTIAL | The order "tags before any table" is specified. Replay of authentic frames bypasses it (G4), and pre-session wrap (G3). |
| S3 | CRIT | SOUND | A SEEK never closes a session (4.1.3). |
| S2 | CRIT | SOUND as a rule | The 12.1 MUSTs are clear. The provisioning order that implements them is not (G24), and they kill the cable paths that 8.6/12.6 rely on (G1, G11). |
| S8, S9, S10, S12 | HIGH | SOUND / PARTIAL | S8, S9 sound. S10 epochs exist, but the transition is broken (G1). S12 ORIGIN works only until the 16-bit wrap or 24 h expiry (G3). |
| S13 | HIGH | PARTIAL (accepted) | The penalty list is specified; insider residual risk is stated. |

---

## 2. Findings

### G1 [CRITICAL] Key-epoch activation makes every laggard permanently deaf; every leaf dies at the first rotation

Section: 8.4 (hop_tag "recomputed by every transmitter", receiver tries E
then E-1), 8.6 ("A node that missed the activation ... receives the update
when next reached"), 4.4 (leaves are senders only), 12.1 (UART download
mode disabled by eFuse).

Failure in the field:

1. Month 3: the key server rotates to E+1 (routine, or after a theft). It
   reaches 45 of 50 nodes. Five are missed: two relays powered down for
   maintenance, and every leaf, because a leaf never serves a group and a
   KEY_UPDATE session needs the target to act as probe for its unit ID.
2. Activation. Every activated node now sends its hop_tag under K_mesh(E+1).
   A laggard holds only E and E-1, so step 5 drops every frame from every
   updated neighbour (`hop_tag_fail`).
3. The laggard can still transmit (its E tag is accepted as "previous"), but
   it can never receive anything: no HELLO, no BIND_ACK, no RESUME_ACK, no
   ACK, and no KEY_UPDATE either, because the KEY_UPDATE that would cure it
   arrives re-tagged under E+1 by the last relay. The 8.6 sentence
   "receives the update when next reached" cannot happen.
4. Leaves: each wake sends RESUME (accepted), drops the RESUME_ACK, falls
   back to SEEK, drops every HELLO, and loops in backoff with the radio on.
   Each leaf flattens its battery in days (estimate) while flooding the
   mesh.
5. Recovery "by cable" (8.6) is impossible. Under 12.1 the field image has
   UART download disabled and flash encryption in release mode, so the NVS
   cannot be rewritten from outside. Each laggard is a site visit and a
   board swap.

Activation timing makes the same partition temporary for everyone.
Activation mode 0 ("when every peer has acknowledged") cannot be evaluated
by a node, which only knows its own ACK, so it falls to the 86400 s fallback
counted from each node's own receipt time. Nodes updated hours apart
activate hours apart. During that window, activated and non-activated
neighbours cannot hear each other, because a pending E+1 is not in the
accept set.

Fix:
1. Three-phase rollover. (a) On receipt, add E+1 to the receive set
   immediately (accept E-1, E, E+1). (b) At activation, switch the transmit
   epoch to E+1. (c) Retire E only by an explicit, later RETIRE item, never
   implicitly.
2. Per-neighbour transmit epoch. The link table records the newest epoch
   that verified each neighbour's hop_tag. Unicast to a neighbour uses that
   epoch. Floods are sent under the oldest epoch any live neighbour still
   uses, until RETIRE.
3. Give leaves a management path: see G10.
4. Replace activation mode 0 with `at_utc_s` only. Nodes without time
   activate on an explicit ACTIVATE item, pushed after the key server has
   collected all ACKs.
5. Define an app-level, authenticated re-provisioning path (UART console
   gated by a per-device recovery key from the manifest). Under the field
   profile, "by cable" means only that.

### G2 [CRITICAL] Default liveness traffic saturates a 50-node mesh, and ROUTE_TTL 6 s makes the only alternative a flood per burst

Section: 4.2, 7, 9 (keepalive_ms default 250 ACK / 500 PING, ACK_EVERY),
11.6 (ROUTE_TTL_MS 6000; keepalive > 2 s MUST re-anchor with RESUME), 11.11
(gateway polls DIAG).

Failure in the field. Take a building with 40 sessions (sensors at one sample
per second to one per minute), an average route length of 2 hops, and
ESP-NOW at its default 1 Mbps PHY rate. A small unicast frame costs about
1.5 ms of air per hop, counting the long preamble, the 802.11 ACK, DIFS and
backoff (estimate).

- Each session with `keepalive_ms` = 0 sends 4 probe ACKs per second.
  Sessions idle for 250 ms also send probe PINGs and sender PONGs (7: "sends
  a PING of its own whenever it has heard nothing for keepalive_ms"). That
  is 4-8 frames/s per session whatever the data rate.
- 40 sessions x 4-8 frames/s x 2 hops x 1.5 ms is 0.5-1.0 s of airtime per
  second. One collision domain is saturated by keepalives alone, before any
  DATA, PARITY, flood or DIAG. Relays near the gateway or probes carry most
  of it.
- The escape hatch is a larger `keepalive_ms`. But routes die after 6 s, so
  11.6 then requires one RESUME flood per DATA burst. A flood at 50 nodes
  is up to 49 rebroadcasts x FLOOD_REPEAT 2, about 100 ms of air (estimate).
  20 slow sensors each reporting once a minute is 20 floods/min of this.
- The gateway's DIAG round-robin (one node every few seconds) always finds
  the route expired (6 s TTL, minutes between polls of one node), so every
  poll is a mesh-wide flood (11.4: "MAY flood it instead").
- The 32-entry route table at a funnel relay holds 2 entries per session
  plus a reverse route for every flood origin seen in the last 6 s. When it
  is full, "earliest expiry" evicts exactly the slow sessions.

The result is a mesh that works on a 5-node bench and collapses at 30-50
nodes: ACK loss, then SESSION_TIMEOUT, then re-SEEK floods, then more loss.

Fix:
1. ROUTE_TTL_MS = 300 s and ROUTE_ENTRIES = 64 (64 x 12 = 768 bytes). Stale
   routes cost nothing until a failure, and failures are already detected
   end to end by SESSION_TIMEOUT plus the penalty list. Delete the 11.6
   RESUME-per-burst rule for non-leaves.
2. Default keepalive 5000 ms. Probe ACKs only on ACK_EVERY, FLAG_ACK_REQ or
   keepalive expiry since the last frame it sent. No probe PING when the
   sender is within its keepalive. The sender PINGs only when no ACK has
   arrived for keepalive_ms.
3. Publish an airtime budget table in section 9 (frames/s per session x
   hops x 1.5 ms at 1 Mbps, plus floods). State the rule "keepalive traffic
   <= 10 % of airtime at the funnel". Consider `esp_wifi_config_espnow_rate`
   at 6 Mbps or higher for mains nodes, and measure the range loss.

### G3 [HIGH] Pre-session frames reuse a 16-bit seq under K_mesh with ROC 0; ORIGIN freshness wraps, black-holes origins and admits replays

Section: 3.5 ("ROC is 0 in their tag input"; 32-bit counter, low 16 bits on
the wire), 8.4, 11.5 (ORIGIN, serial arithmetic, 24 h), 11.8 ("Replay (R5)"
under outsider cannot).

Failure in the field:

1. The gateway originates most pre-session traffic: TIME_RESP to 50 nodes
   every 600 s, DIAG_REQ every few seconds, its HELLOs and BIND_ACKs. That
   is 20k-70k frames/day (estimate), so its 16-bit seq wraps every 1-3
   days.
2. A relay that last recorded the gateway's flood at seq s sees the next one
   when the counter has moved by more than 32768. Serial arithmetic calls it
   "not newer", so the gateway's floods (KEY_UPDATE SEEKs, flooded DIAG/TIME)
   are dropped as `relay_drop_stale` at that relay until its ORIGIN entry
   ages out, up to 24 h. No attacker is needed. The 11.5 claim "this filter
   never black-holes a legitimate node" is false.
3. Outsider replay. Any recorded SEEK/BIND/DIAG/TIME flood carries a valid
   K_mesh tag forever, because ROC is 0. Once the origin's counter is within
   32768 below a recorded seq, the recording is "newer". Replaying the
   recording with seq = last_seq + 30000 makes every relay in range advance
   last_seq by 30000. The real origin's floods are then dropped for its next
   30000 pre-session frames: weeks for an ordinary node at about 200/day.
   One frame, no keys.
4. After 24 h without a flood from X, X's ORIGIN entry expires. Any recorded
   SEEK of X is then forwarded mesh-wide, installs reverse routes, and gets
   HELLOs from probes.
5. Insider variant. SEEK, BIND-outer and flooded DIAG/TIME carry only a
   K_mesh tag, so any K_mesh holder can originate floods with any `src_id`.
   A captured node forges a SEEK "from the gateway" with a far-ahead seq. It
   overwrites reverse routes to the gateway via itself (a fresher flood
   replaces routes, 11.4), and it poisons ORIGIN so the real gateway's
   repair floods are dropped for 24 h. 11.8 says an insider cannot "claim
   another unit ID". That holds for sessions only.

Fix:
1. Put the full 32-bit pre-session counter on the wire in every pre-session
   payload (add `preseq_hi u16`, so SEEK becomes 16 bytes) and include it
   in the tag. ORIGIN compares 32-bit values, with no wrap in practice
   (about 160 years at 70k/day).
2. ORIGIN refuses a jump of more than 2^20 ahead of the stored value, so a
   forged far-future seq cannot black-hole an origin. Drop ORIGIN_TTL to
   1 h, which is safe with 32-bit values.
3. Correct 11.5 and 11.8. A K_mesh holder can impersonate any origin's
   floods. Record this in 12.7 as a reason for asymmetric identities, or tag
   floods under a per-origin key the relays can verify (for example a
   relay-verifiable signature on SEEK only).

### G4 [HIGH] hop_tag has no freshness and no binding to the carrier address: a replayed authentic frame poisons links, raises collision alarms and floods RESUME

Section: 8.4 (hop_tag), 11.4 steps 5-6 and 9b (RESUME exempt), 11.9
(replacement vs collision), 8.7 (S19 "alarms cannot be triggered by
outsiders"), 11.8 (outsider cannot "enter any table ... be forwarded").

Failure in the field. An outsider with a sniffer records broadcast and
unicast ESP-NOW frames (headers and tags are clear), then retransmits them
verbatim from its own MAC:

- Step 5 passes (the bytes are unchanged), and step 6 learns
  `(prev_hop, ESP-NOW) -> attacker MAC`. That is exactly the F22 (A) link
  poisoning, done with no forgery. Step 6 runs before step 8, so even
  nodes that only overhear the frame learn it.
- If the victim's entry is live, 11.9 calls it a collision, and every node
  in range raises `PL_EVT_ID_COLLISION` once per replay. The alarm the
  gateway relies on for F3 becomes noise.
- If the entry has expired, 11.9 calls it a replacement, and the attacker
  now owns that neighbour's address. Leaves are the easiest target: their
  entries always expire while they sleep, so the RESUME_ACK goes to the
  attacker and every wake falls back to a full SEEK (3-5x energy, 4.4).
- RESUME is exempt from 9b, and dedup lasts only 5 s. A recorded RESUME
  replayed every 5 s is re-flooded to ttl, re-installs reverse routes, and
  drains the leaf's flood bucket (depth 6, refill 2/s), so the leaf's real
  RESUME and SEEK are dropped as `relay_drop_rate`.
- Replayed unicast frames are forwarded hop by hop to the endpoint, which
  only then drops them on its replay window. "Cannot be forwarded" is
  false.

Fix:
1. Add per-hop freshness. Put `hop_ctr u16` in the hop fields (a per-node
   persistent counter, like pl/preseq), covered by the hop_tag. The link
   table keeps the last 32-bit value per (unit_id, transport), with a 32-bit
   reconstruction as in 3.5. Drop non-newer frames before step 6. The
   header is still unfrozen, so this is the moment to add it (costs 2 bytes
   per frame; IR drops to 20 data bytes).
2. Minimum alternative without header change: learn or replace link
   addresses only from fresh floods (after 9b/9c) and from HELLO and
   RESUME_ACK; ordinary unicast frames only refresh an entry whose address
   already matches. Give RESUME the pre-session counter (G3 fix 1) so 9b
   covers it. Raise collision alarms only from fresh floods.
3. Correct 8.7 and 11.8.

### G5 [HIGH] Step 9b runs before 9c, so the F6 best-copy routing can never run for SEEK/BIND

Section: 11.4 steps 9b, 9c, 9e, 9f; 11.5 jitter paragraph; 4.1.2 (HELLO
reports the best copy's path_cost).

Failure in the field. Copy 1 of a SEEK (seq s) passes 9b-9e, and 9e inserts
`last_seq = s` into ORIGIN. Copy 2 of the same SEEK, maybe the lower-cost
one from the near relay, reaches 9b. Its seq s is "not newer than last_seq",
so it is dropped as `relay_drop_stale` before 9c, where "a lower-cost copy
still updates the reverse route". The same happens at the probe, which runs
the same pipeline. So every reverse route and every HELLO path_cost comes
from the first copy: the gray-zone behaviour of round 1, F6, unchanged.
RESUME (session_id != 0) skips 9b, so best-copy works only for RESUME.

A second, related gap: 4.1.2 sets HELLO `max_frame` from "the SEEK's
path_mtu" without saying which copy. A probe that takes path_mtu from copy 1
(ESP-NOW, 250) but routes on lower-cost copy 2 (via a BLE-64 bridge, 61)
negotiates 250. Every DATA frame then dies at the bridge with
`relay_drop_mtu`, and MODE_ACK never says "too big", because MODE itself
fits.

Fix:
1. Reorder: dedup lookup (9c, including best-cost update) first. Then
   ORIGIN only for frames not in dedup, with "strictly older" as the drop
   test. ORIGIN is updated when the dedup entry is created.
2. State that the route, path_mtu and path_cost reported in HELLO all come
   from the same (lowest-cost) copy, and that 9f forwards that copy's
   path_mtu.
3. Add an Appendix A case: two copies, second cheaper, and the expected
   route and HELLO fields.

### G6 [HIGH] Forward routes are installed only by HELLO: RESUME_ACK, DIAG_RESP and TIME_RESP never install them, so a leaf's first DATA after wake is dropped

Section: 4.4 ("RESUME_ACK ... installs the forward routes"), 11.4 event table
and step 10a (HELLO only), 11.4 last paragraph ("the reply installs the
route"), 11.6.

Failure in the field. A leaf sleeps 60 s. Every relay route to and from it
has expired (6 s TTL).

1. RESUME (flood) installs reverse routes to the leaf.
2. RESUME_ACK travels back to the leaf on those routes. Per 11.4 it only
   refreshes routes; 10a installs a forward route only for type HELLO.
3. The leaf sends DATA. The first relay has no route to the probe (unless
   unrelated traffic to that probe happens to pass the same relay), so the
   DATA is dropped as `relay_drop_noroute`.
4. ACK_REQ goes unanswered. After RTO x 3 the leaf falls back to a full
   SEEK, which does install routes via HELLO. The F1 saving is gone on
   every wake, and the leaf's own route table, cleared by deep sleep, also
   has no next_hop from RESUME_ACK under 11.4.

Same mechanism elsewhere:

- DIAG_RESP and TIME_RESP replies to flooded requests install nothing, so
  the gateway never learns a route to the nodes it polls. Every poll stays
  a flood (G2).
- Slow non-leaf sessions: the probe's ACK or PING at keepalive_ms (for
  example 30 s) always meets an expired route at the probe's first hop and
  is dropped. The sender sees no ACK and closes after 8 x keepalive_ms,
  unless it happens to set FLAG_ACK_REQ, which 4.4 requires of leaves only.

This shows up on the bench the first time a leaf is tested through one
relay, hence HIGH, not CRITICAL.

Fix:
1. Step 10a: "unicast HELLO, BIND_ACK, RESUME_ACK, DIAG_RESP or TIME_RESP
   received from prev_hop installs a forward route to src_id". Add the same
   rule to the event table.
2. With G2 fix 1 (ROUTE_TTL 300 s), slow sessions no longer need RESUME.
   Keep RESUME for leaves only.
3. Leaves keep `next_hop` and the link address of their first hop in RTC
   memory along with the session state.

### G7 [HIGH] PL_SELECT_BEST cannot bind on a direct link: the sender waits 600 ms, the probe gives up at about 490-545 ms

Section: 4.1.4 (BEST waits SEEK_BASE_MS = 600), 4.1.10 (BIND_TIMEOUT(1) =
490 from HELLO; the inequality assumes BEST adds only SELECT_MARGIN_MS = 20),
9 (SELECT_MARGIN_MS "extra wait for PL_SELECT_BEST").

Failure in the field, hops = 1:

- The probe hears the SEEK at about t = 5 ms and sends HELLO at t = 5-55.
  BIND_TIMEOUT(1) = 490 ms, so it returns to LISTENING at t = 495-545.
- The BEST sender sends BIND at t = 600.
- A LISTENING probe ignores a BIND naming it (4.1.6), and so do the
  fallback candidates, which timed out the same way.
- The sender re-SEEKs and the same thing happens. With BEST, direct links
  never bind.

At 2 hops the first BIND makes it, but its retries do not (the last retry
lands at about 1080 ms against a 910 ms timeout). The two sections define
the BEST wait differently (600 ms vs 20 ms), so two implementations
disagree.

Fix: delete PL_SELECT_BEST (cut list, G14). Relay-side best-copy routing
(G5 fixed) already prefers cheap paths, and first-acknowledger-wins is the
user requirement. If BEST is kept: define its wait as "first HELLO +
SELECT_MARGIN_MS" and keep the inequality. Never use a fixed 600 ms.

### G8 [HIGH] Revocation does not revoke K_mesh for a whole epoch, and the key server needs K_site, which 8.2 says nobody in the field holds

Section: 8.2 (K_site "nobody in the field"; K_pair derived by "tool"), 8.6
("At activation E+1 becomes current and E-1 is erased"; revocation "after
E+1 activates and E is erased its K_mesh is useless"), 11.8 third row, 11.1
(gateway = key server).

Failure in the field:

1. A relay is stolen on day 1. The key server pushes TLV 0x03 and E+1, and
   activates. Per 8.6, E-1 is erased and E becomes "previous", which every
   receiver still accepts. The thief's K_mesh(E) remains a valid hop_tag
   and flood key until the next rotation.
2. For that whole epoch the thief keeps every K_mesh capability, including
   G3 (5): spoofed floods for any src_id, route hijack of the gateway,
   ORIGIN black-holing. 8.6 and 11.8 claim this ends at the first bump. It
   needs two bumps, and with G1 unfixed each bump strands leaves and
   laggards.
3. Key server material. TLV 0x02 carries `K_pair(self, unit_id, E+1)` for
   every pair, and TLV 0x01 carries `K_mesh(E+1)`. Both derive from K_site.
   So either the gateway holds K_site, and capturing the gateway (on a wall
   or pole, like every other node) compromises the whole site, contradicting
   R2 and 12.2; or the offline tool exports per-epoch bundles to the
   gateway, about 1225 pairs x 32 bytes per epoch at 50 nodes. That export
   is not specified.

Fix:
1. Revocation is an immediate retire. TLV 0x03 is followed by an activation
   that sets current = E+1 and erases E on every reached node, with no
   "previous" window for that bump. Laggards are recovered per G1 fix 5.
   State this cost explicitly.
2. K_site never leaves the tool. Specify an epoch bundle: the tool
   generates `K_mesh(E+1)` and only the TLVs for each node, each encrypted
   to that node's current K_pair with the key server. The gateway
   (LAN chip) stores and relays opaque per-node blobs and cannot read them.
   This also keeps a captured gateway down to its own pairs.
3. Delete activation mode 0 (G1 fix 4).

### G9 [HIGH] Probe session capacity: parked leaves hold full 14 KB slots, no sizing rule exists, and the arq_window fix caps a buffer the probe does not have

Section: 4.1.12 (PL_MAX_SESSIONS >= 4; v2 "one session or cap arq_window
at 8"), 4.4 ("The slot counts as occupied"), Appendix B context comment,
section 5 ("Probes never send DATA").

Failure in the field. 50 nodes: 20 leaves reporting every 5 min and 25
mains sensors streaming, to one group.

- Every parked leaf keeps a full slot. Per Appendix B a slot is 1000 (tx
  queue) + 2220 (FEC) + 8000 (ARQ) + 2500 (reorder) + 600 (state) = 14.3 KB
  on ESP-NOW v1, so 45 sessions need about 640 KB.
- An ESP32-C3 probe holds 4-8 slots. The other senders get HELLO FULL and
  back off to the 60 s cap forever. Data loss looks like "sensor offline".
- The spec gives no rule for how many probes a site needs, and no rule for
  how data on 10 different probes reaches the gateway or LAN. The obvious
  build, the gateway as sink, cannot hold more than about 8 sessions.
- 8 KB of each slot is the ARQ retransmit buffer, which only a DATA sender
  uses. Probes never send DATA (section 5), so 32 KB of the quoted 66 KB is
  dead weight on every probe.
- The v2 fix "cap arq_window at 8" limits a sender-side buffer. No field in
  SEEK, HELLO or MODE tells the sender, and the probe's own v2 RAM (reorder
  plus FEC, about 29 KB per slot) is untouched.

Fix:
1. Split a slot into a session record (keys, ROC/seq, replay bitmap, two
   configs, SRTT: about 600 bytes) and a stream buffer (FEC + reorder,
   about 4.7 KB on v1) taken from a small pool only while frames are in
   flight. Parked sessions keep only the record. Probes allocate no ARQ
   buffer.
2. A C3 probe can then hold 64 records (about 38 KB) and 4-8 stream buffers.
   Make PL_MAX_SESSIONS mean records, and add PL_MAX_STREAMS.
3. Publish a capacity rule in 12: records >= senders served; streams >=
   concurrent senders with FEC/reorder in flight.
4. State the sink architecture. Either the sink is a LAN host speaking the
   UDP carrier (unbounded RAM; this is a second implementation, so count
   it), or probes re-send to the gateway over their own sender session.
5. Replace "cap arq_window" with an `arq_window` field in MODE that MODE_ACK
   may reduce.

### G10 [HIGH] Leaves cannot be rekeyed, updated, time-synced on a schedule or diagnosed

Section: 4.4 (leaf = sender only), 8.6 (KEY_UPDATE "S -> P", the key server
SEEKs the target by unit ID), 11.11 ("Any node answers DIAG"), 12.6
(UPDATE_WINDOW via KEY_UPDATE), 4.4 (`power_src` "reported by DIAG").

Failure in the field. Every management path in v0.4 requires the target to
listen or to serve a group, and a leaf does neither:

- KEY_UPDATE is a session in which the target is the probe, so leaves are
  never rekeyed. With G1 they go deaf at the first activation; even with G1
  fixed they are stranded at the second bump.
- No UPDATE_WINDOW, so there is no firmware path for leaves at all, not
  even maintenance WiFi.
- No DIAG, so the one role on a battery is the one role whose battery, reset
  reason and link quality the gateway cannot see. "Reported by DIAG"
  (power_src) never happens for the node it was written for.

Fix:
1. Mailbox. RESUME_ACK and BIND_ACK carry a `pending` flag. When it is set
   the leaf stays awake for MAILBOX_MS (for example 500 ms), and the probe
   sends DIAG_REQ and KEY_UPDATE inside the existing session in the
   p2s direction (allow KEY_UPDATE P -> S, tagged under K_p2s and CCM).
2. The key server queues leaf items at the leaf's probe, or the leaf's
   probe is the key server's relay for them.
3. Every DATA frame from a leaf carries battery mV and the reset reason in a
   2-byte trailer (or a DATA status extension), so leaf health is visible
   without any extra wake time.

### G11 [HIGH] The OTA path fails exactly where the mesh exists, and "by cable" is impossible under the field profile

Section: 12.6, 12.1 (UART download disabled, flash encryption release),
8.6 ("re-provisioned by cable").

Failure in the field:

1. UPDATE_WINDOW sends a node to "the maintenance WiFi". Nodes are meshed
   because they are out of infrastructure range: the far end of an outdoor
   site, a plant room, a car park. Those are the nodes "farthest first"
   reaches first, and they cannot associate. The window expires and the
   bug stays.
2. "IR-only nodes by cable", "UART-only nodes through their UART host" and
   "re-provisioned by cable" all assume esptool or a host flashing path.
   12.1 burns UART download disable, and release-mode flash encryption with
   an on-chip key makes host writes impossible anyway. The only writer left
   is the running app, which has no defined UART update or provisioning
   command.
3. Rollback rule. A probe-only or edge node in a quiet site may neither
   complete a handshake nor forward 100 frames within 10 min of boot. Its
   senders re-bound elsewhere when it rebooted. So a good image rolls back,
   and the next window repeats the cycle.

Fix:
1. Define in-mesh OTA now, kept minimal. A sender session from the update
   server (the LAN host or gateway) to the node, arq = 1, fec_m = 0,
   OTA_BEGIN {size, sha256, version} / OTA_CHUNK {offset u32, data} /
   OTA_END, with the node writing via `esp_ota_write` and Secure Boot
   checking the signature. 1 MB at 20-50 kbit/s over 2-3 hops is 3-7 min
   per node (estimate), so 50 nodes in a night. Keep UPDATE_WINDOW as the
   fast path where WiFi exists.
2. Define an authenticated app-level UART service (recovery key per device
   from the manifest) for update and re-provisioning. Under the field
   profile, this is what "cable" means.
3. Rollback rule: mark valid after the node has verified a hop_tag from at
   least one neighbour and answered one DIAG_REQ from the gateway, which
   polls a freshly updated node immediately. Both prove two-way mesh
   connectivity.

### G12 [HIGH] Two 2.4 GHz transmitters in one enclosure with no isolation or frequency plan: the gateway and every nRF24 bridge desense themselves

Section: 12.4 (two-chip gateway: mesh ESP32 plus LAN ESP32 running STA,
joined by UART), C.6 (nRF24 channels 76-83; bridge ESP-NOW <-> nRF24),
11.1 (bridges are "the normal case").

Failure in the field:

- Gateway. The LAN chip transmits to the AP at up to +20 dBm, a few cm from
  the mesh chip's antenna. Coupling at that distance is roughly 15-25 dB
  (estimate), so the mesh chip's front end sees about 0 dBm while it
  listens for -85 dBm frames. ESP-NOW frames arriving during LAN TX (MQTT,
  OTA, SNTP, TCP ACKs) are lost. Floods have no MAC retry.
- The gateway is the funnel: every session that ends on the LAN side, every
  TIME and DIAG exchange passes through it. Loss correlates with LAN load,
  so it shows up as gaps at busy hours. Nothing in v0.4 separates the AP
  channel from the mesh channel either: 12.4 only says the mesh channel is
  "away from the building AP".
- nRF24 bridges. The ESP32 TX and the nRF24 (or a +20 dBm PA/LNA module)
  share a box with no arbitration; each radio's reception collapses while
  the other transmits (estimate, measure). A 250-byte frame is 9 segments,
  and losing any one drops the frame. C.6's channels 76-83 (2476-2483 MHz)
  also sit inside WiFi channel 13 (2461-2483 MHz), which 12.4 does not
  forbid as the mesh channel.

Fix:
1. Gateway LAN side on Ethernet (ESP32 with LAN8720, or W5500 over SPI on
   C3/S3), with no WiFi STA in the box. If WiFi must be used: external
   antennas at least 30 cm apart, and the mesh channel at least 5 channels
   (25 MHz) from the AP channel, written into the manifest.
2. nRF24 sites: mesh channel restricted to 1-6, nRF channel 76-81 (G29 also
   applies). Antennas separated or cross-polarised. Add a bridge-local rule:
   never start a TX on one radio while the other is mid-reception of a
   multi-segment frame (the adapter knows from `idx` and LAST).
3. Commissioning test: run DIAG `crc_fail` / `seg_fail` / `rx_frames` on
   the gateway and bridges with the co-located radio idle, then loaded.
   Record the delta in the manifest.

### G13 [HIGH] BLE bridges are mesh nodes, mesh nodes MUST run WIFI_PS_NONE, and ESP-IDF requires modem sleep when BT is running

Section: 1.2 and 12.4 (WIFI_PS_NONE mandatory on mesh nodes), 6.4 and 12.5
(a BLE bridge is a central that also forwards ESP-NOW), C.3.

Failure in the field. ESP-IDF's RF coexistence requires Wi-Fi modem sleep
while Bluetooth is enabled. Older IDF versions abort at boot with "Should
enable WiFi modem sleep when both WiFi and Bluetooth are enabled"; newer
ones reject or override the setting. Verify on the pinned IDF.

Either way, a BLE bridge cannot follow 12.4. If it boots, its ESP-NOW
reception is time-sliced against BLE connection events and modem sleep,
and it is the node that forwards every BLE edge's traffic into the mesh.
Broadcast floods to and through it are lost first.

Severity basis: HIGH holds if the pinned IDF aborts or silently forces
modem sleep. If it only logs a warning and honours WIFI_PS_NONE under
coexistence, downgrade to MEDIUM: the remaining problem is BLE time-slicing
loss at the bridge (round 1 F5), which a measured fec_m can absorb.

Fix: build BLE bridges like the gateway. A BLE-only chip (C3 is ideal)
joined to a mesh chip by the UART carrier. The mesh chip never starts BT.
Write in 12.5 that a single-chip BLE bridge is a bench-only configuration.

### G14 [HIGH] Scope exceeds what one engineer can implement and validate; the spec should shrink before anyone writes code

Section: whole document (about 2350 lines, 6 carriers, 2 profiles, 20
message types, about 20 pipeline steps, 3 key layers, epochs, ENC, DIAG,
TIME, park/resume, nRF24 segmentation, IR PHY).

Estimate for an ESP32-C3 (all estimates):

- Code, ProbeLink only:
  - frame and validation: 1.5k lines;
  - RS (errors and erasures) and group FEC: 1k;
  - ARQ and reorder: 1k;
  - session machines (sender, multi-session probe, park/resume): 2.5k;
  - mesh pipeline and tables: 2k;
  - keys, epochs and KEY_UPDATE: 1.5k;
  - DIAG and TIME: 0.8k;
  - transports (ESP-NOW 0.4k, UART 0.4k, UDP 0.5k, BLE 1.2k, nRF24 1k plus
    driver, IR RMT 0.8k): 4.3k;
  - host test harness, fuzzing and a mesh simulator: 2k;
  - Python provisioning and key tool: 1k.
- About 17k lines in total: 6-9 engineer-months to field quality, plus a
  10-node soak. The 50-node behaviours (G2, G3, G5) cannot be seen on a
  bench at all without the simulator.
- Flash: ProbeLink 70-100 KB. Image with WiFi, ESP-NOW, mbedTLS and
  esp_https_ota: 1.0-1.2 MB, plus 150-200 KB with NimBLE. That fits 2 OTA
  slots on 4 MB, but not on 2 MB modules.
- RAM, using Appendix B's own figures: 66 KB for 4 sessions, plus the
  pl_task stack 6 KB, plus a TLS peak of 40-60 KB during esp_https_ota. A C3
  has about 200-230 KB free after WiFi starts. That leaves about 80-100 KB
  without BLE and about 30-50 KB with NimBLE: it fits, but only at 4
  sessions, and only if OTA never runs during heavy traffic. With G9 fix 1,
  the 4-session figure drops to about 30 KB.

Cut list for v0.5. All five core requirements survive: IDs; CRC plus
recovery data; 32-bit digital/analog; HIGH/LOW; seek a group with
first-acknowledger-wins.

1. BLE as a mesh carrier: move it to a separate chip over UART (G13), or
   drop it from v1.
2. IR inside the mesh: allow IR only as a leaf edge (one hop, point to
   point). This removes time_scale for mesh timers, the path_mtu <= 58
   heuristic (G21), 29-byte MODE/DIAG/KEY_UPDATE limits (G16, G17), and IR
   in-frame RS decoding of errors from the mesh path.
3. ESP-NOW v2, FLAG_LEN16 and UDP > 255: one max_frame of 250 everywhere.
   This removes LEN16 parsing, v2 RAM and the arq_window variants.
4. PL_SELECT_BEST (G7).
5. The HMAC-or-CCM dual auth path: in the field always use AES-CCM, with
   HMAC only for the hop_tag. One tag code path, one set of vectors.
6. TIME stratum chaining (G20): listed masters only.
7. KEY_UPDATE activation mode 0 (G1, G8).
8. In-frame RS on PACKET links: fix rs_nsym = 0 there, keep it on UART.

---

### G15 [MEDIUM] SEEK timing: SEEK_TIMEOUT(n) is undefined, full jitter fires early, and BOOT_SPREAD ignores FLOOD_REPEAT

Section: 4.1.8, 9 (no SEEK_TIMEOUT row), 4.1.1, 11.5, 4.4 (RESUME ttl).

Failure in the field:

- Rule 8 says "no usable HELLO within SEEK_TIMEOUT(n)", and no section
  defines it. The obvious reading, that the full-jitter wait
  `rand(0, 600 x 2^n)` is the timeout, re-SEEKs before a 4-hop HELLO can
  return (up to about 550 ms) in about half of first attempts. That is an
  extra mesh-wide flood each time, the F25 problem again.
- Post-outage: 25 senders x (SEEK + BIND) in BOOT_SPREAD 10 s is 5
  floods/s. Each flood is up to 49 x FLOOD_REPEAT 2 broadcasts at about 1.1
  ms, so about 108 ms of air per flood and 54 % of a collision domain
  (estimate), before HELLO, BIND_ACK, MODE and the G2 keepalives.
- SEEK_TTL is fixed at 4. A linear outdoor site (fence line, pipeline,
  corridor) of 50 nodes has a diameter well above 4, so probes beyond 4
  hops are reached only by the "last two attempts" at MAX_HOPS, minutes
  in. RESUME uses `min(hops + 1, SEEK_TTL)`, so a leaf bound at 5 hops
  can never resume.

Fix:
1. SEEK_TIMEOUT(n) = SEEK_BASE_MS(ttl) + rand(0, min(cap, base x 2^n)):
   always wait for the HELLO, then jitter.
2. BOOT_SPREAD_MS = 600 x node_count (30 s at 50 nodes).
3. `pl/seek_ttl` = site diameter + 1, from the manifest. SEEK_BASE_MS is
   derived from it. RESUME ttl = min(hops + 1, MAX_HOPS).

### G16 [MEDIUM] KEY_UPDATE format is undefined and does not fit IR or BLE-64 paths; a busy probe cannot be rekeyed

Section: 5 (KEY_UPDATE "TLV items"), 8.6, 3.6 last row, 4.1.2.

Failure in the field:

- The T and L widths, whether a TLV may span chunks, and how idx/total
  interacts with ARQ are all unspecified. TLV 0x01 (32 bytes plus at least 2
  bytes of T/L plus 3 bytes of header = 37 or more) does not fit an IR
  payload with AUTH (29) or BLE-64 (32), so those nodes cannot receive a
  mesh key at all.
- A probe whose slots are full (or held by parked leaves, G9) answers the
  key server's SEEK with FULL, and the key server backs off for 60 s,
  again and again.

Fix:
1. TLV = type u8, len u8, value. TLVs may span chunks; reassembly happens
   after all `total` chunks are ACKed. Add an Appendix A vector.
2. Reserve one management slot on every probe that only the manifest's key
   server or update server may use.

### G17 [MEDIUM] DIAG_RESP cannot fit the frame it must fit

Section: 11.11 ("The record must fit one frame"), Appendix B pl_stats_t.

Failure in the field. The fixed part is 34 bytes, and pl_stats_t is 30 x
u32 plus a u16 = 122 bytes, so about 156 bytes before either list. Every
link entry is 8 bytes and every route entry is 6.

- ESP-NOW v1 (221-byte payload): at most 7 links and no routes, while an
  open-plan node has 25 neighbours.
- IR (29) and BLE-64 (32): no answer at all.

So the gray-zone hop that F15 was meant to find is usually in the truncated
part. `stack_hwm` is also sent twice.

Fix: paged DIAG. DIAG_REQ carries `section u8` (0 identity and health, 1
counters, 2 links, 3 routes) and `page u8`. Each response fits 29 bytes for
section 0 and pages the rest by path_mtu. Drop the duplicate stack field.

### G18 [MEDIUM] Park/resume mechanics: CLOSE(PARK) ack undefined, RESUME timeout too short, probe-side timeout too short for long parks

Section: 4.2 ("CLOSE reason 6 (PARK) is the exception described in 4.4"),
4.4, 7 (RTO floor).

Failure in the field:

- 4.4 never describes the PARK exception, so whether CLOSE(PARK) is ACKed
  is undefined. If it is lost, the probe applies SESSION_TIMEOUT = 8 x
  60000 = 480 s, so any park_s above 480 drops the session. The RESUME
  then fails silently, and the leaf pays a full handshake.
- The leaf waits RTO x 3 for RESUME_ACK, with RTO at the 100 ms floor
  because SRTT is not in the RTC list. That is 300 ms, while a 4-hop
  RESUME flood (relay jitter up to 50 ms per hop) plus the unicast return
  takes about 300-500 ms (estimate), so multi-hop leaves fall back to SEEK
  routinely.

Fix:
1. CLOSE(PARK) carries FLAG_ACK_REQ; the probe ACKs it; the leaf retries it
   up to 3 times before sleeping.
2. Store SRTT in RTC. RESUME timeout = BIND_TIMEOUT(hops). Retry RESUME once
   before falling back.

### G19 [MEDIUM] The leaf wake budget leaves out Secure Boot validation, an NVS write per wake, and the boot holdoff

Section: 4.4 wake budget, 4.1.1 (boot holdoff "first SEEK after boot"),
4.1.15 (`pl/boot_count` once per boot), 12.1 (Secure Boot v2 MUST).

Failure in the field:

- A deep-sleep wake is a full boot. With Secure Boot v2 the bootloader
  verifies the app image on every wake: ESP-IDF's "skip validation when
  exiting deep sleep" is not available with Secure Boot. Hashing a 1 MB
  image from encrypted flash plus the signature check is roughly 100-300 ms
  (estimate, measure).
- Each wake also writes `pl/boot_count` to NVS.
- A wake that falls back to SEEK may wait up to BOOT_SPREAD_MS (10 s) with
  the radio on, about 0.3 mAh, 30x the budgeted wake.
- Realistic awake time is about 0.5-0.8 s, so one report per minute lasts
  about 2 months on 2000 mAh, not 4 (estimate).
- C3 TX peaks of about 300-350 mA exceed what Li-SOCl2 bobbin cells
  deliver. A tired cell browns out on every TX, and the reboot loop drains
  what is left.

Fix:
1. Use an RTC counter for deep-sleep wakes and increment `pl/boot_count`
   only on power-on and reset causes.
2. Exempt `ESP_RST_DEEPSLEEP` from the boot holdoff. A leaf sleeps through
   any backoff instead of waiting awake.
3. Restate the budget with a measured boot time.
4. Require a battery check before radio start (skip the wake below a
   threshold, report it in the next DATA, G10). Set
   `esp_wifi_set_max_tx_power` to the minimum that closes the link. Require
   a bulk capacitor for primary cells.

### G20 [MEDIUM] TIME trust chain cannot be verified, and TIME_REQ has no nonce

Section: 6.5 ("a node whose TIME_RESP stratum is lower ... and which is
itself synced to a listed master"), 11.8 ("Push time to nodes that do not
list it" under insider cannot), 8.4 ("DIAG/TIME requests carry a 32-bit
nonce"), 5 (TIME_REQ = t1 u64 only).

Failure in the field. A requester cannot check that a responder "is itself
synced to a listed master". It only sees a stratum value tagged under
K_mesh, so any K_mesh holder can claim stratum 1 and shift every node's
UTC, contradicting 11.8. TIME_REQ has no nonce (t1 is predictable), which
contradicts 8.4.

Fix: accept TIME only from listed masters (cut chaining; in a 50-node site
the master is reachable). Add `nonce u32` to TIME_REQ and TIME_RESP and
update the 3.6 sizes.

### G21 [MEDIUM] "IR on the path" is inferred from path_mtu <= 58, which misfires both ways

Section: 4.1.10, 11.7 ("If path_mtu <= 58 ... an IR hop is on the path").

Failure in the field:

- An IR link with rs_nsym 4 has path_mtu 60, so the radio timers are used
  over IR and every handshake times out.
- A BLE link that negotiated MTU 61 gives 58, and so does a UART with a
  small max_frame, so those paths get 10x timers for no reason.

Fix: reserve path_cost bit 7 as SLOW (set by any hop with time_scale > 1;
cost clamp 127), echo it in HELLO, and drop the MTU heuristic. Or apply
cut list item 2.

### G22 [MEDIUM] Carrier adapter traps a single engineer will hit

Section: C.1, C.6, 11.10, 11.2.

Failure in the field:

- IR on RMT. A 64-byte frame is about 512 pulse-distance symbols plus the
  preamble. RMT RX memory is 48 symbols per block on the C3 (two RX blocks)
  and 64 per block on the ESP32 (8 blocks in total), so a frame does not
  fit unless the driver's partial-RX mode is used (ESP-IDF v5.3 or later;
  verify) or a GPIO-capture ISR replaces RMT. The S3 can use RMT DMA.
- nRF24 reassembly "one buffer per neighbour". ESB packets carry no source
  address, and two neighbours sending to the same pipe interleave, so the
  receiver cannot tell whose segment 3 it holds. Only segment 0 carries
  prev_hop (frame offset 6).
- RSSI for path_cost needs `esp_now_recv_info_t` (ESP-IDF v5.0 or later).
  On IR or nRF24, HELLO `rssi` has no defined value; A.9 shows -61 for an
  IR-received SEEK.
- The ESP-NOW peer table: when all 16 peers are referenced by live routes,
  what happens next is undefined.

Fix:
1. Pin ESP-IDF >= 5.3 for IR, or specify GPIO capture.
2. nRF24: buffers keyed by frame_tag and opened by segment 0's prev_hop;
   make frame_tag a per-node (not per-neighbour) counter to cut collisions.
3. Define rssi = -128 (0x80) as "unknown".
4. ESP-NOW peer full: evict the LRU peer anyway and re-add it on the next
   send (add/del is cheap).

### G23 [MEDIUM] Mains/solar nodes: no power sizing and no brown-out policy

Section: 11.1 ("mains or solar, MUST"), 4.4.

Failure in the field. A C3 relay in permanent RX draws about 80-100 mA, or
about 7-8 Wh/day including regulator loss (estimate). An nRF24 PA/LNA adds
more.

- An outdoor solar relay sized by guesswork runs flat after a cloudy week.
  At dawn it browns out in a loop: each boot runs the boot holdoff, writes
  NVS boot_count, and emits floods as soon as the voltage briefly
  recovers.
- DIAG reports `power_src` but not supply voltage, so the slide is
  invisible until the node disappears.

Fix:
1. Add a sizing rule to 11.1: panel W >= daily Wh / (peak sun hours x 0.7),
   and a battery for at least 3 days' autonomy (for example about 25 Wh at
   4 peak sun hours).
2. Low-voltage gate with hysteresis before WiFi start.
3. `vbat_mv u16` in DIAG section 0.

### G24 [MEDIUM] The field-profile provisioning order is unspecified and irreversible

Section: 12.1, 12.2.

Failure in the field. Secure Boot v2 key digest burn, flash encryption
release mode (on-chip key, so no host re-flash afterwards), NVS encryption
and a per-device NVS image from the manifest must happen in the right order
on each of 50 boards.

- NVS encryption uses the HMAC-based scheme on C3/S3, but the ESP32 needs
  an encrypted nvs_keys partition.
- The first boot encrypts flash in place and takes tens of seconds; a power
  cut there bricks the board.
- One wrong step burns eFuses irreversibly. "Generated by nvs_partition_gen"
  does not cover any of this.

Fix: specify a provisioning-station script in 12.2: exact esptool and
espsecure sequence per chip family, a verify step, the eFuse summary stored
per MAC in the manifest, and a dry run on 2 sacrificial boards. Prefer one
chip family (C3) for the field.

---

### G25 [LOW] session_id seed has 4 possible values

Section: 4.1.11. `pl/preseq` stores a multiple of 64, so its low byte is
always 0x00, 0x40, 0x80 or 0xC0, and the seed "so it does not repeat across
reboots" barely varies. Fix: seed from `esp_random()` mixed per 4.1.15, and
skip the last 8 ids used (kept in RTC).

### G26 [LOW] Echo rule stated two ways

Section: 11.4 9a ("src_id is my own ID: echo, not a collision") vs 2 and
11.5 (collision when the seq is not in the 16-entry history). An echo
delayed past 16 later floods raises a false alarm under 11.5, and no alarm
ever fires under 9a. Fix: use 11.5's rule in 9a, with history = all floods
of the last DEDUP_TTL_MS.

### G27 [LOW] Validation and pipeline gaps

Section: 3.6, 5, 11.4.

- The 3.6 table has no rows for BIND_ACK (8), BIND_NAK (5), MODE_ACK (2),
  RESUME_ACK (6) or KEY_UPDATE_ACK (3).
- "len <= max_payload" is undefined at a forwarder, which has no path_mtu.
- The MODE check "one full sample fits in max_payload" should be max_payload
  minus 7, and minus 9 more with FEC.
- BIND_NAK reasons 3 and 4 are unreachable in the field profile.
- The pipeline has no "stop" after local unicast delivery (step 7), so every
  endpoint frame continues to 10b and counts as `relay_drop_noroute`, which
  pollutes DIAG.
- A SEEK addressed to a unit ID, and a RESUME, are re-flooded past their
  destination (9e/9f).
- The ACK bitmap covers 32 seqs while ARQ_WINDOW holds 32 DATA frames,
  which span about 40 seqs with k8/m2.

Fix: add the rows, stop the pipeline after local unicast delivery, and stop
floods at a unicast dst.

### G28 [LOW] API and RAM-table gaps

Section: Appendix B, 11.5, 11.9.

- The sender API has no session handle (`pl_send_samples`, `pl_set_mode`),
  so a gateway cannot run concurrent key-server sessions alongside its own
  data session.
- `pl_rtc_state_t`, `pl_diag_t`, `pl_key_tlv_t` and `pl_keystore_t` are
  undefined.
- The table of BIND nonces for "free retry" and the pending-flood buffers
  for 9f "best copy" (one frame per flood in its jitter wait) are missing
  from the 11.9 RAM table.
- mbedTLS HMAC contexts allocate on the heap unless reused, which
  contradicts "no heap after pl_init".

Fix: add handles and type definitions; add the tables; preallocate the md
contexts.

### G29 [LOW] nRF24 channel 83 at 2 Mbps spills past 2483.5 MHz

Section: C.6. A 2 Mbps signal on 2483 MHz occupies about 2482-2484 MHz,
reaching into the restricted band above 2483.5 MHz (FCC 15.205). Fix:
channels 76-81 at 2 Mbps; 83 only at 250 kbps or 1 Mbps.

---

Counts: CRITICAL 2, HIGH 12, MEDIUM 10, LOW 5

Round-1 fixes confirmed sound (text specifies them and they are consistent):
F3, F11, F14, F18 (minor gaps G27), F19, F20, F21, F23 (G26 aside), F24, F25
items 2-4, F26, F27, F28, F7 (scoped), F8, S3, S8, S9, the session-frame
part of F17 (ROC math and A.10 verified), and the F4 channel/STA rule itself.
Appendix A.1-A.10 all recompute exactly.

Verdict: not deploy-ready, but much closer than v0.3. The wire format,
crypto derivations, FEC, the session ROC and the handshake timer table are
now correct and verified to the byte. What fails is the long-run and
at-scale behaviour that a bench never shows:

- the first key rotation strands every leaf and every node that was offline
  (G1);
- the default keepalives saturate a 50-node mesh, and the 6 s route
  lifetime leaves only a flood per burst as the alternative (G2);
- pre-session freshness wraps and admits replays (G3, G4);
- the F1 leaf path is broken by the routing table it relies on (G6), and
  leaves cannot be managed at all (G10);
- the F6 gray-zone fix is unreachable (G5).

At the same time the document has grown past what one engineer can build
and validate. Before writing firmware:

1. Apply the G14 cut list.
2. Fix G1, G2, G3, G5 and G6 in the text.
3. Build the host-side mesh simulator. It is the only way to see G2, G3 and
   G5 before the site does.

Then soak 10 nodes for 72 h, including one key rotation with a node
powered off and one site-wide power cycle.
