# ROAST-3: ProbeLink v0.5 vs field deployment

Target: PROTOCOL.md, DRAFT v0.5 (wire version 1, minor 0), 1677 lines.
Question: is v0.5 ready to start implementation for a field deployment
(one engineer, ESP-IDF on ESP32 / C3 / S3, 5-50 nodes, unattended for months)?
Scope: deploy-blockers and likely field failures only. BLE (phone link) and
IR (one-hop edge) are USER-DECIDED and not reopened; findings about them are
missing rules inside those decisions. "(estimate)" marks reviewer estimates.

What was run:

- `vectors_v05.py`: prints ALL OK and reproduces A.1-A.13 byte for byte.
  That is self-consistency only. The script generated Appendix A, and it
  hands every receiver the sender's true counters (see H2).
- A scratch copy of the script with one added case: a HELLO whose probe
  `pre_ctr` is 0x00010007. Its header `seq` is the same as for `pre_ctr` 7.
  Decrypting with `ctr_hi` = 0 fails with InvalidTag; decrypting with the
  true `ctr_hi` = 1 succeeds.
- Independent arithmetic checks:
  - frame sizes: header 17 / 20 (SEEK); payloads SEEK 18, HELLO 24, BIND 13,
    BIND_ACK 12, BIND_NAK 9, MODE 13 + descriptors, DATA 7 + samples,
    MGMT 16 / 29;
  - the 6.3 samples-per-frame table and the 4.1.10 BIND_TIMEOUT table;
  - the section 9 airtime rows.
  The tables, section 5 and the vectors agree except where noted below.

---

## 1. Round-2 CRITICAL / HIGH verification

SOUND = specified and consistent. PARTIAL = specified with a gap.
ASSERTED = Appendix D says fixed, the normative text does not deliver it.
REGRESSED = the fix created a new failure.

| ID | Sev | Verdict | Evidence |
|---|---|---|---|
| T2 | CRIT | SOUND | RESUME carries a clear `pre_ctr`; steps 9b-9e treat it as a flood (dedup, ORIGIN, budget); A.11 reproduces. Its counter is in clear, so H2 does not affect it. |
| G1 / T3 | CRIT | REGRESSED | No rule ever makes a node transmit under the newer epoch. Timer-driven retirement then strands laggards (H1). |
| G2 | CRIT | SOUND | ROUTE_TTL 20 min and keepalive 5 s fix the saturation. The keepalive airtime row is wrong (4.8 %, not 0.6 %) but stays under the 10 % rule (MEDIUM list). |
| G3 / T10 | HIGH | PARTIAL | SEEK and RESUME carry a clear 32-bit `pre_ctr`. In encrypted pre-session frames the receiver cannot rebuild the nonce, and relays cannot read a flooded MGMT_REQ's counter (H2). |
| G4 / T1 | HIGH | SOUND, residual | `hop_seq` is checked before learning. The 16-to-32-bit reconstruction rule is not written (MEDIUM list). |
| G5 / T21 | HIGH | SOUND | Dedup runs before ORIGIN; the cheapest copy sets the route, `path_mtu` and the HELLO fields. |
| G6 | HIGH | SOUND for install | RESUME_ACK, BIND_ACK and MGMT_RESP install routes. But "never changes next_hop" plus refresh-on-forward creates H4. |
| G8 / T8 | HIGH | ASSERTED | Bundles are encrypted under a key the gateway holds (H3). |
| G9 | HIGH | PARTIAL | Session records and stream buffers are split. The capacity rule and the sink architecture are not stated, and stream release is undefined (H6). |
| G10 / T5 | HIGH | PARTIAL | Radio leaves pull MGMT. IR leaves cannot (H5). Any leaf behind a dead relay stalls (H4). |
| G11 | HIGH | PARTIAL | In-mesh BULK works for non-leaves. The validity window equals MGMT_PERIOD_S (H4). Leaves cannot be updated (H7). |
| G12 | HIGH | SOUND | Ethernet first, channel and antenna rules, bridge TX arbitration, commissioning test. |
| G14 | HIGH | PARTIAL | The cut list is applied. The build is still about 18-20k lines with the host tools (section 4). |
| T4 | HIGH | PARTIAL | A revocation epoch is erased on a 24 h timer. Under H1 that timer is what partitions the mesh. |
| T6 | HIGH | PARTIAL, accepted | Stated limitation (section 3). |
| T7 | HIGH | SOUND as a rule | Time comes only from listed managers. A rebooted node cannot read MGMT_RESP after about day 9 (H2). |
| T9 | HIGH | PARTIAL | The provisioning steps are listed, but in an order that blocks itself (MEDIUM list). |
| T11, T12, T13 | HIGH | SOUND | Transcript binding (A.9 checks), RTC reserve-ahead, test-key blacklist. |
| G7, G13 | HIGH | removed by cut | - |

---

## 2. Findings (CRITICAL / HIGH)

### H1 [CRITICAL] The transmit epoch never advances, and timer retirement then strands every node that was unreachable for 7 days (24 h after a revocation)

Section: 8.5 (link-table epoch, flood epoch, SEEK `key_epoch`, Retiring,
Revocation), 9 (KEY_RETIRE_S, KEY_REVOKE_GRACE_S), 12.10 (epoch pacing).

Failure in the field:

1. The site is provisioned at epoch 1. In month 2 a routine rotation
   delivers the epoch 2 bundle to every reachable node within hours.
   Every node now holds {1, 2}.
2. 8.5 gives three rules, and none of them ever sends a first frame under
   epoch 2 to a live neighbour:
   - unicast uses "the newest epoch that verified" from that neighbour,
     which is 1;
   - floods use the oldest epoch any live neighbour uses, which is 1;
   - SEEK `key_epoch` is the newest epoch any neighbour has been heard
     under, which is 1.
   So epoch 2 never appears on the air, and "heard under E or newer" never
   becomes true.
3. Retirement then runs on the timer: "or after KEY_RETIRE_S (7 days)", or
   24 h for a REVOKE bundle. `pl/epoch` is not defined as "current" or
   "newest", but under either reading each node erases epoch 1, the only
   epoch in use on the air, 7 days (or 24 h) after its own receipt.
4. Partition at erase time. A node that has erased 1 cannot verify its
   neighbours' frames. Its own unicast rule now names an epoch it no
   longer holds, which is undefined. Neighbours keep flooding under 1
   while any of their other neighbours is still on 1. The partition lasts
   as long as the bundle receipt times are spread: MGMT every 600 s,
   leaves every 10 wakes, one bundle chunk per second.
5. Laggards are lost for good. Example: a solar relay below its
   low-voltage gate for 8 winter days, or a leaf skipping wakes at
   VBAT_MIN. It is not "live", so nothing waits for it. When it returns it
   holds only epoch 1, which nobody accepts any more. Its MGMT_REQ for the
   bundle cannot leave its first hop. Recovery is a site visit with the
   UART station. After a revocation the same happens to any node not
   reached within 24 h.
6. A distant probe that has not yet pulled the newer epoch drops the SEEK
   (3.6: "key_epoch stored"), with no reply, for as long as it lacks the
   epoch.

Minimal fix:

1. Advertise the newest epoch each node holds. Flags bits 2-3 are reserved
   and outside the frozen set: use them for "newest held minus hop_tag
   epoch" (0..2). Then:
   - unicast under min(own newest, the neighbour's advertised newest);
   - floods under the lowest advertised newest among live neighbours;
   - SEEK and pair-key epoch = the oldest epoch the sender holds;
   - a neighbour not yet heard from is treated as advertising the oldest
     epoch held.
2. Delete "or after KEY_RETIRE_S". Erase an epoch only on a retire flag in
   a later bundle. The tool issues it only after every non-revoked node's
   MGMT report shows the newer epoch. Keep the 24 h timer for revocation
   epochs only, and state that a node not reached within 24 h needs the
   UART station.
3. Define `pl/epoch` as the newest epoch held.

### H2 [CRITICAL] Encrypted pre-session frames hide the high half of the CCM nonce: after about 9 days, no rebooted node can read the gateway and no new sender can bind to it

Section: 3.5 (`pre_ctr` is the first payload field; header `seq` holds the
low 16 bits), 8.3 (`ctr_hi` = high 16 bits of `pre_ctr`), 8.4 (last
`pre_ctr` kept per peer and key), 11.4 steps 9b-9e and 11.5 (dedup and
ORIGIN keyed on `pre_ctr`), 11.10, A.9, A.12.

Mechanism. HELLO, BIND, BIND_ACK, BIND_NAK, MGMT_REQ and MGMT_RESP carry
only the low 16 bits of `pre_ctr` in the header. The high 16 bits are
inside the ciphertext, but the receiver needs them to build the nonce
before it can decrypt. The spec gives no rule for estimating them. The only
receiver state it defines ("last pre_ctr per (peer, key)") is empty in two
cases: for every fresh `Ke_hello`, and after every reboot.

A.9 and A.12 use `pre_ctr` 7 and 8, so `ctr_hi` is 0 and the problem never
shows. The scratch check above shows it: `pre_ctr` 0x00010007 fails CCM
when the receiver uses `ctr_hi` 0.

Failure in the field:

1. The gateway originates one MGMT_RESP per node every 600 s. At 50 nodes
   that is 7200 a day, plus bundle chunks, HELLOs and BIND_ACKs. Its
   `preseq` passes 65536 around day 9.
2. After that, any node that reboots (OTA, brownout, watchdog) has no
   counter state for the gateway. It builds the nonce with `ctr_hi` 0 and
   drops every MGMT_RESP. It gets no time (UNSYNCED), no bundles and no
   commands.
3. OTA rolls back. 12.7 marks an image valid only after one MGMT_RESP
   within 10 min of boot, so every update after day 9 rolls back.
4. No new sessions to the sink. A sender seeking any group the gateway
   serves cannot decrypt the gateway's HELLO: `Ke_hello` is fresh, so no
   state exists.
5. Even a node that keeps state cannot estimate the counter after missing
   32768 gateway frames, which is about 4.6 days of MGMT silence.
6. Flooded MGMT_REQ (11.5). Relays need `pre_ctr` for dedup and ORIGIN, but
   it is ciphertext. Implemented literally, a relay writes a random 32-bit
   value into ORIGIN. The node's next real SEEK or RESUME then looks either
   "older" or "more than 2^20 ahead", and is dropped as `relay_drop_stale`
   for up to ORIGIN_TTL_S (1 h). After a site power cycle every node floods
   MGMT_REQ (no routes yet), so this hits the whole mesh at once.

Minimal fix (it removes the encrypted counter rather than adding anything):

1. Send `pre_ctr` in clear on every session_id 0 frame, as SEEK and RESUME
   already do: payload = `pre_ctr` (clear, appended to the AAD) followed by
   the ciphertext of the rest. This reveals nothing new, because the
   counter is part of the nonce anyway. Byte offsets do not change; the
   ciphertexts, tags, hop_tags and CRCs of A.9 and A.12 do.
2. Add HELLO and MGMT_RESP vectors with `pre_ctr` >= 0x10000.
3. State that a node MUST match the `t1` echo in MGMT_RESP; that is what
   gives freshness after a reboot.

### H3 [HIGH] The gateway can read every key bundle, and the bundle wire format is undefined (G8 / T8 not fixed)

Section: 8.5 Bundles, 11.10 (TLVs, chunking), Appendix D G8 / T8 / T23.

Failure in the field:

1. The gateway can decrypt every bundle:
   - 8.5: a bundle is encrypted "under that node's K_mgmt(N, M, E)";
   - 11.10: the manager M (the gateway) answers MGMT under that same key,
     so it holds `K_mgmt` for every node.
   So it can read every bundle it stores: `K_mesh(E+1)` and every node's
   pair keys for E+1. "Holds no other node's keys" is false.
2. Theft. The gateway is stolen from its wall or pole, which is plausible
   over months unattended. Every bundle the tool can produce is now under
   a key the thief holds. The tool cannot revoke the gateway or rotate away
   from it. Recovery is a UART station visit to all 50 nodes.
3. The format is contradictory. 11.10 lists plaintext TLVs 0x01-0x03
   inside MGMT_RESP; 8.5 says the gateway relays opaque blobs it cannot
   read. The spec has no opaque-blob TLV and no AEAD nonce for the tool's
   encryption.
4. Chunks have no index. "The node ACKs a chunk by its next MGMT_REQ", so
   when a MGMT_RESP is lost, the node's retry counts as the ACK and the
   next chunk lands after a hole in the TLV stream. The node then either
   installs shifted key bytes or rejects the bundle; the spec does not say
   which. There is no bundle test vector (T23 deferred).

Minimal fix:

1. Encrypt bundles under `K_mgmt(N, 0x0002, E)`, the station's reserved ID
   (12.2). The gateway holds no 0x0002 pair key. Use the provisioning-time
   `recovery_key` epoch for this key: 12.2 provisions it once and never
   rotates it.
2. Carry the bundle as one opaque TLV 0x05, AES-CCM with nonce (N, E,
   bundle_no). Remove 0x01-0x03 from the MGMT_RESP TLV list; they live
   inside the blob.
3. The node requests chunk i by `page` in MGMT_REQ, and MGMT_RESP echoes i.
4. Add one bundle vector.

### H4 [HIGH] A dead relay black-holes management for its whole subtree, with no end

Section: 11.4 route event table row 3 (forwarding "refreshes expiry of the
routes to src_id and dst_id"; "never changes an existing next_hop"), 11.6
(no RERR), 11.10 (no MGMT timeout or retry), 12.7 (10 min validity).

Failure in the field:

1. Relay R1 dies (solar gate, brownout, theft). It is the next hop toward
   the gateway for relay M and the 6 nodes behind M.
2. The route never expires:
   - each node behind M sends MGMT_REQ every 600 s by unicast;
   - M forwards each one into dead R1 (the ESP-NOW send failure is not
     used);
   - every forward refreshes M's route to the gateway, so it never
     expires;
   - the nodes behind M also forward for each other, so their routes stay
     fresh too, and none of them floods.
3. Sessions recover by themselves (SESSION_TIMEOUT, re-SEEK, HELLO replaces
   routes). MGMT has no end-to-end failure detection, no response timeout
   and no retry. So the subtree loses time sync and bundles, which leads
   straight into H1's stranding at retirement, and stops sending health
   reports. The gateway sees silence with no cause.
4. A good OTA image rolls back. After an OTA reboot a node sends one
   MGMT_REQ. If that request or its reply is lost, the next one goes out
   at MGMT_PERIOD_S = 600 s, which is exactly the 12.7 deadline.
5. Boot storm. After a site power cycle all 50 nodes send their routeless
   MGMT_REQ floods at once (no BOOT_SPREAD). The per-node bucket (depth
   20) drops most of them, and nothing retries for 10 min.

Minimal fix:

1. Refresh a route only on frames received from its `next_hop`. Delete
   "and dst_id" for forwarded frames.
2. MGMT_RESP timeout BIND_TIMEOUT(hops), then 2 retries, then delete the
   route to the manager and flood.
3. Delay the boot MGMT_REQ by rand(0..BOOT_SPREAD_MS).
4. Set the 12.7 validity window to 3 x MGMT_PERIOD_S.

### H5 [HIGH] IR leaves have no management path: no keys, time or health, and they die at the first epoch retirement

Section: 1.2 (`edge_only`), 4.4 (leaves pull MGMT every 10 wakes), 11.10
(managers: gateway, station, phone), 11.11 IR, 12.6.

Failure in the field:

1. An IR leaf's MGMT_REQ to the gateway has to cross from IR into the mesh.
   Steps 9f, 10a and 10c forbid that. So the IR leaf never pulls a bundle.
2. It keeps `K_mesh` and its pair key with the attached node at the
   provisioning epoch. When the attached node erases that epoch (H1's
   timer, or any later retire rule), every IR leaf frame fails hop_tag and
   the leaf is dead.
3. Until then it is never time-synced (UNSYNCED from 30 min after boot),
   its battery is never reported, and it cannot be updated: 12.7's SEEK by
   unit ID cannot cross IR either.
4. Each IR leaf is a site visit at every rotation.

Minimal fix (keeps the user decision):

1. Authenticate the IR edge link under `K_pair(leaf, attached node,
   provisioning epoch)` instead of `K_mesh`, and exempt that key from
   retirement.
2. Make the attached node the IR leaf's only listed manager, for time,
   health and commands.
3. State in 12.6 that rekeying and updating an IR leaf needs the UART
   station.

### H6 [HIGH] No defined path from probes to the LAN: a single sink saturates at 32 senders / 4 streams, and FULL senders flood once a minute forever (G9 residual)

Section: 4.1.2, 4.1.4 (FULL -> 60 s cap), 4.1.12, 12.4, C.2 (115200 baud),
Appendix B. ROAST-2 G9 fix items 3 (capacity rule) and 4 (sink
architecture) were not applied.

Failure in the field. A 50-node building has 25 mains sensors streaming
and 20 leaves, all sending to group "sink". The spec names no way for data
to reach the LAN except a session that ends at the gateway's mesh chip, so
the gateway serves the sink.

1. Records: 32 < 45, so 13 senders get FULL.
2. Streams: there are 4. "Taken only while frames are in flight" has no
   release rule, and a 1 frame/s FEC sender is always in flight. So the
   5th mains sender is already FULL.
3. FULL senders back off to the 60 s cap and SEEK-flood every minute
   forever. 21 senders give about 4 % airtime (estimate), and their data
   is lost; it looks like "sensor offline".
4. The gateway's inter-chip UART at the C.2 default of 115200 baud carries
   about 44 frames/s of 250 bytes. The section 9 scenario (40 sessions at
   1 frame/s plus parity) pushes more than that through it.

Minimal fix:

1. Name the sink in 12: the gateway mesh chip is the probe of the sink
   group, with PL_MAX_SESSIONS >= node_count (50 x 600 B = 30 KB).
2. Hold a stream buffer only for sessions with `fec_m > 0`. Return it when
   the reorder buffer is empty and no FEC group is open.
3. Run the gateway UART at 921600 baud or more.
4. If several probes are meant to share the load instead, say how their
   data reaches the LAN.

### H7 [HIGH] Leaves cannot receive a firmware update (G11 residual)

Section: 12.7 (the update server SEEKs the node by unit ID; "leaves: before
their first park"), 4.4 (leaves never serve and never listen), 11.10 TLV
0x04 command 3.

Failure in the field. Battery leaves are up to 20 of the 50 nodes. In month
2 a leaf firmware bug turns up (battery drain, sensor driver). It cannot be
fixed remotely:

1. The update server's SEEK flood arrives while the leaf sleeps.
2. While awake, the leaf is a sender and does not answer SEEKs.
3. Command 3 ("accept BULK from manager") arms nothing a leaf can act on.

Every leaf becomes a UART station visit.

Minimal fix (one rule): a leaf that receives command 3 skips its next park
and listens as probe of its own unit ID for BULK_WINDOW_S (about 120 s),
then parks. The update server SEEKs it inside that window.

---

## 3. Known limitations (12.10) against months unattended

| Limitation | Verdict |
|---|---|
| Mesh-layer identity rests on `K_mesh` (T6) | Acceptable once revocation works. Today it depends on H1. |
| One recorded unicast frame re-admitted after LINK_TTL expiry | Acceptable. It needs an active attacker, and it heals when the real neighbour next transmits. |
| Epoch pacing is a tool rule | Acceptable as a rule, but not sufficient. The KEY_RETIRE_S / KEY_REVOKE_GRACE_S timers erase epochs whatever the tool does. Promoted into H1. |
| Revoked node keeps mesh access for grace + reach time | Acceptable as a trade-off once H1 is fixed. Today the grace expiry is the event that partitions the mesh (H1). |
| OFFERED denial bounded to one entry per `src_id` | Acceptable. It needs a key holder, and binding recovers when the offers time out. |
| IR outdoors and the IR bit cell unvalidated | Acceptable only as a gate: no IR in the field until C.1 is measured. Indoor or shaded only. |
| R1 is a cost, not a guarantee, on some silicon | Acceptable. Revocation is the control, so it inherits H1 and H3. |
| No TRACE frame | Acceptable. MGMT section 3 gives the path, provided H4 is fixed. |
| FEC / ARQ not auto-tuned | Acceptable. Use ARQ for data that must arrive. See the FEC_FLUSH_MS item in the MEDIUM list. |
| No key-bundle test vector (Appendix D T23, deferred) | Not acceptable. The bundle path is undefined (H3). Promoted. |

---

## 4. Implementation size vs one engineer (estimates)

Start from the ROAST-2 table (about 17k lines for v0.4). Remove the BLE
carrier, the dual auth path, LEN16, SELECT_BEST and time stratum. Add
MGMT, bundles, BULK, the UART station manager, the phone app and the LAN
sink.

- Firmware, about 13.5k lines:
  - frame codec and 3.6 validation, COBS, CRC: 1.2k
  - RS (errors and erasures) and group FEC: 0.9k
  - ARQ and reorder: 0.9k
  - session machines (sender, multi-record probe, MODE, park/resume): 2.2k
  - mesh pipeline, six tables, flood control: 1.8k
  - crypto: HKDF, CCM, hop_tag, transcript, epochs, keystore,
    reserve-ahead counters: 1.2k
  - MGMT (sections, NTP time, bundles, commands) and BULK OTA: 1.3k
  - field-profile checks, maintenance mode: 0.3k
  - transports, 3.7k: ESP-NOW 0.4k, UART 0.3k, UDP 0.4k, nRF24 with
    segmentation and SPI driver port 1.2k, IR RMT PHY 0.8k, BLE GATT phone
    link 0.6k
- Host deliverables, about 5-6k lines, each a separate project:
  - parser fuzz harness and mesh simulator: 2k
  - provisioning, key and bundle tool plus the UART station manager
    (Python): 1.5k
  - phone app speaking MGMT under `K_mgmt` over BLE: 1-2k
  - LAN-side sink, time source and update server: 0.5-1k
- Total about 18-20k lines. That is 7-10 engineer-months to field quality,
  including a 10-node 72 h soak. The 50-node behaviours (H1, H4, H6, the
  airtime budget) are visible only in the simulator.
- Recommended phase 1: ESP-NOW and a UART gateway only, no nRF24, IR or
  phone app, provisioning tool and simulator included. About 11k lines,
  4-5 months. Add nRF24, then IR, after the phase-1 soak.
- RAM and flash fit a C3 (Appendix B: about 49 KB at 32 records / 4
  streams; ProbeLink about 80-100 KB of flash; 4 MB modules for two OTA
  slots).

---

## 5. MEDIUM and LOW (titles only)

MEDIUM:

- `hop_seq` reconstruction rule unwritten; route-held link entries never expire, so a busy funnel desyncs neighbours (8.4, 11.9)
- Retransmitted SEEK / HELLO create several transcripts; which one keys BIND is unspecified (4.1.8, 8.2)
- FEC_FLUSH_MS makes low-rate FEC k=1 (3x airtime); keepalive airtime row 0.6 % should be 4.8 % (3.3, 9)
- Provisioning burns the download-mode eFuse before the writes that need it (12.2)
- "Never STA" ambiguous; WIFI_MODE_AP would beacon (1.2, 12.4)
- nRF24 reassembly cannot separate concurrent transmitters (C.5)
- MODE_RETRY_MS 100 fixed, below multi-hop and IR round trips (6.1)
- Revocation does not close live or parked sessions of the revoked ID (8.5)
- MGMT section layouts, `pl_stats_t` wire order and clone-mismatch field not byte-specified (11.10, 2)

LOW:

- "max payload 212" and IR "max payload 20" should be 219 and 27 (6.1)
- PARITY bound `block_len <= max_payload + 1` should be `max_payload - 8` (3.6)
- `pl_resume()` cannot restore `pl_mode_t`; `pl_keystore_t` / `pl_mgmt_server_t` undefined (App. B)
- Manager / LAN-chip unit IDs not reserved; Appendix D G20 says "pre_ctr echo", MGMT_RESP echoes `t1` (2, 12.2, D)
- A lost BLE phone holds station-equivalent recovery keys with no revocation path (6.4)

---

Counts: CRITICAL 2, HIGH 5, MEDIUM 9, LOW 5

Verdict: NOT READY

Blocking before any session, crypto, mesh-epoch or MGMT code, because
these fixes change wire bytes or vectors:

- H2: every session_id 0 frame changes. Recompute A.9 and A.12 and add a
  vector with `pre_ctr` >= 0x10000.
- H1: epoch advertisement in flags bits 2-3; retirement by tool flag
  instead of a timer.
- H3: station-key bundle, opaque TLV, chunk index, bundle vector.

Can start now against v0.5, in parallel with the v0.6 edit (no finding
touches these layers):

- CRC-16, COBS, RS and group FEC, with A.1-A.5 as fixtures;
- ARQ and reorder;
- the ESP-NOW and UART adapters, and nRF24 segmentation;
- the header parser and fuzz harness (header bytes do not change);
- the host mesh simulator.

Before the first field pilot: fix H4, H5, H6 and H7 in the text. Each is a
sentence or a table edit.

Before field deployment, run the simulator and then a 10-node 72 h soak
that includes:

- one rotation with a node powered off for longer than the retire window;
- one revocation;
- one site power cycle;
- one OTA;
- one relay killed on the gateway path;
- a gateway `preseq` started above 0x10000.
