# ROAST-1: ProbeLink v0.3 vs field deployment

Target: PROTOCOL.md, DRAFT v0.3 (wire version 1).
Deployment assumed: one implementer, ESP-IDF on ESP32 / ESP32-C3 / ESP32-S3,
5-50 nodes in a building or outdoor site, unattended for months. Carriers
ESP-NOW, BLE, WiFi UDP, IR, UART. Mesh is mandatory (not argued here).
Reviewer stance: hostile. Every finding has a field failure scenario and a fix.
Numbers marked "(estimate)" are reviewer estimates, not measurements.

Sanity check done before the review: every Appendix A CRC-16, K_s, K_mesh and
HMAC tag vector (A.1, A.2, A.3 CRC, A.6, A.8) was recomputed independently and
matches. The bit-level spec is consistent; the problems are operational.

## Scorecard

| # | Area | Verdict | Findings |
| --- | --- | --- | --- |
| 1 | Power | FAIL | F1 |
| 2 | Provisioning, IDs, keys | FAIL | F2, F3 |
| 3 | RF reality | FAIL | F4, F5, F6, F7, F8 |
| 4 | Scale (50 nodes, outages) | FAIL | F9, F10, F11, F12 |
| 5 | Upgrades | FAIL | F13, F14 |
| 6 | Operability | FAIL | F15, F16 |
| 7 | Robustness | PARTIAL | F17, F18, F19, F20, F21 |
| 8 | Implementability | PARTIAL | F22, F23, F24, F25, F26, F27, F28 |

Area 8 note: the RAM budget is realistic. One ESP-NOW v1 session context is
about 17.8 KB (Appendix B), which fits on an ESP32-C3 next to WiFi and NimBLE.
CPU is also fine: hardware SHA covers HMAC, and software RS on 255-byte frames
is sub-millisecond (estimate). The only budget problem is ESP-NOW v2
multi-session, covered in F9. Area 7: the spec writes nothing to NVS at
runtime, so NVS wear is not an issue. Keep it that way (see F15 fix).

---

## 1. Power

### F1 [CRITICAL] Deep-sleep leaves cannot work: the session model has no sleep-compatible path

Section: 11.1 (Leaf role "for deep-sleep battery sensors"), 4.2, 7, 9
(SESSION_TIMEOUT_MS 2000, PING_IDLE_MS 500, ACK_MS 250), 11.6.

Failure in the field: an ESP32-C3 temperature leaf on a 2000 mAh cell reports
once per minute. It has two options and both fail the "months" target.

- Option A, keep the session open. The probe ACKs every 250 ms and the session
  dies after 2 s of silence, so the leaf's radio has to stay in RX
  permanently. That draws about 80-100 mA (estimate), so the battery is flat
  in about 1 day.
- Option B, deep sleep between samples. Nothing survives deep sleep: the
  session_id counter is "in RAM" and the pre-session seq is "random start at
  boot". Every wake pays for WiFi init, a SEEK flood, the HELLO wait (580 ms
  first timeout in a mesh, 11.7), a BIND flood, BIND_ACK, MODE/MODE_ACK, DATA
  and CLOSE. That is about 1-1.5 s awake at about 100 mA, or about 0.03-0.04
  mAh per wake. At one wake per minute that is 45-60 mAh/day, so the battery
  lasts roughly 1 month (estimate).

Option B also sends 2 network-wide floods per wake. 20 such leaves make 40
floods/min. At 50 nodes that is up to about 2000 rebroadcasts/min, all paid
for by the relays' airtime.

Three more gaps:

- The spec has no listen window, so a sleeping node can never be a probe.
- The spec never says relays and probes must be mains powered. A relay on
  battery lasts about a day.
- Liveness traffic is fixed-rate, not scaled to the data rate. A session
  carrying one sample per minute still costs about 4 ACK/s plus PINGs per hop,
  forever.

Fix:
1. Add a sessionless REPORT frame for leaves. The leaf sends a DATA-like frame
   to a group with FLAG_ACK_REQ. The first probe that ACKs wins, which keeps
   first-acknowledger-wins. Tag it under a session ticket key (see 2).
2. Or add session resumption. Keep {peer_id, session_id, K_s, seq, config_id}
   in RTC slow memory (RTC_DATA_ATTR). Add CLOSE reason "sleep, resume until
   T" so the probe parks the session instead of dropping it. Add a RESUME
   frame tagged under K_s that the probe accepts inside the park window.
3. Add an ACK/PING interval field to MODE, so a slow session can run with
   ACK_MS = 30 s and use light sleep with ESP-NOW power-save wake windows
   (IDF 5.x).
4. State in 11.1 that non-leaf nodes and probes MUST be mains or solar
   powered. Add a per-role power budget table.

---

## 2. Provisioning, IDs, keys

### F2 [CRITICAL] One shared K_net with no key ID, no rotation and no revocation: one stolen node compromises all 50

Section: 8 (K_net "ideally with NVS encryption + flash encryption"), 11.8
(K_net holder "can do anything").

Failure in the field: a node at an outdoor site is stolen, or a dead node goes
in the bin unwiped. A default ESP-IDF build has no flash encryption, so
`esptool.py read_flash` plus the NVS parser recover pl/net_key in minutes.
Nonces cross the air in clear (SEEK, HELLO), so the attacker can derive every
future K_s. With that the attacker can:

- forge MODE/CLOSE/DATA in any session;
- act as a probe for any group, and since it answers HELLO first, become the
  winning probe and sink data;
- claim any unit ID, because K_s binds src_id only through the shared key.

Recovery means a new K_net, but frames carry no key identifier. During
re-keying, nodes on the new key drop every frame from nodes on the old key
(step 6c, and "a node with a key drops any untagged frame"). The mesh stays
partitioned until the last of 50 nodes has been visited. A half-provisioned
rollout splits the same way: keyed probes BIND_NAK unkeyed senders (reason 3),
while unkeyed probes accept anyone.

Fix:
1. Make Secure Boot v2, flash encryption (release mode) and NVS encryption
   MUST for field builds, not "ideally".
2. Add a key_epoch byte to the end-to-end header now. Nothing is on the air
   yet, so version 1 can still change. Receivers accept the current and the
   previous epoch.
3. Define KEY_UPDATE: the next-epoch key is wrapped under the current key
   (AES-KW) and sent per node over a unicast session with ACK. Activate the
   new epoch once all nodes have ACKed or a set time passes.
4. Ship a revocation list (unit IDs) with each epoch.
5. Decide explicitly whether per-device asymmetric identity is needed
   (X25519/P-256 ECDH at BIND, tens of ms on ESP32 in software, estimate).
   Symmetric shared keys can never stop an insider from spoofing IDs.

### F3 [HIGH] Unit ID provisioning: cloned images, 1.9 % birthday collisions, and detection that misses distant colliders

Section: 2 (CRC-16 of MAC default, "0.3 %" for 20 devices, manual NVS fix),
11.9 (extended detection).

Failure in the field:
- (a) Cloned images. The fastest way to put the same K_net, pl/channel and
  pl/rs_nsym on 50 boards is to provision one board and clone its flash
  (`read_flash` / `write_flash`). That copies pl/unit_id too, so all 50 nodes
  get one ID. Routes flap, every relay raises PL_EVT_ID_COLLISION, and the fix
  is 49 serial-cable visits.
- (b) Random collisions. At 50 nodes the birthday probability is 1.9 %
  (1 - exp(-50*49/2/65279)), not 0.3 %. CRC-16 cannot collide for MACs that
  differ only in the last 2 bytes (a burst of 16 bits or less), so a single
  reel is safe. A mix of ESP32, C3 and S3 modules behaves like random IDs.
- (c) Detection only works locally. 11.9 fires only when one relay hears both
  colliders. Two colliders at opposite ends of a building are never detected:
  each re-SEEK flood points routes for that ID at whichever node flooded more
  recently. The wrong node fails the tag check and drops session frames
  without replying (section 8), and the sender loops SESSION_TIMEOUT ->
  re-SEEK forever.
- (d) Groups. Group subscriptions have no NVS key (pl_listen takes an array
  from code), so changing which probes serve a group means reflashing.

Fix:
1. Store the MAC the ID was assigned to (pl/unit_mac) next to pl/unit_id. At
   boot, if pl/unit_mac differs from the eFuse base MAC, ignore the override,
   use the MAC-derived ID and raise PL_EVT_ID_COLLISION. This catches every
   clone.
2. Provision per-device NVS partitions with nvs_partition_gen.py from a CSV
   manifest keyed by MAC (unit_id, groups, keys). Reject duplicate IDs in the
   manifest before flashing.
3. Add pl/groups (u16 array) to the NVS key list.
4. Report (MAC, unit_id) in the diagnostics response (F15), so a gateway can
   see two MACs for one ID anywhere in the mesh.

---

## 3. RF reality

### F4 [CRITICAL] ESP-NOW channel is pinned in NVS; any node running WiFi STA leaves that channel, and nothing follows it

Section: 1.2 ESP-NOW row ("channel comes from NVS (pl/channel), scanning is
out of scope"), 1.2 WiFi UDP row, section 11 intro (bridges are "the normal
case").

Failure in the field: the gateway is an ESP-NOW <-> WiFi UDP bridge, or does
SNTP/OTA/MQTT over STA. An ESP32 has one radio. Once STA associates, ESP-NOW
runs on the AP's channel whatever pl/channel says. Peers on any other channel
fail (ESP_ERR_ESPNOW_CHAN).

Day 1: the installer pins all 50 nodes to channel 6, because that is the AP's
channel. Week 5: the building AP reboots after a firmware update and
auto-selects channel 11. Enterprise controllers with RRM also retune channels
on their own. The gateway follows to 11 and the other 49 nodes stay on 6.
Every session to the gateway dies, and the fix is re-provisioning 49 nodes.
While the AP is down, the STA reconnect loop scans all channels, so the
gateway is also deaf on channel 6 for most of the outage.

Second problem: with STA connected, ESP-IDF defaults to WIFI_PS_MIN_MODEM. In
modem sleep the radio is off between DTIM beacons, so ESP-NOW frames are lost.
That includes floods, which are broadcast with no MAC retry. The spec never
mentions `esp_wifi_set_ps`.

Fix:
1. Preferred: never run STA and ESP-NOW on one chip in the field. Build the
   gateway from two ESP32s joined by the UART carrier, which the spec already
   supports.
2. If it must be single-chip, add channel follow. The gateway announces its
   channel in HELLO and in a periodic CHAN beacon. A node that hears no
   neighbour for CHAN_LOST_MS (e.g. 60 s) sweeps channels 1-13, spending about
   200 ms on each, then stores the new channel. Limit how often that NVS write
   can happen.
3. Mandate `esp_wifi_set_ps(WIFI_PS_NONE)` on relays and gateways that do not
   run BLE (see F5). Limit STA reconnect scans to the stored channel.
4. Make "AP channel fixed" a written deployment prerequisite. The gateway
   raises an alarm when its channel changes.

### F5 [HIGH] BLE is on every node, and one radio is shared between BLE and ESP-NOW

Section: 6.4 ("Every BLE-capable node advertises", "A node that sees a beacon
connects"), 11.10, C.4.

Failure in the field: every ESP32, C3 and S3 can do BLE, so all 50 nodes
advertise, scan and connect.

- Coexistence. The radio is time-shared between BLE and WiFi. With BT enabled,
  IDF requires WiFi modem sleep (verify for your IDF version), and ESP-NOW
  reception drops during BLE scan windows and connection events. Floods (no
  MAC retry) and HELLOs are lost first: handshake success falls and SEEK
  retries rise across the whole mesh.
- No connection rules. NimBLE's default connection limit is small (3; check
  menuconfig). The spec does not say which beacons to connect to, or which
  side is central. Two nodes can connect to each other twice (two links, so
  every flood is sent twice), or keep connecting and disconnecting as a 4th
  and 5th neighbour appear.
- Foreign beacons. Company ID 0xFFFF is used by many cheap commercial beacons.
  Nodes will try to GATT-connect to them and waste their few connection slots.

Fix:
1. Turn the BLE transport off by default. Enable it only on nodes configured
   as BLE edge (pl/ble = 1). ESP-NOW relays never scan.
2. Fixed roles: BLE edge sensors are peripherals only, bridges are centrals
   only. A central connects only to unit IDs on its NVS allowlist.
3. Put a 2-byte ProbeLink magic and the protocol version inside the
   manufacturer data, so foreign 0xFFFF beacons are ignored.
4. On bridges, set `esp_coex_preference_set` and use long BLE connection
   intervals (100 ms or more). Measure ESP-NOW broadcast loss with BLE active
   and choose fec_m from that measurement.

### F6 [HIGH] First-copy routing picks gray-zone links

Section: 4.1.2, 11.4 (reverse route from the first flood copy), 4.3 ("Dedup
keeps the first copy; reverse route = first path").

Failure in the field: in a corridor, S broadcasts SEEK at 1 Mbps. Far relay R3
hears it at -92 dBm, which delivers about 30 % of frames. Near relay R1 hears
it at -60 dBm. R3's copy skips a hop and reaches the probe first, so HELLO and
every DATA frame go over S -> R3, a link that delivered one broadcast by luck.

Unicast MAC retries hide part of the loss but burn airtime and add latency.
ACKs go missing, SESSION_TIMEOUT fires, and the re-SEEK picks the same long
link again a good share of the time. Floods consistently prefer the longest,
weakest links, because fewer hops arrive first. This is the known "gray zone"
failure of first-copy AODV.

Fix:
1. Carry a path cost in SEEK as a per-hop field next to path_mtu, built from
   RSSI: e.g. cost 1 above -75 dBm, 3 for -75..-85, 10 below -85. Ignore
   copies below -90. A later copy with lower cost replaces the route. Probes
   already wait HELLO_WINDOW_MS, so this costs no extra time.
2. Add a PL_ROUTE_MIN_RSSI floor (e.g. -85 dBm) for route installation, unless
   no other copy arrives within RELAY_JITTER_MS.
3. Keep a per-neighbour RSSI EWMA in the link table and expose it in F15.

### F7 [MEDIUM] IR outdoors is not validated and not scoped

Section: 1.2 IR row, Appendix C.1 ("sketch, to be validated on hardware").

Failure in the field: an outdoor site uses one IR hop across a gap. Afternoon
sun on the TSOP window raises the noise floor, and the receiver loses
sensitivity or outputs noise bursts. The proposed 300 us mark cell has not
been checked against the receiver's minimum burst and gap limits. rs_fail
climbs every afternoon, and the IR session times out daily at the same hours.
Each re-handshake over IR costs 2-4 s or more because of time_scale 10.

Fix:
1. Scope IR as indoor/shaded only, or require an optical filter and hood.
2. Validate the bit cell against the specific TSOP datasheet on hardware.
3. Expose IR link quality (rs_corrected and rs_fail per hour) in F15.
4. Give IR hops a high path cost (F6), so a radio path is preferred when one
   exists.

### F8 [MEDIUM] Counter-based suppression leaves coverage holes

Section: 11.5 (RELAY_SUPPRESS_COUNT 3), C.3 (broadcasts are not retried).

Failure in the field: relay R sits where a dense area meets a wing whose only
link to the rest is R. R hears 3 copies from the dense side within its 0-50
ms jitter and cancels its rebroadcast. The wing never sees the SEEK. The
topology is fixed, so this repeats on many retries, and probes in the wing
cannot be reached for new sessions whenever the dense side is busy.
Broadcasts have no MAC retry, so a single lost copy is never repaired.

Fix:
1. Default RELAY_SUPPRESS_COUNT to 0 (disabled) at 5-50 nodes. The rate limit
   already bounds flood load.
2. Add a per-node "never suppress" setting for chokepoint relays.
3. On carriers without MAC retry, send each flood copy twice with independent
   jitter when measured broadcast loss is above 10 %.

---

## 4. Scale

### F9 [HIGH] One session per probe: several concurrent senders starve

Section: 4.1.3 (a bound probe ignores SEEK), 4.1.12 ("serves one session at a
time"; more is "may"), 5 (caps has no multi-session bit).

Failure in the field: group 0xFF01 is served by 3 probes, and 10 sensors
stream to it. The first 3 bind. Bound probes ignore all other SEEKs without
replying, so senders 4-10 get no HELLO, run through the full backoff and
return PL_ERR_NO_PROBE. Depending on the app policy they then loop forever,
and every loop sends SEEK floods across the whole mesh. A sender cannot tell
"group full" from "group gone".

RAM: one ESP-NOW v1 context is about 17.8 KB, so a C3 probe can hold 4-8
sessions. With ESP-NOW v2 frames (1470 bytes), one context grows to about 90
KB (32 x 1470 ARQ + 10 x 1470 reorder + FEC + queues, estimate). That does not
fit more than once next to WiFi and NimBLE on a C3.

Fix:
1. Make multi-session MUST, with PL_MAX_SESSIONS >= 4 for v1 frames.
2. A full probe still answers SEEK, with HELLO status FULL. The sender learns
   that the group exists but is full, and backs off for a long time instead of
   re-flooding.
3. Limit v2 frames to single-session probes, or cap arq_window for v2.
4. Define the sender policy after FULL/BUSY/NO_PROBE (see F10).

### F10 [HIGH] Post-outage reboot storm: synchronized deterministic backoff, undefined give-up, tables sized for 16 nodes

Section: 4.1.8 (backoff 100..1600 ms, then PL_ERR_NO_PROBE), 9, 11.5, 11.6,
11.9.

Failure in the field: mains blips at 03:00. All 50 nodes boot within the same
~300 ms, because ESP32 boot time is nearly deterministic. 25 senders SEEK at
once.

- The channel saturates. Each flood is rebroadcast by up to ~50 nodes at about
  0.8 ms of airtime each at 1 Mbps, including ESP-NOW overhead and preamble
  (estimate). 25 SEEKs plus 25 BINDs is about 2500 broadcasts, roughly 2 s of
  airtime wanted inside the first second.
- Relays forward at most 10 floods/s (SEEK_RATE_TOTAL), so most floods die at
  the first hop.
- Backoff has no jitter. Senders that booted together retry together, 5
  times, then return PL_ERR_NO_PROBE about 3 s after boot (direct) or about
  18 s after boot (mesh timers, 11.7).
- The spec does not say what happens next. Implementations either give up,
  which is an outage until the next reboot, or retry at once, which is a
  storm that never ends.
- Tables are sized for 16 origins ("32 entries cover 16 origins x 2"). With
  more than 8 origins flooding, LRU eviction of the 8 rate buckets resets
  them, so per-origin limiting is effectively off. A 32-entry dedup FIFO at 10
  floods/s covers 3.2 s, less than DEDUP_TTL_MS of 5 s (20 s on IR nodes), so
  late copies get forwarded again.

The same thing happens on a smaller scale when a relay carrying 10 sessions
dies: all 10 senders hit SESSION_TIMEOUT within one ACK period and re-SEEK in
lockstep.

Fix:
1. Boot holdoff: the first SEEK after boot waits rand(0..BOOT_SPREAD_MS), with
   BOOT_SPREAD_MS = 200 ms x node count (10 s at 50 nodes).
2. Full-jitter backoff, wait rand(0, min(cap, base x 2^n)), and never give up:
   after the 5th try keep retrying at a 60 s +-50 % cap. PL_ERR_NO_PROBE
   becomes an event, not a final state.
3. A re-SEEK after SESSION_TIMEOUT starts after rand(0..1000 ms).
4. Size the tables from the network and publish a 50-node table.
   DEDUP_ENTRIES >= SEEK_RATE_TOTAL x DEDUP_TTL_MS / 1000 (50 for radio, 200
   on IR nodes). Rate buckets >= node count, or 64 hashed buckets.
   LINK_ENTRIES per F12.

### F11 [HIGH] The flood rate limiter has no burst size and drops BIND retries in a normal handshake

Section: 11.5 (token bucket, SEEK_RATE_ORIGIN 2/s), 4.1.9 (BIND_RETRY_MS 50,
BIND_RETRIES 3).

Failure in the field: on a 2-hop session, the first BIND broadcast is lost at
hop 2 (broadcast, no MAC retry). The sender retries BIND at +50, +100 and +150
ms. Relay R already spent this origin's tokens on the SEEK and BIND #1 in the
same second. The spec gives a rate but no bucket depth, and a depth of 2 is a
fair reading, so all three retries become relay_drop_rate. The probe times
out, the sender tries the next candidate (another flood, also dropped), then
re-SEEKs.

The spec's argument that "a legitimate origin never exceeds 2 floods per
second" is wrong by its own numbers: SEEK + BIND + 3 retries is 5 floods in
under 1 s. Two implementations with different bucket depths behave
differently exactly when the link is lossy.

Fix:
1. Specify the burst: depth 6 per origin, refill 2/s. Total bucket depth 20.
2. Or rate-limit per handshake (src_id, nonce_s): one new handshake per 500
   ms per origin, with all of its BIND retries allowed.
3. Space BIND retries at least HOP_DELAY_MS x hops apart, so retries do not
   pile up inside one hop's jitter window.

### F12 [HIGH] Link table: 16 entries, no expiry, no eviction rule, wrong key

Section: 9 (LINK_ENTRIES 16), 11.4 step 3 (learn on every frame), 11.9,
11.10 (16-peer ESP-NOW LRU).

Failure in the field:
1. Density. On an open-plan floor a node hears 25 neighbours. Step 3 learns
   the prev_hop of every heard frame, including overheard ones. The spec
   defines no eviction, so an implementation either stops learning (a new
   next_hop has no MAC, and what happens then is undefined) or evicts LRU
   (active next_hops get pushed out by chatter from irrelevant neighbours).
   The ESP-NOW peer LRU churns esp_now_del_peer/add_peer at the same rate.
2. Replacing a dead node. The replacement gets the old unit ID via NVS.
   Neighbours still map that ID to the dead MAC (no expiry) and unicast into
   nothing until the new node happens to transmit. Every neighbour also raises
   PL_EVT_ID_COLLISION (11.9: "same prev_hop from two different carrier
   addresses").
3. Bridges. The key is unit_id only, but a bridge neighbour can be reachable
   over both UART and ESP-NOW. The entry flips between transports, and a route
   that says ESP-NOW gets a UART address.
4. UDP. DHCP hands out new IPs after an outage, and entries stay stale until
   traffic is heard.

Fix:
1. Key entries on (unit_id, transport).
2. Expire entries after LINK_TTL_MS (e.g. 60 s) unless refreshed.
3. Never evict an entry that a live route uses; evict unreferenced entries
   first.
4. LINK_ENTRIES >= expected neighbour count (32 for a 50-node site).
5. Treat a new address seen after the old entry expired as a replacement, not
   a collision.
6. Learn links only from frames that pass the checks in F22.

---

## 5. Upgrades

### F13 [HIGH] No way to update firmware through the mesh

Section: none. Nothing in sections 5 or 11 or Appendix B covers OTA.

Failure in the field: in month 2 a relay bug needs a fix (for example F11).
ESP-NOW-only nodes have no IP path, and the spec has no bulk-transfer or OTA
message. The only update path is a laptop and a USB cable at each of 50
nodes, some on ceilings or poles, so the bug stays in the field until then.
ESP-IDF app rollback (`esp_ota_mark_app_valid_cancel_rollback`) also needs a
rule for "this image works", and the spec gives none.

Fix:
1. Define an OTA session. The node SEEKs a reserved group (e.g. 0xFFF0
   "update server"). Then OTA_BEGIN {size, SHA-256, signature, version},
   OTA_CHUNK frames with arq = 1 plus group FEC, and OTA_END. The node writes
   with esp_ota_write, checks the Secure Boot v2 signature, and reboots. A 1
   MB image at about 100 kbit/s goodput takes 80-90 s per node direct, longer
   per extra hop (estimate). Update one node at a time, farthest first.
2. Rollback rule: the new image marks itself valid only after it completes one
   session handshake, or forwards N frames, within 10 min. Otherwise it
   reboots and the bootloader rolls back.
3. Fallback if mesh OTA is too much: an UPDATE_WINDOW command that makes a node
   join a maintenance WiFi network and pull over HTTPS. This brings back the
   F4 channel problem for the duration.

### F14 [HIGH] Version policy splits the mesh during a rolling upgrade, and there is no minor version

Section: 3 (version policy: unknown version dropped; only a header change
bumps it), 5 (BIND_NAK reason 4 "version"), 11.4 step 2.

Failure in the field: v0.3 already broke the wire format once. The next header
change bumps the version to 2. During a rolling update (one node at a time
over days, F13), every v1 relay drops every v2 frame at step 2, and v2 relays
drop v1 frames. The mesh splits along the update frontier, and sessions over
mixed paths die for days.

Within version 1, behaviour changes that are not header changes (timers,
rate-limit depth, validation, the fixes in this review) are not signalled at
all. A field tech cannot tell which nodes run which rules. BIND_NAK reason 4
can never be sent, because frames with an unknown version are dropped before
any handshake.

Fix:
1. Freeze the per-hop prefix across versions: ver_flags, type, src, dst,
   prev, next, ttl_hops and where len sits. Relays forward frames whose
   version they do not know; the CRC still covers the whole frame. Only
   endpoints reject.
2. Add proto_minor u8 and fw_build u32 to SEEK and HELLO, and to F15.
3. Endpoints accept versions N and N-1 for a declared transition period.
4. Remove BIND_NAK reason 4, or define when it is sent.

---

## 6. Operability

### F15 [HIGH] No remote diagnostics: finding a bad link needs a ladder and a cable

Section: Appendix B (pl_stats_t is a local API), 8 (logs are local
ESP_LOGW).

Failure in the field: users report gaps in sensor 0x2A1C's data. The gateway
sees on_gap and nothing else. The cause could be a gray-zone hop (F6), a full
relay queue, coexistence loss on a bridge (F5) or a distant ID collision
(F3). The counters that would tell them apart exist, but only inside each
node, readable over its own UART console. With nodes on ceilings, finding the
bad hop means one ladder climb per hop.

Counters also reset on every reboot, and nothing reports reset reason, uptime
or minimum free heap. A node that watchdog-resets every night looks healthy.

Fix:
1. Add DIAG_REQ / DIAG_RESP (types 0x40 / 0x41), unicast over existing routes
   and tagged under a key derived from K_net. Any node answers, not only
   endpoints. The response carries:
   - identity: MAC, unit_id, fw and protocol versions;
   - health: uptime, esp_reset_reason(), minimum free heap, stack high-water
     mark;
   - traffic: pl_stats_t;
   - links: per-neighbour RSSI EWMA, rx count, crc_fail;
   - the route table.
2. Add TRACE: a flagged flood in which each relay appends (unit_id, rssi_in),
   so the gateway can draw the path.
3. Keep a small reset log in RTC memory, or a 4 KB NVS ring written at most
   once per boot (bounded wear).
4. Optional: a HEALTH frame every 10 min, unicast to a 0xFFF1 monitor group.

### F16 [HIGH] No network time: sample timestamps restart with every session

Section: 6.5 (session clock starts at BIND_ACK), 4.2 (failover = new session).

Failure in the field: over months of logging, every relay failure, probe
reboot or failover creates a new session, and both clocks restart at
BIND_ACK.

- A probe can anchor t_first_us to its own clock only to within the BIND_ACK
  one-way delay: hundreds of ms over multi-hop radio, seconds over IR
  (estimate).
- The probe has no wall clock either, unless it runs SNTP, which needs STA
  (F4).
- After failover from probe A to probe B, the two halves of one sensor's
  series are stamped by two unrelated clocks.
- Two sensors cannot be aligned, so "what happened at 14:02:07" has no answer.
- A 40 ppm crystal drifts about 104 s in 30 days (estimate), if anyone tries to
  carry time forward locally.

Fix:
1. Add a network time service. The gateway (SNTP or GPS) is time master, and
   nodes sync every 10-15 min with an NTP-style 4-timestamp TIME_REQ/TIME_RESP
   over the mesh, or a 64-bit epoch field added to PING/PONG.
2. Anchor sessions to real time: BIND_ACK or MODE carries
   session_epoch_utc_us (8 bytes), so t_first_us converts to UTC.
3. Add DATA status bit 3 UNSYNCED for when no time source is available.

---

## 7. Robustness

### F17 [CRITICAL] Recorded frames can be replayed after the 16-bit seq wraps inside one long session

Section: 3.5, 8 (replay window: accept if newer than highest_seq), 4.3 row
"seq wraps at 65535 ... Serial arithmetic".

Failure in the field: a session streams 20 frames/s and stays up for weeks.
Nothing in the spec ends a healthy session or rekeys it. seq wraps every 65536
frames, about every 55 min at 20 frames/s and 22 min at 50 frames/s. The tag
covers seq, but every (session_id, seq) value comes back once per wrap under
the same K_s.

1. An attacker records the frame with seq s.
2. One wrap later, when the receiver's highest_seq is s - 10, the attacker
   replays it. (int16)(s - highest) = 10 > 0, so it counts as "newer". The tag
   is valid, and the frame is accepted and delivered: a stale value, with a
   t_first_us 55 min old that the 6.5 extension maps about 16 min into the
   future.
3. When the real frame s arrives, it is dropped as a duplicate.

Replayed ACKs damage the sender's ARQ state the same way. 4.3 marks "seq
wraps" as solved, but serial arithmetic fixes ordering, not replay. This
breaks the end-to-end integrity that 11.1 makes mandatory for field use.

Fix:
1. Implicit 32-bit sequence, as in SRTP: both ends keep a roll-over counter
   (ROC) that is not sent on the wire. ROC goes into tag_input, and the
   receiver estimates ROC from highest_seq.
2. Or force a rekey: at seq 0xC000 the sender starts REKEY with new nonces,
   K_s' is derived as in section 8, and both sides switch at a seq boundary.
3. Cap session lifetime (e.g. 2^15 frames or 24 h) and re-BIND.
4. Correct the 4.3 row.

### F18 [HIGH] Input validation is not specified, and relays parse attacker-supplied headers before any authentication

Section: 3 (len, FLAG_LEN16), 3.3 (PARITY payload), 6.1, 6.2, 11.4.

Failure in the field: every relay parses the header of every frame before any
tag check, and uses len to find the CRC. An outsider sends a 30-byte ESP-NOW
frame with len = 255. An implementation that trusts len reads about 240
bytes past the buffer to compute the CRC, panics (LoadProhibited) and reboots.
That hits every relay in range, once per frame. The spec never says "drop
unless header + len + tag + 2 equals the received length".

Behind the tag, a buggy or version-skewed peer can cause out-of-bounds reads
or writes in static buffers through:

- MODE: ch_count 16 but only 3 descriptors present; digital fmt 0 or above
  32; scale 0, NaN or Inf; fec_k 0 or 1 with fec_m > 0.
- DATA: n_samples x sample size not equal to len - 7.
- PARITY: idx >= m, k > fec_k, block_len larger than the buffer, or
  first_seq outside the receive window.

Two careful implementers will reject different sets of these, and a third
will crash.

Fix: add a normative "Receiver validation" table that gives the valid range
of each field and the action (drop and count bad_frame, or MODE_ACK status 3).

- Header:
  - exact total length;
  - FLAG_LEN16 only when max_frame > 255 and rs_nsym = 0;
  - ttl and hops <= MAX_HOPS;
  - path_mtu >= 33 (17 fixed + 8 tag + 7 DATA header + 1 data byte);
  - unknown type: drop and count.
- MODE:
  - length = 11 + descriptor sizes;
  - ch_count 1..16;
  - kind 0..1, and fmt in range for its kind;
  - scale finite and non-zero;
  - fec_k 2..16 when fec_m > 0;
  - period_us > 0.
- DATA: len = 7 + n_samples x sample bytes.
- PARITY:
  - idx < m <= fec_m;
  - k <= fec_k;
  - block_len <= max_payload + 2;
  - first_seq inside the window.

Ship a fuzz corpus next to Appendix A, and run libFuzzer on a host build of
the parser.

### F19 [MEDIUM] Queue overflow is undefined, and congestion starves control frames

Section: Appendix B (rx_queue between transport callbacks and pl_task), 11.4
step 7f (relay tail drop).

Failure in the field: during a flood storm (F10), or while HMAC and RS work on
a single-core C3 competes with the WiFi task, rx_queue fills. Its depth and
full behaviour are unspecified, and the WiFi task cannot block, so frames are
dropped with no counter in pl_stats_t. Data goes missing while every counter
reads clean.

On relays, the forwarding queue is a single FIFO with tail drop. Under DATA
load, ACK, PONG, MODE_ACK and BIND_ACK get dropped just like DATA. The sender
sees no liveness for SESSION_TIMEOUT, closes and re-SEEKs (two more floods),
and the load goes up again: a positive feedback loop.

Fix:
1. Specify the rx_queue depth (e.g. 16) and an rx_queue_drop counter.
   Callbacks use xQueueSend with timeout 0.
2. Give the relay queue two classes. Control frames (SEEK, BIND, HELLO,
   BIND_ACK, BIND_NAK, ACK, PING, PONG, MODE, MODE_ACK, CLOSE) are never
   dropped in favour of DATA/PARITY. When the queue is full, drop the oldest
   DATA.
3. Count drops per class.

### F20 [MEDIUM] pl_seek blocks long enough to trip the task watchdog and cause a reboot loop

Section: Appendix B ("pl_seek blocks the calling task up to timeout_ms"),
11.7 (mesh SEEK timers).

Failure in the field: the application task is subscribed to the Task WDT
(default 5 s). With mesh timers, the SEEK backoff alone is 580 + 1160 + 2320 +
4640 + 9280 ms, about 18 s. If no probe is reachable (probe offline, full
group as in F9, channel split as in F4), the app task blocks past 5 s, the
TWDT panics, and the node reboots and SEEKs again. The result is a reboot
loop that also floods the mesh every few seconds.

Fix: make pl_seek asynchronous (start the SEEK, report through on_bound /
on_seek_failed). Or require timeout_ms to be shorter than the TWDT timeout,
with the app looping and calling esp_task_wdt_reset(). Document this in
Appendix B.

### F21 [LOW] period_us (u32 microseconds) cannot express periods longer than 71.6 min

Section: 6.1 (period_us u32).

Failure in the field: a soil-moisture node sampling every 2 h cannot state
its period in MODE. Implementers will send 0, saturate, or wrap, and the
receiver's nominal sample times will be wrong.

Fix: add a period unit bit to MODE flags (us or ms), or make the field
period_ms when n_samples = 1.

---

## 8. Implementability and pipeline ordering

### F22 [HIGH] The forwarding pipeline changes state before authenticating, so an outsider can blackhole or silence nodes without jamming

Section: 11.4 steps 3, 6a-6c, 7g; 11.8 threat table (an outsider "can: jam,
inject unicast frames ... dropped by the endpoint tag check").

Failure in the field:
- (A) Link poisoning. An outsider ESP32 sets any MAC and sends one unicast
  frame per second with prev_hop = 0x0042 (a relay on the gateway path) and a
  valid CRC. Step 3 runs before any authentication, so every node in range
  now maps 0x0042 to the attacker's MAC. All traffic routed via 0x0042 is
  unicast to the attacker and disappears. Re-SEEK installs routes through
  0x0042 again, and the poisoned entry is used again.
- (B) Rate starvation. Step 6b (rate limit) runs before 6c (K_mesh tag). Ten
  forged floods per second with random src_ids drain SEEK_RATE_TOTAL at every
  relay in range. No legitimate SEEK or BIND gets forwarded, so no new session
  can form there. Three per second with src_id = victim drains only the
  victim's bucket.
- (C) Dedup poisoning. The spec does not say when (src_id, seq) enters the
  dedup cache. If an implementation inserts at 6a, an attacker who saw one of
  the victim's floods can send forged copies of the next seqs ahead of time
  (the pre-session counter goes +1 per transmission). The victim's real floods
  are then dropped as duplicates for 5 s at a time.

Each attack costs about 10 tiny frames per second and leaves no RF signature,
unlike jamming.

Fix:
1. Fix the processing order: per-hop decode, version, the length and range
   checks from F18, K_mesh tag check for floods. Only after that do dedup
   insert, rate limiting, link learning and route installation. HMAC over 250
   bytes or less takes tens of us (section 8), so it can run first.
2. For unicast frames, add a 4-byte per-hop tag, HMAC(K_mesh, whole frame
   including hop fields), recomputed at each hop. Only learn links and refresh
   routes from frames that pass it. Alternatively use ESP-NOW CCMP with an LMK
   derived from K_mesh, within the encrypted-peer limit.
3. Correct the 11.8 threat table.

### F23 [MEDIUM] The origin hears its own flood echoed back, and the spec does not say what to do

Section: 2 (collision rule), 11.4 steps 3-6, 11.5.

Failure in the field: S floods SEEK. Neighbour R rebroadcasts it on ESP-NOW
(step 6e skips only point-to-point transports), so S hears its own SEEK with
src_id = S from R's MAC. Section 2's rule ("src_id equals its own unit ID ...
different carrier address") raises PL_EVT_ID_COLLISION on every flood.

The spec never says that the origin puts its own (src_id, seq) into its dedup
cache. An implementer who does not will also install a reverse route to
itself via R (6d) and rebroadcast its own SEEK (6e). The collision alarm then
fires constantly and gets ignored, so a real collision (F3) goes unnoticed.

Fix:
1. The origin adds each of its own floods to its dedup cache when it sends
   them.
2. A frame with src_id = own ID whose seq is in the node's own send history is
   an echo: drop it without an alarm.
3. Raise a collision only when that seq is not in the node's own history, or
   when prev_hop = own ID arrives from another address.

### F24 [MEDIUM] BIND decides who owns the session but is protected only by K_mesh

Section: 4.1.5, 8 ("Which key, which frames"), 11.8 table (a K_mesh-only node
"cannot ... forge ... end-to-end header fields or payload undetected").

Failure in the field: BIND is tagged under K_mesh, and a K_mesh-only relay
sees nonce_s (in SEEK) and nonce_p (in HELLO, which it forwards).

- It can forge a BIND that names a different probe_id. Every probe in OFFERED
  for that nonce_s, including the one the sender picked, returns to LISTENING
  (4.1.5). When the real BIND arrives, the chosen probe is no longer OFFERED,
  and what a LISTENING probe does with a BIND naming it is undefined. One
  compromised relay can make the handshake fail every time.
- Or it can forge a BIND with a different session_id. The probe binds with the
  forged id, then treats the genuine BIND as a repeat (4.1.9) and keeps the
  forged id. The sender's frames then count as "unknown session".

Fix:
1. BIND carries a second 8-byte tag under K_s over (nonce_s, nonce_p,
   probe_id, session_id). The sender can compute K_s once HELLO has delivered
   nonce_p.
2. The named probe binds only when that inner tag verifies. Losing probes may
   stand down on the K_mesh tag alone; a forgery then costs only a re-SEEK.
3. Specify that a LISTENING probe ignores a BIND naming it.
4. Correct the 11.8 table.

### F25 [MEDIUM] Contradictions in the spec that will produce incompatible implementations

Section: 4.1.8 vs 9 vs 11.7; 4.1.11 vs 11.2; 6.1 vs 7; 4.1.6-4.1.7.

Failure in the field:
1. SEEK timeout: 4.1.8 and section 9 say 100 ms first. 11.7 says 580 ms in a
   mesh. A sender using 100 ms on a 3-hop path re-SEEKs before HELLO can
   return (3 hops x 2 x up to 60 ms), which doubles floods per attempt and
   trips the rate limiter (F11).
2. Session key: 4.1.11 matches on (transport, src_id, session_id), 11.2 on
   (src_id, session_id). At a probe with ESP-NOW and UART, a route change
   moves a session's frames to the other transport. Implementation A keeps
   the session; implementation B drops the frames or answers CLOSE
   (UNKNOWN_SESSION).
3. Liveness ACKs: 6.1 MODE flags bit0 means "probe should send ACK even when
   arq = 0", while section 7 says the probe sends ACKs at ACK_MS regardless.
   A probe that follows 6.1 sends no ACK when bit0 is clear. A sender that
   follows section 7 expects one, so the session closes after 2 s, every
   time.
4. Late BIND: a probe back in LISTENING after BIND_TIMEOUT that receives a
   late BIND naming it is undefined. One implementation binds, another
   ignores, so the sender gets BIND_ACK or a timeout depending on whose
   firmware the probe runs.

Fix:
1. One normative timer table, with mesh scaling written into it.
2. One session key, (src_id, session_id), everywhere.
3. Delete MODE flags bit0, or make section 7 depend on it.
4. Add the LISTENING + BIND row to the probe state table.

### F26 [MEDIUM] The WiFi UDP carrier is underspecified for real networks

Section: 1.2 WiFi UDP row.

Failure in the field:
- No port or multicast group is defined. Two implementers pick different
  ports, or broadcast vs multicast, and their nodes never see each other.
- Building WiFi often has client isolation or filters broadcast and multicast
  (typical on IoT and guest SSIDs). SEEK never reaches the probes, UDP
  sessions never start, and unicast ping still works, which misleads the
  installer.
- DHCP re-addresses nodes after an outage, leaving stale link entries (F12).

Fix:
1. Fix the UDP port, an administratively scoped multicast group, and TTL 1.
2. Require DHCP reservations or static IPs.
3. Allow a configured unicast peer list (SEEK unicast to each peer) for
   networks with client isolation, and state that otherwise isolation must be
   off.

### F27 [MEDIUM] Control frames carry no recovery data on packet links (gap against the stated requirement)

Section: 1.1, 1.2 (rs_nsym 0 default on PACKET links), 3.3 (FEC covers only
DATA groups). User requirement: "integrity check + recovery data in every
packet".

Failure in the field: on ESP-NOW, BLE and UDP, SEEK, HELLO, BIND, BIND_ACK,
MODE and ACK carry a CRC and nothing else. Floods are broadcast with no MAC
retry. On a 3-hop path with 10 % loss per hop, one path delivers a flood 0.9^3
= 73 % of the time, and the handshake needs two floods plus four unicast
replies to all succeed. Under coexistence loss (F5) or post-outage load
(F10), handshakes need several rounds, and each round is a network-wide
flood. The spec meets the requirement for DATA only.

Fix: choose one and write it down.
1. Get the requirement explicitly relaxed to "recovery by FEC or by retry".
2. Or add recovery to control frames: send each flood copy twice with
   independent jitter on carriers without MAC retry. This is a repetition
   code, and cheap because floods are small.

### F28 [LOW] Nonces and seq start points are weak on nodes with the radio off

Section: 4.1.1 (nonce_s from esp_random()), 3.5 (random pre-session seq).

Failure in the field: on a UART-only or IR-only node, WiFi and BT are never
started. ESP-IDF documents esp_random() as only pseudo-random in that state,
unless bootloader_random_enable() is active. nonce_s, nonce_p and the
pre-session seq start become predictable, which weakens the replay protection
that depends on fresh nonces and makes F22 (C) easier.

Fix: on nodes without RF, call bootloader_random_enable() while generating
nonces (it borrows the SAR ADC, so not while the app uses the ADC), or start
WiFi briefly at boot to collect entropy. State this in 4.1.1.

---

Counts: CRITICAL 4, HIGH 13, MEDIUM 9, LOW 2

Verdict: not deploy-ready for 5-50 nodes unattended for months. As a bench
and single-hop protocol it is careful work: the erasure model, CRC/RS/FEC
maths, two-nonce key derivation, static memory, the memcpy rule and the
per-hop vs end-to-end split are sound, and the Appendix A vectors recompute
exactly. Deployment fails on the operational layer the spec leaves out:

- power: no sleep path for the leaves it promises (F1);
- keys: one shared key with no rotation (F2);
- channel management with STA present (F4);
- replay protection that expires with every seq wrap (F17);
- tables and backoff sized for 16 nodes on a quiet bench (F9-F12);
- no OTA, versioning, remote diagnostics or network time (F13-F16).

Fix the four CRITICALs and F9, F10, F15 and F18 before building hardware for
the site. The rest can go into a v0.4 that is soak-tested on 10 nodes for
72 h, including a forced power-cycle of all nodes at once, before the full
rollout.
