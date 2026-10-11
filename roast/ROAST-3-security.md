# ROAST-3 (security): ProbeLink v0.5 requirements audit

Spec: `PROTOCOL.md` (DRAFT v0.5, wire version 1, minor 0). Baseline:
ROAST-2-security (properties P1-P12, gaps T1-T24) and the Appendix D
disposition. Scope: sections 3.5, 3.6, 4.1, 4.4, 5, 6.4, 6.5, 8, 11.4, 11.5,
11.8-11.10, 12.1, 12.2, 12.7, 12.8, 12.10, Appendix A and B.

Format: requirements audit. Each property states holds / partial / fails,
the mechanism and section it relies on, and for each gap a short
description and the defensive fix. No exploitation procedures.

Field profile assumed for task 3: months-long unattended deployment of 5-50
nodes, every node (including the gateway) physically reachable.

Severity: CRITICAL = contradicts an explicit property statement of the spec
in the field profile. HIGH = holds only partially, or depends on a step the
spec does not specify. MEDIUM = bounded impact, insider-only availability,
or defence in depth. LOW = hygiene, style or test coverage.

## Summary

| ID | Sev | Property | Title | Section |
|---|---|---|---|---|
| U1 | CRITICAL | P1, P10 | Key bundles are encrypted under K_mgmt(N, M, E), which the gateway (M) holds for every node; a manager can also author any key TLV | 8.2, 8.5, 11.10 |
| U2 | CRITICAL | P3, P4 | hop_tag authenticates only the 16-bit hop_seq; hop freshness does not survive a wrap of the transmitter's txseq | 3.5, 8.3, 8.4, 11.9 |
| U3 | HIGH | P5, P4, P9 | pre_ctr of encrypted session_id 0 frames is inside the ciphertext: receivers cannot form ctr_hi of the nonce, relays cannot apply dedup/ORIGIN to flooded MGMT_REQ | 3.5, 8.3, 11.4, 11.5 |
| U4 | HIGH | P4, P8 | Endpoint pre_ctr state is RAM-only and MGMT_RESP is not bound to the outstanding request; recorded responses (commands, time) are accepted after a node reboot | 8.4, 11.10, App. B |
| U5 | HIGH | P10 | No rule for when a node first transmits under its newest epoch; erase rules do not say which "E" they are relative to | 8.5 |
| U6 | HIGH | P1, P5, P11 | Recovery key is shared by the station and phones as unit 0x0002, cannot be rotated, and its K_mgmt nonce space is not partitioned | 6.4, 8.2, 12.2 |
| U7 | HIGH | P11 | "First boot of an unprovisioned node" opens BLE maintenance with no specified authentication, and a field node can regress to that state | 6.4, 12.2, App. B |
| U8 | MEDIUM | P1, P10 | Revocation epoch is not required to exceed every epoch already issued to the revoked node | 8.5 |
| U9 | MEDIUM | P3, P9 | hop_seq has no forward-jump bound (ORIGIN has one) | 3.5, 11.4, 11.9 |
| U10 | MEDIUM | P9 | Maintenance mode has no exit timeout; a button on a reachable relay removes it from the mesh indefinitely | 6.4 |
| U11 | MEDIUM | P5 | Leaf counter source of truth between RTC blob and NVS reserve is not stated | 3.5, 4.4, App. B |
| U12 | MEDIUM | P11 | BULK update has no anti-rollback (secure version) requirement | 12.7, 12.1 |
| U13 | MEDIUM | P1 | No requirement for the gateway to alarm on missing reports or changed secure-state bits (capture detection) | 11.10, 12.10 |
| U14 | LOW | P6 | K_mesh is used directly as the hop_tag HMAC key and as HKDF input | 8.2, 8.3 |
| U15 | LOW | P2 | 12.1 admits original ESP32 rev 3, but 12.2 describes only the eFuse HMAC NVS-key path | 12.1, 12.2 |
| U16 | LOW | P10 | Clock source for KEY_RETIRE_S and KEY_REVOKE_GRACE_S is unstated | 8.5, 9 |
| U17 | LOW | P9 | ORIGIN_MAX_JUMP (2^20) sized for the gateway applies to every origin | 11.5 |
| U18 | LOW | P9 | "One OFFERED entry per src_id" is a weaker bound than stated, because src_id is K_mesh-authenticated only | 4.1.2, 12.10 |
| U19 | LOW | P12 | Vector coverage: no bundle, MGMT_RESP or flooded MGMT_REQ vector | App. A |

## 1. Property audit (P1-P12)

### P1 Compromise of one node does not expose other pairs' keys; the node can be revoked

Verdict: partial (holds for ordinary nodes, fails for the gateway).

- Holds for ordinary nodes: per-pair `K_pair(A, B, E)` from the offline
  `K_site` (8.2); a captured node yields its own pairs and the stored K_mesh
  epochs only. R2 is correctly narrowed to the session and management layers.
- Revocation: pair keys of the revoked ID are deleted at once (8.5), so
  session and management access end immediately; mesh-layer access ends
  with the revocation epoch (bounded by KEY_REVOKE_GRACE_S plus reach time).
- Fails for the gateway: U1. The manager holds the key that encrypts every
  node's bundle, so a captured gateway yields every node's next-epoch pair
  keys, and every following epoch, because each bundle carries the next
  K_pair(N, M). The recovery-key holders (station, phones) have the same
  shape for the devices they cover (U6).
- Residuals: U8 (revocation epoch ordering), U13 (capture detection).

### P2 Keys at rest are protected

Verdict: holds as specified (as a cost, not a guarantee).

- 12.2 now gives an ordered provisioning sequence: chip revision check,
  Secure Boot v2 digest and JTAG / download-mode eFuses, signed images,
  release-mode flash encryption, NVS key, per-device encrypted NVS image,
  verification through MGMT section 0, eFuse summary kept per MAC. Closes T9.
- `pl_init` refuses to start without secure boot, release-mode flash
  encryption and an encrypted key partition (12.1, App. B); MGMT section 0
  reports the three bits (11.10).
- R1 restated as cost, supported chips listed, revocation named as the
  bounding control (8.1, 12.1). Closes T20.
- Residual: U15 (original ESP32 NVS-key path not described).

### P3 Every state-changing frame is authenticated (and fresh) before the change

Verdict: partial.

| Step (11.4) | Finding |
|---|---|
| 1-4 | Decode, length/header/hop-field checks, version, FLAG_AUTH mandatory. No state. Holds. |
| 5 | hop_tag under any stored epoch, then hop_seq newer than the link entry. Holds against forgery. Freshness holds only within one 16-bit cycle of the transmitter's txseq (U2). |
| 6 | Link learning only after step 5. Holds, subject to U2 and U9 (address replacement on "newer" hop_seq). |
| 7 | Endpoint: CCM tag plus index or pre_ctr window. Holds for session frames. Pre-session frames depend on U3 (nonce formation) and U4 (state after reboot). |
| 8 | Overheard unicast: no state change. Holds. |
| 9a-9e | Dedup before ORIGIN (closes T21), ORIGIN with a jump bound, budget after freshness. Holds for SEEK and RESUME (pre_ctr is readable and covered by the hop_tag, and by Ke_mesh for SEEK). Not specifiable for flooded MGMT_REQ, whose pre_ctr is ciphertext (U3). |
| 9f, 10a-10e | Forwarding and route refresh run only after admission. Route table rule "never changes an existing next_hop" for ordinary frames limits replay impact. Holds. |

### P4 Replay protection across seq wrap, reboot and power loss

Verdict: partial.

- Holds, session layer: 48-bit index (ROC u32 << 16 | seq) inside the CCM
  nonce and AAD, SRTP-style ROC estimate confirmed by the tag, 64-entry
  window (3.5, 8.3, 8.4). Fresh keys per handshake from the transcript.
- Holds, relays, SEEK and RESUME: 32-bit persistent `pre_ctr` on the wire,
  ORIGIN with 1 h TTL and jump bound (11.5). Closes T2 and T10 for these
  types. The post-expiry one-flood residual is stated and bounded.
- Fails, hop layer: U2 (wrap). Partial, pre-session endpoints: U3, U4.

### P5 Nonces never repeat under one key

Verdict: partial.

- Holds by layout: 13-byte nonce `dir || src || dst || session_id || ctr_hi
  || seq || 0x00` (L = 2), directional session keys, per-session keys bound
  to `session_id` and transcript T, retransmissions byte-identical from the
  ARQ buffer (section 7, closes T18), leaf RTC reserve-ahead with CRC32 and
  `ESP_RST_DEEPSLEEP` gate (4.4, closes T12).
- Gaps: U3 (the receiver cannot reconstruct ctr_hi for encrypted pre-session
  frames; the easy workaround, ctr_hi = 0, reuses nonces under the
  epoch-long K_mgmt once a counter passes 65536); U6 (two senders as unit
  0x0002 under one key); U11 (RTC vs NVS counter source).

### P6 Key derivation uses standard constructions correctly

Verdict: holds.

- HKDF-SHA256 (RFC 5869). K_mesh and K_pair use distinct Extract salts
  ("ProbeLink-mesh", "ProbeLink-pair") with fixed-width info (1 and 5
  bytes). Session and management keys share one PRK construction
  (`Extract("ProbeLink-v1", K_pair)`) and are separated by Expand labels
  "hello", "hs", "s2p", "p2s", "mgmt": prefix-distinct, each followed by
  fixed-width fields, so no two info strings can coincide. Closes T22.
- Transcript T (and T0 for Ke_hello) binds both nonces, both `pre_ctr`,
  caps, `max_frame`, `key_epoch`, `proto_minor` into every handshake and
  session key (8.2). Closes T11 and T17 (uniqueness is deterministic through
  the persistent `pre_ctr` values).
- Style only: U14.

### P7 Downgrade resistance

Verdict: holds.

- ENC is no longer negotiated: CCM is the only end-to-end construction
  (8.3), so the T11 downgrade path is removed by the cut. Caps and
  `proto_minor` are in the transcript; a probe ignores senders without AUTH
  (section 5); `ver_flags` is in the AAD.

### P8 Forwarders with only K_mesh cannot alter end-to-end content or forge session or management control

Verdict: holds for ordinary nodes; see U1 for the manager.

- HELLO under Ke_hello, BIND / BIND_ACK / BIND_NAK under Ke_hs, session
  frames under directional keys, MGMT under K_mgmt (8.2, section 5). BIND is
  unicast and nothing on the air cancels an offer (4.1.5), which removes
  T14 and T16. Time comes only from listed managers under K_mgmt and drives
  no key event (6.5, 8.5), which closes T7.
- Residual: U4 (stale management responses after reboot).

### P9 Flood amplification and state exhaustion are bounded, authenticated before counted

Verdict: holds for outsiders on SEEK and RESUME; partial overall.

- Budgets after freshness (11.5); dedup sized for full load; static tables
  (11.9); OFFERED one per src_id with oldest replaced (4.1.2, closes T15 for
  outsiders).
- Gaps: U2 (recorded unicast re-admitted after wrap), U3 (flooded MGMT_REQ
  freshness), U9 (hop_seq jump), U10 (maintenance-mode denial). Insider
  items are the stated mesh-identity limitation (section 3).

### P10 Rotation, epoch change and revocation without splitting the mesh

Verdict: partial.

- Holds: three-epoch accept window, per-neighbour epoch record, pulled
  bundles that reach leaves through MGMT on wake, tool-side pacing,
  revocation epochs with a stated residual window (8.5, 4.4, 11.10). The
  T3 split on activation and the T5 leaf gap are closed in design.
- Gaps: U5 (transmit-epoch advancement unspecified), U1 (bundles readable
  by the manager), U8, U16.

### P11 Test keys cannot ship; fail-closed defaults

Verdict: partial.

- Holds: tool refuses the Appendix A `K_site`; firmware rejects degenerate
  keys and the hash prefixes of K_mesh(E) for all 256 test epochs (every
  field node holds a K_mesh, so any site built from the test K_site is
  caught); separate signing keys for bench and field images with eFuse
  checks (12.1). Closes T13 and T19.
- Gaps: U7 (unprovisioned BLE entry), U12 (no anti-rollback for BULK).

### P12 Appendix A vectors consistent with section 8

Verdict: holds (coverage partial).

- Ran `vectors_v05.py` (python3): all asserts pass ("ALL OK"); the script
  round-trips the A.7 DATA decryption and verifies the A.8 SEEK tag. Its
  output matches the A.2-A.12 text byte for byte (frames, CRCs, RS parity,
  COBS, keys, nonces, ciphertexts, tags, hop_tags, ROC cases).
- Independent check with the `cryptography` library's HKDF / HKDFExpand /
  HMAC / AESCCM, not the script's own HKDF: K_mesh(1) = 15e0339c...720c31c3,
  K_pair(0042, 1234, 1) = 14270866...1bf31af5, PRK = 4a0e7d43...d571749f,
  Ke_s2p (session 7, A.9 T) = df810284505046a3db3233d90f746f95, A.7
  ciphertext || tag = f1075ee6...4b4a e10f1d3a377a7721, K_mgmt(0042 -> 0001)
  = c7ccbdf12bd73a2f349cf415f666d987. All equal to Appendix A.
- Layout checks: SEEK nonce `00 3412 01ff 00 01000000 0100 00` and HELLO
  nonce (dir 1, src P, dst S) follow 8.3; AAD = 10-byte e2e header || ctr_hi
  u32 (|| payload for AAD-only frames) follows 8.3; RESUME uses the session
  index (ROC 0, seq 0x0042) under Ke_s2p as 8.3 states.
- T23 remains partial: U19.

## 2. Round-2 CRITICAL/HIGH resolution (T1-T13) and cut regressions

| ID | Appendix D claim | Verified | Note |
|---|---|---|---|
| T1 | fixed (hop_seq) | partial | hop_seq is checked before step 6, but only its low 16 bits are under the hop_tag, so freshness does not survive a txseq wrap (U2). ROAST-2 asked for the implicit extension inside the hop_tag input. |
| T2 | fixed | yes | RESUME carries a plaintext 32-bit `pre_ctr`, covered by the hop_tag; ORIGIN, dedup and budget apply (4.4, 11.4, 11.5). |
| T3 | fixed (= G1) | partial | No activation message, accept window of three epochs: the split on activation is gone. The rule for starting to transmit the newest epoch is missing (U5). |
| T4 | fixed (= G8) | yes, with U8 | Revocation epoch erases E after neighbours move or 24 h; residual stated. |
| T5 | fixed (= G10) | yes | Leaves pull through MGMT on wake (4.4, 11.10). |
| T6 | fixed (partial) | yes (as narrowed) | R2 narrowed to session and management layers; mesh identity is a stated limitation (11.8, 12.8). Judged in section 3. |
| T7 | fixed | yes | Time only from listed managers under K_mgmt; no time-driven key event. Stale-response residual in U4. |
| T8 | fixed (= G8) | no | Bundles are encrypted under K_mgmt(N, M, E), held by the gateway; "holds no other node's keys" does not hold (U1). |
| T9 | fixed | yes | Provisioning sequence and `pl_init` checks (12.1, 12.2). U15 is a gap for one chip. |
| T10 | fixed | partial | 32-bit `pre_ctr` for SEEK and RESUME; flooded MGMT_REQ and encrypted unicast pre-session frames carry it only inside the ciphertext (U3); endpoint state is RAM-only (U4). |
| T11 | fixed | yes | Transcript T in every key; ENC no longer negotiated. |
| T12 | fixed | yes | Reserve-ahead RTC blob, CRC32, deep-sleep reset gate (4.4); U11 is the remaining interface question. |
| T13 | fixed | yes | Tool refusal plus 256-epoch K_mesh blacklist and degenerate-key check (12.1). |

Regression check of the v0.5 cuts:

| Cut | Security effect |
|---|---|
| BLE phone-only | Removes the BLE carrier attack surface and coexistence issues. Adds a phone-as-manager path whose key handling is under-specified (U6, U7, U10). |
| IR edge-only | No regression: steps 9e, 9f, 10a, 10c stop frames at `edge_only` transports; the attached node is a full endpoint with CCM. |
| AES-CCM end to end + HMAC hop_tag | Standard and correctly laid out (P5, P6). Regression: putting `pre_ctr` inside the ciphertext of encrypted pre-session frames removes the information a receiver needs to form the nonce and a relay needs for flooded MGMT_REQ (U3). |
| MGMT_REQ/RESP merge | Closes T5 and T7. Regression: the one response type now carries keys, time and commands, and its freshness after reboot is not specified (U4); a manager can author key TLVs (U1). |
| BIND unicast | Removes T14 and T16. No regression found. |
| Three-epoch window | Removes the activation split (T3). Transmit advancement is unspecified (U5). |
| Pull-based leaf keys | Closes T5. Bundle confidentiality against the relaying manager fails (U1). |

## 3. Known limitations of 12.10 (security-related)

Judged for a months-long unattended deployment of 5-50 physically reachable
nodes.

| Limitation | Judgement | Reason |
|---|---|---|
| Mesh-layer identity rests on K_mesh (11.8) | Acceptable with condition | Session and management confidentiality and integrity stay pair-keyed, so a K_mesh holder is limited to availability and routing effects, and revocation bounds it. The condition is that capture is noticed: the gateway must alarm on missing MGMT reports, reset_reason changes and secure-state bit changes, and revocation is the documented response (U13). The per-node signature alternative (12.8) remains the full fix. |
| One recorded unicast frame re-admitted after LINK_TTL_MS (8.4) | Acceptable only after U2 | Once the full 32-bit txseq is authenticated, the residual is one frame per expired entry, rejected at the endpoint, unable to change an existing next_hop, and undone by the neighbour's next frame. Without U2 the re-admission is not limited to expired entries. |
| Epoch pacing is a tool rule (8.5) | Acceptable | The tool is the only bundle issuer and sees every node's reported epoch, so enforcing pacing there is sufficient for a single-operator site; the protocol needs U5 so that the paced epochs are actually adopted. |
| Revoked node keeps mesh access for the grace period (8.5) | Acceptable with condition | Pair keys are deleted at once, so the window is mesh-layer only; 24 h is needed to cover leaf pull intervals. Conditions: U8 (revocation epoch strictly newer than anything the revoked node holds) and U13 (detection). |
| OFFERED denial bounded to one entry per src_id (4.1.2) | Acceptable | Outsiders cannot create OFFERED entries (Ke_mesh tag plus pre_ctr freshness). For insiders the bound is per claimed src_id, which is part of the mesh-identity limitation; wording fix only (U18). |
| R1 is a cost, not a guarantee (12.1) | Acceptable for ordinary nodes; must-fix for the gateway | For an ordinary node, a lab extraction yields that node's keys, which revocation retires. For the gateway, extraction yields the key that decrypts every node's bundles for all future epochs and lets the holder author key TLVs, and the gateway cannot be revoked in band. Promoted as U1. |
| IR outdoors and bit cell unvalidated; no TRACE frame; FEC/ARQ not auto-tuned | Out of scope | Not security properties. |

## 4. Findings

### U1 CRITICAL - Key bundles are readable and authorable by the manager

- Property: P1, P10. Section: 8.2 (K_mgmt held by N and M), 8.5 Bundles,
  11.10 TLVs 0x01-0x03, Appendix D T8.
- Gap: 8.5 encrypts each node's bundle under K_mgmt(N, M, E) and states that
  the gateway "holds no other node's keys", but M is the gateway, which
  must hold K_mgmt(N, M, E) for every N to serve MGMT. A captured gateway
  therefore obtains every node's next-epoch K_mesh and pair keys, and each
  bundle also carries the next K_pair(N, M), so confidentiality is not
  regained by later rotation. Because a node cannot tell tool-made TLVs from
  manager-made ones, any K_mgmt holder can also install a pair key for an
  arbitrary peer ID, which contradicts R2 at the session layer. If M is
  instead read as the station's reserved 0x0002, the bundle key is the
  recovery key, which is static, unrotatable and held by every recovery
  device (U6), so the property fails under either reading.
- Fix: (1) Give each node a tool-only key, for example `K_node(N) =
  HKDF(K_site, "ProbeLink-node", N u16, 32)` provisioned at 12.2 and never
  given to any manager; the tool encrypts and authenticates each bundle under
  a key expanded from it ("bundle" || N || epoch) with a bundle sequence
  number in the nonce, so its nonce space is disjoint from frame nonces.
  (2) A node accepts TLVs 0x01-0x03 only from inside a bundle that verifies
  under K_node, with epoch = newest held + 1 and a sequence number above the
  last one stored in NVS. (3) Managers relay bundles as opaque bytes and may
  author only TLV 0x04 commands and time. (4) Define manager replacement:
  the tool can issue a bundle that changes `pl/managers`, so a captured
  gateway can be revoked without a cable visit.

### U2 CRITICAL - hop freshness does not survive a txseq wrap

- Property: P3, P4. Section: 3.5 (`txseq` low 16 bits on the wire, 32-bit
  reconstruction), 8.3 (hop_tag over frame bytes only), 8.4 Hop freshness,
  11.9 (newer hop_seq replaces the address), Appendix D T1.
- Gap: only the 16-bit `hop_seq` is under the hop_tag; the high half of the
  32-bit reconstruction is local and never authenticated, unlike the session
  ROC, which is inside the CCM nonce. A busy relay wraps its 16-bit value in
  under an hour (3.5 sizes txseq at tens of thousands of frames per day), so
  a recorded frame can again look "newer" while the neighbour's entry is
  live. This contradicts 8.4 ("cannot be re-admitted while the neighbour's
  entry lives") and the outsider row of 11.8, and via 11.9 it can also move
  a neighbour's link address.
- Fix: include the full 32-bit txseq in the hop_tag input as an implicit
  field (`HMAC(K_hop, txseq_hi u16 || frame bytes)`), with the receiver
  estimating the high half from its link entry exactly as the ROC is
  estimated in 3.5 and the tag confirming the guess. Accept a frame only if
  its reconstructed txseq is newer and within a bounded forward window (U9),
  and replace a link address only after such a frame.

### U3 HIGH - pre_ctr of encrypted pre-session frames is not available where it is needed

- Property: P5, P4, P9. Section: 3.5 (`pre_ctr` first payload field), 8.3
  (ctr_hi = high 16 bits of pre_ctr; only SEEK and RESUME are plaintext),
  11.4 steps 9b-9c, 11.5 (gateway originates thousands of pre-session
  frames).
- Gap: for HELLO, BIND, BIND_ACK, BIND_NAK, MGMT_REQ and MGMT_RESP, the
  receiver needs ctr_hi to form the CCM nonce before it can decrypt the
  field that contains it; the spec gives no estimation rule, and a receiver
  with no history (a sender hearing a probe for the first time, a node after
  reboot hearing the gateway once the gateway's counter has passed 65536,
  which is days at 50 nodes) has nothing to estimate from. The obvious
  workaround, a fixed ctr_hi, reuses nonces under the epoch-long K_mgmt.
  Relays also cannot read the 32-bit `pre_ctr` of a flooded MGMT_REQ, so 9b
  and 9c can only use the 16-bit header seq for it, reopening T10 for that
  type.
- Fix: carry `pre_ctr` u32 in clear for every session_id 0 frame (an AAD
  prefix of the payload, as SEEK and RESUME already do), keep the rest of the
  payload encrypted, and state that the receiver takes ctr_hi from that
  field. Add a vector for HELLO with ctr_hi != 0 and for a flooded MGMT_REQ.

### U4 HIGH - MGMT_RESP freshness after a node reboot is unspecified

- Property: P4, P8. Section: 8.4 ("endpoints keep the last pre_ctr per
  (peer, key)"), 11.10 (t1 echo), Appendix B (runtime NVS writes do not
  include this state).
- Gap: the per-peer `pre_ctr` high-water mark is RAM state, and 11.10 does
  not require a node to match a MGMT_RESP to its outstanding MGMT_REQ. After
  a node reboots it therefore has no basis to reject a recorded MGMT_RESP,
  whose TLVs include commands 1 (maintenance mode) and 2 (reboot) and whose
  time fields feed the clock. This contradicts R5 at endpoints.
- Fix: make MGMT a challenge-response: a node keeps one outstanding request
  and accepts a MGMT_RESP only if it echoes that request's `pre_ctr` (and
  t1); put the echoed request `pre_ctr` in the response AAD. Optionally
  persist the per-manager high-water mark with the existing reserve-ahead
  scheme. Commands 1 and 2 additionally rate-limited per boot.

### U5 HIGH - Transmit-epoch advancement is unspecified

- Property: P10. Section: 8.5 (per-neighbour transmit epoch = newest epoch
  that verified from that neighbour; floods use the oldest epoch any live
  neighbour uses; SEEK key_epoch = newest heard from a neighbour; "holds
  E+1 erases E-2"; "E-1 is erased when ...").
- Gap: every rule selects an epoch already heard from a neighbour, so no
  rule makes the first node transmit under a newly received epoch. The only
  advancement path is the "its newest if none" case of a node with an empty
  link table (after a reboot), which is accidental, not a mechanism. The erase rules do not say whether E is the newest held or the
  transmit epoch, and with E = newest held the second rotation erases the
  epoch everyone still transmits on.
- Fix: define `E_tx` (transmit epoch) separately from the newest held.
  Accept every stored epoch on receive; switch `E_tx` to the newest held
  after it has been held for a stated delay (at least the longest node pull
  interval, leaves included) or on first hearing any neighbour under it;
  express every erase rule relative to `E_tx`; have the tool's pacing rule
  refer to reported `E_tx` and newest held as two MGMT section 0 fields.

### U6 HIGH - Recovery key is shared, unrotatable and nonce-unsafe

- Property: P1, P5, P11. Section: 6.4 (phone holds the device's recovery
  key and acts as manager), 12.2 (recovery_key = pair key with the
  station's reserved unit ID 0x0002), 8.2 K_mgmt.
- Gap: the station and any number of phones act as the same unit 0x0002
  under one key per device, each with its own `pre_ctr` counter, so their
  MGMT_RESP nonces can collide under that key. No TLV rotates or revokes
  the recovery key, so a lost phone exposes manager-level control of every
  device it held until each is re-provisioned, and with U1 unfixed that
  control includes installing keys.
- Fix: give each recovery holder its own unit ID (station 0x0002, phones
  0x0003-0x000F) and its own key per device, derived by the tool; make
  recovery keys epoch-bound and rotatable through the U1 bundle; allow a
  phone only diagnostics and maintenance commands, never key TLVs, unless
  the bundle it carries verifies under K_node.

### U7 HIGH - Unprovisioned-state BLE entry is not fail-closed

- Property: P11. Section: 6.4 (maintenance mode entered on "the first boot
  of an unprovisioned node"), 12.2 (provisioning is over UART), Appendix B
  (`pl_init` returns PL_ERR_AUTH without keys).
- Gap: the spec does not say what authenticates the phone when the node
  holds no recovery key, and a field node can reach the "unprovisioned"
  state after NVS corruption or an erase-on-error init path, so the field
  profile may expose an unauthenticated BLE management link.
- Fix: in the field profile, a node without keys enters only a UART
  provisioning wait state; BLE requires a stored recovery key. Forbid
  automatic NVS erase in field builds; record the event in the RTC reset log
  and report it at the next successful MGMT.

### MEDIUM

- U8: revocation epoch ordering; the tool issues a revocation as (highest
  epoch ever issued to the revoked node) + 1.
- U9: hop_seq forward-jump bound; accept at most one reserve block (4096)
  ahead.
- U10: maintenance-mode exit timeout; restart the mesh after a stated idle
  time and report entries in MGMT section 0.
- U11: leaf counter source of truth; resume from max(RTC reserve, NVS
  reserve) and keep writing NVS block boundaries on leaves.
- U12: anti-rollback for BULK; secure-version eFuse scheme and no
  `fw_build` below the running one.
- U13: capture detection; the gateway MUST alarm on missed MGMT reports,
  reset changes and secure-state bit changes.

### LOW

- U14: K_mesh used directly as the hop_tag HMAC key and as HKDF input; derive
  `K_hop = Expand(Extract("ProbeLink-v1", K_mesh), "hop", 32)`.
- U15: 12.2 omits the flash-encryption-protected `nvs_keys` path for the
  original ESP32 rev 3 admitted by 12.1.
- U16: KEY_RETIRE_S / KEY_REVOKE_GRACE_S clock source unstated (uptime vs
  network UTC, behaviour across reboot).
- U17: ORIGIN_MAX_JUMP 2^20 sized for the gateway applies to every origin;
  use a per-role bound.
- U18: "one OFFERED entry per src_id" bound is per claimed ID; state it as an
  insider limitation.
- U19: Appendix A lacks a bundle vector (T23 deferral), a MGMT_RESP vector
  and a flooded MGMT_REQ vector.

## Result

Counts: CRITICAL 2, HIGH 5, MEDIUM 6, LOW 6

Properties that hold: P2 (at rest, as cost), P6 (key derivation and domain
separation), P7 (downgrade), P12 (vectors, independently spot-checked).
Partial: P1 (fails for the gateway, U1), P3 and P4 (hop layer U2,
pre-session U3/U4), P5 (U3, U6), P8 (U4), P9, P10 (U5, U1), P11 (U7, U12).

Verdict: NOT READY.

v0.5 closes most of round 2: the transcript-bound handshake, CCM-only
construction, RESUME freshness, leaf reserve-ahead, pulled bundles,
provisioning sequence and test-key blacklist are verified. Two explicit
claims do not hold: the gateway can read and author every node's key
bundles (U1), and hop freshness lapses at each 16-bit txseq wrap (U2).
Fixing U1 and U2 moves the verdict to READY WITH CONDITIONS; the conditions
are U3-U7 closed before the first key rotation in the field, and U13 in
place before relying on the mesh-identity and grace-period limitations.
