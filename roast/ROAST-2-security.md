# ROAST-2 (security): ProbeLink v0.4 requirements audit

Spec: `PROTOCOL.md` (DRAFT v0.4, wire version 1). Baseline: ROAST-1 summary
(S1-S20). Scope: section 8 (R1-R10), 4 (handshake), 11.4 (forwarding
pipeline), 12 (deployment profile), Appendix A and B.

Format: this is a requirements audit. Each property states whether the spec
guarantees it, the mechanism and section it relies on, and where it falls
short, the gap and the defensive fix. Attacker classes are the ones of
section 8: outsider (no keys), thief with one node, K_mesh holder (any node,
or a captured one before revocation).

Severity: CRITICAL = a stated property does not hold in the normal field
profile. HIGH = holds only partially, or depends on a step the spec does not
specify. MEDIUM = defence-in-depth gap with bounded impact or insider-only
availability impact. LOW = hygiene, correctness or test coverage.

## Summary

| ID | Sev | Property | Title | Section |
|---|---|---|---|---|
| T1 | CRITICAL | P3, P4, P9 | hop_tag has no freshness: a recorded unicast frame is re-admitted at relays (forwarded, refreshes routes and links, can rebind an expired link entry) | 8.4, 11.4 steps 5-6 and 10g, 11.8, 11.9 |
| T2 | CRITICAL | P9, P3 | Replayed RESUME floods pass relays: exempt from ORIGIN freshness, not checkable at step 5b, so they spend the origin's flood budget and rewrite reverse routes once dedup (5 s) has expired | 4.4, 11.4 steps 9b-9e, 11.5 |
| T3 | CRITICAL | P10 | Epoch activation splits the mesh: receivers accept only E and E-1, so a node that has activated E+1 is not heard by any peer still on E, including the key server's path to that peer | 8.6, 3.6 Tags row |
| T4 | HIGH | P1, P10 | A revoked node's K_mesh(E) stays valid for one full extra epoch, because E becomes "previous" at activation instead of being erased | 8.6, 11.8 |
| T5 | HIGH | P10 | Leaves cannot receive KEY_UPDATE: they never listen or serve a group, and KEY_UPDATE runs only S -> P | 4.4, 5, 8.6, 11.1 |
| T6 | HIGH | P1 | Mesh-layer identity is authenticated only by the shared K_mesh: R2 "no impersonation of another unit ID" holds at the session layer, not for routes, ORIGIN state, flood buckets or the link table | 8.1 R2, 8.2, 11.4, 11.5, 11.8 |
| T7 | HIGH | P10, P8 | Time master identity is K_mesh-only, and network time drives key activation (`at_utc_s`) | 6.5, 8.6 TLV 0x04, 11.8 |
| T8 | HIGH | P1 | The key server holds every pairwise key of epoch E+1; where it gets them and how long it keeps them is unspecified | 8.2, 8.6, 11.1 |
| T9 | HIGH | P2 | Provisioning does not produce or verify the Secure Boot / flash encryption / NVS encryption state that R1 requires, and `pl_init` does not check it | 8.1 R1, 12.1, 12.2, App. B |
| T10 | HIGH | P4 | Pre-session freshness is 16-bit on the wire and held only in relay RAM; unicast pre-session frames have no endpoint freshness check | 3.5, 8.4, 11.5, 11.8 |
| T11 | HIGH | P7 | ENC is negotiated from caps that are not bound into the handshake transcript; the sender's caps reach the probe only under K_mesh | 4.1.1-4.1.5, 5, 8.5 |
| T12 | HIGH | P5 | Leaf RTC session state can regress after a non-deep-sleep reset, reusing (Ke_s2p, nonce) pairs | 4.4, 8.5, App. B |
| T13 | HIGH | P11 | Test-key blacklist is incomplete: K_site never exists on a node, only listed K_mesh epochs are caught, test K_pair values are not covered | 8.1 R9, 12.1, App. A |
| T14 | MEDIUM | P9 | "Free" BIND retries are keyed on payload `nonce_s`, so a K_mesh holder can exceed the per-origin flood budget | 11.5 |
| T15 | MEDIUM | P9 | OFFERED cap is per probe with an ignore-new policy, so forged or replayed SEEKs keep a probe unbindable | 4.1.2 |
| T16 | MEDIUM | P8 | Losing probes leave OFFERED on the BIND outer K_mesh tag alone: insider handshake denial | 4.1.5 |
| T17 | MEDIUM | P5, P6 | Handshake key uniqueness is probabilistic (32-bit truncated nonces); a repeated (nonce_s, nonce_p, session_id) repeats K_s and every CCM nonce | 4.1.11, 4.1.15, 8.2 |
| T18 | MEDIUM | P5 | ARQ retransmissions reuse the seq, but the spec does not require them to be byte-identical under ENC | 3.5, 7, 8.5 |
| T19 | MEDIUM | P11 | Profile is a build flag only: a bench image signed with the production key would boot on field hardware | 12.1, 12.6 |
| T20 | MEDIUM | P2 | R1 is stated as absolute, but depends on chip revision and does not cover physical fault injection | 8.1 R1, 12.1 |
| T21 | LOW | P3 | Step 9b drops equal-seq copies before 9c, so the lower-cost-copy route update is unreachable; step 5b omits flooded DIAG/TIME | 11.4 |
| T22 | LOW | P6 | KDF style: labels in the HKDF salt, nonces as Extract salt, no label on inner_tag input | 8.2, 5 |
| T23 | LOW | P12 | Appendix A lacks vectors for ROC != 0, FLAG_LEN16 tag input, E-1 hop_tag fallback, RESUME and KEY_UPDATE | App. A |
| T24 | LOW | P4 | `pl/boot_count` is written on every boot, so a crash loop wears NVS without bound | 4.1.15, App. B |

## Property audit

### P1 Compromise of one node does not expose other pairs' keys; the node can be revoked

Verdict: partially holds.

- Holds (session layer): R2 via per-pair `K_pair(A, B, E)` from an offline
  `K_site` (8.2); a captured node holds only its own pairs and K_mesh. K_hs,
  K_s2p, K_p2s of other pairs are not derivable. This closes ROAST-1 S1 for
  session keys.
- Revocation exists (8.6 TLV 0x03 plus epoch bump) but is slow (T4) and
  cannot reach leaves (T5).
- Mesh-layer impersonation remains (T6) and the key server is a single
  node holding everything (T8).

### P2 Keys at rest are protected

Verdict: stated as MUST, not guaranteed by the specified flow.

- Mechanism: R1, 12.1 field column (Secure Boot v2, flash encryption release
  mode, NVS encryption, JTAG and UART download disabled by eFuse).
- Gap: 12.2 generates per-device NVS images from the manifest but does not
  say they are generated encrypted, how the NVS key is provisioned, or that
  eFuses are burned and verified before key material is written (T9). R1
  also reads as absolute (T20).

### P3 Every state-changing frame is authenticated before the change (11.4 line by line)

Verdict: holds against forged frames; fails against replayed ones.

| Step | Finding |
|---|---|
| 1-3 | Decode, range and version checks; no state. OK. |
| 4 | FLAG_AUTH mandatory in field profile; drops untagged. OK (closes S16 on the wire). |
| 5 | hop_tag under K_mesh(E) / (E-1) before any state. OK for forgeries. A bit-identical recorded frame passes, because hop_tag has no freshness input (T1). |
| 5b | SEEK and BIND outer tag under K_mesh. Adds nothing against a K_mesh holder (same key as hop_tag) and does not cover flooded DIAG/TIME (T21). RESUME cannot be checked here (K_s2p) (T2). |
| 6 | Link learning after step 5. Learns from replayed frames too (T1). |
| 7 | Unicast local delivery; endpoint verifies auth_tag and replay window. OK for session frames; unicast pre-session frames have no freshness check (T10). |
| 9b | ORIGIN freshness for session_id 0 floods. 16-bit, RAM-only (T10). RESUME exempt (T2). Drops equal-seq copies before 9c (T21). |
| 9c-9e | Dedup, budget, route install after admission. Ordering correct; budgets are spendable by replays (T2) and by the free-retry rule (T14). |
| 10a | HELLO installs a forward route on hop_tag alone (relays cannot verify K_hs). Any K_mesh holder can install a forward route for any `src_id` (T6). |
| 10g | Forwarding refreshes route expiry; replayed unicast frames do this (T1). |

### P4 Replay protection across seq wrap, reboot and power loss

Verdict: holds for in-session frames at endpoints; does not hold at relays.

- Holds: 48-bit index (ROC << 16 | seq) in tag_input and CCM nonce (3.5,
  8.4), SRTP-style ROC estimate confirmed by the tag, 64-entry window, new
  K_s per session from fresh nonces. Closes S7.
- Holds: persistent pre-session counter `pl/preseq` with one NVS write per
  64 frames; resume-from-stored-value is monotone across power loss.
- Gap: relays have no freshness for unicast (T1) or RESUME (T2); the
  pre-session filter is 16-bit and volatile (T10); boot counter wear (T24).

### P5 Nonces and IVs never repeat under one key

Verdict: partially holds.

- Holds: CCM nonce = dir || src || dst || session_id || ROC || seq || 0x00
  (13 bytes) under a per-session, per-direction Ke; unique while the index
  is monotone. Handshake nonces mix esp_random() with persistent counters
  (4.1.15). Closes S9 in the common case.
- Gaps: leaf RTC state regression (T12); retransmission byte-identity not
  required (T18); key uniqueness depends on 32-bit truncated nonces (T17).

### P6 Key derivation uses standard constructions correctly

Verdict: holds.

- HKDF-SHA256 (RFC 5869) throughout; distinct salts per key class
  ("ProbeLink-mesh", "ProbeLink-pair"); fixed-width info fields, so no
  concatenation ambiguity; S/P order fixed in every label; directional MAC
  keys and separate encryption keys; session_id in K_s info; epoch in mesh
  and pair info. CCM nonce layout is 13 bytes as stated (L = 2), AAD equals
  the tag_input prefix. Style notes only (T22).

### P7 Downgrade resistance

Verdict: holds for AUTH and header version; not for ENC and other caps.

- Holds: FLAG_AUTH mandatory with step 4; `ver_flags` inside tag_input; KDF
  label "ProbeLink-v1"; MODE parameters under K_s2p (ROAST-1 "what holds"
  still valid).
- Gap: T11. Also `proto_minor` and `max_frame` are not in the transcript
  (same fix).

### P8 Forwarders with only K_mesh cannot alter end-to-end content or forge session control

Verdict: holds for integrity and session authority.

- End-to-end fields are under K_s (or CCM); HELLO, BIND inner_tag, BIND_ACK
  and BIND_NAK under K_hs; CLOSE and RESUME under directional K_s. A K_mesh
  holder cannot bind, close, or take over a session of another pair.
  Closes S8 for authority.
- Availability residuals: T16 (handshake cancellation), T7 (time).

### P9 Flood amplification and state exhaustion are bounded, authenticated-before-counted

Verdict: holds for outsider forgeries; not for replays or insiders.

- Holds: buckets, dedup and ORIGIN run after step 5 (11.5); PROBE_OFFERS_MAX
  bounds OFFERED; tables are statically sized (11.9).
- Gaps: T1, T2 (replays counted as authentic), T14 (budget bypass), T15
  (OFFERED denial), T6 (per-origin buckets keyed by spoofable src_id).

### P10 Key rotation, epoch change and revocation during operation without splitting the mesh

Verdict: does not hold.

- Mechanism: two stored epochs, KEY_UPDATE with ENC, activation TLV, DIAG
  epoch reporting (8.6).
- Gaps: T3 (split on activation), T4 (revocation lag), T5 (leaves), T7
  (time-driven activation).

### P11 Test keys cannot ship; fail-closed defaults

Verdict: partially holds.

- Holds: field profile is the default build; `pl_init` returns PL_ERR_AUTH
  without keys; no runtime switch to bench; no replies to unverified
  frames (R10).
- Gaps: T13 (blacklist coverage), T19 (bench image on field hardware), and
  T9 (no check of the at-rest state).

### P12 Appendix A vectors consistent with section 8

Verdict: holds.

- Ran `vectors_v04.py`: all asserts pass ("ALL OK"), and its output matches
  the A.6 and A.10 text byte for byte.
- HKDF spot-check, independent of the script (Python `cryptography` HKDF):
  K_mesh(1) = 15e0339c...720c31c3 and K_pair(0x0042, 0x1234, 1) =
  14270866...1bf31af5, equal to A.6. The script's PRK = Extract(salt =
  nonce_s || nonce_p, IKM = K_pair) matches the 8.2 formula.
- CCM spot-check: nonce 00 3412 4200 07 00000000 0500 00 follows the 8.5
  layout; AAD = e2e header || ROC follows 8.4/8.5; ciphertext 5943208c...
  and tag 7dbf982cb7033cec match A.10, and the script round-trips decrypt.
- Coverage gaps only (T23).

## Findings

### T1 CRITICAL - hop_tag has no freshness; recorded unicast frames are re-admitted at relays

- Property: P3, P4, P9. Section: 8.4 (hop_tag), 11.4 steps 5, 6, 10g; 11.8
  outsider row; 11.9 link table.
- Gap: hop_tag covers only frame bytes, and relays keep no per-session
  replay state, so a bit-identical recorded unicast frame passes step 5 and
  is forwarded, refreshes route expiry, refreshes or (after LINK_TTL_MS)
  rebinds the link entry for `prev_hop`, and can raise the collision alarm.
  This contradicts 11.8 ("outsider cannot enter any table, be forwarded,
  replay, or trigger a collision alarm") and R4/R5. The endpoint still
  rejects the frame, so integrity holds; table state and airtime do not.
- Fix: add per-hop freshness. Preferred: a per-transmitter hop counter
  (`hop_seq`, 2 bytes on the wire with an implicit 32-bit extension, kept
  per neighbour in the existing link table) inside the hop_tag input, with a
  small per-neighbour window; drop non-fresh frames at step 5 before step 6.
  Cheaper alternative: relays keep `(src_id, session_id) -> highest seq`
  for sessions they forward (route table already holds these pairs) and
  drop anything older than highest - REPLAY_WINDOW. Also bind the carrier
  source address into link learning only after a fresh frame.

### T2 CRITICAL - Replayed RESUME floods spend budgets and rewrite reverse routes

- Property: P9, P3. Section: 4.4, 11.4 steps 9b-9e, 11.5.
- Gap: RESUME is exempt from ORIGIN freshness, its auth_tag is under K_s2p
  so relays cannot verify it, and dedup lasts only DEDUP_TTL_MS (5 s). A
  recorded RESUME is therefore admitted again after 5 s, costs the leaf's
  per-origin tokens and installs a reverse route; only the probe rejects
  it. 11.8 states outsiders cannot consume any flood budget.
- Fix: give RESUME a relay-checkable freshness field: carry the origin's
  persistent pre-session counter (`pre_seq u32`) in the RESUME payload,
  covered by hop_tag and auth_tag, and apply step 9b to it like any
  session_id 0 flood. Charge the bucket only after 9b passes (already the
  order).

### T3 CRITICAL - Epoch activation splits the mesh

- Property: P10. Section: 8.6, 3.6 Tags row.
- Gap: receivers accept E (current) and E-1 (previous) only, and a node
  sends under its current epoch. Once any node activates E+1 (at `at_utc_s`,
  on "all acknowledged", or after the 86400 s fallback measured per node),
  its frames fail hop_tag at every neighbour still on E, so frames toward
  late nodes die at the last updated relay. 8.6's claim that a late node
  "receives the update when next reached" does not hold through updated
  relays.
- Fix: separate "accept" from "send". Phase 1: a node that stores E+1
  immediately accepts it on receive (accept set {E-1, E, E+1}). Phase 2:
  switch transmit to E+1 only after the key server confirms every reachable
  node holds it (explicit ACTIVATE command, not a local timer). Phase 3:
  retire E-1. Relays may also pick the outgoing hop key per neighbour from
  the epoch last seen from that neighbour.

### T4 HIGH - A revoked node keeps mesh access for an extra epoch

- Property: P1, P10. Section: 8.6, 11.8 row 3.
- Gap: "At activation E+1 becomes current and E-1 is erased" keeps E as
  the accepted previous epoch, so the revoked node's K_mesh(E) still passes
  hop_tag, SEEK/BIND outer, DIAG and TIME until E+2. 8.6 and 11.8 say E is
  erased at E+1 activation; the two statements conflict.
- Fix: mark revocation bumps; on such an activation erase E as soon as the
  key server confirms all non-revoked nodes hold E+1 (accept set becomes
  {E+1} only). State the residual window explicitly.

### T5 HIGH - Leaves cannot receive key updates

- Property: P10. Section: 4.4, 5 (KEY_UPDATE S -> P), 8.6, 11.1.
- Gap: the key server reaches nodes by SEEKing them by unit ID, but a leaf
  serves no group and is asleep between reports, and KEY_UPDATE exists only
  in the sender-to-probe direction. Leaves fall two epochs behind at the
  second rotation and need a cable.
- Fix: allow KEY_UPDATE / KEY_UPDATE_ACK in the p2s direction inside the
  leaf's own session (probe side pushes TLVs under K_p2s with CCM after
  RESUME_ACK), with the probe acting as relay for the key server.

### T6 HIGH - Mesh-layer identity rests on the shared K_mesh

- Property: P1. Section: 8.1 R2, 8.2, 11.4 (10a, 9b, 9d), 11.5, 11.8, 11.9.
- Gap: `src_id` and `prev_hop` in floods and the HELLO route-install path
  are authenticated only by K_mesh, which every node holds. A K_mesh holder
  can therefore act under another unit ID for route installation, advance
  that ID's ORIGIN `last_seq` (24 h lifetime), drain its per-origin bucket,
  and claim its link entry. R2 says a captured node must not allow
  impersonation of any other unit ID; this holds at the session layer only.
- Fix (short term): limit how far one flood may advance `last_seq` (for
  example 64 ahead of the stored value), shorten ORIGIN_TTL, refuse HELLO
  route install for a `src_id` that is the relay's own established
  neighbour on another address, and expose per-origin `relay_drop_stale` in
  DIAG. Fix (full): per-node signatures (Ed25519) on route-installing frames
  (SEEK, HELLO, BIND outer, RESUME), the 12.7 alternative. Until then,
  narrow R2's wording to the session layer.

### T7 HIGH - Time master identity is K_mesh-only and time drives key activation

- Property: P10, P8. Section: 6.5, 8.6 TLV 0x04, 11.8 row 2.
- Gap: the master allowlist is checked against `src_id`, which TIME_RESP
  authenticates only under K_mesh, and TIME_REQ `t1` is visible to any keyed
  neighbour. A K_mesh holder can therefore shift a node's UTC estimate,
  which changes when `at_utc_s` activation and UPDATE_WINDOW deadlines fire
  (feeding T3). 11.8 claims insiders cannot push time.
- Fix: authenticate TIME_RESP under the pairwise key between requester and
  master (an HMAC under a key derived from K_pair(node, master)), bound the
  per-sync step and slew, and never use network time alone for key
  activation (use the explicit command of T3).

### T8 HIGH - Key server holds every pairwise key of the next epoch

- Property: P1. Section: 8.2 ("K_site held by nobody in the field"), 8.6,
  11.1 (gateway is the key server).
- Gap: TLV 0x02 carries `K_pair(self, peer, E+1)` for every peer, so the key
  server must hold all pair keys of E+1 for the site; the spec does not say
  where they come from, whether the gateway stores them at rest, or when
  they are erased. A captured gateway then breaks R2 for every pair.
- Fix: specify that the offline tool produces per-target KEY_UPDATE bundles
  already encrypted to each target (for example under a key derived from
  K_pair(target, key server, E)), so the gateway relays opaque blobs and
  holds no other pair's plaintext key; bundles are erased after ACK. Put the
  key server on the gateway's LAN-side chip, not the mesh chip.

### T9 HIGH - Provisioning does not establish or verify the at-rest state

- Property: P2. Section: 8.1 R1, 12.1, 12.2, Appendix B `pl_init`.
- Gap: 12.2 builds NVS images with `nvs_partition_gen.py` but names no
  step that burns Secure Boot v2 / flash encryption / JTAG / download-mode
  eFuses, generates the image encrypted, or provisions the NVS key
  (`nvs_keys` partition on chips without HMAC, eFuse HMAC key via
  `nvs_sec_provider` on C3/C6/S3). `pl_init` checks only key presence.
- Fix: (1) a normative provisioning sequence: burn and verify eFuses,
  enable release-mode flash encryption, generate the NVS image encrypted
  with a per-device key, then write keys; (2) in the field profile `pl_init`
  returns PL_ERR_AUTH unless `esp_secure_boot_enabled()`,
  `esp_get_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE`, and the key
  partition is encrypted; (3) DIAG reports these three bits.

### T10 HIGH - Pre-session freshness is 16-bit and volatile

- Property: P4. Section: 3.5, 8.4, 11.5, 11.8 "SEEK amplification".
- Gap: the wire carries the low 16 bits of the 32-bit pre-session counter
  and ROC is 0 in its tag input, so a recorded flood becomes "newer" again
  after 32768 of the origin's pre-session frames (DIAG/TIME traffic makes
  this days, not years); the ORIGIN table is RAM-only, so a relay reboot or
  an evicted or 24 h old entry accepts any recorded flood. 11.8's "after 24 h,
  by dedup" does not hold (dedup is 5 s). Unicast pre-session frames
  (DIAG_REQ) have no freshness check at the endpoint.
- Fix: put the full 32-bit pre-session counter into tag_input (as ROC =
  upper 16 bits, estimated like 3.5, or carried in the SEEK/BIND/DIAG
  payload); persist a coarse ORIGIN high-water mark per origin (one NVS
  write per origin per 64 floods, or rely on the T1 hop counter); apply the
  same per-origin check at endpoints for unicast DIAG/TIME requests.

### T11 HIGH - Capability negotiation (ENC) is not bound to the handshake

- Property: P7. Section: 4.1.1-4.1.5, 5 (caps intersection), 8.5.
- Gap: the probe learns the sender's caps only from SEEK, which is under
  K_mesh; BIND carries no caps, MODE has no ENC bit, and the header flag bit
  3 is reserved, so the two ends can hold different views of whether ENC is
  on. Whether HELLO's `caps` is the probe's own value or the intersection is
  not specified, so the result is either a confidentiality downgrade by a
  K_mesh holder or a silent session failure.
- Fix: transcript binding. HELLO echoes the received `caps_s` and
  `max_frame_s`; the BIND inner_tag and the PRK salt (or K_s info) cover
  `caps_s || caps_p || max_frame || key_epoch || proto_minor`; each end
  rejects a mismatch. Optionally let a site policy require ENC (manifest
  flag) so a missing ENC bit is refused, not negotiated.

### T12 HIGH - Leaf RTC state can regress and reuse CCM nonces

- Property: P5. Section: 4.4 (RTC_DATA_ATTR state), 8.5, App. B `pl_park` /
  `pl_resume`.
- Gap: ROC/seq are exported to RTC memory at `pl_park`, but RTC slow memory
  survives watchdog and software resets. A reset between resume and the next
  park leaves an older seq in RTC; resuming from it reuses (Ke_s2p, nonce)
  pairs with new plaintext. The probe drops the frames, but the reuse has
  already happened on the air.
- Fix: reserve ahead, as for `pl/preseq`: write `seq + 64` to RTC before
  transmitting and resume from the reserved value; discard the RTC blob
  unless `esp_reset_reason() == ESP_RST_DEEPSLEEP`; protect the blob with a
  CRC32 and fall back to a full handshake on mismatch.

### T13 HIGH - Test-key blacklist is incomplete

- Property: P11. Section: 8.1 R9, 12.1 Test keys row, App. A.6.
- Gap: the blacklist compares SHA-256 of K_site or K_mesh, but field nodes
  never hold K_site, the A.6 K_mesh covers only epoch 1, and test-derived
  K_pair values are not listed. A site provisioned from the test K_site at
  any other epoch, or after its first rotation, passes.
- Fix: the provisioning tool refuses the Appendix A K_site (it is the only
  place K_site exists); the firmware blacklist holds truncated hashes of
  K_mesh(E) for all 256 epochs of the test K_site (about 2 KB at 8 bytes
  each) and rejects all-zero / repeated-byte keys; optionally the tool signs
  each device's key bundle with a site provisioning key whose public half is
  in the signed field image.

### T14 MEDIUM - Free BIND retries bypass the flood budget

- Property: P9. Section: 11.5 Flood budget.
- Gap: a BIND matching `(src_id, nonce_s)` of a BIND forwarded in the last
  2 s is free; both values are chosen by the originator, so a K_mesh holder
  can send unbudgeted BIND floods, contradicting 11.8 ("budgets cap any
  origin at 2 floods per second").
- Fix: allow at most BIND_RETRIES free retries per `(src_id, nonce_s)`,
  then charge tokens; count free retries against the per-node total bucket.

### T15 MEDIUM - OFFERED exhaustion denies binding

- Property: P9. Section: 4.1.2 (PROBE_OFFERS_MAX 4, ignore further SEEKs).
- Gap: four SEEKs with fresh nonces fill a probe's OFFERED set and it then
  ignores genuine SEEKs; a K_mesh holder can sustain this within the per-node
  bucket (replays via T10 also count).
- Fix: at most one OFFERED entry per `src_id`; when full, replace the oldest
  entry instead of ignoring the new SEEK; prefer senders the probe holds a
  K_pair for (8.2 already requires a pair key before answering).

### T16 MEDIUM - BIND outer tag cancels losing offers

- Property: P8 (availability). Section: 4.1.5.
- Gap: probes other than the named one return to LISTENING on the K_mesh
  outer tag alone, so any K_mesh holder can cancel every pending offer for a
  nonce_s it has seen. Authority is not affected; repeated use delays
  handshakes indefinitely.
- Fix: losing probes keep OFFERED until BIND_TIMEOUT (it already bounds the
  cost), or release early only when the BIND names a probe they know is in
  the same group; count releases per origin in DIAG.

### T17 MEDIUM - Session key uniqueness is probabilistic

- Property: P5, P6. Section: 4.1.11, 4.1.15, 8.2.
- Gap: nonces are 32-bit truncations of a hash, so "never repeat" is a
  probability statement; if `(nonce_s, nonce_p, session_id)` recurs for a
  pair within an epoch, K_s and Ke repeat and the CCM index restarts at 0.
- Fix: add the sender's and probe's persistent pre-session counters (the
  seq of BIND and HELLO, full 32 bits) to the K_s / Ke info, which makes
  uniqueness deterministic; keep the random part for unpredictability.

### T18 MEDIUM - Retransmissions under ENC must be byte-identical

- Property: P5. Section: 3.5 (retransmits keep seq), 7, 8.5.
- Gap: CCM with a reused nonce is safe only if the plaintext is identical;
  the spec does not forbid re-building a retransmitted frame with changed
  fields (status bits, timestamps).
- Fix: state that a retransmission is the stored ciphertext and tag sent
  again, never re-encrypted; ARQ buffers hold the encoded frame.

### T19 MEDIUM - Bench image can run on field hardware

- Property: P11. Section: 12.1 Build flag row, 12.6.
- Gap: the profile is a compile-time flag; if a bench build is signed with
  the production Secure Boot key it boots on field devices with
  authentication optional.
- Fix: separate signing keys for bench and field images; a bench image
  refuses to start when `esp_secure_boot_enabled()` reports production
  fuses, and a field image refuses to start without them.

### T20 MEDIUM - R1 depends on chip revision and does not cover fault injection

- Property: P2. Section: 8.1 R1, 12.1.
- Gap: Secure Boot v2 on the original ESP32 needs chip revision v3.0 or
  later, and published fault-injection research on ESP32-family parts shows
  a lab attacker with the board can defeat at-rest protection on some
  revisions. R1's "MUST NOT yield usable key material" cannot be guaranteed
  absolutely.
- Fix: list supported chip revisions in 12.1 and have the provisioning tool
  reject older ones; restate R1 as raising cost, and name revocation
  (8.6, with T3/T4 fixed) as the control that bounds a captured node.

### T21 LOW - Pipeline ordering details

- Property: P3. Section: 11.4 steps 5b, 9b, 9c.
- Gap: 9b drops a copy whose seq equals `last_seq` (not newer), and 9e sets
  `last_seq` on the first copy, so later lower-cost copies never reach the
  9c route improvement; route quality, not security. Step 5b names SEEK and
  BIND only, though flooded DIAG/TIME are also K_mesh-tagged.
- Fix: in 9b treat equal seq as "duplicate, go to 9c" and drop only older;
  extend 5b to every flood whose auth_tag is under K_mesh.

### T22 LOW - KDF style

- Property: P6. Section: 8.2, 5 (BIND inner_tag).
- Gap: labels sit in the HKDF salt and the handshake nonces are the Extract
  salt; this is valid HKDF use and gives correct domain separation, but is
  unusual and harder to review. The inner_tag input has no label (length
  differs from every K_hs tag_input, so no collision today).
- Fix: optional: PRK = Extract(salt = "ProbeLink-v1", IKM = K_pair) and put
  nonces plus the T11 transcript in Expand info; prefix the inner_tag input
  with "ProbeLink-v1 bind".

### T23 LOW - Test vector coverage

- Property: P12. Section: Appendix A.
- Gap: no vector exercises ROC != 0 in tag_input, the 5-byte e2e header
  with FLAG_LEN16, hop_tag acceptance under E-1, RESUME, or KEY_UPDATE with
  CCM. The script's `e2e()` helper assumes a 1-byte `len`.
- Fix: add those five vectors; make `e2e()` honour FLAG_LEN16.

### T24 LOW - Boot counter wear in a crash loop

- Property: P4. Section: 4.1.15, Appendix B (NVS writes).
- Gap: `pl/boot_count` is written once per boot; a node in a fast crash
  loop writes NVS on every boot with no bound.
- Fix: reserve boot counts in blocks like `pl/preseq`, or derive the
  boot-unique input from `pl/preseq` alone (already persistent and
  monotone).

## Result

Counts: CRITICAL 3, HIGH 10, MEDIUM 7, LOW 4

Properties that hold: P6 (key derivation), P8 (integrity and session
authority against K_mesh holders), P12 (vectors consistent; HKDF and CCM
spot-checked independently). Partially: P1, P5, P7 (AUTH and version hold),
P9 (outsider forgeries), P11. Not as stated: P2 (unspecified flow), P3 and
P4 at relays (replays), P10.

Verdict: v0.4 is a large step from v0.3. Per-pair keys close S1 for session
keys, the 48-bit index closes S7, session authority is out of the mesh key,
and the forwarding pipeline now authenticates before it counts, which
closes ROAST-1's outsider forgery findings. What remains comes from three
gaps. First, the hop layer authenticates bytes but not freshness, so
recorded frames still move relay state (T1, T2, T10). Second, every
mesh-layer identity, including the time master, rests on one shared key
(T6, T7). Third, the epoch lifecycle as written splits the mesh on
activation, keeps a revoked node's mesh key alive for a full extra epoch,
and cannot reach leaves (T3, T4, T5). T3, T4, T9 and T12 are text fixes;
T5 and T11 change payloads (a KEY_UPDATE direction, HELLO echo fields, a
wider inner_tag input) but not the header; T1/T2 add a hop field and a
RESUME field. T6/T7 need either the per-node signatures of 12.7
or a narrower R2. Fix the three CRITICAL items before any field pilot; the
HIGH items should be closed before the first key rotation in the field.
