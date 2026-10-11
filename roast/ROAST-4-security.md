# ROAST-4 (security): ProbeLink v0.6 requirements audit

Spec: `PROTOCOL.md` (DRAFT v0.6, wire version 1, minor 0). Baseline:
ROAST-3-security (properties P1-P12, gaps U1-U19) and the Appendix D round-3
disposition. Scope: sections 2, 3.5, 3.6, 5, 6.4, 8, 11.4, 11.5, 11.8-11.11,
12.1, 12.2, 12.7, 12.10, Appendix A and D.

Format: requirements audit, not attack walkthroughs. Each property states
holds / partial / fails with its mechanism and section; each gap gets a short
description and a defensive fix. No exploitation procedures.

Field profile for task 3 and the hardware audit: months-long unattended
deployment of 5-50 nodes, every node including the gateway physically
reachable, target modules ESP32-WROOM (original ESP32, Xtensa dual-core).

Severity (as ROAST-3): CRITICAL = contradicts an explicit property statement
of the spec in the field profile. HIGH = holds only partially, or depends on
a step the spec does not specify, or a condition the spec's own stated
limitations rely on is not robustly met. MEDIUM = bounded impact, insider- or
lab-only, or defence in depth. LOW = hygiene, tiering or attestation detail.

New gap IDs are V1..V7.

## Summary

| ID | Sev | Property | Title | Section |
|---|---|---|---|---|
| V1 | HIGH | P1, P2 | Capture detection is entirely self-reported by the node it is meant to catch, so the "capture is noticed" condition the mesh-identity and grace-period limitations depend on is not robustly met | 8.7, 11.8, 12.10 |
| V2 | MEDIUM | P2 | ESP32-WROOM is the weakest at-rest tier (no HMAC key root; NVS confidentiality reduces to flash-encryption strength) and the field profile does not restrict the manager/gateway/sink role to an HMAC-capable variant | 12.1, 12.2, 8.5 |
| V3 | MEDIUM | P9, P10 | The retired epoch slot admits MGMT_REQ at the hop layer for KEY_RECOVERY_S, extending the K_mesh-holder flood/reverse-route nuisance to old or revoked key holders for up to 30 days | 8.5, 11.4, 11.5 |
| V4 | LOW | P1, P10 | IR edge pair key is never rotated; compromise of a leaf or its attached node persists until a cable rekey | 8.2, 11.11, 12.6 |
| V5 | LOW | P11 | Secure Boot v2 anti-rollback uses a bounded secure-version eFuse count on the original ESP32; lifetime security-version budget is unstated | 8.7, 12.7 |
| V6 | LOW | P2 | `pl_init` and section-0 bit0 do not distinguish Secure Boot v2 from the weak v1 on the original ESP32 | 11.10, 12.1 |
| V7 | LOW | P5 | Clear `pre_ctr` prefix exposes each node's `preseq` to passive observers | 3.5, 8.3 |

## 1. Round-3 CRITICAL/HIGH resolution (U1-U7) and regression check

All seven confirmed resolved in the spec text and the Appendix A vectors; no
regressions found. `python3 tools/vectors.py` prints `ALL OK`, cross-checking
RS with `reedsolo` and AES-CCM with the `cryptography` library, and A.2-A.14
match the document byte for byte including the new A.9/A.12 frames carrying
`pre_ctr >= 0x10000` and the A.14 bundle.

| ID | Claim (App. D) | Verified | Mechanism and note |
|---|---|---|---|
| U1 | fixed (= H3) | yes | 8.2 adds `K_node(N)` and `Kb(N)`, tool-only, never given to a manager; 8.6 bundles are AES-CCM under `Kb(N)` with `bundle_no` monotonic in NVS, AAD `"PLB1" \|\| N \|\| bundle_no`; managers relay opaque chunks and may author only TLV 0x04 and time; a node applies key TLVs only inside a verified bundle. A.14 round-trips. A captured gateway can no longer read or author any node's key material. R2 and R8 restated to match. |
| U2 | fixed | yes | Header carries the full 32-bit `txseq` as `hop_seq` (19-byte header, 22 in SEEK); the hop_tag covers it; receiver keeps the last 32-bit value per (unit_id, transport) with `HOP_MAX_JUMP` 2^16; no reconstruction, no wrap inside the 2.7-year counter life. 3.4, 3.5, 8.4, A.8 confirm. Freshness now survives any counter value. |
| U3 | fixed (= H2) | yes | 8.3 carries `pre_ctr` as a clear 4-byte AAD prefix on every session_id 0 frame and RESUME; `ctr_hi` is read from it with no stored state; relays read the 32-bit `pre_ctr` of a flooded MGMT_REQ for dedup/ORIGIN/budget. A.9 (HELLO) and A.12 (MGMT) verify with no estimation rule needed. |
| U4 | fixed | yes | 8.4 and 11.10 make MGMT a challenge-response: a node keeps one outstanding request and accepts MGMT_RESP only if the encrypted `req_ctr` echoes it; commands 1 and 2 are rate-limited to once per 10 minutes. After a reboot there is no outstanding request, so a recorded response matches nothing. A.12 carries the echo. |
| U5 | fixed (= H1) | yes | 8.5 defines `E_old`, `E_new` and the retired slot; everything transmits under `E_old`; `E_new` is installed from a bundle; retirement is only an explicit TLV 0x06, never a timer; erase rules are expressed relative to `E_old`; stragglers recover through the retired slot for MGMT_REQ. Convergence argument is sound for a single-operator tool. |
| U6 | fixed | yes | Recovery holders are IDs 0x0003..0x000F (section 2), each with its own pair key and `K_mgmt` per device (6.4, 8.2); their keys arrive and leave as bundle TLVs 0x02/0x03, so they are rotatable and revocable. Distinct `src_id` per holder keeps their MGMT nonce spaces disjoint under one node's key. |
| U7 | fixed | yes | 6.4 and 12.1: a field node with no keys enters only the UART provisioning wait; BLE requires a stored recovery-holder key; field builds never auto-erase NVS and log and report the no-key state (section-0 bit4). `pl_init` returns `PL_ERR_AUTH` unless secure boot, flash-encryption release mode and an encrypted key partition are present. |

Regression scan of the v0.6 mechanisms: the clear `pre_ctr` prefix is covered
by the CCM tag (a tampered value only fails the tag, no oracle, R10); the
32-bit `hop_seq` cannot be legitimately out-jumped inside `LINK_TTL_MS`
(2^16 frames exceed what a live link entry can miss in 60 s); `req_ctr`
matching drops in-flight responses after a reboot harmlessly; the bundle
nonce (leading 0x02) is disjoint from frame nonces (leading dir 0/1) and
`Kb(N)` is an independent key regardless. The only new mechanism that widens
an attack surface is the retired slot (V3).

## 2. Property audit (P1-P12) against v0.6

### P1 Compromise of one node does not expose other pairs' keys; revocable
Verdict: holds, with the V1 condition.
- With U1 fixed, a captured node (gateway included) yields only its own
  `K_mesh`, `K_node` and its own pair keys (8.2); it cannot derive another
  `K_pair` or `K_node`, hence cannot read or author another pair's session,
  management or bundle keys. Revocation deletes pair keys at once and the
  revocation epoch is strictly above everything the node held (8.5, U8).
- Residual: the model's recovery control is revocation, which the spec says
  is triggered when capture is noticed; V1 shows that noticing is
  self-reported. Mesh-identity residual is the stated limitation (11.8).

### P2 Keys at rest are protected
Verdict: holds as specified (a cost, not a guarantee), weakest on the WROOM.
- 12.1/12.2 give the full at-rest sequence and `pl_init` enforces it:
  Secure Boot v2 with the secure-version eFuse, flash encryption in release
  mode, NVS encryption, JTAG and UART-download disabled by eFuse, chip
  revision checked and unsupported parts refused, separate bench/field
  signing keys, test-key blacklist.
- ESP32-WROOM audit (new hardware fact):
  - Secure Boot v2 (RSA-3072) exists on the original ESP32 only at silicon
    revision v3.0 (ECO3) and later; earlier revisions have only the weaker
    AES-based Secure Boot v1. The field profile already requires rev 3.0+
    (12.1) and the provisioning station refuses unsupported revisions (12.2).
    This is the correct and necessary variant floor. Confirm it: the field
    profile MUST require ESP32-WROOM at silicon revision v3.0 (ECO3) or later;
    rev v0/v1/v2 parts MUST be refused.
  - Flash encryption on the original ESP32 (AES-256, key in eFuse BLOCK1)
    offers development and release modes; the field profile requires release
    mode, which disables UART-download decryption and key readback. Correct.
  - NVS encryption: the original ESP32 has no HMAC peripheral, so the
    HMAC-eFuse NVS-key scheme used on -S3/-C3/-C6 is unavailable; it must use
    the flash-encryption-based scheme with a flash-encrypted `nvs_keys`
    partition (12.1 states this, U15). Consequence: on the WROOM, NVS
    confidentiality has no key root independent of flash encryption -- if
    flash encryption is defeated, the NVS keys fall with it. On the
    HMAC-capable parts the NVS key can be read-protected in an eFuse block of
    its own. The WROOM is therefore the weakest at-rest tier (V2).
  - Published fault-injection work against ESP32 flash encryption and secure
    boot shows the at-rest guarantee is not absolute even at rev 3.0. The
    spec acknowledges this and names revocation as the bounding control. For
    a months-long deployment of physically reachable nodes, a stolen or
    briefly-borrowed WROOM must be assumed lab-extractable within the
    deployment lifetime. What a successful lab attacker extracts from one
    WROOM: that node's `K_mesh` (mesh-layer identity, revocable), its own
    pair keys (its own sessions, revocable) and `K_node(N)` (which only
    authenticates bundles destined to the node already held). No cross-node
    key is exposed; R2 holds. The blast radius is largest for the
    gateway/manager/sink, which holds the directional session keys of every
    current sink session (V2).
- Verdict holds; the conditions are V1, V2 and V6.

### P3 Every state-changing frame is authenticated and fresh before the change
Verdict: holds.
- Step 5 admits on hop_tag under a held `K_hop` epoch (retired slot for
  MGMT_REQ only) plus a strictly-newer 32-bit `hop_seq` within `HOP_MAX_JUMP`
  (U2); step 7 applies the CCM tag with `ctr_hi` from the clear `pre_ctr` or
  the ROC estimate (U3); pre-session freshness is request/response matching
  that survives reboots (U4). Nothing after step 5 touches a table for an
  unadmitted frame (11.4).

### P4 Replay protection across seq wrap, reboot and power loss
Verdict: holds.
- Session layer: 48-bit index in the CCM nonce and AAD, SRTP-style ROC
  confirmed by the tag, 64-entry window (3.5, 8.4, A.10). Relays and
  pre-session: 32-bit persistent `pre_ctr`, ORIGIN with TTL and jump bound.
  Hop layer: 32-bit `hop_seq` on the wire (U2). Counters resume from
  max(RTC, NVS) reserve-ahead, so no reset reuses a nonce (U11). The one
  recorded unicast frame re-admitted after `LINK_TTL_MS` is stated, bounded
  and cannot change an existing route (8.4).

### P5 Nonces never repeat under one key
Verdict: holds, including across the live/retired epoch slots and bundles.
- Layout: 13-byte nonce `dir || src || dst || session_id || ctr_hi || seq ||
  0x00`, directional keys, per-session keys bound to `session_id` and the
  transcript. Checked for the cases the task names:
  - Epoch E appears only in the key derivation (`K_mesh(E)`, `K_pair(...,E)`,
    `K_mgmt` via `K_pair(N,M,E)`), never in the nonce, so the same (ctr_hi,
    seq) under two epochs is two different keys. `preseq` and `txseq` are
    per-node monotonic in NVS and never rewind on rotation or reboot, so the
    retired-slot key `K_mgmt(N,M,E_retired)` used for recovery MGMT_REQ
    continues the node's monotonic `pre_ctr`; no value repeats under it.
  - `Ke_mesh(E)` is shared across nodes but the nonce carries `src_id` and
    `dst_id`, and each originator's `preseq` is monotonic, so two SEEKs never
    share a nonce.
  - A manager's single `preseq` feeds all its MGMT_RESP nonces, but
    `K_mgmt(N,M,E)` differs per node N, so there is no cross-node reuse; per
    node the value is monotonic.
  - Bundle nonce `0x02 || N || bundle_no || zeros` under `Kb(N)` varies only
    in the monotonic `bundle_no`; disjoint from frame nonces by the leading
    byte and keyed independently.
- U6 removes the shared-recovery-identity collision (separate `src_id`).

### P6 Key derivation uses standard constructions correctly
Verdict: holds, including the new derivations the task names.
- HKDF-SHA256 throughout. Domain separation checked:
  - `K_mesh`, `K_pair`, `K_node` each Extract from `K_site` with a distinct
    salt (`"ProbeLink-mesh"`, `"ProbeLink-pair"`, `"ProbeLink-node"`), giving
    independent PRKs.
  - `K_hop(E)` and `Ke_mesh(E)` both Extract from `K_mesh(E)` with salt
    `"ProbeLink-v1"` then Expand with distinct, non-prefix info (`"hop"` vs
    `"mesh-enc"`); the Expand counter byte keeps the full info strings
    distinct.
  - `Kb(N)` Expands from `Extract("ProbeLink-v1", K_node(N))` with label
    `"bundle"`, independent of every frame key.
  - Session and management Expand labels (`"hello"`, `"hs"`, `"s2p"`,
    `"p2s"`, `"mgmt"`) are prefix-distinct, each followed by fixed-width
    fields. No two info strings coincide.
- Transcript `T` binds both nonces, both `pre_ctr`, caps, `max_frame`,
  `key_epoch`, `proto_minor` into every handshake key (8.2); persistent
  `pre_ctr` makes uniqueness deterministic (U14 closed).

### P7 Downgrade resistance
Verdict: holds. CCM is the only end-to-end construction; caps and
`proto_minor` are in the transcript; `ver_flags` is in the AAD; AUTH is
mandatory in the field profile (8.3, section 5). Unchanged from v0.5.

### P8 Forwarders with only K_mesh cannot alter end-to-end content or forge control
Verdict: holds. Session frames under directional keys, MGMT under `K_mgmt`,
bundles under `Kb(N)`; a manager authors only commands and time (U1); a
K_mesh holder is confined to the mesh-layer effects listed in 11.8. U4
removes the stale-response residual.

### P9 Flood amplification and state exhaustion are bounded, authenticated before counted
Verdict: holds for outsiders; the insider bound is the stated limitation,
now with the V3 retired-slot tail.
- Budgets run after freshness (11.5); dedup and ORIGIN use the full 32-bit
  `pre_ctr` for every flood type including MGMT_REQ (U3); `HOP_MAX_JUMP` caps
  hop-seq jumps (U9); maintenance mode has an exit timeout (U10).
- V3: the retired slot admits MGMT_REQ under a retired `K_hop` for
  `KEY_RECOVERY_S`, so an old or revoked K_mesh holder can flood MGMT_REQ and
  install reverse routes at the mesh layer for up to 30 days, bounded by the
  flood budget and ended at the manager (no pair key). Within the stated
  mesh-identity limitation but widened in time by the new slot.

### P10 Rotation, epoch change and revocation without splitting the mesh
Verdict: holds. `E_old`/`E_new`/retired defined, transmit under `E_old`,
explicit RETIRE, retired-slot recovery for stragglers, bundles opaque to
managers, revocation epoch strictly above everything the revoked node held
(U5, U1, U8). Residuals: the rollout window (floods from un-RETIREd nodes
dropped at RETIREd nodes until the failure-triggered MGMT pull, stated in
12.10) and V3/V4.

### P11 Test keys cannot ship; fail-closed defaults
Verdict: holds. Field node without keys waits for UART only; BLE needs a
stored holder key; no automatic NVS erase (U7). Tool refuses the Appendix A
`K_site`; firmware rejects degenerate keys and the 256-epoch test `K_mesh`
hashes (12.1). Anti-rollback via the secure-version eFuse and the `fw_build`
gate (U12); see V5 for the eFuse count budget on the original ESP32.

### P12 Appendix A vectors consistent with section 8
Verdict: holds. `tools/vectors.py` prints `ALL OK`; RS is cross-checked with
`reedsolo`, AES-CCM with the `cryptography` library, HKDF/HMAC with the
Python standard library, and the printed frames, nonces, AADs, tags, hop_tags
and CRCs match A.1-A.14 byte for byte. A.12 now carries MGMT_RESP with the
`req_ctr` echo and A.14 a key bundle (U19 closed). ROC estimation cases
(A.10) and the second-cycle frame verify.

## 3. Judgement of the 12.10 security limitations

| Limitation | Judgement | Reason |
|---|---|---|
| Mesh-layer identity rests on `K_mesh` until per-node signatures (11.8) | Acceptable with condition | Session and management stay pair-keyed; a K_mesh holder is confined to availability and routing effects, revocation-bounded. Condition is that capture is noticed -- which V1 shows is not robustly met by self-reported detection. The per-node signature path (12.8) is the full fix. |
| One recorded unicast frame re-admitted at a relay after `LINK_TTL_MS` (8.4) | Acceptable | One frame per expired entry, rejected at the endpoint, cannot change an existing next_hop, undone by the neighbour's next frame. With U2 in place the re-admission is bounded to expired entries only. |
| Epoch pacing and 24 h revocation cap are tool rules (8.5) | Acceptable | The tool is the sole bundle issuer and sees every node's reported epoch; sufficient for a single-operator site. |
| Revoked node keeps mesh-layer access until the old epoch is retired (8.5) | Acceptable with condition | Pair keys deleted at once, so the window is mesh-layer only and budget-bounded; conditions U8 (epoch ordering) and V1 (detection). V3 notes the retired-slot tail. |
| Retirement rollout drops floods from un-RETIREd nodes at RETIREd nodes until the MGMT pull (12.10) | Acceptable | Transient availability only; self-healing through the failure-triggered MGMT_REQ (4.1.8). |
| Node absent beyond `KEY_RECOVERY_S` or two retirements needs the UART station | Acceptable | Deployment reality; 30 days of uptime is generous for a 5-50 node site. |
| IR leaves rekeyed and updated by cable only; edge pair key never retired (12.6) | Acceptable, deliberate (V4) | The IR link is one hop, contained, indoor; the non-rotating edge key means a compromised leaf or attached node persists until a cable rekey, but the exposure does not leave that pair. Rated LOW. |
| R1 is a cost, not a guarantee, on some silicon (12.1) | Acceptable for ordinary revocable nodes; must-fix-as-condition for the manager/gateway/sink on the WROOM (V2) | An ordinary node's extraction yields revocable keys; the gateway concentrates every current sink session key and `K_mesh` on possibly the weakest at-rest silicon, physically reachable, with self-reported capture detection (V1). |
| No TRACE frame; FEC/ARQ not auto-tuned; nRF24 same-low-byte interleave | Out of scope / availability only | Not confidentiality or integrity properties. |

## 4. Findings

### V1 HIGH - Capture detection is self-reported by the node it is meant to catch
- Property: P1, P2. Section: 8.7, 11.8, 12.10.
- Gap: the mesh-identity limitation (11.8) and the grace-period and
  R1-is-a-cost limitations (8.5, 12.1) are all declared acceptable on the
  stated condition that a capture is noticed and the node revoked. The only
  detection the spec defines (8.7) fires on missed MGMT reports, a changed
  `reset_reason` pattern, a changed secure-state bit or an epoch regression
  -- every one of which is a value the node itself reports and that an
  attacker who has extracted keys and returned a running node can suppress or
  keep consistent. The detection therefore gives no assurance against the one
  attack (silent key extraction) the limitations are conditioned on.
- Fix (defensive): add detection the returned node cannot forge. Track each
  node's report cadence and key-epoch and counter continuity at the gateway,
  where the record is outside the node's control, and alarm on a gap the node
  cannot reset; require high-value nodes to answer a periodic manager
  challenge with fresh device entropy; add physical tamper-evidence to the
  gateway and manager; where silicon allows, root attestation in the HMAC
  peripheral rather than in self-reported bits.

### V2 MEDIUM - ESP32-WROOM is the weakest at-rest tier and the manager role is not restricted to it
See title list. Fix: require the gateway/manager/sink (and any node holding
broad session-key exposure) to be an HMAC-capable variant (ESP32-S3, -C3 or
-C6) or to carry physical tamper protection; admit the original ESP32-WROOM
only at silicon revision v3.0 (ECO3) or later with flash-encryption release
mode, a flash-encrypted `nvs_keys` partition, Secure Boot v2, and JTAG plus
UART-download disabled by eFuse; state the role-to-silicon mapping in 12.1.

### MEDIUM (title list)
- V2 - ESP32-WROOM weakest at-rest tier; manager/gateway/sink role not
  restricted to an HMAC-capable variant.
- V3 - Retired epoch slot admits MGMT_REQ at the hop layer for
  `KEY_RECOVERY_S`, extending the K_mesh-holder flood and reverse-route
  nuisance to old or revoked key holders for up to 30 days (budget-bounded).

### LOW (title list)
- V4 - IR edge pair key is never rotated; compromise persists until a cable
  rekey.
- V5 - Secure Boot v2 anti-rollback uses a bounded secure-version eFuse count
  on the original ESP32; the lifetime security-version budget is unstated.
- V6 - `pl_init` and section-0 bit0 do not assert Secure Boot v2 specifically
  on the original ESP32, so a v1 (weak) secure boot would self-report as
  present.
- V7 - Clear `pre_ctr` prefix exposes each node's `preseq` to passive
  observers (within the already-stated enumeration-visible model).

## Result

Counts: CRITICAL 0, HIGH 1, MEDIUM 2, LOW 4.

Properties that hold: all twelve. P3, P4, P6, P7, P8 and P12 hold outright.
P1, P2, P5, P9, P10 and P11 hold subject to the conditions below.

Verdict: READY WITH CONDITIONS.

Conditions:
1. Close V1: add capture detection that a returned, key-extracted node cannot
   forge (gateway-side report-gap and counter/epoch continuity tracking the
   node cannot reset; a periodic manager challenge answered with fresh device
   entropy; physical tamper-evidence on the gateway and managers). The
   mesh-identity, grace-period and R1-is-a-cost limitations are only
   acceptable once capture is actually detectable.
2. Close V2: require the gateway, manager and sink (and any node with broad
   session-key exposure) to be an HMAC-capable variant (ESP32-S3/-C3/-C6) or
   physically tamper-protected; admit the ESP32-WROOM only at silicon
   revision v3.0 (ECO3) or later with release-mode flash encryption, a
   flash-encrypted `nvs_keys` partition, Secure Boot v2, and JTAG and
   UART-download disabled by eFuse; document the role-to-silicon mapping.
3. Keep the retired-slot window (V3) tight: bound `KEY_RECOVERY_S` to the
   real straggler-return need and keep the revocation and RETIRE pacing cap
   short so the mesh-layer tail for old or revoked K_hop holders stays small.
4. Assert Secure Boot v2 specifically at runtime on the original ESP32 (V6)
   and budget the anti-rollback secure-version increments over the device
   lifetime (V5).

v0.6 resolves all of round 3. The two v0.5 criticals are genuinely closed:
key bundles are now encrypted to a tool-only `K_node` that no manager holds
(U1), and hop freshness rides the full 32-bit `txseq` on the wire (U2). The
clear `pre_ctr` prefix, request-bound MGMT_RESP, separate recovery identities,
fail-closed unprovisioned state, defined epoch transmit/retire rules, and the
K_node / K_hop derivations all check out, and nonce uniqueness holds across
the live and retired epoch slots. What remains is not a protocol defect but
the at-rest and detection reality of running a symmetric-key mesh on
physically reachable ESP32-WROOM modules: revocation is the control, and
revocation needs a capture signal the captured node cannot author.
