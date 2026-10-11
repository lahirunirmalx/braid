# ROAST-1 (security): ProbeLink v0.3

Reviewer: hostile security review. Spec: `PROTOCOL.md` (DRAFT v0.3, wire version 1).
Focus: section 4 (handshake), 8 (security), 11 (mesh), appendices A/B.

Deployment assumed: 5-50 ESP32 nodes, unattended for months, physically
reachable by strangers. Carriers: ESP-NOW, BLE, WiFi UDP, IR, UART. Mesh is
mandatory; every fix below keeps forwarding and says how to secure it.

Attackers:

- (a) Outsider in radio range (SDR or a spare ESP32), no keys. On WiFi UDP
  this also means anyone on the same LAN/VLAN.
- (b) Thief who takes one node and dumps its flash. The spec does not mandate
  flash encryption, so assume plaintext.
- (c) Malicious or buggy relay inside the mesh.

## Summary

| ID | Sev | Title | Section |
|---|---|---|---|
| S1 | CRITICAL | One stolen node yields K_net: every session key is derivable and every unit ID can be impersonated | 8, 11.1, 11.8 |
| S2 | CRITICAL | Keys and firmware are unprotected at rest: plaintext NVS, flash encryption and secure boot only "ideally" | 8, App. B |
| S3 | CRITICAL | A replayed SEEK kills any live session (the reboot rule trusts a SEEK that has no freshness) | 4.1.3, 8, 11.8 |
| S4 | CRITICAL | An outsider can write routes: a forged HELLO installs forward routes and a raced SEEK copy installs reverse routes | 11.4, 11.8 |
| S5 | CRITICAL | The link table learns `prev_hop` from every CRC-valid frame before any check | 11.4 step 3 |
| S6 | CRITICAL | Unauthenticated frames use up flood control: rate buckets, dedup and suppression all run before the K_mesh tag is checked | 11.4 steps 6a-6c, 11.5 |
| S7 | CRITICAL | The 16-bit seq wraps in minutes under one K_s for months, so frames from the previous cycle replay as "newer" | 3.5, 8 |
| S8 | HIGH | K_mesh gives session authority: a forged BIND or SEEK hijacks or kills a handshake, which contradicts 11.8 | 4.1.1, 4.1.5, 8, 11.8 |
| S9 | HIGH | Nonce entropy at boot is unspecified: synchronized reboots can repeat nonces, reuse K_s and allow a whole session to be replayed | 4.1.1, 8 |
| S10 | HIGH | No key ID, epoch, rotation or revocation | 8, 11.8, App. B |
| S11 | HIGH | Hop fields are unauthenticated: ttl is not clamped to MAX_HOPS, and path_mtu can be forced down or up | 3, 11.2, 11.3, 11.4 |
| S12 | HIGH | A replayed SEEK is amplified across the mesh and exhausts OFFERED state | 4.1.2, 4.1.8, 11.5 |
| S13 | HIGH | Black holes, gray holes and wormholes persist because a re-SEEK lands on the same poisoned path | 11.4, 11.6 |
| S14 | MEDIUM | Unauthenticated frames refresh liveness and route expiry | 4.2, 11.4 |
| S15 | MEDIUM | Blind unicast forwarding lets outsiders fill relay queues along live paths | 11.4 step 7, 11.8 |
| S16 | MEDIUM | AUTH fails open: a NULL key means no auth, open relays are allowed, and a test key will ship | 8, 11.1, 11.8, App. A.6, App. B |
| S17 | MEDIUM | Home-grown construction: no confidentiality, one K_s for both directions, and a raw HMAC KDF | 8 |
| S18 | MEDIUM | Carrier admission: BLE accepts any central, UDP accepts any LAN host | 1.2, 6.4, C.4 |
| S19 | LOW | Enumeration and location leaks; ID-collision alarms can be triggered remotely | 2, 4.1.2, 6.4, 11.9 |
| S20 | LOW | Security counters never leave the node | 8, App. B |

## What holds (checked, no finding)

- **Downgrade via MODE/FEC/HIGH-LOW parameters.** MODE, MODE_ACK and PARITY
  are tagged under K_s. An outsider cannot change k, m, arq or the resolution
  mode.
- **Version downgrade.** `ver_flags` is inside the tag and the KDF label is
  "ProbeLink-v1". Unknown versions are dropped.
- **CLOSE/BIND_NAK spoofing under AUTH.** Both are tagged under K_s, and 8
  forbids replying to frames that fail authentication, so no error oracle
  exists.
- **Tag length.** HMAC-SHA256 truncated to 8 bytes is an acceptable online
  forgery bound (2^-64 per attempt). The problem is what the tag covers and
  under which key, not its length.
- **AUTH strip by an outsider.** FLAG_AUTH is in the tag, and "a node with a
  key drops any untagged frame". The remaining downgrade is by configuration
  (S16), not on the wire.

---

## CRITICAL

### S1. One stolen node yields K_net: every session key is derivable and every unit ID can be impersonated

- Severity: CRITICAL. Attacker: (b), then (a) from anywhere in range.
- Spec: 8 (`K_s = HMAC-SHA256(K_net, "ProbeLink-v1" || src_id || dst_id || nonce_s || nonce_p)`),
  11.1 (default role "Node" originates and terminates sessions), 11.8 ("Node
  with K_net ... a compromised one can do anything").

**Scenario.**

1. Every default-role node is an endpoint, so it holds K_net. The K_mesh-only
   relay is the exception, not the rule.
2. The thief takes any node from a ceiling or a pole and dumps NVS (S2) to
   get K_net.
3. All inputs to K_s are in clear on the air: src_id and dst_id in the header,
   nonce_s in SEEK, nonce_p in HELLO.
4. The attacker returns to radio range. They sniff the SEEK/HELLO of any
   session and compute its K_s. They then inject MODE (switch to LOW with a
   bogus scale/offset), DATA (fake readings) or CLOSE into any live session in
   the building.
5. They can also claim any unit ID or serve any group as a "probe" and receive
   every sender's data.

11.8 records this as accepted. With 5-50 nodes physically exposed for months,
it is the most likely attack path of all, not a corner case.

**Fix.** Replace the single network secret with per-pair keys and per-device
authorization:

1. **Pairwise keys (works at this scale).**
   - The provisioning tool holds an offline `K_site` and computes