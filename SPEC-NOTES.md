# SPEC-NOTES - implementation decisions on Braid v0.8 ambiguities

This specification is licensed under CC BY-SA 4.0 (see LICENSE-DOCS). The reference implementation is licensed under AGPL-3.0-or-later (see LICENSE).

Identifiers in older rows use the pre-rename pl_/PL_ names (now br_/BR_; project renamed ProbeLink -> Braid).

All spec line citations in N1-N73 refer to PROTOCOL.v0.8.md (frozen); later rows cite PROTOCOL.md v0.9 or later by section.

Binding for the firmware until folded into the spec as v0.9 errata.
Line numbers refer to PROTOCOL.md v0.8 (frozen copy PROTOCOL.v0.8.md).
When code and tests disagree on a spec reading, this file decides.

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N1 | 294, 107-109 | Whether "manager IDs" includes recovery holders 0x0003-0x000F | Manager IDs are 0x0001-0x000F inclusive. |
| N2 | 294, 168 | `next_hop` must be "a unit ID or 0xFFFF", but a direct link to the gateway has `next_hop = dst_id = 0x0001` | `next_hop` may be a unit ID, a manager ID (N1), or 0xFFFF. |
| N3 | 296 | Version rule {N, N-1} with N = 1 would admit version 0 | `PL_PROTO_VERSION_MIN = 1`; only version 1 is accepted. |
| N4 | 293, 200-201 | Length row adds `rs_nsym` but 3.2 strips RS before CRC | The validator receives the frame after RS correction with the parity bytes still appended, so the line 293 length formula holds literally. |
| N5 | 286-306 | CRC is not placed in the 3.6 order | Receive order is: minimum length -> RS decode/correct (RAW links only) -> CRC check -> Length row -> remaining 3.6 rows in spec order. CRC position does not depend on `len`, so line noise counts as `crc_fail`. |
| N6 | 293 | 229-byte payload cap ignores the 22-byte SEEK header and IR max_frame 80 | Added reject reason `PL_REJ_LEN_MAX_FRAME`: received frame length must be <= the receiving link's max_frame. Implementation addition, not in the spec; tests and fuzzers must treat it as a valid named reject. |
| N7 | 302 | MODE failures | Answered with MODE_ACK status 3 or 2, not counted as `bad_frame`. Documented in `pl_frame_check_type_len`. |
| N8 | 271-273 | ROC estimate undefined at roc - 1 with roc == 0 and at roc + 1 with roc == UINT32_MAX | Return `PL_ERR_REJECT` (underflow) or `PL_ERR_TOO_BIG` (overflow). |
| N9 | 154 vs 3.6 | No 3.6 row enforces header `session_id == 0` on pre-session types | Not checked in the validator (spec-literal). Candidate errata for v0.9. |
| N10 | 1890 | Appendix B `pl_err_t` lacks several codes | Values 0-8 kept exactly as in the spec; appended NOT_IMPLEMENTED, CRC, DECODE, UNCORRECTABLE, CRYPTO, REJECT, NO_MEM as 16-22. |
| N11 | 1728-1730 | COBS wire length of 52 includes the trailing 0x00 | `pl_cobs_encode` writes the 0x00 delimiter; decode accepts input with or without it. |
| N12 | 178 | Forwarders reading unknown versions can find `len` only if type 0x01 always means SEEK | `pl_hdr_len_for_type` assumes type 0x01 is SEEK in every version (frozen prefix). |

## Added after phase 1a (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N13 | 1364 | "8-byte hash prefixes of K_mesh(E)" | Read as SHA-256(K_mesh(E))[0..7] for E 0..255 of the test K_site. |
| N14 | 1364 | Blacklist covers K_mesh only; "all-zero or repeated-byte" rule scope unstated | Repeated-byte rule applies to any key of length >= 1. K_node, K_pair, K_hop, Ke_mesh from the test K_site are NOT yet refused (errata candidate). Check is internal (`pl_internal.h`); public `pl_key_check_field()` proposed. |
| N15 | 92, 1725-1731 | COBS: input ending in exactly 254 non-zero bytes - trailing 0x01 code or not | Encoder emits the trailing 0x01 code (matches tools/vectors.py); decoder accepts both forms. |
| N16 | ~297 vs N9 | header seq == low 16 bits of pre_ctr check scope | Applied whenever session_id == 0, regardless of type. |
| N17 | 783 | "HELLO plaintext payload" in the T transcript definition | Means the 28 bytes: clear pre_ctr followed by the 24-byte secret (matches PLV_A9_T). |
| N18 | pl_crypto.h | `pl_hop_tag` documents covered_len >= 27, SEEK needs >= 30 | Header doc to be corrected at next API revision. |
| N19 | pl_crypto.h | `pl_ccm_nonce` refuses dir > 1, A.14 bundle nonce uses dir 2 | Bundle nonce built separately; add dir 2 at next API revision (needed for MGMT/bundles). |
| N20 | pl_crypto.h | ARG vs STATE precedence unstated | NULL pointer -> ARG, then uninitialised ctx -> STATE, then length/range -> ARG. |
| N21 | vectors_generated.h:768 | Comment says 22 bytes, PLV_A12_REQ_SECRET_LEN is 26 | Comment bug in tools/vectors.py emitter; value 26 is correct (spec line 1829). |

## Applied in the phase 1a header revision (2026-10-08, headers re-frozen after it)

- N14: `pl_key_check_field()` is public in `pl_crypto.h`; its doc lists exactly what it refuses and the N14 non-refusals.
- N18: `pl_hop_tag()` requires covered_len >= `pl_hdr_len_for_type(frame[1]) + 8` (27, SEEK 30) and enforces it (27 first, then the SEEK 30).
- N19: `pl_ccm_nonce()` accepts `PL_DIR_BUNDLE` (2) and then builds the 8.6 layout `02 || N || bundle_no || 00 x 6` from src_id = N and ctr_hi = bundle_no; dst_id, session_id and seq must be 0. test_crypto.c:776 still expects dir 2 to be refused (test update pending).
- N20: precedence documented in the `pl_crypto.h` file header.
- CCM note below: `pl_crypto_t.ccm` and the `mbedtls/ccm.h` include are gone; the rationale and evidence are in the `pl_crypto.h` file header.
- On-chip self-test: `pl_selftest_run()` (PL_SELFTEST builds, `firmware/SELFTEST.txt`).

## Added in phase 1b step 1 (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N22 | none (12.1 bench profile, 1.2 transport contract) | Bench boards on one desk all hear each other, so a multi-hop topology (A <-> B <-> C, A and C never in contact) cannot be built on the air | Bench mechanism NOT in the spec: a per-transport neighbour allowlist (`pl_bench_allowlist_t` in `pl_transport_t`, `pl_node.h`). The transport adapter calls `pl_transport_admit()` on every received frame and drops any frame whose header `prev_hop` (offset 6, frozen prefix) is not listed (or that is shorter than 8 bytes) BEFORE `pl_node_rx()`: the core sees nothing, counts nothing, learns nothing. `prev_hop` is unauthenticated at that point, so this is topology shaping for tests, never a security control. Bench profile only: compiled out when `PL_FIELD_BUILD` is defined (`pl_transport_admit()` then always admits). The simulator applies the same filter (`plsim_set_allowlist()`). |
| N23 | 266, 571, 721 | First session seq and the ACK `cum_seq` before anything arrives | First frame after BIND_ACK is seq 0; `cum_seq` starts at 0xFFFF (`pl_arq_rx_init`). |
| N24 | 716-718 | Only "reported missing" seqs are retransmitted, so a lone lost ACK_REQ DATA waits for keepalive (up to 5 s) | An ACK_REQ frame with no ACK within RTO counts as missing and is retransmitted, up to ARQ_MAX_RETRIES (`pl_arq.h`). |
| N25 | 1912, 1112 | `on_samples` carries no hop count or source | `pl_samples_meta_t` adds source and `hops` = header hops + 1 (links traversed; A -> B -> C gives 2). |
| N26 | 80-83, 1909-1919 | Transport and callbacks have no `user` pointer; spec uses `set_rx_cb` | `user` pointers everywhere; adapters push frames with `pl_node_rx()` / `pl_node_tx_status()`. `pl_node_t` is statically allocated (Appendix B heap ctx overridden); only `pl_crypto_init` uses heap, once. |
| N27 | 439, 1952-1958 | Frames for an unknown session are "dropped and counted" but `pl_stats_t` has no counter | New counter `unknown_session` appended to `pl_stats_t`; NOT in the MGMT section 1 layout until a v0.9 errata adds it. |
| N28 | 349-352, 1140 | Which window the probe uses to pick "the lowest-cost SEEK copy" | The probe's own HELLO delay window. |
| N29 | 11.5, 11.9 (FLOOD_PENDING 4) | Relay overflow of pending flood copies has no counter or behaviour | Drop the new flood and count `flood_pending_full` (appended to `pl_stats_t` after `unknown_session`; not in MGMT section 1 until v0.9 errata). |
| N30 | 439, 4.1.13 | CLOSE(2) for an unknown session cannot be authenticated: the probe has no key for that peer | Under AUTH no CLOSE(2) is sent for unknown sessions (spec says MAY); the sender relies on ACK_REQ retries and session timeout. |
| N31 | 4.1.12, line 423 | Stream taken at bind/MODE or at first DATA | Taken at first DATA (literal reading); FULL decided at HELLO. Scenario r12b asserts it. |

## Added at the phase 1b gate (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N32 | 355, A.9 | HELLO `path_cost`: field as received vs field plus link cost | Spec vector wins: HELLO carries the SEEK copy's `path_cost` as received (A.9: 1 at 2 hops). The `pl_offer_t.cost` doc is corrected; HELLO payload bytes are asserted against `PLV_A9_HELLO_PAYLOAD`. |
| N33 | 426 | More bound ARQ sessions than streams | The late session finds no stream at first DATA and degrades to arrival-order delivery without ARQ. |
| N34 | 1120 | Route cost for HELLO/OTHER rows: "the HELLO's cost" is inside the ciphertext | Relays use hops x link cost. |
| N35 | 861, 729 | Strict hop_seq vs same-instant copies; gaps from lost MODE/PING/ACK | Same-instant FLOOD_REPEAT copies or retransmit + new DATA may be counted `hop_replay` on reordering links (expected); lost MODE/PING seqs and lost ACKs always produce `on_gap`. |
| N36 | 1142, 264 | FLOOD_REPEAT and "broadcast retry" | FLOOD_REPEAT always applied on broadcast transports; each copy takes its own txseq. |
| N37 | 443 | "ARQ_MAX_RETRIES unanswered requests" | 3 consecutive ACK_REQ frames that exhausted their retries; any ACK resets the count. |
| N38 | ~370 | FULL backoff start | Starts at n = 0, 60 s cap. |
| N39 | 300, 386 | Authentic but stale pre-session replies | Late HELLO, duplicate BIND_ACK, BIND to a LISTENING probe dropped silently; mismatch found after decryption counts `bad_frame`. |
| N40 | 302 | LOW scale sign | Negative LOW scale refused (spec says only non-zero). |
| N41 | HELLO rssi | Offer stores no RSSI | HELLO rssi sent as -128 until carriers report RSSI. |
| N42 | config | `caps == 0` | Means the demo capability set. COBS in the transport adapter, RS in the node. |

## Added with the UART link adapter (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N43 | none (N22), 3.2, N42 | `pl_bench_allowlist_admit()` is specified on bytes "after COBS / RS on RAW links", but the adapter must call it BEFORE `pl_node_rx()` and RS runs inside the node (N42), so line noise on bytes 6..7 would turn into a bogus allowlist drop | The UART adapter (`uart_link_deliver()`) runs the allowlist on an RS-corrected scratch copy; the node still receives the bytes as they came off the wire and does its own RS (so `rs_corrected` / `rs_fail` stay node counters). If the scratch RS decode fails, the frame is passed on unchecked and the node counts `rs_fail`. Bench only (compiled out with `PL_FIELD_BUILD`, like N22). |
| N44 | 1.2 (`mac_retry`, `addr_len`), 11.6 | A wire has no MAC delivery report and no carrier address | UART transport: `mac_retry` false, `addr_len` 0, `link_cost` 1, `can_broadcast` false. The adapter reports `delivered = true` for every frame the UART driver accepted, after the node call returns (never from inside `send()`); the core ignores it (`mac_retry` false), so 11.6 link deletion never fires on UART and a dead cable is found by ARQ / N37, keepalive, session timeout and table expiry. The RX hint carries no address (`addr_len` 0, rssi unknown); the link is learnt from the header `prev_hop`. |
| N45 | C.6, 12.4 | Which UART controller carries the "UART1 role" | ESP32: UART2 on GPIO17 TX / GPIO16 RX (its IO_MUX pins); ESP32-S3: UART1 on GPIO17 TX / GPIO18 RX. Other pins go through the GPIO matrix. Strapping pins are refused for both link pins (the peer holds our RX high through reset; ESP32 GPIO12 high selects 1.8 V flash). 8N1, default 921600 baud. |

## Simulator vs hardware correspondence

- Real ESP-NOW unicast retries at the MAC layer before reporting `ESP_NOW_SEND_FAIL`; this corresponds to simulator `mac_attempts` 3 (100/100 runs delivered every press at 10% loss), not `mac_attempts` 1 (88/100). The adapter maps the ESP-NOW send callback status to `pl_node_tx_status(delivered)`, so the 11.6 link-deletion rule (3 consecutive failures) counts MAC-retried failures.
- Environment note: the shell has `IDF_PATH=/home/lahiru/esp/esp-idf` (IDF 4.4.6). PlatformIO overrides it; running `idf.py` directly would use 4.4.6, not the pinned 5.5.3.

## Other implementation choices (not spec ambiguities)

- AES-128-CCM (RFC 3610, M=8, L=2) is implemented in pl_crypto.c on a stack `mbedtls_aes_context` (hardware AES on both chips), because `mbedtls_ccm_setkey()` allocates on every re-key. Differentially tested against Python `cryptography` (pt 0..255, aad 0..269, tamper cases). `pl_crypto_t.ccm` is now unused (drop at next API revision).

- Protocol core `components/app_probelink` is C11 (spec API is C, core must build on host). App shell is C++.
- Crypto backend is mbedtls on host and device (same source tree, mbedtls 3.6.5 from ESP-IDF 5.5.3).
- Each crypto call takes a caller-owned `pl_crypto_t`, so no heap is used after init (Appendix B).
- Appendix A key material in `firmware/test/host/vectors_generated.h` is public TEST ONLY data. Field builds must refuse those exact keys (spec 12.1 test-key blacklist).

## Added with the lost-first-MODE fix (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N46 | 255-283 (3.5), 338-456 (4.1), 598-651 (6.1), 707-741 (7); N23, N24, N35 | Control retries take new seqs (3.5) and "DATA only in STREAMING" (4.1), so a lost MODE or PING leaves a permanent hole in the probe's ARQ seq space; section 7 makes the probe wait REORDER_MS for every hole and the sender ignore cleared non-DATA bits. A hole at the FIRST MODE (session seq 0, N23) stalled the session: the stream seeded at the first DATA (N31) waited for seq 0, held every later DATA, stopped acking once its 4 reorder slots were full and the sender exhausted ARQ retries (reported by the UART loopback test). | Probe rule, "DATA floor": when a MODE at index k is answered with MODE_ACK and its `config_id` is the ONLY config the record holds (the session's first config, new or re-acked; a rejected MODE on a record with no config counts too), every missing seq below k is a control gap: the sender sends DATA only in STREAMING, enters it on the MODE_ACK of that config and stops resending the MODE once it has that MODE_ACK (6.1), so every MODE of the first config precedes every DATA. Those holes are given up at once (no REORDER_MS): reported through `on_gap(first, count)` per run (informational; counted in `gaps`), and the record's DATA floor rises to k + 1 so the stream seeded at the first DATA starts there. Holes below a MODE of any LATER config may be DATA of the previous config still in flight (6.1: DATA keeps the old `config_id` until MODE_ACK; the probe keeps two configs) and are indistinguishable from it, as is a lost PING mid-stream: they keep the section 7 wait and expire as `on_gap` (N35), ACK bitmaps keep flowing meanwhile, the sender ignores the cleared control bit, delivery of the frames behind the hole is delayed by at most REORDER_MS and nothing is lost while at most 4 DATA arrive in the first REORDER_MS - 3 x RTO of the wait (later ones are refused as TOO_FAR and come back by ARQ). Sender side unchanged, verified: MODE / PING retries never enter the ARQ window (`pl_arq_tx_push` is called only for DATA), do not count `arq_retx` or ACK_REQ give-ups, and a lost ACK is covered by N24 (tail-loss retransmission, the probe re-acks the duplicate). Storage: the floor is the 16-bit seq in the probe record's `pl_tx_index_t.reserved` (`PL_PRB_DATA_BASE`, pl_internal.h; the public header is frozen), rebuilt as a 48-bit index against `highest + 1` at seeding. Candidate v0.9 errata: give control frames their own seq space, or let MODE_ACK carry `cum_seq`, so a mid-stream control loss costs no REORDER_MS either. Tests: test_scen_mode_loss.c (first MODE lost once / twice, MODE change lost with old-config DATA in flight, PING lost, clean trace hash unchanged). |

## Added with the WiFi UDP adapter (2026-10-08)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N47 | 80 (addr_len 4 for UDP) | IPv4 alone cannot distinguish several nodes on one host (loopback tests, NAT'd LANs) | UDP `addr_len` is 6: IPv4 || UDP port, network order. On a real LAN the port bytes are constant (40888). Candidate v0.9 errata. |
| N48 | 11.4 step 6 | Where the UDP adapter learns ip:port <-> unit id | No adapter-side table. The adapter passes the sender's ip:port as the `pl_rx_meta_t` hint; the core records it in the link table at step 6, after the hop_tag check, so a spoofed `prev_hop` cannot poison the mapping. |
| N49 | 11.4 | Unicast to a `next_hop` with no link entry | The core calls `send(addr = NULL)`; the UDP adapter floods that frame (multicast or peer list) and counts `unknown_next_hop`. |
| N50 | 1.2 `mac_retry`, 11.6 | Datagrams have no MAC delivery report | UDP `mac_retry` false; accepted datagrams are reported delivered=true from the owner task (never inside `send()`), like UART (N44); 11.6 link deletion does not fire on UDP. |
| N51 | C.4 | Several nodes in one process need multicast loopback | `mcast_loop` is a config flag: on for host tests, off on a device. |
| N52 | C.4, 1.2 | RSSI and link cost on UDP | RSSI unknown (-128 in HELLO per N41); `link_cost` 1. |

## Added with the nRF24L01+ adapter (2026-10-08; the adapter's own report numbered these N46-N58, renumbered here)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N53 | C.5 | Segment header bit layout | byte 0 src (low byte of unit id), byte 1 tag (per-transmitter frame counter), byte 2 bit 7 LAST + bits 6..0 idx; 29 frame bytes per segment, 9 segments for 250 B. |
| N54 | C.5 | Empty frame | One 3-byte LAST segment; the adapter refuses len 0 like UART. |
| N55 | C.5 | Duplicate / out-of-order segments | Repeat of the last accepted segment or of a completed frame is ignored and counted `dup`; any other idx mismatch drops the open frame. Orphans (idx > 0, no open frame) counted per segment, not as frame drops. |
| N56 | C.5 | Reassembly buffer full | Newcomer dropped (`buffer_full`); open buffers reclaimed by timeout (50 ms) only, idle ones by LRU. Buffers are 250 B, not C.5's 258 (oversize beyond max_frame is dropped anyway). |
| N57 | C.5 | Address byte order | C.5 list order is on-air order; registers are written reversed (A5 U_lo U_hi 4C 50). Unit U = 50 4C U_hi U_lo A5; broadcast 50 4C FF FF A5. |
| N58 | C.5 | "NO_ACK pipe" | EN_AA stays set on the broadcast pipe (DPL requires ENAA_Px); floods use the per-packet NO_ACK flag (W_TX_PAYLOAD_NO_ACK, EN_DYN_ACK). |
| N59 | 1.2 | prev_hop hint on nRF24 | Hint address derived from the header's prev_hop; a src-byte mismatch is counted but the frame is still delivered. `seg_fail` is fed by the adapter through the core hook `pl_node_count_seg_fail()` (added in the integration pass): one call per reassembly frame drop (timeout, gap, foreign tag, oversize, buffer full), none for orphan segments. |
| N60 | 12.4, C.5 | Collision avoidance | No TX start within 1 ms of the last received segment (beyond the 2 ms guard); without it a lost hardware ACK on a LAST segment produced a head-on PTX pair. Cross-radio arbitration is left to the bridge via `nrf24_link_radio_busy()`. |
| N61 | 11.6 | MAX_RT on one segment | Abandons the whole frame at the first failing segment and reports delivered=false; a fully received frame may thus be reported undelivered (node dedup absorbs the retransmit). |

## Added with the 12.4 bridge radio arbitration (2026-10-08; firmware/RADIO-ARB.txt)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N62 | 12.4 (1448-1450), C.5, N60 | "A bridge never starts a transmission on one radio while the other is mid-reception of a multi-segment frame": what "mid-reception" is per radio, whether the hold is bounded, and what is gated | Both directions are gated, on what each radio can observe (fidelity table below): an ESP-NOW start waits while `nrf24_link_radio_busy()` (own nRF24 TX, or < 1 ms since the last received segment, N60); an nRF24 frame start waits while an ESP-NOW frame of ours is in flight (TX only: ESP-NOW reception is invisible; it is a single packet, so no multi-segment reception exists on that side). WiFi STA (LAN side) is not arbitrated: nothing is observable inside the closed driver. Only frame STARTS are gated (an nRF24 frame is never paused between segments). Bounded hold: cap 20 ms (a 9-segment nRF24 frame at 2 ms polling is ~18 ms busy); at the cap the start goes and counts `arb_to`, and that busy signal is treated as stale (later starts go at once, each counted) until it reads idle once, so a wedged signal costs one cap, not one per frame; `arb_to` = starts made while the other radio read busy. Single-radio boards: no-op, zero added latency. All decisions in the protocol task. Implementation addition: counters `arb_hold_e`, `arb_hold_n`, `arb_to`, `arb_defer`, `arb_qfull`, `arb_derr` (PLSTAT, bridge only). Tests: test_radio_arb.c. |
| N63 | 1.2 transport contract, 4.1 | A held ESP-NOW frame: refuse it (error to the core) or delay it | Delayed: `espnow_link` (portable wrapper around node_app `tr_send`) keeps a static 4-frame FIFO; `send()` returns PL_OK for a queued frame, so a held BIND / HELLO / SEEK costs latency, not a retry round (ARQ covers only DATA). Order is kept (a new frame queues behind older ones even when the nRF24 radio is idle). FIFO full -> PL_ERR_QUEUE_FULL (the code `tr_send` already returns for a busy radio), counted `arb_qfull`. A queued frame the radio refuses at drain time is dropped and counted `arb_derr` (the core already counted it in `tx_frames`). |
| N64 | 11.11 (ESP-NOW send callback), 12.4 | The ESP-NOW tx-status event exists only for unicast (port_espnow.cpp drops the broadcast callback), so it cannot clear an "ESP-NOW TX in flight" flag after a SEEK / flood copy, and a dropped event would pin it | New HAL call `hal_radio_tx_inflight()`: frames between `esp_now_send()` returning OK and its send callback, which the driver runs for every accepted frame, broadcast included. The port keeps a `std::atomic` counter (+1 before `esp_now_send`, -1 on refusal, -1 at the top of `send_cb`, never below 0); the protocol task reads it when deciding. The unicast verdict path (11.6) is unchanged. |

12.4 fidelity, as implemented (N62):

| Direction | Signal | Fidelity |
|---|---|---|
| Hold ESP-NOW TX while nRF24 busy | `nrf24_link_radio_busy()`: own TX in progress or < 1 ms since the last RX segment (as fresh as the pump: 2 ms polling, or the IRQ pin) | good |
| Hold nRF24 TX while ESP-NOW active | `hal_radio_tx_inflight() > 0`: between `esp_now_send` and its send callback | TX only; ESP-NOW RX is invisible to the app |
| Hold nRF24 TX while WiFi STA active | nothing (lwIP sends are inside the closed driver) | none: not arbitrated; the 12.4 channel plan and antenna separation are the only protection |

## Added with the single-chip WiFi + nRF24 gateway mode (2026-10-08; v0.9 candidates; N65-N68 because the arbitration rows took N62-N64)

| # | Spec line | Ambiguity | Decision taken |
|---|---|---|---|
| N65 | 1416-1453 (12.4) | 12.4 forbids WiFi STA on mesh nodes because association moves the channel ESP-NOW is pinned to; an nRF24-only mesh has no such dependency | New topology, a 12.4 variant (v0.9 candidate): ONE chip runs the nRF24 mesh (SPI) and a WiFi STA uplink at once, ESP-NOW off (console `nrf=on wifi=on espnow=off`). Small sites only: it does NOT replace the 12.4 two-chip gateway sized for 50 records / N streams (no PSRAM stream buffers, nRF24 30-60 kbit/s shared with the board's own WiFi, WROOM-32E withdrawn as a field gateway by 12.2/12.4). The gateway runs as a probe with a UNIT ID: the core refuses manager IDs (N1) as `unit_id` and serves no MGMT, so `id=0x0001` is refused by the console; 12.4's "manager 0x0001 and the probe of the sink group" is today the probe half only. nRF24 vs WiFi arbitration is best effort (WiFi TX is not observable from the app; firmware/RADIO-ARB.txt). firmware/GATEWAY-NRF24.txt. |
| N66 | 12.4, C.4 | Console coupling: the station was implied by `udp=on`, which mixed "has WiFi" with "carries frames over UDP" | New key `wifi=on|off` (NVS u32 `wifi`). Policies: the station (wifi=on, or udp=on) is refused with espnow=on (12.4); `udp=on` requires the station (`udp=on wifi=off` refused); `ssid=` / `pass=` belong to wifi (wifi=on needs ssid=); wifi alone is not a transport (espnow, uart, udp or nrf must be on); nrf=on + wifi=on + espnow=off is allowed. Compatibility: a `pl set` line with `udp=` and no `wifi=` sets wifi to the same value (the old behaviour); NVS written before `wifi=` existed (udp=1, no `wifi` key) loads as wifi=on, and a stored udp=1 always implies the station. `pl show` keeps the old udp text when udp=on and prints ` wifi=on ssid=.. pass=set|unset` otherwise. Host test test_console_gateway.c. |
| N67 | 12.4 (nRF24 sites: mesh channel 1-6, nRF channel 76-81) | On the single-chip gateway the WiFi channel is the AP's, chosen by the router, not by the manifest | Clearance = nRF frequency (2400 + nch MHz) minus the nearest edge of the AP channel's occupied band (centre 2407 + 5 N MHz, ch 14 2484, edges +/- 11 MHz; negative = inside). Read after association (`esp_wifi_get_channel`, `hal_udp_wifi_sta_info`), re-checked every 5 s. Below 20 MHz (estimate, measurement item) the gateway logs `PLNRF coexist: AP ch N, nRF ch M, X MHz apart - move the router to ch 1-6`, plus `or set nch=83` (with `nrate=1m` at 2 Mbps) only when nch 83 would clear 20 MHz. It never retunes the nRF24 itself: every other mesh node would have to follow. AP ch 1-6 give >= 28 MHz from every nch 76..83; ch 11 is 3 MHz from nch 76; ch 13 overlaps it by 7 MHz. 40 MHz APs are not modelled. |
| N68 | 691-706 (6.5) | Network time: "every node syncs with its manager"; where the manager gets UTC is unstated | The gateway's time source is SNTP over its WiFi station (ESP-IDF esp_netif_sntp, no external dependency), server from console `ntp=` (default pool.ntp.org), resync every CONFIG_LWIP_SNTP_UPDATE_DELAY (1 h); log `PLNTP synced <ISO-8601 UTC> sync=N server=..` on the first sync and every resync. The core has no network-time hook (MGMT time sync not served), so SNTP time is logged only; when a hook exists, `hal_time_utc_us()` feeds it (TODO in node_app.cpp ntp_poll). |
| N69 | 12.4 (gateway uplink), C.4 | The WiFi station stopped reconnecting after 10 consecutive failures (port_udp.cpp kMaxConnectRetries): a router outage longer than that left an unattended gateway offline until `pl reboot` | The station retries forever. Every WIFI_EVENT_STA_DISCONNECTED (any reason: AP gone, AP not found, wrong passphrase) arms ONE one-shot esp_timer retry; the event handler never blocks and never calls esp_wifi_connect() itself (only the STA_START first attempt); a second DISCONNECTED while a retry is pending is not counted or logged again. Schedule (portable, hal_udp.h hal_udp_wifi_backoff_next(), host test test_console_robust.c): base = min(1 s x 2^(n-1), 60 s) for the n-th consecutive failure (1, 2, 4, 8, 16, 32, 60, 60 ... s), delay uniform in base +/- 20 % (jitter on the capped base: 48..72 s at the cap), so gateways behind one router do not reassociate in lockstep; IP_EVENT_STA_GOT_IP resets n. Log `PLWIFI sta down (reason=N) retry in X.Ys` once per attempt (about one line a minute at the cap, also for a wrong passphrase). hal_udp_wifi_sta_retry_info() exposes n and the last reason; PLSTAT adds `wifi_retry=n` (and `wifi_reason=R` when n > 0) only when the station is on. PMF: capable, not required (routers without PMF still work); PMF "required" on the router blocks spoofed deauth (GATEWAY-NRF24.txt 4). |
| N70 | none (demo console, NVS namespace "pl") | One corrupt stored blob blocked the boot: a non-printable byte in `ntp` became '?' and node_cfg_ready() refused "ntp not a host name", so the board waited at the console; a bad nbr / udp_peers length failed the whole load (all defaults); a bad ssid was silently "sanitised" to '?' (association with a wrong SSID) | node_cfg_load_blobs() (portable, node_console.c) decodes and validates each blob key on its own after the u32 keys and the legacy wifi rule. OPTIONAL keys fall back to the default with `PLCFG <key> invalid in NVS, using default` and the rest loads: ntp -> pool.ntp.org, nbr -> none, udp_peers -> none (unless required), ssid / pass -> empty (only while the station is off). REQUIRED keys (ssid and pass with the station on, udp_peers with udp=on mcast=off) are flagged in node_cfg_t.nvs_bad (never stored): node_cfg_ready() refuses with a reason naming the NVS key (`NVS key pass invalid ...`), `pl set <key>=` clears the flag, and cfg_save() does not overwrite a flagged key, so a corrupt pass is never turned into an open AP. Validity = what the console accepts (ntp rule, 1..8 distinct unit IDs other than uid, 1..8 unicast ip:port, pass 8..63 of 0x20..0x7E); ssid 1..32 bytes without control bytes, 0x80..0xFF kept raw for UTF-8 SSIDs and shown as '?' only when printed (node_fmt_ssid). A blob longer than its buffer (hal_kv HAL_ERR_NO_MEM) counts as invalid; other NVS errors still fail the load as before. u32 keys unchanged (out-of-range values are refused by node_cfg_ready()). |
| N71 | 12.2 (credentials) | Copies of the WPA2 passphrase stayed on stacks and in static buffers; plain memset() on dead locals may be removed by the optimiser and was skipped on error returns | Rule: every transient copy of the passphrase is wiped with a volatile byte loop (node_wipe() in node_console.c; a local wipe() in port_udp.cpp, which cannot depend on app_node) on every path out, via scope guards in C++: the parsed command and the working copy in console_exec, the SHOW copy, the boot copy in node_app_run, the NVS read buffer in cfg_load, node_cfg_apply()'s working copy, the console line buffer after each line, the port's wifi_config_t after esp_wifi_set_config(). Kept on purpose: g_cfg (the stored configuration, rewritten whole to NVS on `pl set`) and the WiFi driver's own copy (reconnects). Bench profile limitation: plaintext in NVS and in g_cfg; the field profile needs NVS encryption + flash encryption (12.2). |
| N72 | none (demo console) | Error texts quoted up to 24 characters of the offending token unless the line contained "pass": a passphrase pasted without pass= (`pl set Hunter2Secret`, a bare line, `pl Hunter2Secret`, `pl show Hunter2Secret`) reached the log | Tokens that are not key=value of a known key are never quoted: "expected key=value", "unknown command", "unknown verb" and "unexpected ... after the command" print `<hidden> (N characters)` instead. Keys and values of known keys are still quoted on lines without "pass" (any case); on lines with it nothing is quoted (unchanged). Host test test_console_robust.c. |
| N73 | 691-706 (6.5) | SNTP (N68) is unauthenticated: any host on the LAN path can answer with a forged time | No code change while SNTP time is only logged. REQUIRED before SNTP time feeds the core (the TODO in node_app.cpp ntp_poll): a max-step guard - once the clock has been set, a correction larger than a bound (e.g. 10 s per resync) is refused and logged instead of applied, so a spoofed reply cannot move key epochs, replay windows or session expiry; NTS or an authenticated manager time source is the long-term answer. |
| N74 | 8.2 (key table), App. A, App. D v0.9 | Project renamed ProbeLink -> Braid: the four KDF domain-separation labels carried the old name, and the self-test and host tests passed hand-written label lengths (12u / 14u) that would silently hash the wrong bytes once a label length changed | Labels are "Braid-v1", "Braid-mesh", "Braid-pair", "Braid-node" (non-name labels such as "hop", "mgmt", "bundle", "PLB1" unchanged). One C definition: PL_LABEL_* in probelink/pl_crypto.h, used by pl_session.c, pl_selftest.c and test_crypto.c; every length is PL_LABEL_LEN() (sizeof - 1), never a literal. tools/vectors.py names them once (LBL_*) and regenerates Appendix A (--emit-md), vectors_generated.h (--emit-c) and the 12.1 test-key blacklist in pl_crypto.c (--emit-kmesh-hash8). Wire version stays 1: nothing was ever deployed or run on hardware. |
