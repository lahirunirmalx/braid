# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.6 (round-3 fixes; wire version 1, minor 0)

One protocol, four mesh carriers (ESP-NOW, WiFi UDP, nRF24L01+, UART) plus
an IR edge link. Every device has an ID. Every frame is integrity-checked and
carries enough redundancy to recover damaged or lost data. Payloads are
digital or analog 32-bit values, sent in HIGH or LOW resolution.

Reading guide: sections 1-10 keep the v0.1 numbering so the drafts can be
diffed. Section 11 is the mesh layer (mandatory). Section 12 holds the
deployment profile, every design decision with its alternative (BLE and IR
are user decisions), the known limitations and the implementation readiness
list. Appendix D maps every review finding to its disposition. Numbers
marked "(estimate)" are not measurements.

Normative words: MUST, SHOULD, MAY as in RFC 2119. "Field profile" is the
default; "bench profile" relaxations are named where they apply (12.1).

---

## 1. Layer stack

```
+---------------------------------------------------------+
| Application   pl_send_samples(), on_samples()           |
+---------------------------------------------------------+
| Session       SEEK / HELLO / BIND / MODE / DATA / CLOSE |
|               RESUME (parked sessions), MGMT (s.11.10)  |
+---------------------------------------------------------+
| Mesh          flood SEEK/RESUME, hop-by-hop unicast     |  every node
+---------------------------------------------------------+
| Group FEC     RS erasure code across k DATA frames,     |  any link
|               m PARITY frames (m = 1 is plain XOR)      |
+---------------------------------------------------------+
| Frame         header + payload [+ tags] + CRC-16        |  CRC mandatory
|               [+ in-frame RS parity on UART / IR]       |
+---------------------------------------------------------+
| Transport     ESP-NOW | UDP | nRF24 (segments) | UART   |  IR: edge only
+---------------------------------------------------------+
```

### 1.1 Two kinds of link, two kinds of damage

| Link class | Carriers | Damage | Recovery |
|---|---|---|---|
| PACKET | ESP-NOW, WiFi UDP, nRF24L01+ | The radio MAC checks its own CRC and drops bad frames, so damage is a missing frame. | CRC-16 (mandatory), cross-frame FEC and/or ARQ |
| RAW | UART, IR | Bytes arrive flipped, missing or inserted. | CRC-16 plus in-frame RS; cross-frame FEC and ARQ optional |

The application CRC is mandatory on PACKET links too: ESP-IDF issue #9575
(open, ESP32-C3, IDF 4.4.2) reports ESP-NOW frames with an invalid 802.11 FCS
being accepted, and the nRF24L01+ CRC is only 16 bits per 32-byte packet.
In-frame RS is fixed at 0 on PACKET links.

Unified recovery model: the frame layer turns every kind of damage into an
erasure (a frame either fully correct or absent); FEC and ARQ deal only with
erasures. Recovery data per packet: DATA frames carry it (RS parity on RAW
links, PARITY frames everywhere); control frames rely on CRC plus repetition
(`FLOOD_REPEAT`, 11.5) and handshake retries. Stricter option: 12.3.

### 1.2 Transport adapter contract

```c
typedef enum { PL_LINK_PACKET = 0, PL_LINK_RAW = 1 } pl_link_class_t;

typedef struct {
    const char     *name;          /* "espnow", "udp", "nrf24", "uart", "ir" */
    pl_link_class_t link_class;
    uint16_t        max_frame;     /* 250 on mesh carriers; 64 on IR (incl. RS parity) */
    uint8_t         rs_nsym;       /* 0 PACKET, 8 UART, 6 IR */
    bool            can_broadcast; /* floods by broadcast (ESP-NOW, UDP multicast, nRF24) */
    bool            mac_retry;     /* carrier reports unicast delivery (ESP-NOW, nRF24): used for failover (11.6) */
    bool            edge_only;     /* IR: frames are never forwarded to or from this transport */
    uint8_t         link_cost;     /* for carriers without RSSI (11.4): UART 1, nRF24 2 */
    uint8_t         addr_len;      /* carrier address bytes in the link table: 6 ESP-NOW, 5 nRF24, 4 UDP, 0 UART/IR */
    int  (*send)(const uint8_t *addr, const uint8_t *buf, uint16_t len);   /* addr NULL = broadcast; returns delivery status where mac_retry */
    void (*set_rx_cb)(void (*cb)(const uint8_t *addr, const uint8_t *buf, uint16_t len, int8_t rssi));
} pl_transport_t;
```

| Carrier | Class | max_frame | Notes |
|---|---|---|---|
| ESP-NOW | PACKET | 250 | Broadcast FF:FF:FF:FF:FF:FF for floods, unicast to the `next_hop` MAC otherwise. One dedicated channel (`pl/channel`) for all mesh nodes; `WIFI_MODE_STA` never associated and never AP; `esp_wifi_set_ps(WIFI_PS_NONE)`; BT never runs while the mesh is up (12.4, 12.5). `rssi` from `esp_now_recv_info_t` (ESP-IDF >= 5.0). |
| WiFi UDP | PACKET | 250 | LAN side of the gateway only (12.4). Port 40888, multicast 239.255.40.88 TTL 1 for floods, unicast otherwise; static IPs or DHCP reservations; a configured unicast peer list replaces multicast on isolated LANs (C.4). |
| nRF24L01+ (SPI) | PACKET | 250 (reassembled) | 32-byte packets, segmented and reassembled inside the adapter per hop (C.5). ESB CRC-16, auto-ACK unicast on unit-ID-derived addresses, NO_ACK broadcast address for floods. No RSSI: fixed `link_cost` 2; `rssi` reported as -128 (unknown). |
| UART | RAW | 250 (incl. 8 RS bytes) | COBS, 0x00 delimiter; COBS bytes are outside max_frame. Point to point. Also the carrier of the two-chip gateway (921600 baud or more, 12.4) and of the provisioning station (12.2). |
| IR (RMT) | RAW, edge | 64 (incl. 6 RS bytes) | One hop, point to point, between an IR leaf and one mesh node; never forwarded (user decision, 12.6). 38 kHz, half duplex, indoor or shaded. Keyed by the edge pair key, not the mesh key (8.3). Both ends apply `IR_TIME_SCALE` (10) to the handshake timers of that link only. |

BLE is not a carrier. It is a phone link for commissioning and diagnostics
that runs only while the mesh radio is stopped (6.4, 12.5).

---

## 2. Device IDs

16-bit IDs. Small enough for IR, large enough for a site of 50 nodes.

| Range | Meaning |
|---|---|
| 0x0000 | Unassigned. Never valid on the air. |
| 0x0001 | Gateway / manager. |
| 0x0002 | Provisioning station (UART recovery manager, 12.2). |
| 0x0003 - 0x000F | Recovery holders (phones, 6.4), one ID per device. |
| 0x0010 - 0xFEFF | Unit ID. One per node. |
| 0xFF00 - 0xFFFE | Group (destination) ID. Several probes can subscribe to one group. |
| 0xFFFF | Flood. |

- Unit IDs come from the provisioning manifest (12.2), one row per device
  keyed by its eFuse base MAC, written to NVS (`pl/unit_id`) with the MAC it
  belongs to (`pl/unit_mac`). At boot, if `pl/unit_mac` differs from
  `esp_read_mac(ESP_MAC_BASE)` the image is a clone: the node ignores the ID,
  uses the fallback below, and sets the `clone` bit of its MGMT section 0
  (11.10). A fallback node holds no pairwise keys, so it can report and do
  nothing else until re-provisioned; that is the intended outcome.
- Fallback ID: CRC-16/CCITT-FALSE (3.1) of the base MAC; if below 0x0010 or
  >= 0xFF00, `(crc % 0xFEEF) + 0x0010`.
- Collision detection: a frame with `src_id` or `prev_hop` equal to the
  node's own ID that is not an echo of its own flood (11.5) raises
  `PL_EVT_ID_COLLISION`. MGMT reports carry (MAC, unit_id), so the gateway
  sees two MACs for one ID anywhere in the mesh.
- A "destination" is a group ID. Each probe that serves it subscribes to it
  (up to `PL_MAX_GROUPS` = 8, NVS `pl/groups`). A sender seeks the group, not a
  probe. A unit ID is also a valid SEEK destination (a group of one); the
  update server uses that (12.7).
- A node accepts a frame whose `dst_id` is its unit ID, a group it
  subscribes to, or 0xFFFF. After BIND all session frames are unicast to the
  peer's unit ID.

---

## 3. Frame format

All multi-byte fields little-endian; float32 is IEEE-754 binary32 LE. Fields
are packed without padding; read them with `memcpy()`, never by casting a
`uint32_t *` into the buffer (unaligned loads fault on Xtensa and the cast is
undefined behaviour anyway).

```
Off  Size  Field                                                          scope
0    1     ver_flags   bits 7..4 version (=1), bits 3..0 flags             end-to-end
1    1     type        message type (section 5)                            end-to-end
2    2     src_id      origin unit ID                                      end-to-end
4    2     dst_id      final destination: unit ID, group, or 0xFFFF        end-to-end
6    2     prev_hop    unit ID of the node that transmitted this copy      per hop
8    2     next_hop    unit ID of the intended receiver; 0xFFFF = flood    per hop
10   1     ttl_hops    bits 7..4 ttl (hops remaining), 3..0 hops done     per hop
11   4     hop_seq     the transmitter's txseq, full 32 bits (3.5)         per hop
[15  2     path_mtu    SEEK only: smallest (max_frame - rs_nsym) so far    per hop]
[17  1     path_cost   SEEK only: sum of link costs so far (11.4)          per hop]
..   1     session_id  0 in SEEK/HELLO/BIND/BIND_ACK/BIND_NAK/MGMT         end-to-end
..   2     seq         low 16 bits of the end-to-end index (3.5)           end-to-end
..   1     len         payload length 0..255                               end-to-end
..   len   payload     clear prefix (pre_ctr on session_id 0 and RESUME;   end-to-end
                       all of SEEK and RESUME) + AES-CCM ciphertext (8.3)
..   8     auth_tag    if FLAG_AUTH: AES-CCM tag (section 8)               end-to-end
..   4     hop_tag     if FLAG_AUTH: HMAC(K_hop) over bytes 0..auth_tag    per hop
..   2     crc16       CRC-16/CCITT-FALSE over byte 0 .. end of hop_tag    per hop
..   n     rs_parity   rs_nsym bytes on RAW links                          per hop
```

Header 19 bytes (22 in SEEK). Fixed overhead with CRC: 21 bytes, +12 with
FLAG_AUTH, +rs_nsym; max payload 229 - rs_nsym without AUTH, 217 - rs_nsym
with it. Per-hop fields are rewritten by every forwarding node (section
11); a direct link is a one-hop route with `prev_hop = src_id` and
`next_hop = dst_id`. End-to-end fields never change between origin and final
destination.

| Flag bit | Name | Meaning |
|---|---|---|
| 0 | FLAG_ACK_REQ | Receiver replies ACK immediately |
| 1 | FLAG_AUTH | `auth_tag` and `hop_tag` present. Mandatory in the field profile. |
| 2, 3 | reserved | 0 on send, ignored on receive |

Frozen prefix: bytes 0..14, the SEEK hop fields, the positions of
`session_id`, `seq` and `len`, flag bit 1 and the tag sizes are frozen across
future versions, so a forwarding node can locate `len`, the tags and the CRC
of a version it does not know, verify the hop_tag and forward it. Only
endpoints reject unknown versions; they accept version N and N-1 during a
rollout (12.7). `proto_minor` in SEEK/HELLO and MGMT identifies behaviour
changes that keep the layout.

### 3.1 CRC-16

CRC-16/CCITT-FALSE: polynomial 0x1021, init 0xFFFF, no reflection, xorout 0.
Check value CRC("123456789") = 0x29B1. It detects all 1-, 2- and 3-bit errors,
all odd-bit errors and all bursts up to 16 bits at these frame sizes; a
parity bit misses half of all random errors, which is why the user's "parity
check" is a CRC here.

### 3.2 In-frame Reed-Solomon (UART and IR)

RS over GF(2^8), primitive polynomial 0x11D, first consecutive root 0,
generator alpha = 2, systematic (the defaults of Arduino-FEC, libcorrect and
Python `reedsolo`). `rs_nsym` parity bytes correct up to `rs_nsym / 2` bytes
anywhere in the frame; the RS block (frame + parity) is <= 255 bytes.
Transmit: frame -> CRC -> RS -> (UART: COBS + 0x00). Receive: (COBS) -> RS
decode, drop if uncorrectable -> CRC, drop if wrong (catches RS
mis-correction). Interleaving does not help a single codeword; size
`rs_nsym >= 2 x B_max + 2` for the longest expected burst of B_max bytes
(UART 8, IR 6). A corrupted 0x00 breaks COBS framing before RS can act, so
UART relies on FEC/ARQ for long bursts.

### 3.3 Group FEC (cross-frame erasure code, any link)

A systematic Reed-Solomon erasure code across frames (as wfb-ng, k = 8, n =
12 there) with the GF(2^8) tables of 3.2. Set in MODE: `fec_k` data frames
per group (2..16), `fec_m` parity frames (0..4; 0 = off).

- Each DATA frame maps to a block `[len u8] [plaintext payload] [zero pad]`
  of `block_len` = longest payload in the group + 1. FEC runs on plaintext:
  below encryption at the sender, above decryption at the receiver.
- Parity block j is computed column-wise: for each byte position the k data
  bytes are RS-encoded with nsym = m and parity symbol j goes to block j.
  With m = 1 the parity is the XOR of the k bytes, so XOR is a special case,
  not a second code path.
- Any k of the k + m blocks reconstruct the rest by erasure decoding (every
  RS library in section 10 has decode-with-erasures).
- Membership is explicit in the PARITY payload (seq / K would break at the
  wrap and because PARITY frames consume seqs):

```
first_seq u16, k u8 (actual, 1..fec_k), m u8, idx u8 (0..m-1), block_len u16, reserved u8, parity[block_len]
```

- Sender: members are the k consecutive seqs from `first_seq`, all DATA; no
  other type inside a group (MODE, PING, CLOSE go between groups). A group
  closes early after `FEC_FLUSH = max(FEC_FLUSH_MS, 2 x period)` without a
  new DATA frame (so a slow sensor still fills groups), or before MODE/CLOSE.
  With `fec_m > 0` the DATA payload is capped at `max_payload - 9` so the
  PARITY frame fits. Retransmitted DATA keeps its seq and stays a member.
- Receiver: buffer the last `fec_k + fec_m` frames per stream, RAM
  `(k + m) x (max_payload + 1)` = 10 x 218 = 2180 bytes for k 8, m 2 on the
  mesh path. Decode when k blocks are reachable; deliver through the reorder
  buffer (section 7). Overhead `m / k`, latency up to `k + m` frame periods.

| k | m | Overhead | Recovers | Suits |
|---|---|---|---|---|
| 8 | 2 | 25 % | any 2 of 10 | default for radio streaming |
| 8 | 4 | 50 % | any 4 of 12 | noisy 2.4 GHz |
| 2 | 1 | 50 % | any 1 of 3 | IR edge, low-rate sensors |
| 16 | 2 | 12.5 % | any 2 of 18 | clean link, bandwidth matters |

### 3.4 Header budget

One header everywhere. The mesh fields cost 9 bytes and the field-profile
tags 12: 8 % of a 250-byte frame, 33 % of a 64-byte IR frame. Compressing
the header for IR or point-to-point links was rejected (at most 4 bytes, two
parsers, and IR is bit-rate limited). The 32-bit hop_seq costs 2 bytes over a
16-bit one and removes a reconstruction rule and a replay window at every
wrap (review U2). The nRF24L01+ 32-byte packet is segmented inside its
adapter (C.5), never by shrinking this header.

### 3.5 Counters and sequence numbers

Three counters, two of them persistent across reboots (reserve-ahead: the
NVS value is the next block boundary; at boot the node resumes from it; one
write per block; leaves also keep both in the RTC blob and resume from the
larger of the two values, 4.4):

| Counter | Scope | On the wire | Persistent | Block |
|---|---|---|---|---|
| `txseq` | per node, every transmission (own frames, forwarded frames, each FLOOD_REPEAT copy) | `hop_seq`, full 32 bits | NVS `pl/txseq` | 4096 (about 1000 writes/day at 50 frames/s; the 32-bit space lasts about 2.7 years at that rate, after which the node is re-provisioned: the wrap affects hop freshness only) |
| `preseq` | per node, every originated pre-session frame (SEEK, HELLO, BIND, BIND_ACK, BIND_NAK, MGMT) and every RESUME | full 32 bits as `pre_ctr`, the clear first payload field; header `seq` = low 16 bits for session_id 0 frames | NVS `pl/preseq` | 64 |
| session index | per session and direction: ROC u32 (implicit) << 16 \| `seq` u16, from 0 at BIND_ACK, +1 per frame of any type; retransmitted DATA reuses its index | `seq` | leaf RTC blob only (4.4) | - |

- The 48-bit session index is what the CCM nonce covers (section 8), so a
  frame recorded before a 16-bit wrap is never valid after it. The receiver
  estimates the sender's ROC as in SRTP (RFC 3711, 3.3.1): with `s_l` the
  highest seq received and `roc` the current estimate, a frame uses `roc - 1`
  if `s_l < 32768` and `seq - s_l > 32768`, `roc + 1` if `s_l >= 32768` and
  `s_l - 32768 > seq`, otherwise `roc`; the tag confirms the guess (A.10).
- `hop_seq` gives every transmission per-hop freshness: a neighbour keeps the
  last value per (unit_id, transport) in its link table and drops anything
  not newer, or more than `HOP_MAX_JUMP` (2^16) ahead, before learning or
  forwarding (11.4). `pre_ctr` gives floods and pre-session frames
  end-to-end freshness at relays (ORIGIN table, 11.5) and is the high half
  of the CCM nonce at endpoints (8.3).
- Serial-number arithmetic (RFC 1982) compares the 16-bit `seq`; the 32-bit
  counters are compared as plain unsigned integers. Receivers keep a
  64-entry seen-bitmap below the highest index and drop duplicates.

### 3.6 Receiver validation (normative)

Checks run in this order before any other processing; a failure drops the
frame, increments the counter and sends nothing. Forwarding nodes apply the
Length, Header, SEEK hop field, Version and hop_tag rows; payload rows and the
CCM tag apply at the endpoint that holds the key.

| Stage | Check | Counter |
|---|---|---|
| Length | received length == header + len + (12 if FLAG_AUTH) + 2 + rs_nsym; len <= 229 - rs_nsym without AUTH, 217 - rs_nsym with AUTH | `bad_frame` |
| Header | ttl <= MAX_HOPS; hops < MAX_HOPS; prev_hop and src_id are unit IDs or manager IDs; next_hop is a unit ID or 0xFFFF; dst_id != 0 | `bad_frame` |
| SEEK hop fields | MIN_PATH_MTU (48) <= path_mtu <= (max_frame - rs_nsym) of the link it arrived on; path_cost <= 250 | `bad_frame` |
| Version | endpoints: version in {N, N-1}; forwarders: any version with the frozen prefix | `bad_version` |
| hop_tag | valid under a held K_hop epoch (retired slot: MGMT_REQ only, 8.5); hop_seq newer than the link-table value for (prev_hop, transport) and at most HOP_MAX_JUMP ahead | `hop_tag_fail`, `hop_replay` |
| CCM tag | valid under the key of section 8.3 with `ctr_hi` from the clear `pre_ctr` (session_id 0) or the ROC estimate (session frames, RESUME included) | `auth_fail` |
| SEEK | len 18; caps reserved bits 0; max_frame >= MIN_PATH_MTU; key_epoch is a live epoch | `bad_frame` |
| HELLO | len 28; status 0..1; nonce_s and seek_ctr match an outstanding SEEK | `bad_frame` |
| BIND / BIND_ACK / BIND_NAK | len 17 / 12 / 9; nonces (and hello_ctr) match an OFFERED or BINDING entry; session_id != 0 (BIND) | `bad_frame` |
| MODE | len 13 + descriptor bytes (mode 2: 13 + 40); ch_count 1..16 (mode 0/1); kind 0..1; fmt 0..2 analog, 1..32 digital; scale finite and non-zero, offset finite; period > 0; fec_m 0..4; fec_k 2..16 when fec_m > 0; arq 0..1; keepalive_ms 1000..60000; one full sample <= max_payload - 7 (- 9 more with FEC) | MODE_ACK status 3 or 2 |
| MODE_ACK / ACK / RESUME_ACK / PING / PONG / CLOSE / RESUME | len 2 / 6 / 6 / 4 / 8 / 3 / 5; cum_seq inside the ARQ window | `bad_frame` |
| DATA | config_id known; len == 7 + n_samples x sample bytes (mode 2: 7 + n_samples) | `bad_frame` |
| PARITY | idx < m == fec_m; k 1..fec_k; block_len <= max_payload - 8; first_seq inside the window | `bad_frame` |
| MGMT_REQ / MGMT_RESP | fixed part 17 / 33; MGMT_RESP `req_ctr` equals the node's outstanding request; TLVs (type u8, len u8) within len; section 0..3 | `bad_frame`, `replay_dropped` |

Build the parser as a host-side library and fuzz it (libFuzzer or AFL) with
the Appendix A frames as seeds; it touches no hardware.

---

## 4. Session state machine

```
Sender:   IDLE -> SEEKING -> BINDING -> CONFIGURING -> STREAMING (<-> PARKED) -> CLOSED -> IDLE
Probe:    LISTENING -> OFFERED -> BOUND -> STREAMING (-> PARKED) -> LISTENING   (one record per session, 4.1.12)
```

```
Sender                           Probe A           Probe B
  | SEEK flood (nonce_s) --------->|----------------->|      ttl seek_ttl, under Ke_mesh(E_old)
  |<---- HELLO (nonce_s, nonce_p)  |                  |      under Ke_hello, reverse route
  |<-------------------------------------- HELLO      |      kept as fallback candidate
  | BIND unicast (session_id) ---->|                  |      under Ke_hs; B times out
  |<------------------- BIND_ACK   |
  | MODE (cfg 1, HIGH) ----------->|                         Ke_s2p from here on
  |<------------------- MODE_ACK   |                         Ke_p2s
  | DATA x8, PARITY x2 ----------->|                         one FEC group
  |<------------------------ ACK   |                         ACK_EVERY frames or keepalive
  | MODE (cfg 2, LOW) ------------>|                         switch any time
  | CLOSE (PARK, 300 s) ---------->|                         leaf sleeps
  | RESUME flood ----------------->|                         wake: no new handshake
  |<------------------ RESUME_ACK  |
  | DATA ... --------------------->|
```

### 4.1 Rules

1. SEEK is flooded (`next_hop` 0xFFFF, `ttl` = `pl/seek_ttl`, 11.5) with
   `dst_id` = target group or unit ID, a fresh `nonce_s` (rule 14), the
   sender's caps, `max_frame`, `key_epoch` = its `E_old` (8.5), `proto_minor`
   and `fw_build`. Its payload is in clear but authenticated under
   `Ke_mesh(key_epoch)` so relays can read `pre_ctr` (8.3). SEEK carries no
   session authority. The first SEEK after a cold boot waits
   `rand(0..BOOT_SPREAD_MS)` with `BOOT_SPREAD_MS = 600 x pl/node_count` (30 s
   at 50 nodes); a deep-sleep wake is exempt. The sender keeps the payloads
   of its last 5 SEEK transmissions keyed by `pre_ctr` (90 bytes).
2. Each probe subscribed to the group that holds a pairwise key for the
   sender at `key_epoch` waits `rand(0..HELLO_WINDOW_MS)` and sends HELLO
   unicast along the reverse route installed by the lowest-cost SEEK copy it
   received inside the window (11.4): `pre_ctr` (clear), then encrypted
   under `Ke_hello` (8.2): `seek_ctr` (that copy's `pre_ctr`), `nonce_s`, a
   fresh `nonce_p`, its caps, `max_frame` = min(own `max_frame - rs_nsym`,
   that copy's `path_mtu`), `rssi`, `status` (0 ok, 1 full), that copy's
   `path_cost`, `proto_minor`, `fw_build`. It enters OFFERED with a
   `BIND_TIMEOUT(hops)` timer (rule 10). One OFFERED entry per `src_id`; when
   `PROBE_OFFERS_MAX` (4) entries exist the oldest is replaced. A probe
   without a free record, or without a free stream for a sender that needs
   one (rule 12), still answers with `status` 1 and keeps no state.
3. A probe bound to sender X that receives a new SEEK from X answers HELLO
   like any other and keeps the existing session untouched. Only a BIND that
   decrypts under the new `Ke_hs` replaces the old session with X; a
   replayed or forged SEEK changes nothing.
4. Selection: the first valid HELLO with `status` 0 wins (the user's
   first-acknowledger-wins) and BIND is sent at once. Up to
   `HELLO_CANDIDATES` (4) further HELLOs are kept as fallbacks until the
   session is established; a candidate whose first hop (`prev_hop` of its
   HELLO) is on the penalty list (4.2) ranks last. If every HELLO says FULL
   the sender treats the group as present but busy and backs off
   `rand(0, min(FULL_CAP_S, 60 x 2^n))` seconds (n = consecutive FULL
   results, cap 3600 s) before the next SEEK; n resets on success (review
   H6).
5. BIND is unicast to the chosen probe along the route its HELLO installed:
   `pre_ctr` (clear), then under `Ke_hs`: `hello_ctr` (the chosen HELLO's
   `pre_ctr`), both nonces and the new `session_id`. Both ends derive `Ke_hs`
   and the session keys from the SEEK copy named by `seek_ctr` and the HELLO
   named by `hello_ctr` (8.2), so retries never produce two transcripts. The
   probe replies BIND_ACK (`Ke_hs`) and enters BOUND. Losing probes time out
   of OFFERED (rule 7); nothing on the air cancels an offer early.
6. A BIND whose nonces match no OFFERED entry, or that fails to decrypt, is
   dropped silently. A probe in OFFERED that lost its last free stream since
   its HELLO replies BIND_NAK (reason 1 busy; reason 2 caps mismatch). The
   sender then tries its next candidate, and if none is left restarts SEEK.
7. A probe that hears no valid BIND within `BIND_TIMEOUT(hops)` returns to
   LISTENING. A LISTENING probe ignores any BIND naming it.
8. No usable HELLO within `SEEK_TIMEOUT(n) = SEEK_BASE_MS + rand(0, min(60000,
   600 x 2^n))`, where `SEEK_BASE_MS = HELLO_WINDOW_MS + 2 x seek_ttl x
   HOP_DELAY_MS` (530 ms at ttl 4): resend SEEK with the same `nonce_s` and a
   new `pre_ctr`. The sender always waits long enough for a HELLO to return,
   then jitters, and never gives up: after the cap it floods about once a
   minute. `PL_EVT_NO_PROBE` is raised after the 5th attempt as an event.
   Two consecutive attempts without any HELLO (or, on a leaf, a failed
   RESUME and fallback SEEK) trigger an immediate MGMT_REQ: it is admitted
   under the retired epoch slot and its response carries the key bundle
   that lets a node behind a retirement rejoin (8.5). A probe in OFFERED that hears the same `nonce_s` with a newer `pre_ctr`
   assumes its HELLO was lost and sends HELLO again (new delay, same
   `nonce_p`, new `seek_ctr`).
9. The session starts on BIND_ACK. Without BIND_ACK the sender resends BIND
   every `BIND_RETRY(hops) = max(BIND_RETRY_MS, hops x HOP_DELAY_MS)` up to
   `BIND_RETRIES` (3) times, then falls to rule 6. A probe already BOUND to
   these nonces answers a repeated BIND with BIND_ACK again (idempotent).
10. `BIND_TIMEOUT(hops) = HELLO_WINDOW_MS + (BIND_RETRIES + 2) x
    BIND_RETRY(hops) + 2 x hops x HOP_DELAY_MS`. It must exceed HELLO travel
    + all retries + last BIND travel = `HELLO_WINDOW_MS + hops x HOP_DELAY_MS
    + BIND_RETRIES x BIND_RETRY(hops) + hops x HOP_DELAY_MS`, and does, with
    two retry intervals of margin:

    | hops | BIND_RETRY | BIND_TIMEOUT | needed |
    |---|---|---|---|
    | 1 | 60 | 470 | 350 |
    | 2 | 120 | 890 | 650 |
    | 4 | 240 | 1730 | 1250 |
    | 8 | 480 | 3410 | 2450 |

    On an IR edge link both ends multiply these by `IR_TIME_SCALE` (10); the
    probe knows the link is IR because the SEEK arrived on its IR transport.
11. `session_id`: 1..255, never 0, chosen by the sender from `esp_random()`
    (rule 14) and never equal to any of the last 8 it used (kept in RTC
    memory). Sessions are matched on `(src_id, session_id)` on every
    transport.
12. Capacity (reviews G9, H6): a probe keeps `PL_MAX_SESSIONS` session
    records (keys, index state, replay bitmap, two configs, SRTT: about 600
    bytes each) and `PL_MAX_STREAMS` stream buffers (FEC + reorder, about
    4.7 KB each). A stream is taken only by a session with `arq` 1 or
    `fec_m` > 0 when its first DATA arrives, and released when the reorder
    buffer is empty, no FEC group is open and `REORDER_MS` has passed since
    the last DATA; sessions with `arq` 0 and `fec_m` 0 deliver in arrival
    order with no stream. Parked sessions hold a record and no stream.
    "Full" (rule 2) means no free record, or no free stream for a sender
    whose caps include ARQ or FEC. Probes allocate no ARQ buffer. Sizing:
    records >= senders served (parked leaves included); streams >= senders
    with ARQ/FEC streaming at the same time. The sink probe (12.4) uses
    `PL_MAX_SESSIONS` = `node_count` and `PL_MAX_STREAMS` 8.
13. Frames for an unknown `(src_id, session_id)` are dropped and counted. In
    the bench profile the receiver MAY reply CLOSE (reason 2) once per
    second per peer; in the field profile nothing is sent (R10). A sender
    wanting fast detection of a rebooted probe sets FLAG_ACK_REQ on one frame
    per keepalive and closes after `ARQ_MAX_RETRIES` unanswered requests.
14. Nonces: `esp_random()` is used only while WiFi is running, or with
    `bootloader_random_enable()` on nodes without RF; every nonce is
    `SHA-256(esp_random() || preseq || txseq || unit_id ||
    esp_timer_get_time())[0..3]`. Key uniqueness does not depend on it: the
    handshake transcript, including both `pre_ctr` values, enters every key
    (8.2).
15. Half duplex (IR, nRF24): a probe starts its HELLO delay only after the
    SEEK frame has fully ended plus the carrier guard time.

Why three messages, not two: with SEEK + ACK only, two probes that both answer
both believe they own the session. BIND tells the winner it won; the others
time out.

### 4.2 Liveness, failover, penalties

- Cadence is a session parameter, `keepalive_ms` in MODE (default 5000).
  The probe sends ACK every `ACK_EVERY` (8) frames, on FLAG_ACK_REQ, or when
  `keepalive_ms` has passed since its last own frame and it has received
  something; it never sends PING. The sender sends PING when no ACK has
  arrived for `keepalive_ms`. `SESSION_TIMEOUT = max(4 x keepalive_ms, 8 x
  SRTT)` on both ends. Airtime: 2 frames per keepalive per session, about
  4.8 % of a 1 Mbps collision domain for 40 two-hop sessions at the default
  (section 9 table).
- Sender failover: after `SESSION_TIMEOUT` without ACK or PONG the sender
  sends CLOSE twice, waits `rand(0..RESEEK_JITTER_MS)`, and re-SEEKs the
  group. Any other probe can take over.
- Penalty list: on each such timeout the sender records the route's first
  hop. For `PENALTY_MS` (60 s) HELLO candidates via that hop rank last; three
  timeouts through the same first hop within 10 minutes exclude it for 10
  minutes. This stops a re-SEEK from landing on the same black hole.
- Probe side: after `SESSION_TIMEOUT` without any frame from the sender the
  probe frees the record (parked sessions excepted, 4.4).
- CLOSE is not acknowledged except CLOSE(PARK) (4.4); the timeouts cover a
  lost CLOSE. `MODE_RETRY` = the session RTO (section 7), not a fixed 100 ms.

### 4.3 Race catalogue

| Scenario | Rule |
|---|---|
| Two probes answer the same SEEK | BIND is unicast to one; the other times out (4.1.5, 4.1.7) |
| Two senders SEEK one group at once | Multi-session probes serve both; a full probe says FULL or BIND_NAKs (4.1.2, 4.1.6) |
| Bound probe hears a SEEK from its own sender (replay or reboot) | HELLO answered; the old session is replaced only by a BIND that decrypts under the new Ke_hs (4.1.3) |
| BIND or BIND_ACK lost | Retries inside BIND_TIMEOUT at every hop count; idempotent BIND_ACK (4.1.9-10) |
| HELLO lost; SEEK retried | Same nonce_s with newer pre_ctr triggers a new HELLO; seek_ctr / hello_ctr echoes pick one transcript (4.1.5, 4.1.8) |
| Late BIND after BIND_TIMEOUT | Ignored by a LISTENING probe (4.1.7) |
| seq wraps at 65535 | Serial arithmetic for ordering; 48-bit index with implicit ROC in the CCM nonce for replay (3.5, 8) |
| Two senders pick the same session_id | Sessions keyed by (src_id, session_id) (4.1.11) |
| Replayed SEEK / HELLO / BIND / MGMT_RESP | pre_ctr freshness at relays; nonce and ctr echoes at endpoints; transcript-bound keys (8.4) |
| 50 nodes reboot together | Boot holdoff for SEEK and MGMT, full-jitter backoff, jittered re-SEEK (4.1.1, 4.1.8, 4.2, 11.10) |
| Probe hears SEEK copies via two paths | Dedup; lowest-cost copy inside the window sets route, path_mtu and HELLO fields (11.4) |
| Relay on a session path dies | SESSION_TIMEOUT -> re-SEEK installs new routes; penalty list avoids the dead first hop (4.2) |
| Relay on the management path dies | Send failures and the response timeout delete the route; the next MGMT_REQ floods (11.6, 11.10) |
| Every probe of a group is FULL | Exponential backoff to a 1 h cap, not a flood per minute (4.1.4) |
| Node returns holding only a retired epoch | Its MGMT_REQ is accepted under the retired slot, the bundle is epoch-independent, it rejoins (8.5) |
| Origin hears its own flood echoed | Dropped by its own dedup entry, no alarm (11.5) |
| Leaf wakes after a park | RESUME flood re-installs routes both ways (4.4, 11.4) |

### 4.4 Parked sessions and leaves

Leaves are battery nodes that deep-sleep between reports. They are senders
only, never serve a group (except the update window below) and never
forward; non-leaf nodes MUST be mains or solar powered (11.1).

- Park: the leaf sends CLOSE with reason 6 (PARK) and `park_s` (1..3600),
  with FLAG_ACK_REQ, up to 3 times until ACKed. The probe keeps the session
  record for `park_s + PARK_GRACE_S` (60) and stops expecting liveness; no
  stream buffer is held.
- RTC blob (`RTC_DATA_ATTR`, about 200 bytes, CRC32-protected): probe_id,
  session_id, route hops and first-hop address, `Ke_s2p`, `Ke_p2s`,
  `key_epoch`, the active `pl_mode_t`, ROC/seq reserved ahead by 64 (written
  before transmitting), `preseq` and `txseq` reserved ahead, SRTT, the last 8
  session_ids. The blob is used only when `esp_reset_reason() ==
  ESP_RST_DEEPSLEEP` and its CRC matches; otherwise the leaf does a full
  handshake. Counters resume from the larger of the RTC and NVS reserves,
  and leaves keep writing NVS block boundaries (3.5). Reserving ahead means a
  reset can never reuse a CCM nonce.
- Wake: the leaf floods RESUME (type 0x31, clear `pre_ctr` and `config_id`,
  authenticated under `Ke_s2p`) with `ttl = min(hops + 1, MAX_HOPS)`. Relays
  treat it as a flood (ORIGIN freshness on its `pre_ctr`, dedup, budget) and
  it re-installs reverse routes; the probe verifies the tag and the session
  index, replies RESUME_ACK on the reverse route, which installs the forward
  routes (11.4), and the leaf sends DATA. Timeout `BIND_TIMEOUT(hops)`; one
  retry with a new `pre_ctr` and a new session seq (an identical retry would
  be a dedup hit), then a full SEEK.
- Management on wake: every `MGMT_EVERY_WAKES` (10) wakes, and on the first
  wake after any non-deep-sleep boot (an update included), the leaf sends
  MGMT_REQ to its manager after DATA and stays awake for the reply chain
  (11.10). This is how a leaf receives keys and time and reports its battery;
  nothing is pushed to a sleeping node, so a bundle waits at most 10 wakes.
  An IR leaf's manager is its attached node (11.11).
- Update window (review H7): a leaf that receives MGMT command 3 skips its
  next park, subscribes to its own unit ID as a probe for `BULK_WINDOW_S`
  (120) and, once bound, stays awake until the BULK session closes or times
  out (minutes for a 1 MB image, 12.7); then it parks. Its image is marked
  valid by one MGMT_RESP received before the first park after the update.
- Power: battery voltage is checked before the radio starts; below
  `VBAT_MIN` the wake is skipped and reported in the next MGMT section 0.
  Lowest TX power that closes the link; a bulk capacitor for primary cells.
  Wake budget (estimate, measure): Secure Boot check 100-300 ms + radio
  start 120 ms + RESUME round trip 100-500 ms + DATA, 0.4-0.9 s at about
  100 mA, roughly 0.02 mAh per wake: about 2 months on 2000 mAh at one
  report per minute, over a year at one per five minutes.

---

## 5. Message types

Every session_id 0 frame and RESUME starts its payload with the clear
`pre_ctr` u32 (marked P); the rest is AES-CCM ciphertext under the key shown,
except SEEK and RESUME, whose whole payload is in clear and authenticated.

| Type | Name | Dir | Key (8.3) | Payload |
|---|---|---|---|---|
| 0x01 | SEEK | S -> group (flood) | Ke_mesh(E_old), clear | P, nonce_s u32, caps u16, max_frame u16, key_epoch u8, proto_minor u8, fw_build u32 (18) |
| 0x02 | HELLO | P -> S | Ke_hello | P; seek_ctr u32, nonce_s u32, nonce_p u32, caps u16, max_frame u16, rssi i8 (-128 = unknown), status u8 (0 ok, 1 full), path_cost u8, proto_minor u8, fw_build u32 (28) |
| 0x03 | BIND | S -> P | Ke_hs | P; hello_ctr u32, nonce_s u32, nonce_p u32, session_id u8 (17) |
| 0x04 | BIND_ACK | P -> S | Ke_hs | P; nonce_s u32, nonce_p u32 (12) |
| 0x07 | BIND_NAK | P -> S | Ke_hs | P; nonce_s u32, reason u8 (1 busy, 2 caps mismatch) (9) |
| 0x05 | MODE | S -> P | Ke_s2p | 6.1 |
| 0x06 | MODE_ACK | P -> S | Ke_p2s | config_id u8, status u8 (0 ok, 1 unsupported, 2 too big, 3 bad arg) |
| 0x10 | DATA | S -> P | Ke_s2p | 6.2 |
| 0x11 | PARITY | S -> P | Ke_s2p | 3.3 |
| 0x12 | ACK | P -> S | Ke_p2s | cum_seq u16, bitmap u32 (seqs cum_seq+1 .. +32, bit set = received) |
| 0x20 | PING | S -> P | Ke_s2p | t_tx_us u32 |
| 0x21 | PONG | P -> S | Ke_p2s | t_echo_us u32, t_local_us u32 |
| 0x30 | CLOSE | either | Ke dir | reason u8 (0 normal, 1 timeout, 2 unknown session, 3 application, 4 auth failure, 5 reboot, 6 park, 7 bulk complete), park_s u16 |
| 0x31 | RESUME | S -> P (flood) | Ke_s2p, clear | P, config_id u8 (5) |
| 0x32 | RESUME_ACK | P -> S | Ke_p2s | cum_seq u16, bitmap u32 |
| 0x40 | MGMT_REQ | node -> manager | K_mgmt | P; 11.10 (fixed 17) |
| 0x41 | MGMT_RESP | manager -> node | K_mgmt | P; 11.10 (fixed 33) |

"Ke dir" is the directional session key of whoever sends (`Ke_s2p` from the
sender, `Ke_p2s` from the probe). Every frame's `hop_tag` is under `K_hop`.

caps (u16): 0 HIGH, 1 LOW, 2 ARQ, 3 AUTH, 4 group FEC, 5 RELAY (clear on
leaves), 6 MULTI (probe serves several sessions), 7-15 reserved. A session
uses the intersection of both ends' caps; the transcript (8.2) binds both
values, so neither end can be fooled about the other's. In the field profile
a probe drops SEEKs that fail the `Ke_mesh` tag and ignores senders whose
caps lack AUTH.

`max_frame` in SEEK is the sender's own; HELLO's is min(probe's own `max_frame
- rs_nsym`, the chosen SEEK copy's `path_mtu`); the session uses min(sender's
own `max_frame - rs_nsym`, HELLO `max_frame`) = the path MTU (11.3). SEEK and
RESUME are flooded; MGMT_REQ is flooded when the node has no route to its
manager; everything else is unicast hop by hop.

Probes never send DATA. Only the sender chooses the resolution mode.

---

## 6. Data and resolution modes

### 6.1 MODE frame

```
config_id      u8    1..255 (never 0), increments on every change, wraps to 1
mode           u8    0 = HIGH, 1 = LOW, 2 = BULK (12.7, update images)
ch_count       u8    1..16 (0 in mode 2)
period         u32   nominal sample period, us (flags bit0 = 0) or ms (bit0 = 1)
fec_k          u8    2..16 (ignored if fec_m = 0)
fec_m          u8    0 = no group FEC, else 1..4
arq            u8    0 = fire-and-forget, 1 = retransmit on ACK gaps
flags          u8    bit0 period unit; bits 1-7 reserved, 0
keepalive_ms   u16   ACK / PING cadence, 1000..60000 (default 5000)
mode 0/1, per channel:
  kind         u8    0 = digital, 1 = analog
  fmt          u8    analog: 0 uint32, 1 int32, 2 float32; digital: number of lines 1..32
  [LOW analog only] scale f32, offset f32
mode 2:          bulk_size u32, sha256[32], fw_build u32
```

- MODE must fit one frame (no fragmentation anywhere). Fixed part 13 bytes;
  16 LOW analog channels need 173, fine on every mesh path (max payload
  217). On the IR edge link (max payload 25 with AUTH) MODE fits one channel
  of any kind (LOW analog: 23 bytes); IR leaves use one channel, or one
  channel per session.
- One complete sample must fit a DATA frame, else MODE_ACK status 2.
- MODE may be sent at any time after BIND_ACK; DATA keeps the old
  `config_id` until MODE_ACK; MODE is resent every `MODE_RETRY` (= RTO) until
  acknowledged; the probe re-acks an active `config_id` without side effects
  and keeps the last two configs.

### 6.2 DATA payload

```
config_id   u8
status      u8    bit0 CLIP, bit1 OVERRUN (samples dropped before this frame), bit2 INVALID present,
                  bit3 UNSYNCED (no network time), bits 4-7 reserved
t_first_us  u32   first sample, sender session clock (6.5); mode 2: byte offset into the image
n_samples   u8    1..255; mode 2: number of image bytes that follow
samples     n_samples x (all channels, descriptor order), sample-major; mode 2: raw bytes
```

| Channel kind | HIGH | LOW |
|---|---|---|
| Analog uint32 / int32 | 4 bytes raw | 2 bytes int16 q, value = offset + q x scale |
| Analog float32 | 4 bytes IEEE-754 LE, NaN/Inf allowed | 2 bytes int16 q; NaN/Inf -> INVALID |
| Digital | 4 bytes, line i = bit i | ceil(lines / 8) bytes, line i = byte i/8 bit i%8 |

Digital is lossless in both modes; resolution applies to analog. LOW
quantization in float32: `q = clamp(round((v - offset) / scale), -32767,
32767)`, CLIP set when clamped; `q = -32768` means INVALID. For a range
`[min, max]` use `scale = (max - min) / 65534`, `offset = (max + min) / 2`
(0..3.3 V: 50.36 uV per step). Saturate, never wrap, and flag it.

### 6.3 What fits in one frame

Data bytes per frame = path_mtu - 21 (header + CRC) - 7 (DATA header) - 12
(AUTH) (- 9 more with fec_m > 0). Example: 4 analog channels.

| Link / path | path_mtu | Data bytes (AUTH) | HIGH / LOW samples per frame | bench, no AUTH |
|---|---|---|---|---|
| ESP-NOW, nRF24, UDP, or any path of them | 250 | 210 | 13 / 26 | 222: 13 / 27 |
| Path with a UART hop (250 - 8) | 242 | 202 | 12 / 25 | 214: 13 / 26 |
| IR edge link (64 - 6) | 58 | 18 | 1 / 2 | 30: 1 / 3 |

Throughput (estimates): ESP-NOW at 1 Mbps about 100 kbit/s goodput (50 full
frames/s per collision domain); nRF24 at 2 Mbps 30-60 kbit/s per link (C.5);
IR about 3 frames/s. Keep the frame rate under the carrier's limit with
margin for PARITY and retransmissions.

### 6.4 BLE phone link

BLE is used only for commissioning and local diagnostics from a phone, and
only while the node is in maintenance mode: the mesh radio is stopped, BLE
starts, the phone connects and exchanges MGMT frames (11.10) over one GATT
characteristic pair under `K_mgmt(node, holder)`, where the holder is a
recovery ID 0x0003..0x000F with its own pair key per device (8.2). A phone
is a manager for commands and time only; it carries key bundles as opaque
bytes and cannot author keys (8.6). Entering maintenance mode: a button, or a
MGMT command 1 from the gateway; it ends on command, or after
`MAINT_TIMEOUT_S` (600) without a frame, and the mesh restarts. BLE and
ESP-NOW never run at the same time on one chip (review G13). Fail closed
(review U7): a field node that holds no keys enters only the UART
provisioning wait of 12.2; BLE requires at least one stored recovery-holder
key; field builds never erase NVS automatically, log such a state in the RTC
reset log and report it in the next MGMT section 0.

### 6.5 Timestamps and network time

- Session clock: each end starts a 32-bit microsecond counter at BIND_ACK
  (or RESUME_ACK). Receivers extend to 64 bits assuming consecutive DATA
  frames are less than 2^31 us apart. Crystal drift is 20-40 ppm (estimate);
  the receiver can trust `t_first_us` per frame and resample, or fit the
  sender's clock from PING/PONG pairs.
- Network time: every node syncs with its manager through MGMT_REQ/RESP
  (NTP's four timestamps, 11.10) every `MGMT_PERIOD_S` (600 s); a node slews
  at most `TIME_MAX_SLEW_PPM` (500) and steps only when the offset exceeds
  1 s. Without a sync in `3 x MGMT_PERIOD_S` the node sets DATA status bit 3
  (UNSYNCED). A probe stamps records in UTC by its own synced clock plus the
  fitted sender offset; accuracy over radio hops is a few ms (estimate).
  Network time drives no key event (8.5).

---

## 7. Reliability modes

| Setting | Use when | Behaviour |
|---|---|---|
| arq 0, fec_m 0 | UART, short cable | CRC + RS only; lost frames stay lost; no stream buffer |
| arq 0, fec_m 2, fec_k 8 | Streaming telemetry over radio | Any 2 losses in 10 rebuilt, no retry latency |
| arq 1, fec_m 2, fec_k 8 | Data that must arrive | FEC first, ACK-bitmap gaps resent |
| arq 1, fec_m 0 | Low-rate sensors, leaves, BULK | Pure ARQ |

- Sender keeps the last `ARQ_WINDOW` (24; 4 on leaves) encoded DATA frames
  (ciphertext and tag as sent, so a retransmission is byte-identical under
  the same nonce; only the hop fields, hop_tag and CRC are rebuilt). 24 DATA
  frames span about 30 seqs with k 8 / m 2 (more if control frames fall
  between groups), inside the 32-bit ACK bitmap.
- A seq reported missing and older than the RTO is retransmitted up to
  `ARQ_MAX_RETRIES` (3) times, then reported as a gap. `RTO = max(ARQ_RTO_MS,
  2 x SRTT)`; SRTT is seeded by the BIND round trip and updated as
  `7/8 SRTT + 1/8 RTT` from PING/PONG and FLAG_ACK_REQ/ACK pairs.
  `REORDER_MS = max(500, 4 x SRTT)`.
- `cum_seq` is the highest seq such that every seq up to it is received,
  recovered, or expired from the reorder buffer; the receiver cannot know
  whether a missing seq was DATA, so the sender retransmits cleared-bit seqs
  it still holds as DATA and ignores the rest; `on_gap()` counts may include
  non-DATA seqs.
- Delivery is in seq order through a reorder buffer of `fec_k + fec_m` frames
  (4 without FEC) or `REORDER_MS`; a frame still missing when its slot
  expires is reported as `on_gap(first_seq, count)`. Stream buffers are held
  and released per 4.1.12.
- Queues: the transport RX queue (`RX_QUEUE_FRAMES` 16) is filled with
  timeout 0 and a full queue counts `rx_queue_drop`. The forwarding queue
  (`RELAY_QUEUE_FRAMES` 8) has two classes: when full, a control frame (any
  type but DATA/PARITY) evicts the oldest DATA/PARITY frame
  (`relay_drop_queue_data`); a control frame is dropped only when the queue
  holds nothing else (`relay_drop_queue_ctrl`).

---

## 8. Security

Requirements with their mechanism. Attacker classes: an outsider in radio
range or on the LAN (no keys); a thief who removes one node, the gateway
included, and reads its flash; a node holding the mesh key (any node, or a
captured one before it is revoked). Reviews F2, F17, F22, S1-S20, G1, G3, G4,
G8, T1-T24, H1-H7 and U1-U19 are addressed here and in 11.8.

### 8.1 Requirements

| Req | Statement | Mechanism |
|---|---|---|
| R1 | Keys at rest MUST be protected so that reading a node's flash costs a lab attack, not a cable. | Field profile MUSTs and the provisioning sequence (12.1, 12.2); `pl_init` verifies them. Revocation (8.5) bounds what a successful lab attack yields. |
| R2 | A captured node, the gateway included, MUST NOT allow derivation of other pairs' keys, nor impersonation of another unit ID at the session or management layer, nor authoring of key material. | Per-pair keys from the offline `K_site`; bundles encrypted to a per-node `K_node` that no manager holds (8.2, 8.6). Mesh-layer identity (routes, flood budgets) rests on the shared mesh key and is a stated limitation (11.8). |
| R3 | Every frame an endpoint acts on MUST be authenticated and encrypted end to end, including its sequence position, with nothing the receiver needs for the nonce hidden inside the ciphertext. | AES-128-CCM over the end-to-end header, the 48-bit index or clear `pre_ctr`, and the payload (8.3). |
| R4 | A forwarding node MUST NOT change any table because of a frame it has not authenticated as fresh, at any counter value. | `hop_tag` under `K_hop` with the full 32-bit `hop_seq` on the wire, checked before any state change (8.4, 11.4). |
| R5 | A frame MUST NOT be accepted twice, and a recorded frame MUST NOT be accepted later, within or across sessions, at endpoints or relays, including after a reboot. | 48-bit session index; 32-bit `pre_ctr`; `hop_seq`; persistent counters; request/response matching for every pre-session exchange (3.5, 8.4). |
| R6 | Session authority MUST NOT be obtainable from the mesh key. | HELLO under `Ke_hello`, BIND/BIND_ACK/NAK under `Ke_hs`, session frames under directional keys, all from the pair key and the handshake transcript (8.2). |
| R7 | Keys MUST be rotatable and nodes revocable without a site visit, and a node that was unreachable through a rotation MUST be able to recover through its manager path. | Two live epochs plus a retired slot accepted for management requests; bundles pulled by each node; explicit tool-issued retirement (8.5). |
| R8 | Management MUST be authenticated between a node and its listed managers only, and a manager MUST NOT be able to install keys. | `K_mgmt` from the pair key of node and manager; managers author commands and time only; keys arrive in `K_node` bundles the manager relays opaquely (8.6, 11.10). |
| R9 | The field profile MUST NOT run unauthenticated, MUST fail closed when keys are missing, and test keys MUST NOT work. | `pl_init` refuses a field build without keys or without the at-rest state of R1 and waits for UART provisioning; the tool refuses the Appendix A `K_site`; firmware rejects degenerate keys and the test `K_mesh(E)` hashes (12.1). |
| R10 | A node MUST NOT answer a frame that fails any check. | Drop, count, rate-limited log; no CLOSE, NAK or error (no oracle). |

### 8.2 Keys

HKDF-SHA256 (RFC 5869) throughout; `||` is concatenation; integers
little-endian as on the wire; S = sender unit ID, P = probe unit ID, N = a
node, M = a manager ID (0x0001 gateway, 0x0002 station, 0x0003..0x000F
recovery holders), in every label.

| Key | Formula | Held by |
|---|---|---|
| `K_site` | 32 random bytes, generated and kept by the offline provisioning tool | nobody in the field |
| `K_mesh(E)` | `HKDF(IKM = K_site, salt = "ProbeLink-mesh", info = E u8, L = 32)` | every node, epochs E_old and E_new plus one retired |
| `K_hop(E)` | `Expand(Extract(salt = "ProbeLink-v1", IKM = K_mesh(E)), "hop", 32)`; hop_tag key | derived from K_mesh(E) |
| `Ke_mesh(E)` | `Expand(Extract("ProbeLink-v1", K_mesh(E)), "mesh-enc", 16)`; SEEK CCM key | derived from K_mesh(E) |
| `K_pair(A, B, E)` | `HKDF(K_site, "ProbeLink-pair", min(A,B) u16 \|\| max(A,B) u16 \|\| E u8, 32)` | A and B only; includes pairs with manager IDs |
| `K_node(N)` | `HKDF(K_site, "ProbeLink-node", N u16, 32)`, provisioned once at the bench, never rotated, never given to any manager | node N and the tool |
| `Kb(N)` | `Expand(Extract("ProbeLink-v1", K_node(N)), "bundle", 16)`; bundle CCM key | derived from K_node(N) |
| `PRK` | `Extract(salt = "ProbeLink-v1", IKM = K_pair(S, P, key_epoch))` | S, P |
| `T0`, `T` | `T0 = SHA-256(SEEK e2e header \|\| SEEK payload)` of the SEEK copy named by `seek_ctr`; `T = SHA-256(the same \|\| HELLO e2e header \|\| HELLO plaintext payload)` of the HELLO named by `hello_ctr` | S, P |
| `Ke_hello` | `Expand(PRK, "hello" \|\| S \|\| P \|\| T0, 16)` | S, P (derivable before HELLO arrives) |
| `Ke_hs` | `Expand(PRK, "hs" \|\| S \|\| P \|\| T, 16)` | S, P |
| `Ke_s2p`, `Ke_p2s` | `Expand(PRK, "s2p" \|\| S \|\| P \|\| session_id u8 \|\| T, 16)`, same with "p2s" | S, P |
| `K_mgmt(N, M, E)` | `Expand(Extract("ProbeLink-v1", K_pair(N, M, E)), "mgmt" \|\| N \|\| M, 16)` | node N and manager M |
| edge keys | on an `edge_only` link between leaf L and node A: `K_hop_edge = Expand(Extract("ProbeLink-v1", K_pair(L, A, E_prov)), "edge-hop", 32)`, `Ke_edge = Expand(..., "edge-enc", 16)`, replacing `K_hop` and `Ke_mesh` on that link; `E_prov` is the provisioning epoch and this pair key is never retired | L and A |

- The transcript binds caps, `max_frame`, `key_epoch`, `proto_minor`, both
  nonces and both `pre_ctr` values into every key, so the two ends either
  agree on all of them or derive different keys and the handshake fails
  closed. HELLO names the SEEK copy it answers (`seek_ctr`) and BIND names
  the HELLO it accepts (`hello_ctr`), so retries never leave the two ends
  with different transcripts (review H8). Persistent `pre_ctr` values make
  key uniqueness deterministic.
- The manifest lists each node's peers (default: all nodes, 49 x 32 bytes per
  epoch at 50 nodes), its managers and its recovery holders. A probe answers
  only senders it holds a pair key for; a node accepts MGMT only from listed
  managers and holders.
- A captured node yields its `K_mesh` epochs, `K_node` and its own pair
  keys: it can impersonate itself, forward, drop and misroute as a node,
  originate floods within the budgets, and act under other IDs at the mesh
  layer (11.8). It cannot derive any other `K_pair` or `K_node`, hence no
  other session, management or bundle key (R2). A captured gateway yields
  the same for ID 0x0001: its own pair keys and the opaque bundles it stores.
  Recovery is revocation plus an epoch bump (8.5); a captured manager is
  replaced by a bundle TLV 0x07 (8.6).
- Bench profile: a single `pl/net_key` MAY stand in for `K_site` on the
  device, with everything derived locally. Not permitted in the field.

### 8.3 One construction: AES-CCM end to end, HMAC per hop

Every frame's end-to-end part is protected by AES-128-CCM with an 8-byte tag
(mbedtls, hardware AES on all ESP32 variants); every frame's hop part by
HMAC-SHA256 truncated to 4 bytes. HMAC-SHA256 is also the HKDF primitive.

- Nonce (13 bytes): `dir u8 || src_id u16 || dst_id u16 || session_id u8 ||
  ctr_hi u32 || seq u16 || 0x00`. `dir` is 0 for sender -> probe and node ->
  manager, 1 for the reverse. `ctr_hi` is the ROC for session frames
  (RESUME included) and the high 16 bits of the clear `pre_ctr`,
  zero-extended, for session_id 0 frames. Every (key, nonce) pair is unique
  because the index never repeats under a key (3.5).
- Clear prefix: session_id 0 frames and RESUME carry `pre_ctr` as the first
  4 payload bytes in clear; SEEK and RESUME carry their whole payload in
  clear. The receiver takes `ctr_hi` from that field, so no state is needed
  to form the nonce (reviews H2, U3). The clear bytes are appended to the
  AAD; the rest of the payload is the ciphertext.
- AAD: `e2e_header || ctr_hi u32 || clear prefix`, where `e2e_header` is
  bytes 0..5 of the header plus `session_id`, `seq`, `len` (10 bytes).
- Keys per type are in the section 5 table. SEEK uses `Ke_mesh(key_epoch)`:
  it carries no authority and must be verifiable by a probe that shares no
  pair key yet. RESUME uses `Ke_s2p` of the parked session; relays verify
  only its hop_tag. On an `edge_only` link `Ke_edge` and `K_hop_edge`
  replace `Ke_mesh` and `K_hop` (8.2).
- `hop_tag = HMAC-SHA256(K_hop(E), frame[0 .. end of auth_tag])[0..3]`,
  recomputed by every transmitter (the hop fields change). The receiver tries
  its held epochs and records which one verified for that neighbour (8.5).
  32 bits is enough: a forged hop_tag gains at most one table entry and the
  attempt rate is bounded by airtime.

### 8.4 Freshness and replay windows

- Session frames: per session and direction the receiver keeps the highest
  48-bit index and a 64-entry seen-bitmap below it; accept iff newer than the
  highest or within the window and unseen. Retransmitted DATA (same index,
  byte-identical ciphertext) is dropped as a duplicate by the ARQ layer before
  this check. Across sessions a new key makes old frames fail; within a
  session the ROC makes frames from a previous 16-bit cycle fail.
- Pre-session frames are request/response pairs, and freshness at the
  endpoint comes from matching, which survives reboots because the matching
  state is created by the node's own request: HELLO must match an
  outstanding SEEK (`nonce_s`, `seek_ctr`), BIND an OFFERED entry (`nonce_p`,
  `hello_ctr`), BIND_ACK/NAK a BINDING entry, MGMT_RESP the node's single
  outstanding MGMT_REQ (`req_ctr`, authenticated inside the encrypted payload),
  RESUME the parked session's index (review U4). The manager alone keeps a
  per-node `last pre_ctr` for MGMT_REQ (RAM, 64 entries); after a manager
  reboot a replayed request costs one rate-limited response that no node is
  waiting for. Relays apply the ORIGIN rule (11.5) to floods. Because
  `pre_ctr` is persistent and 32 bits wide on the wire, a recording never
  becomes "newer" again.
- Hop freshness: every neighbour keeps the last 32-bit `hop_seq` per
  (unit_id, transport) and drops any frame not newer than it, or more than
  `HOP_MAX_JUMP` (2^16) ahead, before learning or forwarding (11.4). The
  value is on the wire and under the hop_tag, so there is no reconstruction
  and no wrap inside the counter's 2.7-year life (review U2). A link address
  is replaced only by such a fresh frame (11.9). Known limitation: after
  `LINK_TTL_MS` expiry one recorded frame can be re-admitted once, until the
  real neighbour next transmits; it cannot change an existing route.
- Cost: two HMACs plus one CCM per forwarded frame, tens of microseconds each
  on ESP32 hardware (estimate).

### 8.5 Epochs, rotation, revocation and recovery

State per node: two live epochs, `E_old` and `E_new` (`E_new` = `E_old` or
`E_old + 1`), and one retired slot holding the most recently retired epoch
for `KEY_RECOVERY_S` (30 days of uptime, counted from the retirement; NVS
`pl/epoch_old`, `pl/epoch_new`, `pl/epoch_retired`, `pl/mesh_key/<E>`,
`pl/pair/<id>/<E>`). The IR edge pair key is outside this scheme (8.2).

| Rule | Statement |
|---|---|
| Accept | hop_tag verifies under any live epoch for any frame; under the retired epoch only for frames of type MGMT_REQ (flood or unicast). SEEK decrypts under `Ke_mesh(key_epoch)` for any live epoch; the handshake uses `K_pair(S, P, key_epoch)`. MGMT decrypts under `K_mgmt` of the epoch the request arrived in; the manager keeps the retired epoch's pair keys for `KEY_RECOVERY_S` too. |
| Transmit | everything under `E_old`: SEEK `key_epoch`, flood hop_tags, the pair key for new handshakes, `K_mgmt` for a node's own requests. Exception: a unicast hop_tag uses the epoch last verified from `next_hop` (link table), which is how a reply reaches a node that is behind. |
| Receive E+1 | a bundle (8.6) with `E_new + 1`: install it as `E_new`; `E_old` is unchanged. A bundle for `E_new + 2` or beyond is rejected (the tool never issues one). |
| Retire | only on a bundle TLV 0x06 naming `E_old`: `E_old` moves to the retired slot, `E_new` becomes `E_old`. Never on a timer. |
| Tool pacing | the tool issues RETIRE(`E_old`) when every reachable non-revoked node's MGMT section 0 reports `E_new` held, with a wait cap (24 h for a revocation, operator-chosen otherwise), and lists the unreached nodes; a new epoch only after the previous RETIRE. Unreached nodes recover through the retired slot (below) within `KEY_RECOVERY_S`, or by the UART station after it. A dead node therefore never blocks rotation. |
| Revoke | a bundle TLV 0x03 deletes the named IDs' pair keys at once (sessions with them, live or parked, are closed) and marks the accompanying `E_new` as a revocation epoch; the revocation epoch is strictly above every epoch ever issued to the revoked node (tool rule, review U8). After RETIRE of the old epoch the revoked node holds nothing live; until then it keeps mesh-layer (not session or management) access, bounded by the pacing cap. |
| Recover | a node that returns holding only the retired epoch, or whose handshakes fail twice (4.1.8), floods MGMT_REQ under it; neighbours accept it through the retired slot, forward it re-tagged under their `E_old`, the manager answers under the epoch it arrived in, the last relay re-tags the MGMT_RESP under the epoch it verified from that neighbour, and the bundle inside is under `K_node`, independent of epochs. The node installs the live epochs and rejoins without a visit (reviews H1, U5). A revoked node's request under the retired epoch reaches the manager and dies there (pair key deleted), bounded by the flood budget. |

Why this converges: every node transmits under `E_old`, which all hold until
the tool has seen every node report the next epoch; retirement is an explicit
decision, not a timer; the retired slot is the door back in for stragglers.
A node absent past `KEY_RECOVERY_S` or two retirements is re-provisioned by
cable (12.2).

### 8.6 Key bundles

A bundle is produced only by the offline tool, for one node, and is opaque
to every manager (reviews H3, U1).

```
bundle     bundle_no u32 | AES-128-CCM(Kb(N), nonce, AAD, TLVs) | ccm_tag[8]
nonce      0x02 || N u16 || bundle_no u32 || 0x00 x 6        (13 bytes; disjoint from frame nonces by the leading 0x02)
AAD        "PLB1" || N u16 || bundle_no u32
TLVs       type u8, len u8, value:
  0x01     K_mesh: epoch u8, key[32]
  0x02     pair key: unit_id u16 (a node, manager or recovery holder), epoch u8, key[32]
  0x03     revoke: unit_id u16 (sessions with it are closed, pair keys deleted, ID refused until a later 0x02)
  0x06     retire: epoch u8 (must equal the node's E_old)
  0x07     managers: n u8, unit_id u16 x n (replaces pl/managers; also how a captured gateway is replaced)
```

- `bundle_no` is strictly increasing per node (NVS `pl/bundle_no`, one write
  per accepted bundle); a bundle with a lower or equal number, or a failed
  tag, is dropped and counted (`bundle_fail`).
- Transport: MGMT_RESP TLV 0x05 carries `bundle_no u32, idx u8, total u8,
  bytes`. The node asks for chunk `idx` with the `page` field of MGMT_REQ and
  the response echoes it; chunks are reassembled in order, the whole bundle
  is verified once complete, and only then are its TLVs applied, in order.
  A bundle of 50 pair keys is about 1.9 KB, ten chunks on a 250-byte path.
- Managers (gateway, station, phones) store bundles as bytes, hand out
  chunks, and may author only TLV 0x04 commands and time inside MGMT_RESP.
  A node ignores key TLVs anywhere but inside a verified bundle.
- Recovery holders are rotated and revoked like any peer: their pair keys
  arrive as TLV 0x02 and leave as TLV 0x03 (review U6). A lost phone is one
  bundle per device it held.

### 8.7 Other requirements

- Logs MUST NOT print keys, nonces or tags at any level in a field build.
- `esp_random()` quality: rule 4.1.14.
- Capture detection (review U13): the gateway MUST alarm when a node misses
  three consecutive MGMT reports, reports a changed `reset_reason` pattern,
  a changed secure-state bit, or an epoch below the one it last reported;
  revocation is the documented response.
- Anti-rollback (review U12): the field image sets the Secure Boot v2
  secure version eFuse; a node refuses a BULK image whose `fw_build` is
  below the running one.
- Security counters (`auth_fail`, `hop_tag_fail`, `hop_replay`,
  `replay_dropped`, `bundle_fail`, `relay_drop_rate`) are in MGMT section 1.
- Enumeration: unit IDs, caps and beacons are visible to anyone in range;
  the protocol hides readings and keys, not topology. Collision alarms
  cannot be triggered by outsiders because the frames that raise them must
  pass the hop_tag.

---

## 9. Constants and budgets

Radio defaults; `hops` is the route hop count (1 on a direct link); the IR
edge link multiplies handshake timers by `IR_TIME_SCALE` on both ends.

| Name | Default | Note |
|---|---|---|
| HELLO_WINDOW_MS | 50 | probe random delay range |
| HELLO_CANDIDATES / PROBE_OFFERS_MAX | 4 / 4 | fallback probes kept / OFFERED entries per probe (one per src_id) |
| BIND_RETRY_MS / BIND_RETRIES | 50 / 3 | `BIND_RETRY(hops) = max(50, hops x HOP_DELAY_MS)` |
| BIND_TIMEOUT | formula 4.1.10 | 470 ms direct, 1730 ms at 4 hops; also the RESUME and MGMT_RESP timeout |
| SEEK_BASE_MS | 50 + 2 x seek_ttl x 60 | 530 ms at ttl 4 |
| SEEK_TIMEOUT(n) | SEEK_BASE_MS + rand(0, min(60000, 600 x 2^n)) | never gives up |
| FULL_CAP_S | 3600 | FULL backoff rand(0, min(3600, 60 x 2^n)) s (4.1.4) |
| BOOT_SPREAD_MS | 600 x pl/node_count | first SEEK and first MGMT_REQ after a cold boot |
| RESEEK_JITTER_MS / PENALTY_MS | 1000 / 60000 | |
| MODE_RETRY | = RTO | |
| keepalive_ms | 5000 (1000..60000) | MODE field; SESSION_TIMEOUT = max(4 x keepalive_ms, 8 x SRTT) |
| ACK_EVERY | 8 frames | |
| FEC_K / FEC_M / FEC_FLUSH_MS | 8 / 2 / 100 | flush after max(FEC_FLUSH_MS, 2 x period) |
| ARQ_WINDOW / ARQ_RTO_MS / ARQ_MAX_RETRIES | 24 (4 on leaves) / 100 / 3 | RTO = max(100, 2 x SRTT) |
| REORDER_MS / REPLAY_WINDOW | 500 (x 4 SRTT) / 64 | |
| RX_QUEUE_FRAMES / RELAY_QUEUE_FRAMES | 16 / 8 | |
| PL_MAX_GROUPS / PL_MAX_SESSIONS / PL_MAX_STREAMS | 8 / 32 (sink: node_count) / 4 (sink: 8) | |
| PARK_GRACE_S / MGMT_EVERY_WAKES / BULK_WINDOW_S | 60 / 10 / 120 | |
| MGMT_PERIOD_S / MGMT_RETRIES / TIME_MAX_SLEW_PPM | 600 / 2 / 500 | response timeout BIND_TIMEOUT(hops) |
| KEY_RECOVERY_S / MAINT_TIMEOUT_S | 2592000 (30 days, uptime) / 600 | |
| seek_ttl / MAX_HOPS / MIN_PATH_MTU | manifest (site diameter + 1, default 4) / 8 / 48 | |
| HOP_DELAY_MS / RELAY_JITTER_MS / FLOOD_REPEAT | 60 / 50 / 2 | |
| DEDUP_ENTRIES / DEDUP_TTL_MS | 64 / 5000 | |
| ORIGIN_ENTRIES / ORIGIN_TTL_S / ORIGIN_MAX_JUMP / HOP_MAX_JUMP | 64 / 3600 / 65536 / 65536 | |
| ROUTE_ENTRIES / ROUTE_TTL_MS / LINK_FAIL_MAX | 64 / 1200000 / 3 | 20 min; 3 consecutive send failures delete the link (11.6) |
| LINK_ENTRIES / LINK_TTL_MS | 32 / 60000 | |
| FLOOD_BUCKET_ORIGIN / FLOOD_BUCKET_TOTAL / FLOOD_BUCKETS | depth 6, 2/s / depth 20, 10/s / 64 | |
| IR_TIME_SCALE / IR_GUARD_MS / NRF_GUARD_MS | 10 / 20 / 2 | |
| VBAT_MIN | board-specific | leaf wake gate (4.4) |

Airtime budget at 1 Mbps ESP-NOW (estimates; a small unicast frame costs
about 1.5 ms of air per hop including preamble, 802.11 ACK and backoff; a
flood costs about `node_count x FLOOD_REPEAT x 1.1 ms`):

| Traffic | Per unit | 40 sessions, 2 hops, 50 nodes |
|---|---|---|
| Keepalive (ACK + PING) at 5 s | 2 x 1.5 ms x hops per keepalive | 4.8 % |
| DATA at 1 frame/s per session | 1.5 ms x hops per frame | 12 % |
| MGMT every 600 s per node | 2 x 1.5 ms x hops | 0.05 % |
| Floods (SEEK, RESUME, routeless MGMT) | about 110 ms each | 20 leaves at one wake per 5 min: 0.7 % |

Rule: keepalive plus management traffic at the funnel SHOULD stay under 10 %
of airtime; data rate and `fec_m` are chosen against the remainder.

---

## 10. Prior art

| Project | Carriers | Addressing | Integrity | FEC | Discovery / session | Typed samples | Verdict |
|---|---|---|---|---|---|---|---|
| PJON | ThroughSerial, ESPNOW, AnalogSampling (IR/LED), LocalUDP, SoftwareBitBang | 1-byte IDs (+ bus ID) | CRC8/CRC32, optional ACK | none | none | none | Closest match; lacks FEC, seek/first-ACK session, multi-hop, auth, sample typing |
| MAVLink v2 | any byte stream | 1-byte sys + comp IDs | CRC-16/MCRF4XX, optional signing | none | heartbeat | fixed message set | Good signing model, no FEC |
| RadioHead | radio chips (incl. nRF24) | node addresses, RHMesh | radio CRC | none | none | none | No ESP-NOW/IR |
| RF24Network / RF24Mesh | nRF24L01+ | 16-bit octal tree, master-assigned | ESB CRC only | none | tree join to a master | none | nRF24-only static tree; fragments 24-byte payloads; no multi-carrier bridging, no auth. ProbeLink reuses only the RF24 driver's raw packet, pipe, DPL and NO_ACK features |
| SerialTransfer | UART | none | COBS + CRC-8 | none | none | none | Framing reference |
| wfb-ng | raw 802.11 (Linux) | none | per packet | RS erasure across packets (k 8, n 12) | none | none | Model for 3.3 |
| BTHome v2 | BLE advertising | MAC | AES-CCM | none | advertising | value encoding with factors | Model for LOW scale/offset |
| ESP-WIFI-MESH | WiFi | MAC | WiFi | none | mesh formation | none | WiFi only |

Why not just PJON: it covers four carriers with IDs, CRC and ACK, but has no
FEC, no seek-a-group / first-acknowledger handshake, no forwarding, no
authentication and no HIGH/LOW typing; its light-sampling code is a starting
point for the IR PHY. RS libraries for ESP32: Arduino-FEC, libcorrect (C,
decode-with-erasures), Schifra; a minimal GF(2^8) encoder plus erasure
decoder is about 300 lines of C.

References: github.com/gioblu/PJON; MAVLink v2; RadioHead; nRF24/RF24,
RF24Network, RF24Mesh; SerialTransfer (PowerBroker2); wfb-ng (svpcom); BTHome
v2; ESP-IDF ESP-WIFI-MESH; ESP-IDF issue #9575; RFC 5869 (HKDF); RFC 3711
(SRTP implicit ROC); RFC 1982; NIST SP 800-38C (CCM).

---

## 11. Mesh layer

Forwarding is part of the base protocol: every frame carries origin/final and
hop fields, every node runs the pipeline below, and a direct link is a
one-hop route. Sessions never know how many hops they cross. A node that
bridges two carriers (UART <-> ESP-NOW, ESP-NOW <-> nRF24) is the normal case.

### 11.1 Roles

| Role | caps RELAY | Power | Does |
|---|---|---|---|
| Node (default) | 1 | mains or solar, MUST | Originates and terminates sessions, forwards, serves groups |
| Bridge | 1 | mains or solar, MUST | Node with 2+ transports; re-frames per carrier |
| Gateway | 1 | mains | Bridge with a LAN side (12.4); manager 0x0001: time source, bundle relay, report sink, sink probe |
| Leaf | 0 | battery | Sender only, parks sessions (4.4), forwards nothing, serves nothing except its own update window |

Routes never pass through a leaf: routes are installed from the `prev_hop`
of transmitted frames and a leaf transmits only frames it originates.
"Relay" below means any non-leaf node in its forwarding role. A permanent-RX
node draws 80-100 mA (estimate): solar relays need a panel of `daily Wh /
(peak sun hours x 0.7)` (about 8 Wh/day), three days of battery and a
low-voltage gate with hysteresis before WiFi start.

Per hop (rewritten by every forwarder): COBS, RS parity, nRF24 segments,
CRC-16, `hop_tag`, `prev_hop`, `next_hop`, `ttl_hops`, `hop_seq`, SEEK
`path_mtu` and `path_cost`. End to end (never modified): everything else,
including the CCM tag, FEC, ARQ, replay windows and session timers. A relay
with a memory bug can corrupt a payload and recompute a valid CRC; only the
end-to-end tag catches that, which is why AUTH is mandatory in the field.

### 11.2 Hop fields

- `prev_hop`: not every carrier gives a usable link address (UART, IR) and
  the address-to-ID mapping is not known in advance; route learning needs it.
- `next_hop`: lets the intended node act on a frame heard by several on a
  shared medium and lets bridges pick the outgoing transport. 0xFFFF = flood.
- `ttl_hops`: `MAX_HOPS` 8; receivers drop anything above (3.6).
- `hop_seq`: the transmitter's full 32-bit `txseq` (3.5, 8.4).
- `path_mtu` (SEEK): lowered hop by hop, clamped to the incoming link (3.6).
- `path_cost` (SEEK): the origin writes 0; each node adds the cost of the
  link the copy arrived on. From RSSI where available: 1 at or above
  -75 dBm, 3 in -85..-75, 10 in -90..-85; copies below -90 dBm are ignored.
  Fixed costs otherwise: UART 1, nRF24 2.

### 11.3 Mixed carriers: path MTU, not fragmentation

SEEK leaves the origin with `path_mtu = max_frame - rs_nsym` of its outgoing
transport (a bridge floods one copy per transport, same `pre_ctr`); each
forwarder lowers it to its outgoing link. The probe's HELLO `max_frame` is
min(own, path_mtu of the chosen copy); the session uses min(sender, HELLO)
(section 5). With one `max_frame` of 250 on every mesh carrier the path MTU is
250, or 242 through a UART hop; IR is an edge and never part of a path.
Forwarders still check fit (`header + len + 12 + 2 <= max_frame - rs_nsym`)
and count `relay_drop_mtu`. Failover is a new SEEK and a new MODE, so a
smaller path is caught by MODE_ACK status 2.

Mesh-layer fragmentation was rejected: per-relay reassembly state,
fragments that cannot be tag-verified alone, frame loss on any lost fragment,
and FEC groups defined over whole frames. nRF24 segments inside its adapter
only (C.5).

### 11.4 Routing: AODV-lite on SEEK and HELLO

Route entry: `{dst_id u16, next_hop u16, transport u8, hops u8, cost u8,
expiry u32}`, `ROUTE_ENTRIES` 64, `ROUTE_TTL_MS` 20 minutes. Every event
below happens only for frames admitted at step 5; nothing an unverified or
stale frame carries ever reaches a table.

| Event (frame admitted) | Route action |
|---|---|
| Flood (SEEK, RESUME, flooded MGMT_REQ) from `prev_hop` on T | Reverse route to `src_id` via `prev_hop`, `hops + 1`, `cost = path_cost + link cost`; inside the node's jitter window a lower-cost copy replaces it; afterwards only a fresher flood (newer `pre_ctr`) does |
| Unicast HELLO from `prev_hop` | Forward route to `src_id` (the probe) via `prev_hop` with the HELLO's cost; replaces an existing entry |
| Any other admitted frame that is for me or that I forward (not overheard) | Installs a route to `src_id` via `prev_hop` if none exists (RESUME_ACK, BIND_ACK, MGMT_RESP install forward routes this way); never changes an existing `next_hop` |
| Frame received from `prev_hop` whose `src_id` is `dst` of a route with `next_hop = prev_hop` | Refreshes that route's expiry. Forwarding a frame toward `dst` refreshes nothing: liveness is evidence only in the return direction (review H4) |

Pipeline run by every node on every received frame, in order; one counter
per drop. Nothing after step 5 runs for a frame that fails step 5.

| Step | Condition | Action |
|---|---|---|
| 1 | per-hop decode fails (COBS, RS, nRF24 reassembly, CRC) | drop, `crc_fail` / `rs_fail` / `seg_fail` |
| 2 | 3.6 length / header / SEEK hop-field checks fail | drop, `bad_frame` |
| 3 | version unknown and the frozen prefix does not parse | drop, `bad_version` (an unknown version with a valid prefix is forwarded, never delivered locally) |
| 4 | field profile and FLAG_AUTH clear, or AUTH set and `len` leaves no room for the tags | drop, `auth_fail` |
| 5 | hop_tag fails under every held epoch (retired slot only for type MGMT_REQ), or `hop_seq` not newer than the link table's value for (prev_hop, transport), or more than HOP_MAX_JUMP ahead | drop, `hop_tag_fail` / `hop_replay`; nothing learned, nothing replied |
| 6 | admitted | learn or refresh link: (prev_hop, transport) -> address, hop_seq, verified epoch (11.9) |
| 7 | unicast with `dst_id` = me or a group of mine, and `next_hop` = me | deliver to the endpoint logic (CCM tag, matching per 8.4); install or refresh routes per the table above; stop |
| 8 | unicast, `next_hop` != me | overheard: drop silently, no route change |
| 9a | flood, `src_id` = me | echo of my own flood: drop silently, no alarm (11.5) |
| 9b | flood, `(src_id, pre_ctr)` in dedup | duplicate: update the entry's best cost and reverse route if this copy is cheaper (inside the jitter window); drop, `relay_drop_dedup` |
| 9c | flood, `pre_ctr` older than ORIGIN `last_ctr`, or more than `ORIGIN_MAX_JUMP` ahead of it | drop, `relay_drop_stale` |
| 9d | flood, per-origin or total bucket empty (11.5) | drop, `relay_drop_rate` |
| 9e | flood, otherwise | insert dedup and ORIGIN; install reverse route; deliver locally if `dst_id` is me or a group of mine; if `dst_id` = me (unicast destination), or node is a leaf, or `ttl <= 1`, or the frame arrived on an `edge_only` transport: stop (`relay_drop_ttl` for the ttl case) |
| 9f | flood, forwarding | after `rand(0..RELAY_JITTER_MS)` take the lowest-cost copy seen; ttl - 1, hops + 1, prev_hop = me, new hop_seq, path_mtu lowered, path_cost += that copy's link cost; recompute hop_tag (`E_old`) and CRC; send on every transport except `edge_only` ones and the point-to-point one it arrived on, `FLOOD_REPEAT` copies where the carrier has no broadcast retry |
| 10a | unicast, no route to `dst_id`, or node is a leaf, or the frame arrived on an `edge_only` transport | drop, `relay_drop_noroute` (no RERR: a relay cannot verify the frame and is not an endpoint) |
| 10b | unicast, `route.next_hop == prev_hop` | drop, `relay_drop_loop` |
| 10c | unicast, `ttl <= 1`, or does not fit the outgoing link, or outgoing transport is `edge_only` | drop, `relay_drop_ttl` / `relay_drop_mtu` |
| 10d | unicast, forwarding queue full | class-aware drop (section 7) |
| 10e | unicast, otherwise | ttl - 1, hops + 1, prev_hop = me, next_hop = route.next_hop, new hop_seq; recompute hop_tag under the epoch last verified from next_hop, CRC; per-hop encode; send; on a reported send failure apply 11.6; install routes per the table; `relay_fwd` |

Endpoints originate unicast frames with `ttl = min(MAX_HOPS, route.hops +
2)`; floods with `ttl = seek_ttl` (RESUME: `min(hops + 1, MAX_HOPS)`),
`prev_hop = own ID`, `hops = 0`, `path_cost = 0`. A node without a route to
its manager floods MGMT_REQ; the MGMT_RESP installs the route for next time.

### 11.5 Flood control

Flooded frames: SEEK, RESUME, and MGMT_REQ without a route. BIND is unicast.

- Origin bookkeeping: before a flood the origin inserts its own `(src_id,
  pre_ctr)` into its dedup cache, so echoes are dropped at 9a/9b. A frame
  with `src_id` = own ID and a `pre_ctr` not in the node's dedup cache, or
  with `prev_hop` = own ID from another carrier address, raises
  `PL_EVT_ID_COLLISION`.
- Dedup: `DEDUP_ENTRIES` (64) x `(src_id, pre_ctr, timestamp, best_cost,
  pending copy)`, FIFO, `DEDUP_TTL_MS` 5 s. Sized so an entry outlives its TTL
  under full load (10 floods/s x 5 s = 50 < 64). `FLOOD_REPEAT` copies share
  one `pre_ctr` and are dropped after the first; they exist to survive a
  broadcast collision.
- ORIGIN: 64 x `(src_id, last_ctr u32, timestamp)`, `ORIGIN_TTL_S` 1 h. A
  flood is dropped if its `pre_ctr` is older than `last_ctr` or more than
  `ORIGIN_MAX_JUMP` (2^16) ahead of it: between two floods a node originates
  at most a few thousand pre-session frames (MGMT every 10 minutes, a few
  handshakes), so 2^16 is generous for every role within the 1 h TTL.
  Entries are checked after dedup, so equal copies reach 9b and can improve
  the route. After expiry one recorded flood is forwarded once, costs one
  token, and can start no session (its keys are stale); accepted.
- Budget: token buckets after the freshness checks. Per origin depth 6,
  refill 2/s, 64 buckets hashed by `src_id`; per node depth 20, refill 10/s.
  A handshake is one SEEK flood (BIND is unicast), a wake one RESUME, a
  routeless report one MGMT_REQ.
- Jitter: `rand(0..RELAY_JITTER_MS)` before rebroadcast, keeping the
  lowest-cost copy; one pending frame buffer per flood in its jitter window
  (`FLOOD_PENDING` 4).
- TTL: `seek_ttl` from the manifest (site diameter + 1, default 4),
  `MAX_HOPS` 8. No counter-based suppression: the budgets bound flood load
  and suppression creates coverage holes.

### 11.6 Route and link lifetime

- Routes expire `ROUTE_TTL_MS` (20 min) after the last frame received from
  their `next_hop` with `src_id = dst` (11.4). Live sessions and the
  10-minute MGMT exchange refresh their routes in the return direction; a
  route used only in one direction dies after 20 minutes, which is the
  intended signal that nothing is answering.
- Fast failover (review H4): where the carrier reports unicast delivery
  (ESP-NOW, nRF24), `LINK_FAIL_MAX` (3) consecutive send failures to a
  `next_hop` delete its link entry and every route through it; the next
  frame for those destinations has no route, and if it is a flood-capable
  type (SEEK, RESUME, MGMT_REQ) the origin floods it, otherwise the
  endpoints' timeouts recover. A link entry that expires (`LINK_TTL_MS`, 60
  s without a frame from that neighbour) likewise deletes the routes through
  it; entries referenced by routes are not exempt.
- Sessions detect failure end to end (`SESSION_TIMEOUT`), re-SEEK, and the
  new flood and HELLO overwrite routes on the new path. Management detects
  failure by its response timeout (11.10). Loss of a relay is never signalled
  (no RERR). Full route table: evict the earliest expiry
  (`route_evictions`). 64 entries hold the two routes of 32 sessions.

### 11.7 Timers across hops

Handshake timers use hop counts (no RTT yet): `SEEK_BASE_MS`, `BIND_RETRY`,
`BIND_TIMEOUT` (4.1.8-10) with `HOP_DELAY_MS` 60. Session timers use
measured RTT (section 7). Only the IR edge link scales handshake timers.

### 11.8 Security in a mesh

| Attacker | Can | Cannot (mechanism) |
|---|---|---|
| Outsider (no key) | Jam; cost each node one HMAC per received frame | Enter any table, consume a budget, be forwarded, or trigger an alarm (hop_tag + 32-bit hop_seq before any state, R4/R5); forge, alter or replay session or management frames (R3, R5) |
| Node holding K_mesh (any node, or a captured one before revocation) | Originate floods within the budgets; forward, drop, delay or misroute frames through it; at the mesh layer act under another unit ID: install routes toward itself, advance that ID's ORIGIN counter by up to ORIGIN_MAX_JUMP, spend that ID's flood budget | Derive any pair key or K_node it was not given, hence read, forge or alter any session, management or bundle it is not party to, or impersonate another ID to that ID's peers (R2, R6, R8); raise `path_mtu` or ttl (3.6); push time or keys (K_mgmt, K_node) |
| Captured gateway | The row above for ID 0x0001; read its own pair keys and the opaque bundles it stores | Read or author any bundle (K_node); it is replaced by TLV 0x07 and revoked like any node (8.6) |
| Revoked node | Mesh-layer access until the tool retires the old epoch (pacing cap 24 h) | Session or management access (pair keys deleted at once); receiving the new epoch |

Known limitation (reviews T6, G3): mesh-layer identity for routes and flood
budgets rests on the shared mesh key; a compromised node can misdirect
routes until revoked. The penalty list (4.2), send-failure rule (11.6), MGMT
link statistics (11.10) and gateway alarms (8.7) make it visible; removing
it needs per-node signatures (12.8). Unkeyed relays cannot exist in the
field profile: without `K_mesh` nothing a node sends is admitted.

### 11.9 Tables and RAM

Link table: keyed `(unit_id, transport)`, entry `{address[6], hop_seq u32,
epoch u8, fails u8, rssi_ewma i8, expiry}`, `LINK_ENTRIES` 32, `LINK_TTL_MS`
60 s. A frame from a new address with a newer `hop_seq` replaces the address
(node swapped, DHCP renewed); the alarm fires only on `prev_hop` = own ID.
Eviction: unreferenced entries first, then earliest expiry.

| Table | Entry | Count | Bytes |
|---|---|---|---|
| Route table | 12 | 64 | 768 |
| Dedup cache (+ pending copy pointers) | 12 | 64 | 768 |
| ORIGIN | 12 | 64 | 768 |
| Link table | 20 | 32 | 640 |
| Flood buckets | 8 | 64 | 512 |
| Pending flood copies | 250 | 4 | 1000 |
| Forwarding queue | 250 | 8 | 2000 |
| nRF24 reassembly (if present) | 258 | 4 | 1032 |
| HMAC / CCM contexts, preallocated | | | ~600 |
| Total, ESP-NOW node | | | ~7.0 KB (8 KB with nRF24) |

Minimum a conforming non-leaf node MUST provide: half of each count above.
Leaves keep a 2-entry route table, an 8-entry dedup cache and no queues
(about 200 bytes). Keys in NVS: 32 bytes per peer per live epoch plus the
retired epoch (about 4.7 KB for 49 peers x 3), `K_node`, and the bundle in
progress (2 KB).

### 11.10 Management (MGMT_REQ / MGMT_RESP)

One request/response pair, between a node and a manager from its NVS list
`pl/managers` (the gateway 0x0001; the station 0x0002 over UART; a recovery
holder 0x0003..0x000F over BLE in maintenance mode; for an IR leaf, its
attached node), encrypted under `K_mgmt(N, M, E)`. It carries time, health
reports, commands and opaque key bundles, and works for leaves because the
node always initiates. A node sends MGMT_REQ every `MGMT_PERIOD_S` (600 s),
`rand(0..BOOT_SPREAD_MS)` after a cold boot, immediately after an update
boot, after installing a bundle, and (leaves) per 4.4.

```
MGMT_REQ   pre_ctr u32 (clear); encrypted: t1 u64 (requester clock, us), e_new u8, e_old u8,
           flags u8 (bit0 want_bundle, bit1 more_follows), section u8, page u8, section bytes
MGMT_RESP  pre_ctr u32 (clear); encrypted: req_ctr u32 (echo of the request's pre_ctr), t1 u64 (echo),
           t2 u64, t3 u64 (manager UTC rx/tx, us), flags u8 (bit0 TLVs present, bit1 more chunks pending),
           TLVs: type u8, len u8, value   (0x04 command: 1 enter maintenance, 2 reboot, 3 open update window;
                                           0x05 bundle chunk: bundle_no u32, idx u8, total u8, bytes)
```

- Freshness: the node keeps one outstanding request and accepts a MGMT_RESP
  only if `req_ctr` echoes it (review U4). Commands 1 and 2 are accepted at
  most once per 10 minutes. The manager keeps the last `pre_ctr` per node
  and answers at most one request per second per node; it never answers an
  unverified one.
- Failure (review H4): no MGMT_RESP within `BIND_TIMEOUT(hops)` is retried
  `MGMT_RETRIES` (2) times with new `pre_ctr`; after the last failure the node
  deletes its route to the manager, and the next MGMT_REQ floods. A node
  without a sync for `3 x MGMT_PERIOD_S` is UNSYNCED (6.5).
- Report sections, one per request, rotated by the node; pages sized to the
  path MTU:

```
section 0 (34 bytes): mac[6], unit_id u16, proto_ver u8, proto_minor u8, fw_build u32, e_new u8, e_old u8,
                      role u8, power_src u8 (0 mains, 1 solar, 2 battery), vbat_mv u16, uptime_s u32,
                      reset_reason u8, reset_count u16, min_free_heap u32, stack_hwm u16,
                      state u8 (bit0 secure boot, bit1 flash enc release, bit2 NVS encrypted, bit3 clone
                      mismatch, bit4 no-key wait seen, bit5 maintenance entered since last report)
section 1: pl_stats_t as little-endian u32 in Appendix B declaration order
section 2: n u8, then n x { unit_id u16, transport u8, rssi_ewma i8, rx u16, crc_fail u16, fails u8 }
section 3: n u8, then n x { dst u16, next_hop u16, hops u8, cost u8 }
```

- Bundles (8.6): a node whose `e_new` is behind, or whose request sets
  `want_bundle`, receives TLV 0x05 chunks, one per response, requesting each
  with `page`; the chain keeps a leaf awake until `more` clears.
- Time: the requester computes offset and round trip from t1..t4 as NTP does
  (6.5); time is accepted only from a listed manager and drives no key event.
- The gateway alarms per 8.7 on missing or inconsistent reports.

### 11.11 Carrier notes for mesh links

- ESP-NOW: unicast to the link table's MAC (MAC retries; the send callback's
  status feeds 11.6), broadcast for floods. 20 peers maximum: LRU peer table
  of 16 plus broadcast; when all 16 are referenced by live routes evict the
  LRU anyway and re-add on the next send. Fixed channel, `WIFI_PS_NONE`,
  `WIFI_MODE_STA` unassociated, never AP, no BT while the mesh is up.
- nRF24L01+: unicast to the `next_hop` address derived from its unit ID with
  ESB auto-ACK (the MAX_RT flag feeds 11.6); floods on the broadcast address
  with NO_ACK; per-hop segmentation (C.5). Fixed link cost 2.
- UART: point to point; a flood is never sent back on the transport it
  arrived on. `prev_hop` / `next_hop` are still carried so the format is
  uniform.
- WiFi UDP: LAN side of the gateway only; multicast for floods, unicast
  otherwise; peer list on isolated LANs (C.4).
- IR edge (review H5): the IR leaf and its attached node form a two-node
  link keyed by their pair key at the provisioning epoch (8.2), which no
  rotation touches; frames never cross between IR and any other transport
  (steps 9e, 9f, 10a, 10c). The attached node is the leaf's probe and its
  only manager: time, health and commands flow over the IR link by MGMT,
  pulled by the leaf; the attached node's section 2 row for the leaf is how
  the gateway sees it. Rekeying or updating an IR leaf needs the UART station
  (12.6). The attached node republishes the leaf's data as its own sender
  session if the site needs it elsewhere (application level).

---

## 12. Deployment profile and decisions

Each item is a decision with its alternative so it can be flipped. Items
marked USER-DECIDED were set by the user.

### 12.1 Bench vs field profile

| | Bench | Field (default) |
|---|---|---|
| Keys | optional; `pl/net_key` MAY derive everything locally | MUST: `K_node`, pair keys and `K_mesh` from the offline `K_site` (8.2) |
| FLAG_AUTH | optional | MUST on every frame |
| At rest | development build | MUST: Secure Boot v2 with the secure-version eFuse, flash encryption release mode, NVS encryption, JTAG and UART download disabled by eFuse; `pl_init` returns `PL_ERR_AUTH` unless `esp_secure_boot_enabled()`, `esp_get_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE` and the key partition is encrypted, and then waits for UART provisioning (fail closed, review U7) |
| Chips | any | ESP32-C3, -S3, -C6 (eFuse-HMAC NVS key); original ESP32 at silicon revision 3.0 or later with a flash-encrypted `nvs_keys` partition (review U15). R1 raises the cost of extraction; published fault-injection work shows it is not absolute, so revocation (8.5) is the control |
| Signing | any key | separate Secure Boot signing keys for bench and field images; a field image refuses to start without production eFuses and a bench image refuses to start with them |
| Test keys | allowed | the tool refuses the Appendix A `K_site`; firmware rejects all-zero or repeated-byte keys and the 8-byte hash prefixes of `K_mesh(E)` for all 256 epochs of the test `K_site` (2 KB table) |
| Replies to unverified frames | CLOSE(2) allowed | never |
| NVS erase on error | allowed | never; the condition is logged and reported (6.4) |
| Logging | anything | no key, nonce or tag bytes at any level |

### 12.2 Provisioning (decision)

A provisioning station (host script plus a UART cable, manager ID 0x0002)
runs, per board and in this order: read the base MAC and chip revision
(refuse unsupported); burn and verify the Secure Boot v2 digest and the JTAG
eFuse; flash the signed bootloader and app; enable flash encryption in
release mode and wait for the first-boot encryption to finish on a stable
supply; provision the NVS encryption key; write the per-device encrypted NVS
image generated from the manifest row (`unit_id`, `unit_mac`, `role`,
`groups`, `managers`, `channel`, `nrf_channel`, `seek_ttl`, `node_count`,
`epoch_old`, `epoch_new`, `K_mesh` x 2, `K_node`, pair keys including those
with 0x0001, 0x0002 and the assigned recovery holders); verify by reading the
node's MGMT section 0 over the UART; burn the UART download-mode eFuse last
(review H11). Dry-run on two sacrificial boards; store the eFuse summary per
MAC in the manifest. Later re-provisioning and recovery use the same station
as a manager under `K_pair(node, 0x0002)`: that is the only meaning of "cable"
in the field profile.

### 12.3 Control-frame recovery (decision)

Repetition (`FLOOD_REPEAT` 2) and handshake retries satisfy "recovery data in
every packet" for control frames. Alternative not chosen: in-frame RS on
control frames, 4-8 bytes against a failure (a whole lost frame) it cannot fix.

### 12.4 Radio, gateway and sink (decision)

All ESP-NOW nodes use one dedicated channel from the manifest, `WIFI_PS_NONE`,
`WIFI_MODE_STA` never associated and never AP. The gateway is two chips
joined by UART at 921600 baud or more (the section 9 scenario needs about
60 frames/s through it, review H6): the mesh chip (manager 0x0001 and the
probe of the sink group, with `PL_MAX_SESSIONS` = `node_count` and
`PL_MAX_STREAMS` 8: about 30 KB of records plus 38 KB of streams on a C3 or
S3), and a LAN chip that SHOULD use Ethernet (W5500 over SPI, or LAN8720 on an
ESP32) and runs the LAN sink, time source and bundle store. If the LAN chip
must use WiFi STA: external antennas at least 30 cm apart and the mesh
channel at least 5 channels from the AP channel, both in the manifest. WiFi
UDP nodes live on the LAN side only. The only other path to the LAN is a
non-gateway probe re-originating its received samples as its own sender
session to the sink group (application level); several such probes spread
load but each adds one hop of latency. nRF24 sites: mesh channel 1-6, nRF
channel 76-81, antennas separated or cross-polarised, and a bridge never
starts a transmission on one radio while the other is mid-reception of a
multi-segment frame. Commissioning test: compare `crc_fail` / `seg_fail` /
`rx_frames` at the gateway and bridges with the co-located radio idle and
loaded. Alternative not chosen: channel-follow of the AP.

### 12.5 BLE: phone link only (USER-DECIDED)

BLE never carries mesh traffic and is not a carrier. It is a commissioning
and diagnostics link to a phone holding a recovery-holder identity, active
only in maintenance mode while the mesh radio is stopped, with an idle
timeout (6.4). Alternative (v0.4): BLE as an optional carrier on a separate
chip over UART; not needed once BLE sensors are out of scope.

### 12.6 IR: one-hop edge only (USER-DECIDED)

IR connects a leaf to exactly one mesh node and is never forwarded. The
attached node terminates the session and is the leaf's manager (11.11). The
link is keyed by the pair key of the two nodes at the provisioning epoch and
is outside epoch rotation, so an IR leaf never goes deaf; rekeying it or
updating its firmware is done with the UART station, which is a deployment
rule (review H5). IR stays indoor/shaded until its bit cell is validated on
hardware (C.1). Alternative (v0.4): IR as a mesh hop with scaled timers;
rejected by the user.

### 12.7 Firmware update (decision)

In-mesh, minimal: the update server (the gateway's LAN chip, through the mesh
chip) SEEKs the node by unit ID, BINDs, and sends MODE mode 2 (BULK:
`bulk_size`, `sha256`, `fw_build`) with `arq` 1 and `fec_m` 0, then DATA
frames whose `t_first_us` is the byte offset; the node writes with
`esp_ota_write`, verifies the SHA-256 at CLOSE reason 7, refuses a `fw_build`
below the running one (8.7), lets Secure Boot verify the signature at
reboot, and marks the image valid (`esp_ota_mark_app_valid_cancel_rollback`)
only after it has received one MGMT_RESP within `3 x MGMT_PERIOD_S` of boot
(it sends MGMT_REQ immediately after an update boot; leaves: before their
first park, 4.4). Any final ARQ gap aborts the image. A 1 MB image at 20-50
kbit/s over 2-3 hops takes 3-7 minutes per node (estimate). Nodes accept
BULK only from a listed manager armed by MGMT command 3; for a leaf, command
3 opens the update window of 4.4 (review H7). IR leaves are updated by the
UART station (12.6). Version transition: endpoints accept N and N-1 during a
rollout; forwarders forward any version with the frozen prefix. Alternative
(v0.4): a maintenance-WiFi window; rejected because meshed nodes are the
ones without WiFi coverage.

### 12.8 Key architecture (decision)

Pairwise symmetric keys from an offline site key, a per-node bundle key,
two live epochs plus a retired slot, pulled bundles, explicit retirement
(8.2, 8.5, 8.6). Alternative: per-node X25519/Ed25519 identities with
site-signed certificates: closes the mesh-layer identity limitation (11.8)
and removes per-peer key lists, at tens of ms of software crypto per
handshake (estimate) and a larger SEEK/HELLO. Not chosen; the SEEK/HELLO
payloads have room for a 32-byte public key later.

### 12.9 Leaf model (decision)

Sender-only leaves that park and resume sessions, pull management on wake,
and open a probe window for updates on command (4.4). Not chosen: a
sessionless REPORT frame (bypasses seek/bind and MODE); a buffering parent
relay (session state in relays); cable-only updates (20 of 50 nodes on poles).

### 12.10 Cuts applied and known limitations

Cut since v0.4: BLE carrier; IR as a mesh hop; ESP-NOW v2 / LEN16 / big UDP;
PL_SELECT_BEST; the HMAC-or-CCM dual path; time stratum chaining; key
activation modes and retirement timers; in-frame RS on PACKET links; flooded
BIND; counter suppression; separate DIAG/TIME/KEY_UPDATE types; endpoint
per-peer counter state; the third live epoch.

Known limitations, deliberate: mesh-layer identity for routes and flood
budgets rests on `K_mesh` until per-node signatures exist (11.8), so OFFERED
denial and route misdirection by an insider are bounded, not eliminated; one
recorded unicast frame can be re-admitted at a relay after `LINK_TTL_MS`
until the real neighbour transmits (8.4); epoch pacing and the 24 h
revocation cap are tool rules (8.5); a revoked node keeps mesh-layer access
until the old epoch is retired; during a retirement rollout, floods from
nodes that have not yet pulled the RETIRE bundle are dropped at nodes that
have, until the failure-triggered MGMT pull (4.1.8) catches them up; a node
absent beyond `KEY_RECOVERY_S` or two retirements needs the UART station; IR leaves are rekeyed and updated by
cable only; IR outdoors and the IR bit cell are unvalidated (C.1); R1 is a
cost, not a guarantee, on some silicon (12.1); no TRACE frame (MGMT section 3
gives the path); FEC/ARQ parameters are not auto-tuned to measured loss; the
nRF24 segment header separates concurrent transmitters only by the low byte
of `prev_hop` (C.5).

### 12.11 Implementation readiness

Buildable now against this document and Appendix A: frame codec and the 3.6
validator (fuzz harness), CRC/COBS/RS/group FEC, ARQ and reorder, crypto and
keystore (HKDF, CCM, hop_tag, transcript, epochs, counters), session machines
(sender, multi-record probe, park/resume), the forwarding pipeline and its
tables, MGMT with bundles, the provisioning and bundle tool, the ESP-NOW and
UART adapters, the two-chip gateway and LAN sink, and the host mesh
simulator. Phase 1 SHOULD be ESP-NOW plus the UART gateway, with the
simulator, and a 10-node 72 h soak that includes one rotation with a node
powered off past the retirement, one revocation, one site power cycle, one
update, one relay killed on the gateway path, and a gateway `preseq` started
above 0x10000.

Gated on measurement before field use: the IR bit cell and outdoor behaviour
(C.1); nRF24 goodput, segment loss and desense (C.5, 12.4); airtime and
failover timing at 50 nodes (section 9 figures are estimates); the leaf wake
budget on the chosen board and cell (4.4); gateway radio desense (12.4).

---

## Appendix A. Test vectors

Computed by `vectors_v06.py` (Python `hmac`/`hashlib` for HKDF and HMAC,
`cryptography` for AES-CCM, `reedsolo` cross-check for RS). Hex is wire
order. Key material is TEST ONLY and refused by field builds (12.1). IDs: S
0x1234 (sender), P 0x0042 (probe), R 0x0099 (relay), M 0x0001 (gateway).

A.1 CRC-16/CCITT-FALSE: `"123456789"` -> 0x29B1

A.2 SEEK on ESP-NOW, bench profile (no tags)

```
prev 0x1234, next 0xFFFF, ttl 4 / hops 0, hop_seq 1, path_mtu 250, path_cost 0, session 0, seq 1;
payload: pre_ctr 1, nonce_s 0xA1B2C3D4, caps 0x0033 (HIGH|LOW|FEC|RELAY), max_frame 250, epoch 0, minor 0, fw 1
10 01 34 12 01 ff 34 12 ff ff 40 01 00 00 00 fa 00 00 00 01 00 12
01 00 00 00 d4 c3 b2 a1 33 00 fa 00 00 00 01 00 00 00  e9 a5            42 bytes, CRC16 = 0xA5E9
```

A.3 Same SEEK on UART: path_mtu 242, RS nsym 8, then COBS

```
frame (42): as A.2 with f2 00 at offset 15 and CRC 0b a8 (0xA80B)
RS parity:  59 af 85 16 e4 bc 1f 03
COBS wire (52): 0d 10 01 34 12 01 ff 34 12 ff ff 40 01 01 01 02 f2 01 01 02 01 03 12 01 01 01 06 d4 c3 b2 a1
                33 02 fa 01 01 02 01 01 01 0b 0b a8 59 af 85 16 e4 bc 1f 03 00
```

A.4 RS standalone: RS(6) of "ProbeLink" = 28 76 02 56 91 f1; RS(1) of 12 34 56 78 9a = 92 (= XOR)

A.5 Cross-frame FEC (unchanged since v0.2): k 2 / m 1 blocks `03 01 02 03 00`, `04 10 20 30 40`
-> parity `07 11 22 33 40`; k 4 / m 2 blocks `02 aa bb 00`, `03 11 22 33`, `01 ff 00 00`,
`03 01 02 03` -> parity `2d 01 2d 19`, `2e 44 b6 29`; erasing blocks 1 and 3 and decoding with
erasure positions {1, 3} reproduces them.

A.6 Keys (K_site TEST ONLY = bytes 0x00..0x1F)

```
K_mesh(1)  = 15e0339cd6e0d2252a7ba30c238e504c70c651eb217736caca7e54c1720c31c3
K_hop(1)   = f01d0bf17a22ac552d4702483d14fd93189c775c2d32484402d03ce14cddd2f8
K_hop(0)   = 06425850835ccbda2ea542ef03047e28e381dca66e42f58fd62834c4fac2c779
Ke_mesh(1) = cf6945811a150c490d9b97523507296f
K_pair(0042, 1234, 1) = 1427086608cb09c6cc10fa2d6ea68ddd3de5a73fbd9a0c10e7754a1a1bf31af5
PRK = Extract("ProbeLink-v1", K_pair) = 4a0e7d437c9d90f9dd777e602767a34b2049542478e05a938e39ecfbd571749f
```

A.7 DATA on a direct link (Ke_s2p from A.9), session 7, seq 5, ROC 0, hop_seq 9, one float32 1.5 at t = 1000 us

```
header: 12 10 34 12 42 00 34 12 42 00 30 09 00 00 00 07 05 00 0b
plaintext = 01 00 e8 03 00 00 01 00 00 c0 3f ; nonce = 00 34 12 42 00 07 00 00 00 00 05 00 00
AAD = 12 10 34 12 42 00 07 05 00 0b 00 00 00 00 ; ciphertext = 30 5f 1e 73 e0 26 11 46 27 c1 04
ccm_tag = 9c 49 d1 13 b4 ab 87 c1 ; hop_tag = HMAC(K_hop(1), frame[0..37])[0..3] = b4 65 07 56
frame (44): header || ciphertext || ccm_tag || b4 65 07 56 || a1 da              CRC16 = 0xDAA1
```

A.8 Two hops: the A.7 frame via R, and a keyed SEEK flood

```
DATA hop 1 (S -> R): prev 0x1234, next 0x0099, ttl 4 / hops 0, hop_seq 9
12 10 34 12 42 00 34 12 99 00 40 09 00 00 00 07 05 00 0b 30 5f 1e 73 e0 26 11 46 27 c1 04
9c 49 d1 13 b4 ab 87 c1 7e 8d 0b 60 0b c5                                       CRC16 = 0xC50B
DATA hop 2 (R -> P): prev 0x0099, next 0x0042, ttl 3 / hops 1, hop_seq 0x00010131
12 10 34 12 42 00 99 00 42 00 31 31 01 01 00 07 05 00 0b 30 5f 1e 73 e0 26 11 46 27 c1 04
9c 49 d1 13 b4 ab 87 c1 f6 2e 15 78 4f a0                                       CRC16 = 0xA04F
Same hop 2 re-tagged under epoch 0 (R replying to a neighbour it last verified under 0, 8.5):
hop_tag 71 31 d9 43, CRC16 = 0x9709

SEEK, field profile: pre_ctr 0x00010001 (header seq 0x0001), caps 0x003B (HIGH|LOW|AUTH|FEC|RELAY), key_epoch 1
payload (clear) = 01 00 01 00 d4 c3 b2 a1 3b 00 fa 00 01 00 01 00 00 00
nonce = 00 34 12 01 ff 00 01 00 00 00 01 00 00 ; AAD = e2e header || 01 00 00 00 || payload
ccm_tag (over empty plaintext, Ke_mesh(1)) = 89 e7 25 07 07 1f d7 16
hop 1 (S, hop_seq 7, path_mtu 250, cost 0) (54):
12 01 34 12 01 ff 34 12 ff ff 40 07 00 00 00 fa 00 00 00 01 00 12 01 00 01 00 d4 c3 b2 a1 3b 00 fa 00
01 00 01 00 00 00 89 e7 25 07 07 1f d7 16 58 a7 02 10 d2 dc                      CRC16 = 0xDCD2
hop 2 (R, hop_seq 0x00010130, ttl 3 / hops 1, path_mtu 250, cost 1) (54):
12 01 34 12 01 ff 99 00 ff ff 31 30 01 01 00 fa 00 01 00 01 00 12 01 00 01 00 d4 c3 b2 a1 3b 00 fa 00
01 00 01 00 00 00 89 e7 25 07 07 1f d7 16 26 c9 3c f2 2d 2e                      CRC16 = 0x2E2D
```

A.9 Handshake keys, HELLO (pre_ctr above 0x10000) and BIND

```
T0 = SHA-256(SEEK e2e header || SEEK payload) = 87e4b0aba23b9b44a3cd96a5821c90a50bff4ba265353095e969132881f53f99
Ke_hello = Expand(PRK, "hello" || 34 12 || 42 00 || T0, 16) = 9239b60dae4214844f7a69dab1213e95
HELLO (P -> S via R): header 12 02 42 00 34 12 42 00 99 00 40 03 00 00 00 00 07 00 1c, pre_ctr 0x00010007
clear = 07 00 01 00 ; secret plaintext = 01 00 01 00 d4 c3 b2 a1 0d f0 ad 0b 3b 00 fa 00 c3 00 01 00 02 00 00 00
        (seek_ctr 0x00010001, nonce_s, nonce_p 0x0BADF00D, caps, max_frame 250, rssi -61, status 0, cost 1, minor 0, fw 2)
nonce = 01 42 00 34 12 00 01 00 00 00 07 00 00 ; AAD = 12 02 42 00 34 12 00 07 00 1c 01 00 00 00 07 00 01 00
payload = 07 00 01 00 af e2 fb d9 7d 6e 08 44 8e 30 bc 84 45 a8 4c 12 e8 1b cc ff 9c 81 6d 5f ; tag = 56 8b cc 47 13 50 60 38
frame (61): header || payload || tag || hop_tag 69 09 a4 04 || 66 36                 CRC16 = 0x3666
T  = SHA-256(SEEK e2e || SEEK payload || HELLO e2e || HELLO plaintext payload) = be09b4a6362349e0abd82354e798e1f262478d0e652d430dbe0ad6e5239f4427
Ke_hs = 30f75c3790a3ffe42d83706658f3cd68 ; Ke_s2p = 127f453b23f0f2d68d313579fd0138f0 ; Ke_p2s = 20202f07edc6da33a817af62cc1036eb
BIND (S -> P via R): header 12 03 34 12 42 00 34 12 99 00 40 08 00 00 00 00 02 00 11, pre_ctr 0x00010002
clear = 02 00 01 00 ; secret = 07 00 01 00 d4 c3 b2 a1 0d f0 ad 0b 07 (hello_ctr, nonces, session 7)
nonce = 00 34 12 42 00 00 01 00 00 00 02 00 00 ; payload = 02 00 01 00 46 e9 bc 98 36 ec 9c ff 60 1a 67 bd a3
tag = 7c a2 e8 84 c2 6a 45 58 ; frame (50): header || payload || tag || hop_tag 3c e8 46 60 || 36 d1   CRC16 = 0xD136
```

A.10 ROC: estimation cases and a second-cycle frame

```
(seq, highest, roc) -> roc used: (0x0005, 0xFFF0, 0) -> 1; (0xFFF0, 0x0005, 1) -> 0;
(0x8001, 0x0000, 3) -> 2; (0x7FFF, 0xFFFF, 3) -> 3
A.7 plaintext at ROC 1, seq 5, hop_seq 0x2345: nonce 00 34 12 42 00 07 01 00 00 00 05 00 00
ciphertext = 9e e2 ea f7 c5 e0 ca fa ff 7a 64 ; tag = be 5c b4 ea d4 89 97 17
frame (44): 12 10 34 12 42 00 34 12 42 00 30 45 23 00 00 07 05 00 0b 9e e2 ea f7 c5 e0 ca fa ff 7a 64
            be 5c b4 ea d4 89 97 17 44 cf e2 7e b4 77                           CRC16 = 0x77B4
```

A.11 RESUME flood (clear, Ke_s2p), session 7 at seq 0x0042, ROC 0, pre_ctr 0x00010003, ttl 3, hop_seq 0x4000

```
header 12 31 34 12 42 00 34 12 ff ff 30 00 40 00 00 07 42 00 05 ; payload 03 00 01 00 01
nonce = 00 34 12 42 00 07 00 00 00 00 42 00 00 ; ccm_tag = 45 d2 d9 a1 98 1a fc 05
frame (38): header || payload || tag || hop_tag cd ea 1a ad || 3e 37                  CRC16 = 0x373E
```

A.12 MGMT_REQ (flooded, no route) from P and the MGMT_RESP from M

```
K_pair(0001, 0042, 1) = 6368f6bf23c97acb0b9c36574f0cc2981456ae5c71d335a5b07cd180b2607088
K_mgmt(0042 -> 0001) = Expand(Extract("ProbeLink-v1", K_pair), "mgmt" || 42 00 || 01 00, 16) = c7ccbdf12bd73a2f349cf415f666d987
MGMT_REQ: header 12 40 42 00 01 00 42 00 ff ff 40 04 00 00 00 00 08 00 19, pre_ctr 0x00010008
secret = 15 cd 5b 07 00 00 00 00 01 01 01 00 00 11 11 11 11 11 11 11 11 (t1 123456789, e_new 1, e_old 1, want_bundle, section 0, page 0, 8 bytes)
nonce = 00 42 00 01 00 00 01 00 00 00 08 00 00 ; payload = 08 00 01 00 93 b9 29 ae 8b d7 6c 0a 78 cc c5 66 22 b4 91 74 3a 43 03 e5 84
tag = 89 6a 14 26 57 39 bc 39 ; frame (58): header || payload || tag || hop_tag e9 52 0a f0 || 28 22   CRC16 = 0x2228
MGMT_RESP: header 12 41 01 00 42 00 01 00 99 00 40 05 00 00 00 00 05 00 21, pre_ctr 0x00020005
secret = 08 00 01 00 15 cd 5b 07 00 00 00 00 00 40 1e 18 24 0a 06 00 f4 41 1e 18 24 0a 06 00 00
         (req_ctr 0x00010008, t1 echo, t2 1700000000000000, t3 1700000000000500, flags 0)
nonce = 01 01 00 42 00 00 02 00 00 00 05 00 00
payload = 05 00 02 00 dc bd a5 fb fd 58 15 15 fd 52 12 2b 43 16 6a ed b6 b9 dd 56 81 86 61 52 7c f6 10 c5 ae
tag = f2 a1 91 20 28 23 29 9b ; frame (66): header || payload || tag || hop_tag 7a f0 6f 57 || 91 93   CRC16 = 0x9391
```

A.13 LOW quantization, range 0..3.3 V: scale 5.0356e-5, offset 1.65; v 0.00 -> q -32767; 1.65 -> 0;
3.30 -> 32767; 4.00 -> 32767 with CLIP.

A.14 Key bundle for node P: K_mesh(2) and its pair key with S for epoch 2

```
K_node(0042) = a0c1a1a62bf676517ae48c057ee1bba19e3a334af81836e5dca7d8e06520f2b1
Kb = Expand(Extract("ProbeLink-v1", K_node), "bundle", 16) = b454dbe89e96728e36bb0f2d9837d173
K_mesh(2) = df35c2e61873bb426390dff4d94cd1ce614a8cee59cfb65e9351b2b69f8dde33
K_pair(0042, 1234, 2) = 1b2d304fb26118f3f6fcf4900704f7d643409b45cc965982e26e9840658fe288
TLVs (72) = 01 21 02 <K_mesh(2)> 02 23 34 12 02 <K_pair(0042,1234,2)>
bundle_no 3 ; nonce = 02 42 00 03 00 00 00 00 00 00 00 00 00 ; AAD = 50 4c 42 31 42 00 03 00 00 00
bundle wire (84) = 03 00 00 00 || ciphertext (72) || tag:
03000000196fd869d83d4ad2f5da4e42246c9481c6da63369733bffff94af088105a72385a98896f6c8f5e9528290baed7adca87
204bc02d343ddcdb48d29d2110f7d2023e4e0f3d5c3cba550f5e0b216abe8bb7
```

## Appendix B. Minimal C API

Rules: no heap after `pl_init()` (mbedtls HMAC and CCM contexts are
preallocated); every call returns `pl_err_t`; transport RX callbacks only
copy into a queue with timeout 0; one `pl_task()` does all protocol work;
nothing blocks the caller longer than the Task Watchdog period. Runtime NVS
writes: `pl/txseq` and `pl/preseq` block boundaries, accepted bundles
(`pl/bundle_no`, keys, epochs), and `pl/boot_count` on power-on or external
reset only.

```c
typedef enum { PL_OK = 0, PL_ERR_ARG, PL_ERR_STATE, PL_ERR_NO_PROBE /* event */, PL_ERR_TIMEOUT,
               PL_ERR_BUSY, PL_ERR_TOO_BIG, PL_ERR_AUTH, PL_ERR_QUEUE_FULL } pl_err_t;
typedef enum { PL_ROLE_NODE = 0, PL_ROLE_BRIDGE, PL_ROLE_GATEWAY, PL_ROLE_LEAF } pl_role_t;
typedef uint8_t pl_session_t;                 /* handle: index of a session record */

typedef struct {                              /* all from NVS (12.2) */
    uint16_t unit_id; pl_role_t role; uint8_t node_count, seek_ttl;
    uint8_t max_sessions, max_streams;        /* records / stream buffers (4.1.12) */
    pl_keystore_t *keys;                      /* encrypted-NVS backed: K_mesh epochs, K_node, pair keys, managers, bundle_no */
    const uint8_t *net_key;                   /* bench profile only */
} pl_config_t;

typedef struct {
    uint8_t config_id, mode, ch_count; uint32_t period; uint8_t fec_k, fec_m, arq, flags; uint16_t keepalive_ms;
    struct { uint8_t kind, fmt; float scale, offset; } ch[16];
    struct { uint32_t size; uint8_t sha256[32]; uint32_t fw_build; } bulk;   /* mode 2 */
} pl_mode_t;

typedef struct {
    void (*on_seek_result)(pl_session_t s, pl_err_t result, uint16_t probe_id, uint8_t hops);
    void (*on_bound)(pl_session_t s, uint16_t peer_id);                        /* probe side */
    void (*on_mode)(pl_session_t s, const pl_mode_t *mode);
    void (*on_samples)(pl_session_t s, const pl_mode_t *mode, const uint8_t *samples,
                       uint8_t n_samples, uint32_t t_first_us, uint64_t utc_us, uint8_t status);
    void (*on_gap)(pl_session_t s, uint16_t first_seq, uint16_t count);
    void (*on_closed)(pl_session_t s, uint8_t reason);
    void (*on_mgmt_command)(uint8_t command);                                  /* 11.10 TLV 0x04 */
    void (*on_bundle)(uint32_t bundle_no, bool accepted);                      /* 8.6 */
    void (*on_event)(uint16_t event, uint32_t arg);                            /* PL_EVT_ID_COLLISION, PL_EVT_NO_PROBE, PL_EVT_LINK_FAIL, ... */
} pl_callbacks_t;

typedef struct { uint8_t blob[200]; uint32_t crc32; } pl_rtc_state_t;         /* 4.4, RTC_DATA_ATTR; includes pl_mode_t */
typedef struct pl_keystore pl_keystore_t;                                      /* opaque: get/put by (kind, id, epoch) */
typedef struct pl_mgmt_server pl_mgmt_server_t;                                /* opaque: bundle store, time source, report sink callbacks */
typedef struct pl_ctx pl_ctx_t;                                                /* opaque, PL_CTX_STATIC(...) */

/* RAM, approximately: session record ~600 B x max_sessions; stream buffer (FEC 2180 + reorder 2500)
 * x max_streams; sender ARQ buffer 24 x 250 = 6 KB per active sender session; forwarding tables ~7 KB
 * (11.9); rx queue 16 x 250. A C3 probe with 32 records and 4 streams: ~19 + 19 + 7 + 4 = ~49 KB;
 * the sink with 50 records and 8 streams: ~30 + 38 + 7 + 4 = ~79 KB. */
#define PL_CTX_STATIC(name, max_sessions, max_streams) ...

pl_err_t pl_init(pl_ctx_t *ctx, const pl_config_t *cfg, const pl_callbacks_t *cb);   /* PL_ERR_AUTH if 12.1 fails: UART wait */
pl_err_t pl_add_transport(pl_ctx_t *ctx, const pl_transport_t *tr, uint8_t *index_out);
/* sender: asynchronous; seeking continues with the 4.1.8 backoff until success or cancel */
pl_err_t pl_seek(pl_ctx_t *ctx, uint16_t dst_id, pl_session_t *s_out);
pl_err_t pl_seek_cancel(pl_ctx_t *ctx, pl_session_t s);
pl_err_t pl_set_mode(pl_ctx_t *ctx, pl_session_t s, const pl_mode_t *mode);
pl_err_t pl_send_samples(pl_ctx_t *ctx, pl_session_t s, const void *samples, uint8_t n, uint32_t t_first_us, uint8_t status);
pl_err_t pl_close(pl_ctx_t *ctx, pl_session_t s, uint8_t reason);
pl_err_t pl_park(pl_ctx_t *ctx, pl_session_t s, uint16_t park_s, pl_rtc_state_t *out);   /* leaf */
pl_err_t pl_resume(pl_ctx_t *ctx, const pl_rtc_state_t *in, pl_session_t *s_out);         /* leaf, after deep sleep */
/* probe / manager */
pl_err_t pl_listen(pl_ctx_t *ctx, const uint16_t *groups, uint8_t n_groups);
pl_err_t pl_mgmt_request(pl_ctx_t *ctx);                                   /* send MGMT_REQ now (default: periodic) */
pl_err_t pl_mgmt_serve(pl_ctx_t *ctx, pl_mgmt_server_t *srv);              /* gateway / station / phone */
pl_err_t pl_maintenance_mode(pl_ctx_t *ctx, bool enter);                   /* stop mesh, start BLE phone link (6.4) */
void     pl_task(void *ctx);                                               /* FreeRTOS task; stack 6144 as a start, measure */

typedef struct {
    uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail, seg_fail, bad_frame, bad_version,
             auth_fail, hop_tag_fail, hop_replay, replay_dropped, bundle_fail, fec_recovered, arq_retx, gaps,
             id_collisions, rx_queue_drop, relay_fwd, relay_drop_ttl, relay_drop_dedup, relay_drop_stale,
             relay_drop_noroute, relay_drop_mtu, relay_drop_rate, relay_drop_queue_data,
             relay_drop_queue_ctrl, relay_drop_loop, route_evictions, link_evictions, link_fail_drops;
    uint16_t stack_hwm_words;
} pl_stats_t;                                                              /* MGMT section 1, this order */
```

Task layout: transport callbacks -> `xQueueSend` (timeout 0) -> `pl_task`
(validation, pipeline, FEC/ARQ, callbacks, framing, CCM, hop_tag, `send()`,
whose result feeds the 11.6 failover). `pl_send_samples()` only enqueues.

## Appendix C. Carrier notes

C.1 IR edge link (to be validated on hardware; indoor or shaded only)

- 38 kHz carrier via RMT, TSOP-style receiver. Pulse-distance cell: mark
  300 us, space 300 / 600 us, about 2 kbit/s (estimate); validate against the
  receiver's minimum burst and gap. Preamble 9 ms mark + 4.5 ms space; 10 ms
  trailing silence delimits a frame (no COBS; 0x00 is legal).
- RMT RX memory is 48 symbols per block on the C3, so a 64-byte frame (about
  512 symbols) needs the driver's partial-receive mode (ESP-IDF >= 5.3;
  verify) or a GPIO-capture ISR; the S3 can use RMT DMA.
- Half duplex: never transmit while receiving; wait `IR_GUARD_MS` after a
  received frame. `rs_nsym` 6; `fec_k` 2, `fec_m` 1; `rssi` -128. Keys per
  8.2 (edge pair key, never retired).

C.2 UART: 8N1; 115200 for sensors, 921600 or more for the gateway inter-chip
link (12.4) and the provisioning station; COBS with 0x00 delimiter,
resynchronise on any 0x00; FIFO-threshold or idle-line interrupt, frames
processed in `pl_task`.

C.3 ESP-NOW: peers per 11.11; unicast is MAC-retried and the send callback's
status is the 11.6 failover signal; broadcast is not retried, so floods are
sent `FLOOD_REPEAT` times. RSSI from `esp_now_recv_info_t`.

C.4 WiFi UDP (LAN side only): port 40888; floods to multicast 239.255.40.88,
IP TTL 1, IGMP join at start; unicast to the link table's address; static
IPs or DHCP reservations; `pl/udp_peers` unicast list where multicast or
client isolation blocks it; otherwise the UDP carrier is unusable and the
installation must say so.

C.5 nRF24L01+ over SPI

- Facts: 32-byte packets (dynamic length), Enhanced ShockBurst CRC-16,
  auto-ACK and auto-retransmit, 6 RX pipes, 5-byte addresses, 250 kbps / 1 /
  2 Mbps, channels 0-125 at 2400 + n MHz, no RSSI.
- Segmentation (adapter only): a frame of n bytes goes as `ceil(n / 29)`
  packets of `src u8 (low byte of prev_hop), tag u8 (per-node counter),
  idx:7 | LAST:1, up to 29 bytes`. Reassembly buffers are keyed by
  `(src, tag)` and opened by segment 0 (`NRF_REASM` 4 buffers of 258 bytes);
  segments in order; a gap, a foreign tag before LAST, or
  `NRF_REASM_TIMEOUT_MS` (50) drops the frame (`seg_fail`). Two
  neighbours whose unit IDs share a low byte can still interleave; the
  frame-level CRC then drops both (known limitation, 12.10). ESB retries
  (ARC 15, ARD 500 us) make a lost unicast segment rare; MAX_RT after the
  retries is the 11.6 failover signal. The adapter reports `max_frame` 250,
  so the path MTU never sees 32.
- Overhead: a 250-byte frame is 9 packets, about 1.5x on the air with ESB
  framing; roughly 3-4 ms per frame clean at 2 Mbps, 30-60 kbit/s of frame
  payload (estimate); divide by about 6 at 250 kbps.
- Addresses: unicast address of unit U = `50 4C U_hi U_lo A5`; broadcast =
  `50 4C FF FF A5`. Pipe 0 and pipe 1 have independent 5-byte addresses:
  pipe 0 listens on the node's own address (and is reprogrammed to the
  destination during an auto-ACK transmit, as RF24 does), pipe 1 on the
  broadcast address. Floods use `W_TX_PAYLOAD_NOACK` (EN_DYN_ACK) with
  `FLOOD_REPEAT` copies. The link table address is derived, not learned.
- Channel: `pl/nrf_channel` 76-81 at 2 Mbps (2476-2481 MHz, above WiFi
  channel 13 and inside the 2483.5 MHz ISM limit; a 2 Mbps signal on 82-83
  spills past it, so use those only at 250 kbps or 1 Mbps). With an nRF24
  site the ESP-NOW mesh channel is 1-6 (12.4).
- Half duplex: PRX between frames, `NRF_GUARD_MS` 2 after a transmit. Link
  cost 2. Driver: nRF24/RF24 (ESP-IDF SPI port), raw packet, pipe, DPL and
  NO_ACK features only.

## Appendix D. Change history and review disposition

History: v0.2 CRC on all links, RS erasure code across frames, probe nonce,
ARQ, two-nonce keys; v0.3 mandatory mesh; v0.4 hop_tag, 48-bit index,
per-pair keys, epochs, validation table, leaves, nRF24L01+; v0.5 BLE as a
phone link, IR as an edge, one max_frame, CCM + HMAC hop_tag, unicast BIND,
MGMT_REQ/RESP, pulled bundles. Round-1 and round-2 dispositions are in
PROTOCOL.v0.4.md and PROTOCOL.v0.5.md; all round-2 items closed in v0.5
except those reopened by round 3 (G1/T3 -> H1/U5, G3/T10 -> H2/U3, G8/T8 ->
H3/U1, G6 -> H4, G10 -> H5/H7, G9 -> H6, T1 -> U2).

v0.6 (round-3 fixes; this document):

- Header: `hop_seq` is the full 32-bit `txseq` (19 bytes, SEEK 22); `pre_ctr`
  is a clear AAD prefix on every session_id 0 frame and RESUME; HELLO and
  BIND echo the SEEK and HELLO counters they answer. Vectors A.2-A.12
  recomputed, A.12 adds MGMT_RESP, A.14 adds a bundle.
- Keys: `K_hop` derived from `K_mesh`; `K_node` per node with `Kb` for
  bundles; recovery holders as separate IDs 0x0003..0x000F with their own
  pair keys; edge pair key for IR.
- Epochs: two live epochs plus a retired slot; everything transmits under
  `E_old`; retirement only by bundle TLV 0x06 after the tool has seen every
  node; recovery of stragglers through the retired slot for MGMT_REQ;
  revocation epoch strictly above everything the revoked node held.
- Bundles: defined wire format (8.6), opaque to managers, chunked by index,
  manager replacement TLV 0x07.
- Mesh: route refresh only from the next hop in the return direction, send
  failures delete links and routes, MGMT response timeout with retries and
  flood fallback, boot spread for MGMT, FULL backoff to a 1 h cap, stream
  buffer hold/release rule, sink sizing and the gateway UART rate.
- Leaves: update window on command 3, MGMT after an update boot, counters
  from max(RTC, NVS); IR leaves managed by the attached node.
- Also: fail-closed field boot and BLE (U7), maintenance timeout, capture
  alarms, anti-rollback, MODE_RETRY = RTO, FEC flush scaled to period,
  airtime row corrected, section 0 byte layout, provisioning order,
  `nvs_keys` for the original ESP32, nRF24 segment source byte, 12.11
  readiness list.

Round 3 disposition. Field MEDIUM/LOW items had no IDs in ROAST-3-field.md;
they are numbered here H8-H16 (MEDIUM) and H17-H21 (LOW) in that file's order.

| ID | Sev | Disposition | Where / reason |
|---|---|---|---|
| H1 | CRITICAL | fixed | 8.5: transmit under E_old, explicit RETIRE by bundle, no timers, retired slot for MGMT_REQ recovery |
| H2 | CRITICAL | fixed | 8.3: clear pre_ctr prefix in the AAD of every session_id 0 frame; req_ctr echo; A.9 / A.12 recomputed with pre_ctr >= 0x10000 |
| H3 | HIGH | fixed | 8.6: K_node bundles with wire format, nonce, AAD, chunk index; managers relay opaquely; A.14 |
| H4 | HIGH | fixed | 11.4 refresh only from next_hop in the return direction; 11.6 send-failure link deletion; 11.10 timeout, retries, flood; boot spread; 12.7 validity 3 x MGMT_PERIOD_S |
| H5 | HIGH | fixed | 8.2 edge pair key never retired; 11.11 attached node is the IR leaf's manager; 12.6 rekey/update by station |
| H6 | HIGH | fixed | 12.4 sink = gateway mesh chip with node_count records and 8 streams, 921600 baud, re-origination as the other path; 4.1.12 stream hold/release; 4.1.4 FULL backoff |
| H7 | HIGH | fixed | 4.4 update window on command 3, awake until the BULK session ends; 12.7 |
| H8 | MEDIUM | fixed | hop_seq 32-bit on the wire (no reconstruction); link entries expire regardless of routes (11.6, 11.9) |
| H9 | MEDIUM | fixed | seek_ctr / hello_ctr echoes select one transcript (4.1.5, 8.2) |
| H10 | MEDIUM | fixed | FEC flush max(FEC_FLUSH_MS, 2 x period) (3.3); keepalive row 4.8 % (4.2, 9) |
| H11 | MEDIUM | fixed | download-mode eFuse burned last (12.2) |
| H12 | MEDIUM | fixed | WIFI_MODE_STA unassociated, never AP (1.2, 11.11, C.3) |
| H13 | MEDIUM | fixed (partial) | nRF24 segment header carries the low byte of prev_hop; same-low-byte interleave remains a stated limitation (C.5, 12.10) |
| H14 | MEDIUM | fixed | MODE_RETRY = RTO (4.2, 6.1) |
| H15 | MEDIUM | fixed | revocation closes live and parked sessions with the revoked ID (8.5) |
| H16 | MEDIUM | fixed | section 0 byte layout incl. clone bit, pl_stats_t wire order (11.10, App. B) |
| H17 | LOW | fixed | max payload 217 / IR 25 (3, 6.1) |
| H18 | LOW | fixed | PARITY block_len <= max_payload - 8 (3.6) |
| H19 | LOW | fixed | RTC blob carries pl_mode_t; pl_keystore_t / pl_mgmt_server_t declared (4.4, App. B) |
| H20 | LOW | fixed | manager and holder IDs reserved (2); round-2 G20 wording superseded by this table |
| H21 | LOW | fixed | lost phone = holder ID revoked by bundle (8.6, 6.4) |
| U1 | CRITICAL | fixed | = H3; R2 and R8 restated; managers author commands and time only |
| U2 | CRITICAL | fixed | full 32-bit hop_seq under the hop_tag, HOP_MAX_JUMP (3.5, 8.4) |
| U3 | HIGH | fixed | = H2 |
| U4 | HIGH | fixed | MGMT_RESP bound to the outstanding request by req_ctr; commands 1-2 rate limited; endpoint counter state replaced by matching (8.4, 11.10) |
| U5 | HIGH | fixed | = H1: E_old / E_new / retired defined, erase rules relative to E_old |
| U6 | HIGH | fixed | recovery holders 0x0003..0x000F with own pair keys, rotatable and revocable by bundle, disjoint nonce spaces by src_id (2, 6.4, 8.6) |
| U7 | HIGH | fixed | field node without keys waits for UART only; BLE needs a stored holder key; no automatic NVS erase (6.4, 12.1) |
| U8 | MEDIUM | fixed | revocation epoch above every epoch issued to the revoked node (8.5) |
| U9 | MEDIUM | fixed | HOP_MAX_JUMP 2^16 (3.5, 9) |
| U10 | MEDIUM | fixed | MAINT_TIMEOUT_S 600, reported in section 0 (6.4) |
| U11 | MEDIUM | fixed | counters resume from max(RTC, NVS); leaves keep writing NVS (3.5, 4.4) |
| U12 | MEDIUM | fixed | secure-version eFuse; fw_build never below running (8.7, 12.7) |
| U13 | MEDIUM | fixed | gateway alarms on missed reports, reset pattern, secure-state bits, epoch regression (8.7) |
| U14 | LOW | fixed | K_hop derived from K_mesh (8.2) |
| U15 | LOW | fixed | original ESP32 nvs_keys path (12.1) |
| U16 | LOW | fixed | the only remaining timer, KEY_RECOVERY_S, is uptime-based; retirement has no timer (8.5, 9) |
| U17 | LOW | fixed | one bound, 2^16, justified for every role (11.5) |
| U18 | LOW | fixed | OFFERED bound stated as an insider limitation (12.10) |
| U19 | LOW | fixed | A.12 MGMT_RESP and flooded MGMT_REQ, A.14 bundle |
