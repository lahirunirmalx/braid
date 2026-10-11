# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.8 (two chip families: ESP32-WROOM and ESP32-S3-WROOM-1; wire version 1, minor 0, unchanged from v0.7)

One protocol, four mesh carriers (ESP-NOW, WiFi UDP, nRF24L01+, UART) plus
an IR edge link. Every device has an ID. Every frame is integrity-checked and
carries enough redundancy to recover damaged or lost data. Payloads are
digital or analog 32-bit values, sent in HIGH or LOW resolution.

Reading guide: sections 1-10 keep the v0.1 numbering so the drafts can be
diffed. Section 11 is the mesh layer (mandatory). Section 12 holds the
deployment profile for two chip families (bench: any ESP32-WROOM or
ESP32-S3-WROOM-1; field: S3-WROOM-1U gateway, S3 or WROOM-32E nodes, 12.1,
12.12), every design decision with its alternative (BLE, IR and gateway
silicon are user decisions), the known limitations and the implementation
readiness list. One wire format serves both chips (12.12). Section 13
gives application profiles. Appendix D maps every review finding to its
disposition. Numbers marked "(estimate)" are not measurements. Versions
before v0.7 were never on the air; the frozen prefix of section 3 applies
from v0.7 on.

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
    uint16_t        max_frame;     /* 250 on mesh carriers; 80 on IR (incl. RS parity) */
    uint8_t         rs_nsym;       /* 0 PACKET, 8 UART, 6 IR */
    bool            can_broadcast; /* floods by broadcast (ESP-NOW, UDP multicast, nRF24) */
    bool            mac_retry;     /* carrier reports unicast delivery (ESP-NOW, nRF24): used for failover (11.6) */
    bool            edge_only;     /* IR: frames are never forwarded to or from this transport */
    uint8_t         link_cost;     /* for carriers without RSSI (11.4): UART 1, nRF24 2 */
    uint8_t         addr_len;      /* carrier address bytes in the link table: 6 ESP-NOW, 5 nRF24, 4 UDP, 0 UART/IR */
    int  (*send)(const uint8_t *addr, const uint8_t *buf, uint16_t len);   /* addr NULL = broadcast; queues the frame */
    void (*set_rx_cb)(void (*cb)(const uint8_t *addr, const uint8_t *buf, uint16_t len, int8_t rssi));
    void (*set_tx_cb)(void (*cb)(const uint8_t *addr, bool delivered));    /* where mac_retry: asynchronous delivery status (ESP-NOW send callback, nRF24 MAX_RT), feeds 11.6 */
} pl_transport_t;
```

| Carrier | Class | max_frame | Notes |
|---|---|---|---|
| ESP-NOW | PACKET | 250 | Broadcast FF:FF:FF:FF:FF:FF for floods, unicast to the `next_hop` MAC otherwise. One dedicated channel (`pl/channel`) for all mesh nodes; `WIFI_MODE_STA` never associated and never AP; `esp_wifi_set_ps(WIFI_PS_NONE)`; BT never runs while the mesh is up (12.4, 12.5). `rssi` from `esp_now_recv_info_t` (ESP-IDF >= 5.0). |
| WiFi UDP | PACKET | 250 | LAN side of the gateway only (12.4). Port 40888, multicast 239.255.40.88 TTL 1 for floods, unicast otherwise; static IPs or DHCP reservations; a configured unicast peer list replaces multicast on isolated LANs (C.4). |
| nRF24L01+ (SPI) | PACKET | 250 (reassembled) | 32-byte packets, segmented and reassembled inside the adapter per hop (C.5). ESB CRC-16, auto-ACK unicast on unit-ID-derived addresses, NO_ACK broadcast address for floods. No RSSI: fixed `link_cost` 2; `rssi` reported as -128 (unknown). |
| UART | RAW | 250 (incl. 8 RS bytes) | COBS, 0x00 delimiter; COBS bytes are outside max_frame. Point to point. Also the carrier of the two-chip gateway (921600 baud or more, 12.4) and of the provisioning station (12.2). |
| IR (RMT) | RAW, edge | 80 (incl. 6 RS bytes) | One hop, point to point, between an IR leaf and one mesh node; never forwarded (user decision, 12.6). 74-byte path MTU carries every control frame (A.15). 38 kHz, half duplex, indoor or shaded, about 0.3 s per frame (estimate). Keyed by the edge pair key, not the mesh key (8.3). Both ends apply `IR_TIME_SCALE` (10) to the handshake timers of that link only. |

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
  `PL_EVT_ID_COLLISION`; MGMT reports carry (MAC, unit_id), so the gateway
  sees two MACs for one ID anywhere in the mesh.
- A "destination" is a group ID; probes subscribe to up to `PL_MAX_GROUPS`
  (8, NVS `pl/groups`). A sender seeks the group, not a probe; a unit ID is a
  group of one (the update server uses that, 12.7). A node accepts a frame
  whose `dst_id` is its unit ID, a group it subscribes to, or 0xFFFF; after
  BIND all session frames are unicast to the peer's unit ID.

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

One header everywhere: the mesh fields cost 9 bytes and the field tags 12,
8 % of a 250-byte frame and 26 % of an 80-byte IR frame. Compressing it for
IR or point-to-point links (at most 4 bytes, two parsers) was rejected; the
32-bit hop_seq buys freedom from any wrap (review U2); nRF24 segments inside
its adapter (C.5).

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
| CCM tag | valid under the key of section 8.3 with `ctr_hi` from the clear `pre_ctr` (session_id 0) or the ROC estimate (session frames, RESUME included); for session_id 0 frames header `seq` == low 16 bits of `pre_ctr` | `auth_fail`, `bad_frame` |
| SEEK | len 18; caps reserved bits 0; max_frame >= MIN_PATH_MTU; key_epoch is a live epoch, or equals `E_prov` on an `edge_only` link (8.5) | `bad_frame` |
| HELLO | len 28; status 0..1; nonce_s and seek_ctr match an outstanding SEEK | `bad_frame` |
| BIND / BIND_ACK / BIND_NAK | len 17 / 12 / 9; nonces (and hello_ctr) match an OFFERED or BINDING entry; session_id != 0 (BIND) | `bad_frame` |
| MODE | len 13 + descriptor bytes (mode 2: 13 + 40); ch_count 1..16 (mode 0/1); kind 0..1; fmt 0..2 analog, 1..32 digital; scale finite and non-zero, offset finite; period > 0; fec_m 0..4; fec_k 2..16 when fec_m > 0; arq 0..1; keepalive_ms 1000..60000; one full sample <= max_payload - 7 (- 9 more with FEC) | MODE_ACK status 3 or 2 |
| MODE_ACK / ACK / RESUME_ACK / PING / PONG / CLOSE / RESUME | len 2 / 6 / 6 / 4 / 8 / 3 / 5; cum_seq inside the ARQ window | `bad_frame` |
| DATA | config_id known; len == 7 + n_samples x sample bytes (mode 2: 7 + n_samples) | `bad_frame` |
| PARITY | idx < m == fec_m; k 1..fec_k; block_len <= max_payload - 8; first_seq inside the window | `bad_frame` |
| MGMT_REQ / MGMT_RESP | fixed part 22 / 33; MGMT_RESP `req_ctr` equals the node's outstanding request; TLVs (type u8, len u8) within len; section 0..4 | `bad_frame`, `replay_dropped` |

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
   RESUME and fallback SEEK) trigger an immediate MGMT_REQ, at most once per
   `MGMT_PERIOD_S`: it is admitted under the retired epoch slot and its
   response carries the key bundle that lets a node behind a retirement
   rejoin (8.5). A probe in OFFERED that hears the same `nonce_s` with a newer `pre_ctr`
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
    4.7 KB each). A session with `arq` 1 or `fec_m` > 0 takes a stream at
    its first DATA and holds it until CLOSE, PARK or `SESSION_TIMEOUT`
    (review J4: no release between groups, so a bound session never finds
    its stream gone); sessions with `arq` 0 and `fec_m` 0 deliver in
    arrival order with no stream. Parked sessions hold a record and no
    stream. "Full" is decided once, at HELLO (rule 2): no free record, or no
    free stream for a sender whose caps include ARQ or FEC. Probes allocate
    no ARQ buffer. Sizing from the manifest: records >= senders served
    (parked leaves included); streams >= senders with ARQ or FEC that can be
    bound at the same time. The sink probe (12.4) uses `PL_MAX_SESSIONS` =
    `node_count` and `PL_MAX_STREAMS` = that manifest count; the tool
    refuses a manifest whose sink exceeds the chip budget of 12.4 and points
    to a second sink probe.
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
| seq wraps at 65535 | Serial arithmetic for ordering; 48-bit index with implicit ROC in the CCM nonce for replay (3.5, 8) |
| Replayed SEEK / HELLO / BIND / MGMT_RESP | pre_ctr freshness at relays; nonce and ctr echoes at endpoints; transcript-bound keys (8.4) |
| 50 nodes reboot together | Boot holdoff for SEEK and MGMT, full-jitter backoff, jittered re-SEEK (4.1.1, 4.1.8, 4.2, 11.10) |
| Relay on a session path dies | SESSION_TIMEOUT -> re-SEEK installs new routes; penalty list avoids the dead first hop (4.2) |
| Relay on the management path dies | Send failures and the response timeout delete the route; the next MGMT_REQ floods (11.6, 11.10) |
| Every probe of a group is FULL | Exponential backoff to a 1 h cap, not a flood per minute (4.1.4) |
| Node returns holding only a retired epoch | Its MGMT_REQ is accepted under the retired slot, the bundle is epoch-independent, it rejoins (8.5) |

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
- Wake: the leaf sends RESUME (type 0x31, clear `pre_ctr` and `config_id`,
  authenticated under `Ke_s2p`). If it slept less than `ROUTE_TTL_MS / 2`
  (10 min) the routes it used are still alive on every relay, so RESUME is
  unicast along the stored first hop (no flood: a 60 s check-in costs no
  airtime beyond its own frames, section 13); otherwise it is flooded with
  `ttl = min(hops + 1, MAX_HOPS)`, relays treat it as a flood (ORIGIN
  freshness on its `pre_ctr`, dedup, budget) and it re-installs reverse
  routes. The probe verifies the tag and the session index, replies
  RESUME_ACK on the reverse route, which installs the forward routes (11.4),
  and the leaf sends DATA. Timeout `BIND_TIMEOUT(hops)`; one retry with a
  new `pre_ctr` and a new session seq (an identical retry would be a dedup
  hit), flooded if the first was unicast; then a full SEEK.
- Management on wake: every `MGMT_EVERY_WAKES` (10) wakes, and on the first
  wake after any non-deep-sleep boot (an update included), the leaf sends
  MGMT_REQ to its manager after DATA and stays awake for the reply chain
  (11.10, one request per second, so a 20-chunk bundle costs about 20 s
  awake once per rotation). This is how a leaf receives keys and time and
  reports its battery; nothing is pushed to a sleeping node, so a bundle
  waits at most 10 wakes. An IR leaf's manager is its attached node (11.11).
- Update window (review H7): a leaf that receives MGMT command 3 skips its
  next park, subscribes to its own unit ID as a probe for `BULK_WINDOW_S`
  (120) and, once bound, stays awake until the BULK session closes or times
  out (minutes for a 1 MB image, 12.7); then it parks. Its image is marked
  valid by one MGMT_RESP received before the first park after the update.
- Power: battery voltage is checked before the radio starts; below
  `VBAT_MIN` the wake is skipped and reported in the next MGMT section 0.
  Lowest TX power that closes the link; a bulk capacitor for primary cells.
  Wake budget (estimate, measure): Secure Boot v2 image check 100-300 ms +
  WiFi start 120 ms + RESUME round trip 20-60 ms unicast (100-500 ms
  flooded) + DATA and ACK 20 ms, 0.3-0.9 s at about 100 mA, roughly 0.02 mAh
  per wake: about 2-3 months on an 18650 (2500 mAh) at one wake per minute,
  over a year at one per five minutes. VBAT is read on ADC1 (ADC2 is shared
  with WiFi on the ESP32 and the S3). Wake sources and sleep currents per
  chip: 12.12.

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
| 0x40 | MGMT_REQ | node -> manager | K_mgmt | P; 11.10 (fixed 22) |
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
  217). On the IR edge link (max payload 41 with AUTH) MODE fits two LOW
  analog channels (33 bytes) or 14 digital / HIGH descriptors.
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
| IR edge link (80 - 6) | 74 | 34 | 2 / 4 | 46: 2 / 5 |

Throughput (estimates): ESP-NOW at 1 Mbps about 100 kbit/s goodput (50 full
frames/s per collision domain); nRF24 at 2 Mbps 30-60 kbit/s per link (C.5);
IR about 3 frames/s (80-byte frames at about 2 kbit/s). Keep the frame rate under the carrier's limit with
margin for PARITY and retransmissions.

### 6.4 BLE phone link

BLE is used only for commissioning and local diagnostics from a phone, and
only while the node is in maintenance mode. On the ESP32-WROOM the controller
cannot be started cleanly next to a running WiFi stack without coexistence
time-slicing, so maintenance mode is entered by reboot: the node sets an RTC
flag and restarts; that boot starts NimBLE and never starts WiFi (about
55 KB of DRAM is reserved for the BT controller in every ESP32 image,
Appendix B budgets for it). The S3 controller could coexist with WiFi, but
the reboot rule holds on both chips so there is one code path (12.12). The
phone connects and exchanges MGMT frames (11.10) over one GATT
characteristic pair under `K_mgmt(node, holder)`, where the holder is a
recovery ID 0x0003..0x000F with its own pair key per device (8.2). A phone
is a manager for commands and time only; it carries key bundles as opaque
bytes and cannot author keys (8.6). Entering maintenance mode: a button, or a
MGMT command 1 from the gateway; it ends on command, or after
`MAINT_TIMEOUT_S` (600) without a frame, with a reboot back into mesh mode.
BLE and WiFi never run together on one chip (reviews G13, J11). Fail closed
(review U7): a field node that holds no keys enters only the UART
provisioning wait of 12.2; BLE requires at least one stored recovery-holder
key; field builds never erase NVS automatically, log such a state in the RTC
reset log and report it in the next MGMT section 0.

### 6.5 Timestamps and network time

- Session clock: a 32-bit microsecond counter from BIND_ACK (or RESUME_ACK)
  on each end, extended to 64 bits assuming consecutive DATA frames are less
  than 2^31 us apart; drift 20-40 ppm (estimate), so the receiver resamples
  on `t_first_us` or fits the sender's clock from PING/PONG pairs.
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
  recovered, or expired from the reorder buffer; the sender retransmits
  cleared-bit seqs it still holds as DATA and ignores the rest (`on_gap()`
  may count non-DATA seqs). Delivery is in seq order through a reorder
  buffer of `fec_k + fec_m` frames (4 without FEC) or `REORDER_MS`; a frame
  still missing when its slot expires is `on_gap(first_seq, count)`. Stream
  buffers are held per 4.1.12.
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
G8, T1-T24, H1-H7, U1-U19, J1-J5 and V1-V7 are addressed here and in 11.8.

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
| R11 | Capture of a node MUST be detectable by evidence the node itself cannot author or reset. | Gateway-side record of each node's report cadence and counter / epoch / bundle continuity; periodic manager challenge; tamper-evident enclosures on gateway and managers (8.7, review V1). |

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
| edge keys | on an `edge_only` link between leaf L and node A: `K_hop_edge = Expand(Extract("ProbeLink-v1", K_pair(L, A, E_prov)), "edge-hop", 32)`, `Ke_edge = Expand(..., "edge-enc", 16)`, replacing `K_hop` and `Ke_mesh` on that link; the handshake and `K_mgmt` on that link use `K_pair(L, A, E_prov)` whatever the live epochs are; `E_prov` is the provisioning epoch, held in its own NVS slot and never retired (A.15) | L and A |

- The transcript binds caps, `max_frame`, `key_epoch`, `proto_minor`, both
  nonces and both `pre_ctr` values into every key, so the two ends either
  agree on all of them or derive different keys and the handshake fails
  closed. HELLO names the SEEK copy it answers (`seek_ctr`) and BIND names
  the HELLO it accepts (`hello_ctr`), so retries never leave the two ends
  with different transcripts (review H8). Persistent `pre_ctr` values make
  key uniqueness deterministic.
- The manifest lists each node's peers (default all nodes, 49 x 32 bytes per
  epoch at 50 nodes), managers and recovery holders; a probe answers only
  senders it holds a pair key for, and MGMT is accepted only from listed
  managers and holders.
- A captured node yields its `K_mesh` epochs, `K_node` and its own pair
  keys: it can impersonate itself, forward, drop and misroute, flood within
  the budgets, and act under other IDs at the mesh layer (11.8); it cannot
  derive any other `K_pair` or `K_node` (R2). A captured gateway yields the
  same for ID 0x0001 plus the opaque bundles it stores. Recovery is
  revocation plus an epoch bump (8.5); a captured manager is replaced by
  bundle TLV 0x07 (8.6).
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
  4 payload bytes in clear (SEEK and RESUME: the whole payload), so the
  receiver forms the nonce with no state (reviews H2, U3). AAD =
  `e2e_header || ctr_hi u32 || clear prefix`, `e2e_header` being header
  bytes 0..5 plus `session_id`, `seq`, `len` (10 bytes); the rest of the
  payload is the ciphertext.
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
for `KEY_RECOVERY_S` (7 days, counted in MGMT periods and persisted every 10
periods so it survives reboots; NVS `pl/epoch_old`, `pl/epoch_new`,
`pl/epoch_retired`, `pl/mesh_key/<E>`, `pl/pair/<id>/<E>`). The IR edge pair
key is outside this scheme (8.2). The window is the straggler-return need
(a leaf below `VBAT_MIN` for a week) and no longer: for that long an old or
revoked `K_hop` holder can still spend flood budget on MGMT_REQ (review V3).

| Rule | Statement |
|---|---|
| Accept | hop_tag verifies under any live epoch for any frame; under the retired epoch only for frames of type MGMT_REQ (flood or unicast). SEEK decrypts under `Ke_mesh(key_epoch)` for any live epoch (edge link: `E_prov`); the handshake uses `K_pair(S, P, key_epoch)`. A manager trial-decrypts MGMT_REQ under `K_mgmt` of `E_old`, `E_new`, then the retired epoch (its pair keys are kept for `KEY_RECOVERY_S` too) and answers under the one that verified. |
| Transmit | everything under `E_old`: SEEK `key_epoch`, flood hop_tags, the pair key for new handshakes, `K_mgmt` for a node's own requests. Exception: a unicast hop_tag uses the epoch last verified from `next_hop` (link table), which is how a reply reaches a node that is behind; if the link entry is absent or names the retired slot for a frame other than MGMT_RESP, `E_old` is used. |
| Apply bundle | a bundle (8.6) is a full snapshot of the node's intended state: the live epochs it lists (one or two, consecutive, the lower one in {`E_old`, `E_new`, `E_new + 1`}) become `E_old` / `E_new`; the highest previously live epoch it omits moves to the retired slot (that is retirement); pair keys it omits are deleted and their sessions, live or parked, closed (that is revocation). Any other shape is rejected and counted (`bundle_fail`). A manager additionally keeps the pair keys of the epoch it just retired for `KEY_RECOVERY_S`, whatever its own snapshot says, so the Accept row holds. Because every bundle is a snapshot, a skipped bundle can never strand a node (review J2). |
| Tool pacing | the tool issues a snapshot that drops `E_old` only when every reachable non-revoked node's MGMT section 0 reports `E_new` and the current `bundle_no`, with a wait cap of 24 h (revocation) or the operator's choice bounded by `KEY_RECOVERY_S` (routine); it lists the unreached nodes; a new epoch only after the previous retirement. Unreached nodes recover through the retired slot (below) within `KEY_RECOVERY_S`, or by the UART station after it. A dead node therefore never blocks rotation. |
| Revoke | the snapshot omits the revoked IDs' pair keys and carries a revocation epoch strictly above every epoch ever issued to them (tool rule, review U8). After the old epoch is retired the revoked node holds nothing live; until then it keeps mesh-layer (not session or management) access, bounded by the 24 h cap, plus MGMT_REQ flood budget for `KEY_RECOVERY_S`. |
| Recover | a node that returns holding only the retired epoch, or whose handshakes fail twice (4.1.8), floods MGMT_REQ under it; neighbours accept it through the retired slot, forward it re-tagged under their `E_old`, the manager answers under the epoch that verified, the last relay re-tags the MGMT_RESP under the epoch it verified from that neighbour, and the snapshot inside is under `K_node`, independent of epochs. The node installs the live epochs and rejoins without a visit (reviews H1, U5). A revoked node's request under the retired epoch reaches the manager and dies there (pair key deleted), bounded by the flood budget. |

Why this converges: every node transmits under `E_old`, which all hold until
the tool has seen every node report the next epoch; retirement is an explicit
decision, not a timer; the retired slot is the door back in for stragglers.
A node absent past `KEY_RECOVERY_S` or two retirements is re-provisioned by
cable (12.2).

### 8.6 Key bundles

A bundle is produced only by the offline tool, for one node, is a full
snapshot of that node's key state (8.5), and is opaque to every manager
(reviews H3, U1, J2).

```
bundle     bundle_no u32 | AES-128-CCM(Kb(N), nonce, AAD, TLVs) | ccm_tag[8]
nonce      0x02 || N u16 || bundle_no u32 || 0x00 x 6        (13 bytes; disjoint from frame nonces by the leading 0x02)
AAD        "PLB1" || N u16 || bundle_no u32
TLVs       type u8, len u8, value (every live item is listed; omission means retire or revoke, 8.5):
  0x01     K_mesh: epoch u8, key[32]                        (one per live epoch)
  0x02     pair key: unit_id u16 (node, manager or recovery holder), epoch u8, key[32]   (one per peer per live epoch)
  0x07     managers: n u8, unit_id u16 x n                  (replaces pl/managers; how a captured gateway is replaced)
```

- `bundle_no` is strictly increasing per node (NVS `pl/bundle_no`, one write
  per accepted bundle; the tool persists its counter transactionally before
  encrypting, since a reused number would reuse a CCM nonce under the
  never-rotated `Kb`, review J23). A bundle with a lower or equal number, or
  a failed tag, is dropped and counted (`bundle_fail`).
- Serving (review J2): a manager keeps only the newest bundle per node;
  older ones are superseded snapshots. MGMT_REQ carries the node's last
  accepted `bundle_no`; when the manager's stored number is higher it sends
  TLV 0x05 chunks `bundle_no u32, idx u8, total u8, bytes`, one per response,
  the node requesting each with the `chunk` field (report pages use `page`).
  Chunks are reassembled in order, the whole bundle is verified once
  complete, then applied. The tool marks a bundle delivered only when the
  node's section 0 reports its number. A snapshot with two live epochs for
  49 peers is about 3.6 KB, 20 chunks on a 250-byte path, about 20 s per
  node at the chain pace of 11.10. Bundles that change no epoch (a lost
  phone, a new holder, a manager list) are delivered the same way because
  the number alone triggers them.
- Managers (gateway, station, phones) store bundles as bytes, hand out
  chunks, and may author only TLV 0x04 commands, 0x08 challenges and time
  inside MGMT_RESP. A node ignores key TLVs anywhere but inside a verified
  bundle.
- Recovery holders are rotated and revoked like any peer: present in the
  snapshot or not (review U6). A lost phone is one new snapshot per device it
  held.

### 8.7 Other requirements

- Logs MUST NOT print keys, nonces or tags at any level in a field build.
- `esp_random()` quality: rule 4.1.14.
- Capture detection (R11, reviews U13, V1). Evidence the node reports and
  an attacker holding its keys could keep consistent (reset pattern,
  secure-state bits, its own epoch) is still alarmed on, but the controls
  that count are kept outside the node: (1) the gateway records every
  node's report cadence and alarms after three missed periods; (2) it keeps
  per node the last `pre_ctr`, `bundle_no`, `e_new`/`e_old` and, for direct
  neighbours, `hop_seq`, and alarms on any regression or on a jump beyond
  `ORIGIN_MAX_JUMP`, values a returned node cannot reset without the alarm
  firing; (3) every `CHALLENGE_PERIOD_S` (3600) the manager puts a 16-byte
  random challenge in MGMT_RESP TLV 0x08 and the node's next MGMT_REQ MUST
  carry section 4 = `HMAC-SHA256(K_mgmt, challenge || section 0 bytes)[0..15]`;
  a missing or wrong answer within two of that node's own report intervals,
  as recorded by the gateway, is an alarm; (4) the gateway
  and every manager MUST sit in a tamper-evident enclosure with a case
  switch wired to a GPIO whose state is bit6 of section 0 and latched in the
  gateway's record; (5) revocation is the documented response, and the
  gateway's record is the audit trail. A cloned node with extracted keys can
  answer challenges but cannot hide the report gap of its absence or rewind
  counters the gateway has already seen.
- Anti-rollback (reviews U12, V5): the field image uses the ESP32 app
  anti-rollback `SECURE_VERSION` field (eFuse BLOCK3 bits 128..159, 32
  one-way increments for the device's life); the secure version is bumped
  only on security releases, budgeted at no more than two per year (16 years
  at that rate); a node also refuses a BULK image whose `fw_build` is below
  the running one.
- Security counters (`auth_fail`, `hop_tag_fail`, `hop_replay`,
  `replay_dropped`, `bundle_fail`, `relay_drop_rate`) are in MGMT section 1.
- Enumeration: unit IDs, caps and each node's `pre_ctr` are visible to
  anyone in range (review V7); the protocol hides readings and keys, not
  topology or activity. Collision alarms cannot be triggered by outsiders
  because the frames that raise them must pass the hop_tag.

---

## 9. Constants and budgets

Radio defaults; `hops` is the route hop count (1 on a direct link); the IR
edge link multiplies handshake timers by `IR_TIME_SCALE` on both ends.

| Name | Default | Note |
|---|---|---|
| HELLO_WINDOW_MS | 50 | probe random delay range |
| HELLO_CANDIDATES / PROBE_OFFERS_MAX | 4 / 4 | fallback probes kept / OFFERED entries per probe (one per src_id) |
| BIND_RETRY_MS / BIND_RETRIES | 50 / 3 | `BIND_RETRY(hops) = max(50, hops x HOP_DELAY_MS)` |
| BIND_TIMEOUT | formula 4.1.10 | 470 ms direct, 1730 ms at 4 hops; also the RESUME timeout (MGMT_RESP: floored at 1100 ms) |
| SEEK_BASE_MS | 50 + 2 x seek_ttl x 60 | 530 ms at ttl 4 |
| SEEK_TIMEOUT(n) | SEEK_BASE_MS + rand(0, min(60000, 600 x 2^n)) | never gives up |
| FULL_CAP_S | 3600 | FULL backoff rand(0, min(3600, 60 x 2^n)) s (4.1.4) |
| BOOT_SPREAD_MS | 600 x pl/node_count | first SEEK and first MGMT_REQ after a cold boot |
| RESEEK_JITTER_MS / PENALTY_MS / MODE_RETRY | 1000 / 60000 / = RTO | |
| keepalive_ms | 5000 (1000..60000) | MODE field; SESSION_TIMEOUT = max(4 x keepalive_ms, 8 x SRTT) |
| ACK_EVERY / FEC_K / FEC_M / FEC_FLUSH_MS | 8 frames / 8 / 2 / 100 | flush after max(FEC_FLUSH_MS, 2 x period) |
| ARQ_WINDOW / ARQ_RTO_MS / ARQ_MAX_RETRIES | 24 (4 on leaves) / 100 / 3 | RTO = max(100, 2 x SRTT) |
| REORDER_MS / REPLAY_WINDOW / RX_QUEUE_FRAMES / RELAY_QUEUE_FRAMES | 500 (x 4 SRTT) / 64 / 16 / 8 | |
| PL_MAX_GROUPS / PL_MAX_SESSIONS / PL_MAX_STREAMS | 8 / 32 (sink: node_count) / 4 (sink: manifest count, 4.1.12) | |
| PARK_GRACE_S / MGMT_EVERY_WAKES / BULK_WINDOW_S | 60 / 10 / 120 | |
| MGMT_PERIOD_S / MGMT_RETRIES / MGMT_CHAIN_GAP_MS | 600 / 2 / 1000 | response timeout max(BIND_TIMEOUT(hops), 1100 ms), hops = seek_ttl when flooded (11.10) |
| TIME_MAX_SLEW_PPM / CHALLENGE_PERIOD_S | 500 / 3600 | |
| KEY_RECOVERY_S / MAINT_TIMEOUT_S | 604800 (7 days, MGMT-period count, persisted) / 600 | |
| seek_ttl / MAX_HOPS / MIN_PATH_MTU | manifest (site diameter + 1, default 4) / 8 / 48 | |
| HOP_DELAY_MS / RELAY_JITTER_MS / FLOOD_REPEAT | 60 / 50 / 2 | |
| DEDUP_ENTRIES / DEDUP_TTL_MS | 64 / 5000 | |
| ORIGIN_ENTRIES / ORIGIN_TTL_S / ORIGIN_MAX_JUMP / HOP_MAX_JUMP | 64 / 3600 / 65536 / 65536 | |
| ROUTE_ENTRIES / ROUTE_TTL_MS / LINK_FAIL_MAX | 64 / 1200000 / 3 | 20 min; 3 consecutive send failures delete the link (11.6) |
| LINK_ENTRIES / LINK_TTL_MS | 32 / 60000 | an entry referenced by a route lives as long as the route (11.6) |
| FLOOD_BUCKET_ORIGIN / FLOOD_BUCKET_TOTAL / FLOOD_BUCKETS | depth 6, 2/s / depth 20, 10/s / 64 | |
| IR_TIME_SCALE / IR_GUARD_MS / NRF_GUARD_MS / VBAT_MIN | 10 / 20 / 2 / board-specific | |

Airtime budget at 1 Mbps ESP-NOW (estimates; a small unicast frame costs
about 1.5 ms of air per hop including preamble, 802.11 ACK and backoff; a
flood costs about `node_count x FLOOD_REPEAT x 1.1 ms`):

| Traffic | Per unit | 40 sessions, 2 hops, 50 nodes |
|---|---|---|
| Keepalive (ACK + PING) at 5 s | 2 x 1.5 ms x hops per keepalive | 4.8 % |
| DATA at 1 frame/s per session | 1.5 ms x hops per frame | 12 % |
| MGMT every 600 s per node | 2 x 1.5 ms x hops | 0.05 % |
| Floods (SEEK, RESUME, routeless MGMT) | about 110 ms each | 20 leaves at one wake per 5 min: 0.7 % |
| Gateway outage (every sender re-SEEKs at the 60 s cap plus one MGMT flood per 10 min) | about 110 ms each | 25 senders: about 5 %, capped by the budgets (review J9) |

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

PJON is the closest project and still lacks FEC, the seek / first-acknowledger
handshake, forwarding, authentication and sample typing. RS libraries:
Arduino-FEC, libcorrect, Schifra, or about 300 lines of own GF(2^8) code.

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
node draws 80-100 mA (estimate): a solar relay needs about 8 Wh/day of panel
(`daily Wh / (peak sun hours x 0.7)`), three days of battery and a
low-voltage gate before WiFi start.

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

Mesh-layer fragmentation was rejected (relay state, unverifiable fragments,
loss multiplication, FEC over whole frames); nRF24 segments in its adapter only.

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
  pending copy)`, FIFO, `DEDUP_TTL_MS` 5 s (10 floods/s x 5 s = 50 < 64).
  `FLOOD_REPEAT` copies share one `pre_ctr`; the second is dropped here.
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
  lowest-cost copy (`FLOOD_PENDING` 4 buffers). TTL: `seek_ttl` from the
  manifest (site diameter + 1, default 4), `MAX_HOPS` 8. No counter-based
  suppression (coverage holes); the budgets bound flood load.

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
  endpoints' timeouts recover. A link entry not referenced by any route
  expires after `LINK_TTL_MS` (60 s without a frame from that neighbour); an
  entry referenced by a route lives as long as the route, so a quiet mesh
  with 60 s keepalives over several hops keeps its paths (review J6).
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
60 s for unreferenced entries (11.6). A frame from a new address with a newer `hop_seq` replaces the address
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
progress (4 KB). `pl_ctx_t` is allocated from the heap inside `pl_init()`
(the no-heap rule starts after init), which keeps the sink out of the ESP32
static DRAM segment (12.4, review J4).

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
MGMT_REQ   pre_ctr u32 (clear); encrypted (fixed 18): t1 u64 (requester clock, us), e_new u8, e_old u8,
           flags u8 (bit0 more_follows), section u8, page u8, chunk u8 (bundle chunk wanted), bundle_no u32
           (last accepted), then section bytes
MGMT_RESP  pre_ctr u32 (clear); encrypted (fixed 29): req_ctr u32 (echo of the request's pre_ctr), t1 u64 (echo),
           t2 u64, t3 u64 (manager UTC rx/tx, us), flags u8 (bit0 TLVs present, bit1 more chunks pending),
           TLVs: type u8, len u8, value   (0x04 command: 1 enter maintenance, 2 reboot, 3 open update window;
                                           0x05 bundle chunk: bundle_no u32, idx u8, total u8, bytes;
                                           0x08 challenge: 16 random bytes, answered in section 4 (8.7))
```

- Freshness: the node keeps one outstanding request and accepts a MGMT_RESP
  only if `req_ctr` echoes it (review U4). Commands 1 and 2 are accepted at
  most once per 10 minutes. The manager keeps the last `pre_ctr` per node
  and answers at most one request per second per node; it never answers an
  unverified one.
- Pacing (review J3): the response timeout is `max(BIND_TIMEOUT(hops),
  1100 ms)`, with `hops = seek_ttl` for a flooded request, so a retry never
  lands inside the manager's one-second window; a node waits
  `MGMT_CHAIN_GAP_MS` (1000) after a response before the next request of a
  chain (bundle chunks, paged sections). A 20-chunk bundle therefore takes
  about 20 s at any hop count.
- Failure (review H4): no MGMT_RESP within the timeout is retried
  `MGMT_RETRIES` (2) times with new `pre_ctr`; after the last failure the node
  deletes its route to the manager, and the next MGMT_REQ floods. A node
  without a sync for `3 x MGMT_PERIOD_S` is UNSYNCED (6.5).
- Report sections, one per request, rotated by the node; pages sized to the
  path MTU (section 0 is two pages on the IR edge link):

```
section 0 (38 bytes): mac[6], unit_id u16, proto_ver u8, proto_minor u8, fw_build u32, e_new u8, e_old u8,
                      bundle_no u32, role u8, power_src u8 (0 mains, 1 solar, 2 battery), vbat_mv u16,
                      uptime_s u32, reset_reason u8, reset_count u16, min_free_heap u32, stack_hwm u16,
                      state u8 (bit0 Secure Boot v2, bit1 flash enc release, bit2 NVS encrypted, bit3 clone
                      mismatch, bit4 no-key wait seen, bit5 maintenance entered since last report, bit6 case open)
section 1: pl_stats_t as little-endian u32 in Appendix B declaration order
section 2: n u8, then n x { unit_id u16, transport u8, rssi_ewma i8, rx u16, crc_fail u16, fails u8 }
section 3: n u8, then n x { dst u16, next_hop u16, hops u8, cost u8 }
section 4 (16 bytes): challenge response (8.7), sent in the request after a TLV 0x08 was received
```

- Bundles (8.6): when the manager's stored `bundle_no` for the node is above
  the one in the request, it sends TLV 0x05 chunks, one per response, the
  node requesting each with `chunk`; the chain keeps a leaf awake until
  `more` clears.
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
  (steps 9e, 9f, 10a, 10c). On an `edge_only` link SEEK and RESUME are
  unicast to the one neighbour (ttl 1) and reach the endpoint through step
  7; the leaf's SEEK carries `key_epoch = E_prov` and the attached node
  accepts it on that transport whatever its live epochs are (3.6, 8.5;
  review J1). The 74-byte path MTU carries every
  control frame (A.15). The attached node is the leaf's probe and its only
  manager: time, health and commands flow over the IR link by MGMT, pulled
  by the leaf; the attached node's section 2 row for the leaf is how the
  gateway sees it. Rekeying or updating an IR leaf needs the UART station
  (12.6). The attached node republishes the leaf's data as its own sender
  session if the site needs it elsewhere (application level).

---

## 12. Deployment profile and decisions

Each item is a decision with its alternative so it can be flipped. Items
marked USER-DECIDED were set by the user.

### 12.1 Bench vs field profile

| | Bench | Field (default) |
|---|---|---|
| Chip and module (USER-DECIDED) | any original ESP32 WROOM (-32, -32D, -32U, -32E, -32UE, any silicon revision) and any ESP32-S3-WROOM-1 / -1U (N4 to N16, R2 or R8), dev boards included; mixed benches are the normal case (12.12) | Gateway / manager / sink: ESP32-S3-WROOM-1U N8R8 (12.4). Relays and leaves: ESP32-S3-WROOM-1U N8 or N8R2 (recommended), or ESP32-WROOM-32E / -32UE with chip ESP32-D0WD-V3 / D0WDR2-V3 at silicon v3.0 or later, built with `CONFIG_ESP32_REV_MIN_3`. WROOM-32, -32D and -32U never (revision 1.x silicon has no Secure Boot v2 and no `UART_DOWNLOAD_DIS`). External antenna (-1U, -32UE) on every gateway and bridge chip. Budgets, sleep and interop per chip: 12.12; pins: Appendix C.6 |
| Keys | optional; `pl/net_key` MAY derive everything locally | MUST: `K_node`, pair keys and `K_mesh` from the offline `K_site` (8.2) |
| FLAG_AUTH | optional | MUST on every frame |
| At rest | development build: no Secure Boot, no flash encryption, no eFuse burnt, so every bench board stays reusable and reflashable. NOT protected on the bench: flash and NVS (keys included) read back over the cable or USB, the image is unsigned and replaceable, JTAG / USB-Serial-JTAG open, no anti-rollback, a clone is caught only by the `pl/unit_mac` check (2); bench boards therefore never hold field keys | MUST, per chip (12.2): Secure Boot v2, flash encryption release mode, NVS encryption, debug and download ports closed by eFuse. `pl_init` asserts the per-chip table of 12.2 and returns `PL_ERR_AUTH` unless every row holds, then waits for UART provisioning (fail closed, reviews U7, V6) |
| Partitions | any | ESP32 4 MB: bootloader 0x1000; table at 0xC000 (`CONFIG_PARTITION_TABLE_OFFSET`, the Secure Boot v2 bootloader exceeds the default 0x8000); nvs 0xD000 64 KB; nvs_keys 0x1D000 4 KB (encrypted); otadata 0x1E000 8 KB (encrypted); phy_init 0x20000 4 KB; ota_0 0x30000 1920 KB; ota_1 0x210000 1920 KB (ends 0x3F0000). S3 8 MB: bootloader 0x0; table 0xC000; nvs 0xD000 64 KB; otadata 0x1D000 8 KB (encrypted); phy_init 0x1F000 4 KB; ota_0 0x20000 3 MB; ota_1 0x320000 3 MB; store 0x620000 1920 KB (encrypted; gateway bundle store and 8.7 record, unused on nodes); no nvs_keys (HMAC scheme, 12.2). Expect a 1.2-1.5 MB image with WiFi, NimBLE and mbedtls on either chip (estimate) |
| Pins | any | ESP32: GPIO6-11 reserved (flash); GPIO12 strap: burn the flash-voltage eFuse before UART download is disabled; VBAT and sensors on ADC1 only. S3: GPIO26-37 reserved (flash, and octal PSRAM on R8), strapping GPIO0 / 3 / 45 / 46 left at their defaults, GPIO19 / 20 are USB, GPIO43 / 44 UART0; VBAT and sensors on ADC1 (GPIO1-10). ADC2 is shared with WiFi on both chips. Pin plans: Appendix C.6. `pl_task` pinned to core 1, WiFi and ESP-NOW callbacks stay on core 0 on both chips |
| Signing | any key | one field RSA-3072 Secure Boot v2 key signs both chip images (same scheme on both chips); bench images use a separate key; a field image refuses to start unless a burnt, unrevoked digest equals one of its compiled-in field digests, and a bench image refuses to start when Secure Boot is enabled (12.2) |
| Test keys | allowed | the tool refuses the Appendix A `K_site`; firmware rejects all-zero or repeated-byte keys and the 8-byte hash prefixes of `K_mesh(E)` for all 256 epochs of the test `K_site` (2 KB table) |
| Replies to unverified frames | CLOSE(2) allowed | never |
| NVS erase on error | allowed | never; the condition is logged and reported (6.4) |
| Logging | anything | no key, nonce or tag bytes at any level |

### 12.2 Provisioning (decision)

A provisioning station (host script plus a UART cable, manager ID 0x0002)
runs, per board and in this order (review J5; S3 column new in v0.8). Names
are ESP-IDF v5.5 Kconfig and eFuse names; "check" marks one to confirm in
the IDF docs of the chosen release before the first sacrificial board.

| Step | ESP32-WROOM-32E / -32UE (IDF 5.x, `CONFIG_ESP32_REV_MIN_3`) | ESP32-S3-WROOM-1 / -1U (IDF 5.2 or later for the HMAC NVS scheme) |
|---|---|---|
| 1 Identify | read the base MAC and chip revision; refuse anything below v3.0 | read the base MAC, revision (any), flash and PSRAM size (`esptool.py flash_id`); refuse a module that differs from the manifest row (N8R8 gateway, N8 / N8R2 node) |
| 2 Strap and debug eFuses | burn and verify the flash-voltage eFuse (GPIO12 strap) and `JTAG_DISABLE` | burn and verify `DIS_PAD_JTAG` and `DIS_USB_JTAG` (the Secure Boot bootloader burns both when `CONFIG_SECURE_BOOT_ALLOW_JTAG` is off) and `DIS_USB_SERIAL_JTAG` (no USB console in the field; GPIO19 / 20 become plain GPIO) |
| 3 Secure Boot v2 | `CONFIG_SECURE_BOOT_V2_ENABLED`; one key digest (field key A); this chip has no revocation | `CONFIG_SECURE_BOOT_V2_ENABLED` (RSA-3072); digest 0 = field key A, digest 1 = escrow key B kept offline (it signs the image that burns `SECURE_BOOT_KEY_REVOKE0` if A leaks); the unused slot 2 revoked with `SECURE_BOOT_KEY_REVOKE2` (`esp_secure_boot_init_checks` demands it unless `CONFIG_SECURE_BOOT_ALLOW_UNUSED_DIGEST_SLOTS`); `CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE` off (conservative revocation) |
| 4 NVS key | generate the device's NVS encryption keys on the host (`nvs_partition_gen.py generate-key`) and flash the `nvs_keys` partition in plaintext | generate a 32-byte HMAC key on the host and burn it read-protected with `idf.py efuse-burn-key BLOCK_KEYn hmac_key.bin HMAC_UP` (n = `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID`); build with `CONFIG_NVS_ENCRYPTION` and `CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC`; derive the NVS keys on the host with `nvs_partition_gen.py generate-key --key_protect_hmac --kp_hmac_inputkey hmac_key.bin`; there is no `nvs_keys` partition, the device re-derives the keys from the eFuse at every boot |
| 5 Images | flash the signed bootloader, partition table and app | same, signed with key A |
| 6 Flash encryption | release mode (`CONFIG_SECURE_FLASH_ENC_ENABLED`, `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE`); the first boot, on a stable supply, encrypts every partition flagged `encrypted` in place, `nvs_keys` included; from here the ROM loader can no longer write encrypted data | same options; XTS-AES-128 (`CONFIG_SECURE_FLASH_ENCRYPTION_AES128`, AES-256 optional); the device-generated key lands in an eFuse key block with purpose `XTS_AES_128_KEY`, read-protected; PSRAM traffic is encrypted by the same hardware (IDF external-RAM guide); the bootloader also burns `DIS_DOWNLOAD_MANUAL_ENCRYPT` and, by default in release mode, Secure Download Mode (`ENABLE_SECURITY_DOWNLOAD`) |
| 7 NVS image | generate the per-device NVS image from the manifest row (`unit_id`, `unit_mac`, `role`, `groups`, `managers`, `channel`, `nrf_channel`, `seek_ttl`, `node_count`, `epoch_old`, `epoch_new`, `K_mesh` x 2, `K_node`, pair keys including those with 0x0001, 0x0002 and the assigned recovery holders), encrypt it with the step-4 keys and write it through download mode (the NVS data partition is not flash-encrypted; NVS XTS-encrypts it itself) | same; Secure Download Mode still allows the basic flash write this step needs |
| 8 Verify | boot, read MGMT section 0 over the UART, check the secure-state bits and `unit_id` | same |
| 9 Close download, last | burn `UART_DOWNLOAD_DIS` | site choice: keep Secure Download Mode (no flash read-back; `get_security_info` lets the station audit eFuses later) or burn `DIS_DOWNLOAD_MODE` (`CONFIG_SECURE_DISABLE_ROM_DL_MODE`) for ESP32 parity; confirm `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` and `DIS_USB_OTG_DOWNLOAD_MODE` are covered by the chosen state (check) |
| 10 Records | destroy the host copy of the NVS key file; record the eFuse summary per MAC in the manifest | destroy the host HMAC key and the derived NVS keys; record the eFuse summary, digest slots and revocation bits per MAC |

The S3 Digital Signature peripheral is not used: ProbeLink has no asymmetric
keys (12.8). Dry-run on two sacrificial boards of each chip. Later
re-provisioning and recovery use the same station as a manager under
`K_pair(node, 0x0002)`: that is the only meaning of "cable" in the field
profile.

`pl_init` runtime assertion (field image; compile-time branch on
`CONFIG_IDF_TARGET`; every row MUST hold, else `PL_ERR_AUTH`):

| Check | ESP32 | ESP32-S3 |
|---|---|---|
| Secure Boot v2 | `esp_secure_boot_enabled()`; eFuse `ABS_DONE_1` set and `ABS_DONE_0` clear (a v1 secure boot is refused) | `esp_secure_boot_enabled()`; eFuse `SECURE_BOOT_EN`; at least one slot with `esp_efuse_get_digest_revoke(i)` false holds a digest from the image's compiled-in field list; every other slot revoked |
| Flash encryption | `esp_flash_encryption_enabled()` and `esp_get_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE` (`esp_flash_encryption_cfg_verify_release_mode()`) | same |
| NVS encryption | `nvs_keys` partition present and flagged `encrypted`; `nvs_flash_secure_init()` succeeded | eFuse block `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID` has purpose `HMAC_UP` (`esp_efuse_get_key_purpose()`) and is read-protected (`esp_efuse_get_key_dis_read()`); `nvs_flash_init()` succeeded under the HMAC scheme |
| Debug and download | `JTAG_DISABLE` and `UART_DOWNLOAD_DIS` set | `DIS_PAD_JTAG`, `DIS_USB_JTAG`, `DIS_USB_SERIAL_JTAG` set; `ENABLE_SECURITY_DOWNLOAD` or `DIS_DOWNLOAD_MODE` set |
| Silicon | `efuse_hal_chip_revision() >= 300` | any revision; PSRAM present iff the manifest row says R2 / R8 |
| Keys | keystore holds `K_node`, two live `K_mesh` and the listed pair keys, none degenerate (12.1 test-key row) | same |

Section 0 `state` bit0 means "Secure Boot v2 asserted by this chip's row";
every state bit keeps its v0.7 meaning on both chips, so the gateway learns
a node's chip from the manifest, never from the wire (12.12).

### 12.3 Control-frame recovery (decision)

Repetition (`FLOOD_REPEAT` 2) and handshake retries satisfy "recovery data in
every packet" for control frames; in-frame RS on them was not chosen.

### 12.4 Radio, gateway and sink (USER-DECIDED)

All ESP-NOW nodes use one dedicated channel from the manifest, `WIFI_PS_NONE`,
`WIFI_MODE_STA` never associated and never AP. The gateway is two chips
joined by UART at 921600 baud or more (the section 9 scenario needs about
60 frames/s through it, review H6): the mesh chip (manager 0x0001 and the
probe of the sink group, `PL_MAX_SESSIONS` = `node_count`, `PL_MAX_STREAMS`
= the manifest count of ARQ/FEC senders, 4.1.12), and a LAN chip that runs
the LAN sink, time source, bundle store and the 8.7 record.

Gateway silicon (closes reviews J4, V2): both gateway chips are
ESP32-S3-WROOM-1U N8R8 (8 MB flash, 8 MB octal PSRAM, U.FL), one BOM part.
The WROOM-32E gateway branch of v0.7 is withdrawn because the gateway holds
the directional keys of every sink session and the original ESP32 offers one
Secure Boot digest without revocation, no eFuse-rooted NVS key and published
fault-injection results (CVE-2019-17391); the S3 closes all three (12.2). The
S3 has no Ethernet MAC, so the LAN chip uses W5500 over SPI (the LAN8720
RMII option left with the ESP32 branch).

| | ESP32-S3-WROOM-1U N8R8 gateway mesh chip |
|---|---|
| RAM, 50 records + N streams | records 30 KB + tables 7 KB + rx queue 4 KB + keys and CCM/HMAC contexts, all internal SRAM (`MALLOC_CAP_INTERNAL`); stream buffers N x 4.7 KB in PSRAM (`MALLOC_CAP_SPIRAM`; `CONFIG_SPIRAM_MODE_OCT`, `CONFIG_SPIRAM_SPEED_80M`, `CONFIG_SPIRAM_USE_MALLOC`): N = 50 is 235 KB of 8 MB, so one sink serves every ARQ/FEC sender of a 50-node site; the second-sink rule of 4.1.12 remains the tool's answer to a larger manifest. Internal heap after WiFi: about 300 KB (estimate, measure) |
| PSRAM rules | keys, contexts, queues filled from WiFi callbacks and anything touched while flash is written stay internal; PSRAM holds only FEC/reorder blocks and the bundle-store cache; it is encrypted by the flash-encryption hardware in the field (12.2); `CONFIG_SPIRAM_MEMTEST` off in field images (boot time); FEC decode over PSRAM at 50 frames/s is a measurement item (12.11) |
| What a capture yields | its own pair keys and the current sink session keys, bundles opaque; the controls are the enclosure and record of 8.7 and revocation (8.5) |

Both gateway chips sit in the tamper-evident enclosure of 8.7. If the LAN chip
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
link is keyed by the pair key of the two nodes at the provisioning epoch,
outside epoch rotation, and the leaf's SEEK is accepted at `E_prov` on that
transport whatever the live epochs are, so an IR leaf never goes deaf
(review J1); rekeying it or updating its firmware is done with the UART
station, which is a deployment rule (reviews H5, V4). `max_frame` is 80 so
that every control frame fits (A.15). IR stays indoor/shaded until its bit
cell is validated on hardware (C.1). Alternative (v0.4): IR as a mesh hop
with scaled timers; rejected by the user.

### 12.7 Firmware update (decision)

In-mesh, minimal: the update server (the gateway's LAN chip, through the mesh
chip) SEEKs the node by unit ID, BINDs, and sends MODE mode 2 (BULK:
`bulk_size`, `sha256`, `fw_build`) with `arq` 1 and `fec_m` 0, then DATA
frames whose `t_first_us` is the byte offset; the node writes with
`esp_ota_write`, verifies the SHA-256 at CLOSE reason 7, refuses a `fw_build`
below the running one and a secure version below the eFuse count (8.7), lets
Secure Boot v2 verify the signature at reboot, and marks the image valid
(`esp_ota_mark_app_valid_cancel_rollback`)
only after it has received one MGMT_RESP within `3 x MGMT_PERIOD_S` of boot
(it sends MGMT_REQ immediately after an update boot; leaves: before their
first park, 4.4). Any final ARQ gap aborts the image. A 1 MB image at 20-50
kbit/s over 2-3 hops takes 3-7 minutes per node (estimate). Nodes accept
BULK only from a listed manager armed by MGMT command 3; for a leaf, command
3 opens the update window of 4.4 (review H7). IR leaves are updated by the
UART station (12.6). Version transition: endpoints accept N and N-1 during a
rollout; forwarders forward any version with the frozen prefix. One image
per chip: the update server picks it by the manifest `module` column and a
node refuses an image built for the other target (the IDF image header
`chip_id` check, before any write). Alternative
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

Cut since v0.4: BLE carrier, IR as a mesh hop, ESP-NOW v2 / LEN16 / big UDP,
PL_SELECT_BEST, dual auth path, time stratum chaining, key activation and
retirement timers, RS on PACKET links, flooded BIND, counter suppression,
separate DIAG/TIME/KEY_UPDATE types, endpoint counter state, third live epoch,
retire/revoke TLVs (snapshots).

Known limitations, deliberate: mesh-layer identity for routes and flood
budgets rests on `K_mesh` until per-node signatures exist (11.8), so OFFERED
denial and route misdirection by an insider are bounded, not eliminated; one
recorded unicast frame can be re-admitted at a relay after `LINK_TTL_MS`
until the real neighbour transmits (8.4); epoch pacing and the 24 h
revocation cap are tool rules (8.5); a revoked node keeps mesh-layer access
until the old epoch is retired, plus MGMT_REQ flood budget under the retired
slot for `KEY_RECOVERY_S` (V3); during a retirement rollout, floods from
nodes that have not yet pulled the snapshot are dropped at nodes that have,
until the failure-triggered MGMT pull (4.1.8) catches them up; a node absent
beyond `KEY_RECOVERY_S` or two retirements needs the UART station; IR leaves
are rekeyed and updated by cable only and their edge key never rotates (V4);
IR outdoors and the IR bit cell are unvalidated (C.1); a cloned node with
extracted keys is caught only by the gaps and counters of 8.7, not by any
self-reported bit (V1); the anti-rollback counter allows 32 bumps for the
device's life (V5); each node's `pre_ctr` and activity pattern are visible on
the air (V7); no TRACE frame (MGMT section 3 gives the path); FEC/ARQ
parameters are not auto-tuned to measured loss; the nRF24 segment header
separates concurrent transmitters only by the low byte of `prev_hop` (C.5).

Chip-specific, since v0.8: on WROOM-32E / -32UE field relays and leaves (never
the gateway, 12.4) R1 is a cost, not a guarantee (CVE-2019-17391), there is
one Secure Boot key digest with no revocation and no eFuse-rooted NVS key
(J15, 12.2), so a stolen WROOM-32E node is the first to revoke; S3 nodes
hold the same session keys and their at-rest tier rests on eFuse
read-protection that this document cites but does not prove; a mixed fleet
keeps two provisioning flows and Kconfig sets in step per release (12.2) and
ships one image per chip (12.7); the bench profile protects nothing at rest
(12.1).

### 12.11 Implementation readiness

Buildable now against this document and Appendix A, with vectors to test
against on both chips: frame codec and the 3.6 validator (fuzz harness),
CRC/COBS/RS/group FEC, ARQ and reorder, crypto and keystore (HKDF, CCM,
hop_tag, transcript, epochs, counters), session machines (sender,
multi-record probe, park/resume), the forwarding pipeline and its tables,
the ESP-NOW and UART adapters, the host mesh simulator.

Buildable against this document but with no field precedent and a decision
or measurement still open: MGMT with bundles and the provisioning and bundle
tool (the J2/J3 rules of 8.6 and 11.10 are new in v0.7 and have only been
checked on paper and in A.12/A.14; prove the chunk chain and a straggler
return in the simulator first); the two-chip S3 gateway and LAN sink
(silicon decided, 12.4; its heap and PSRAM figures are estimates); the two
provisioning sequences of 12.2 (the S3 HMAC NVS scheme, digest escrow and
revocation have no precedent in this project; run each sequence on two
sacrificial boards of that chip before any field board; the "check" flags
of 12.2 are confirmed there).

Gated on measurement before field use: the IR bit cell, RMT receive path and
outdoor behaviour on both chips (C.1); nRF24 goodput, segment loss and
desense (C.5, 12.4); airtime and failover timing at 50 nodes (section 9
figures are estimates); the leaf wake budget and deep-sleep current on the
chosen board, per chip (4.4, 12.12); FEC decode over PSRAM at 50 frames/s on
the gateway (12.4); gateway radio desense (12.4).

Phase 1 SHOULD be ESP-NOW plus the UART gateway, with the simulator, and a
10-node 72 h soak on bench boards of both chips (at least three WROOM-32 and
three S3, gateway on S3) that includes one rotation with a node powered off
past the retirement, one revocation, one site power cycle, one update per
chip, one relay killed on the gateway path, a gateway `preseq` started above
0x10000, one bundle chain to a 1-hop leaf, a straggler returning after two
bundles, a 60 s keepalive session over 2 hops, and 25 FEC senders to the
sink.

### 12.12 Two chip families: interop, budgets, sleep (USER-DECIDED)

Requirement: a mesh of mixed ESP32-WROOM and ESP32-S3-WROOM-1 nodes MUST
interoperate at every layer with one wire format and one constant table; no
node learns or needs a peer's chip. Mechanism: the chip stays inside the node.

| Must not reach the wire | Mechanism |
|---|---|
| CPU and crypto hardware (LX6 with AES/SHA engines; LX7 with AES/SHA/HMAC/DS, both 240 MHz) | every timer is a section 9 constant or a measured RTT, never derived from CPU time; CCM and HMAC-SHA256 outputs are fixed by the algorithm, so `CONFIG_MBEDTLS_HARDWARE_AES` / `_SHA` change latency only; Appendix A vectors MUST pass in the host build and on both targets |
| RNG source (`esp_random()` from the RF path on both; `bootloader_random_enable()` without RF) | nonces are hashed per 4.1.14 and keys depend on the transcript, not the RNG; `pre_ctr`, `seq` and `hop_seq` are counters |
| ESP-NOW framing and rate | v1 framing, 250-byte `max_frame`, default PHY rate on both; ESP-NOW v2 / `ESP_NOW_MAX_DATA_LEN_V2` (1470 bytes) stays cut (12.10); RSSI from `esp_now_recv_info_t` on both |
| Float and integer behaviour | both little-endian with an FPU; LOW quantization uses `lroundf()` (half away from zero) on both so one sample gives one `q`; `memcpy()` field access (section 3) |
| MAC and IDs | `esp_read_mac(ESP_MAC_BASE)` and the same fallback CRC rule (2) on both |
| Security state | section 0 bits have one meaning per 12.2; the chip is a manifest column (`module`), not a wire field; section 0 stays 38 bytes (J19) |
| Deep-sleep state | the `RTC_DATA_ATTR` blob (4.4) never leaves the node; 8 KB RTC slow memory on both chips |

Budgets (estimates; the "measure" items are in 12.11):

| | ESP32-WROOM-32E node (N4) | ESP32-S3-WROOM-1 N8 / N8R2 node | S3 N8R8 gateway mesh chip |
|---|---|---|---|
| SRAM | 520 KB; 160-180 KB heap after WiFi and IDF statics (BT reserve 55 KB when built) | 512 KB; about 300 KB heap after WiFi (BLE reserve smaller than the ESP32's; measure) | same, plus 8 MB PSRAM for streams (12.4) |
| ProbeLink RAM | 32 records / 4 streams: about 49 KB (App. B) | same code, same 49 KB; room for 8 streams on a busy relay | 30 KB records internal + 235 KB streams in PSRAM |
| Flash | 4 MB: two 1920 KB OTA slots | 8 MB: two 3 MB OTA slots + store | same |
| Cores | LX6 x 2: WiFi core 0, `pl_task` core 1 | LX7 x 2: same layout (`CONFIG_ESP_WIFI_TASK_PINNED_TO_CORE_0`) | same |
| IR receive (C.1) | GPIO-capture ISR, RMT transmit | same code path; RMT RX with DMA (`rmt_rx_channel_config_t.flags.with_dma`) MAY replace it after C.1 validation | n/a |
| BLE maintenance (6.4) | by reboot, NimBLE, no WiFi in that boot | same rule (one code path) although the S3 controller can coexist with WiFi; BLE only, no Classic | n/a |

Leaf sleep (dev-board figures are set by the board, not the chip):

| | ESP32 | ESP32-S3 |
|---|---|---|
| Wake sources | ext0 (one RTC GPIO, level) or ext1 (RTC GPIO mask, `ESP_EXT1_WAKEUP_ANY_HIGH` / `ALL_LOW`), RTC timer; RTC GPIOs 0, 2, 4, 12-15, 25-27, 32-39 | ext0 or ext1 (`ANY_HIGH` / `ANY_LOW`), RTC timer; RTC GPIOs 0-21 (`SOC_RTCIO_PIN_COUNT` 22); no per-GPIO deep-sleep wake API (that is the C-series) |
| Portable choice | ext1 via `esp_sleep_enable_ext1_wakeup_io()` on both; sensors on the RTC GPIOs of Appendix C.6 | same |
| Deep-sleep current, module alone | about 10 uA (datasheet class; estimate) | about 8 uA (datasheet class; estimate) |
| Dev board in deep sleep | 1-10 mA: LDO quiescent, USB bridge and LEDs dominate (estimate) | same order on a DevKitC-1 (estimate); a field board needs a low-Iq LDO (under 5 uA) and no USB bridge |
| Wake budget | 4.4 figures (0.3-0.9 s at about 100 mA) | same order; PSRAM init adds boot time, so leaves are N8 (no PSRAM) |
| To measure | sleep and wake current with the bench PSU in series, per board and per chip, before any battery claim in section 13 | same |

---

## 13. Application profiles

Each profile names its carriers, modes, capacity and limits. Capacity is
given per collision domain at ESP-NOW 1 Mbps (about 50 full frames/s of
air, section 9); divide by the hop count for multi-hop paths.

### 13.1 Fixed sensor network (default deployment)

Mains or solar relays and probes, battery leaves, one two-chip gateway as
sink and manager; 5-50 nodes over 1-4 hops. Streaming sensors use HIGH or
LOW with FEC k 8 / m 2; leaves use ARQ; management every 10 minutes.
Capacity: 50 frames/s x 26 LOW samples (4 channels) = about 1300 sample
sets/s per domain single hop, about 650 in HIGH, about half of that across a
two-hop funnel; the section 9 budget keeps control traffic under 10 %.
Limits: everything in 12.10; sessions re-form on failover with one
`SESSION_TIMEOUT` of loss.

### 13.2 Vehicle / flight-data recorder

Sensors to an onboard recorder over UART (point to point, 921600 baud) or a
single-hop ESP-NOW link on one vehicle; HIGH mode, `arq` 1, `fec_m` 0 or 2.
The recorder is the probe and MUST store locally (flash or SD) in the order
delivered: the protocol is transport, not storage, and `on_gap()` marks the
holes. An optional LOW-mode downlink to a ground probe runs as one separate
direct ESP-NOW session from the recorder (re-origination, 12.4). Mesh
routing is not suitable for fast-moving nodes: route lifetimes, handshake
timers and penalty lists assume neighbours that stay neighbours for minutes;
use direct links only. Not for certified aviation (no ED-112 claims).
Capacity: UART 921600 about 360 frames/s x 12 HIGH samples = about 4300
sample sets/s; ESP-NOW direct about 650/s.

### 13.3 Campsite perimeter monitoring

Temporary perimeter of battery sensors around a site, watched from a base.

- Sensors: PIR, beam-break, tripwire, reed, vibration as leaves with digital
  channels (bit-packed, lossless), one session each to group 0xFF10 (`arq`
  1, window 4, `fec_m` 0). An IR beam-break sensor is a digital input, not
  the IR carrier; use a modulated-beam sensor so sunlight does not trip it.
- Base: one or two base stations (gateway role, mains or a power bank)
  subscribed to 0xFF10; two bases give redundancy through the group seek,
  since a leaf whose RESUME gets no RESUME_ACK falls back to SEEK and binds
  to whichever base answers first (4.4, 4.2).
- Alarm path: GPIO / ext1 wake from deep sleep -> boot with Secure Boot v2
  check (100-300 ms) -> WiFi start (120 ms) -> RESUME unicast along the
  stored first hop (20-60 ms) -> DATA with FLAG_ACK_REQ, retransmitted at
  the RTO until acked -> alarm at the base. Wake-to-alarm about 0.3-0.6 s
  one hop, plus about 2 ms per extra hop (estimate; measure on the bench).
- Supervision: every sensor checks in every `park_s` (default 60 s,
  configurable) with a one-sample DATA; the base raises SENSOR_OFFLINE after
  three missed check-ins (180 s) and JAMMING when three or more sensors go
  silent within one interval or when `crc_fail` / `hop_tag_fail` / ARQ
  retransmissions in the base's and relays' section 1 counters rise
  together. Battery (estimate): one 60 s check-in costs about 0.02 mAh, so
  about 29 mAh/day, 2-3 months on an 18650 (2500 mAh); a 5 min interval
  gives over a year. Within 10 minutes of the last check-in the routes are
  still alive, so a check-in is four unicast frames and no flood (4.4).
- Relays: power-bank or small-solar nodes where legs exceed one hop; they
  are non-leaf nodes and MUST be powered (11.1). Range (estimate): an
  external antenna (S3-WROOM-1U or WROOM-32UE) gives about 200-400 m line of
  sight outdoors, less through foliage and tents; nRF24 PA+LNA bridges for
  long legs (C.5).
- Silicon: bases and relays SHOULD be ESP32-S3-WROOM-1U (N8R8 for a base,
  N8 for a relay) with external antennas; leaves SHOULD be S3-WROOM-1U N8,
  and WROOM-32E / -32UE at v3.0+ is acceptable for leaves (12.1). Mixed
  sensors interoperate (12.12); the alarm path above is the same on both
  chips, with the leaf wake sources of 12.12.
- Deployment: all provisioning (keys, Secure Boot, flash encryption,
  manifest, per chip per 12.2) is done at home on the bench; on site, place
  and power on. Routes build themselves: each sensor's first SEEK floods and
  binds, the base's MGMT replies install the return routes.
- Capacity: 50 sensors x 4 frames per 60 s check-in x 1.5 ms x 2 hops =
  0.6 s of air per minute, about 1 %; events add one DATA/ACK pair each.
  Far below the domain limit.

---

## Appendix A. Test vectors

Computed by `tools/vectors.py` (Python `hmac`/`hashlib` for HKDF and HMAC,
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
-> parity `07 11 22 33 40`; k 4 / m 2 blocks `02 aa bb 00`, `03 11 22 33`, `01 ff 00 00`, `03 01 02 03`
-> parity `2d 01 2d 19`, `2e 44 b6 29`; erasure-decoding with positions {1, 3} reproduces blocks 1 and 3.

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
MGMT_REQ: header 12 40 42 00 01 00 42 00 ff ff 40 04 00 00 00 00 08 00 1e, pre_ctr 0x00010008
secret = 15 cd 5b 07 00 00 00 00 01 01 00 00 00 00 03 00 00 00 11 11 11 11 11 11 11 11
         (t1 123456789, e_new 1, e_old 1, flags 0, section 0, page 0, chunk 0, bundle_no 3, then 8 illustrative report bytes;
          a real section 0 is 38 bytes)
nonce = 00 42 00 01 00 00 01 00 00 00 08 00 00
payload = 08 00 01 00 93 b9 29 ae 8b d7 6c 0a 78 cc c4 66 22 a5 83 65 2b 52 03 e5 84 c4 12 52 a1 67
tag = a0 96 d2 b8 06 85 a1 11 ; frame (63): header || payload || tag || hop_tag 4d 29 7e b8 || 69 67   CRC16 = 0x6769
MGMT_RESP: header 12 41 01 00 42 00 01 00 99 00 40 05 00 00 00 00 05 00 21, pre_ctr 0x00020005
secret = 08 00 01 00 15 cd 5b 07 00 00 00 00 00 40 1e 18 24 0a 06 00 f4 41 1e 18 24 0a 06 00 00
         (req_ctr 0x00010008, t1 echo, t2 1700000000000000, t3 1700000000000500, flags 0)
nonce = 01 01 00 42 00 00 02 00 00 00 05 00 00
payload = 05 00 02 00 dc bd a5 fb fd 58 15 15 fd 52 12 2b 43 16 6a ed b6 b9 dd 56 81 86 61 52 7c f6 10 c5 ae
tag = f2 a1 91 20 28 23 29 9b ; frame (66): header || payload || tag || hop_tag 7a f0 6f 57 || 91 93   CRC16 = 0x9391
```

A.13 LOW quantization, range 0..3.3 V: scale 5.0356e-5, offset 1.65; v 0.00 -> q -32767; 1.65 -> 0;
3.30 -> 32767; 4.00 -> 32767 with CLIP.

A.14 Key bundle for node P (illustrative two-TLV snapshot: epoch 2 only, so applying it retires epoch 1; a real snapshot lists every peer, this one would revoke all but S)

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

A.15 IR edge link: frame budget and edge-key SEEK / HELLO (leaf L 0x0020, attached node A 0x0021, E_prov 1)

```
Sizes with AUTH: SEEK 54, HELLO 61, BIND 50, BIND_ACK 45, BIND_NAK 42, RESUME 38, RESUME_ACK 39,
MGMT_REQ fixed 55, MGMT_RESP fixed + one command TLV 69; all <= 74 = 80 - 6 (the script asserts this).
K_pair(0020, 0021, 1) = 27fdffdfe06f761c360b12e29c66913d6a5d6e2ff04108af2107bd2e5303ba51
K_hop_edge = f47bea4bc3606d1ed9f823cb4913c8ec1ac0d6425e9a69a84a0c405e180167ce ; Ke_edge = 3d745ef6ec5649379b629bbff6a29f45
SEEK (L -> A, unicast on the edge, ttl 1, hop_seq 0x100, path_mtu 74, pre_ctr 0x11, caps HIGH|LOW|AUTH|FEC, max_frame 80, key_epoch 1):
12 01 20 00 21 00 20 00 21 00 10 00 01 00 00 4a 00 00 00 11 00 12 11 00 00 00 44 33 22 11 1b 00 50 00 01 00 01 00 00 00
1b 37 fb b3 ca 6b 3e 63 b1 4a 6c bd 9d 6e                                        54 bytes, CRC16 = 0x6E9D
RS parity (6): b7 6e 02 0f 71 b1 ; on the air 60 bytes
HELLO (A -> L, pre_ctr 5, nonce_p 0x55667788, rssi -128 unknown, status 0, path_cost 20, fw 1; Ke_hello from PRK of the edge pair key and T0):
12 02 21 00 20 00 21 00 20 00 10 00 02 00 00 00 05 00 1c 05 00 00 00 81 24 c6 c1 e6 99 aa 17 66 0a a2 c7 4b 43 fd 91 5e 09 76 6a f7 be a6 87 3e b1 ca
c7 5e a6 b9 ca 73 62 ca 1b d7 c0                                                 61 bytes, CRC16 = 0xC0D7
RS parity (6): 4a c5 48 da 2d de ; on the air 67 bytes
```

## Appendix B. Minimal C API

Rules: `pl_init()` allocates the context, tables, stream pool and mbedtls
HMAC/CCM contexts from the heap once (review J4); no heap after it; every
call returns `pl_err_t`; transport RX and TX-status callbacks only copy into
a queue with timeout 0 (on the ESP32 they run in the WiFi task on core 0);
one `pl_task()`, pinned to core 1, does all protocol work; nothing blocks the
caller longer than the Task Watchdog period. Runtime NVS
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
typedef struct pl_ctx pl_ctx_t;                                                /* opaque, from pl_alloc() */

/* RAM: record ~600 B x max_sessions; stream (FEC 2180 + reorder 2500) x max_streams; sender ARQ 6 KB per
 * active sender session; tables ~7 KB; rx queue 4 KB. Node (ESP32 or S3), 32 records / 4 streams: ~49 KB
 * from heap; S3 N8R8 sink: 30 KB internal + 4.7 KB per stream from PSRAM (12.4). ESP32 with BT built in
 * reserves ~55 KB of DRAM. Keys, contexts and queues are always MALLOC_CAP_INTERNAL; only the stream pool
 * may be MALLOC_CAP_SPIRAM (streams_in_psram: S3 with PSRAM only, ignored elsewhere). Chip-specific code
 * is confined to pl_init's assertion (12.2) and the transports; nothing above them knows the chip. */
pl_err_t pl_alloc(pl_ctx_t **ctx_out, uint8_t max_sessions, uint8_t max_streams, bool streams_in_psram);   /* heap, once, before pl_init */

pl_err_t pl_init(pl_ctx_t *ctx, const pl_config_t *cfg, const pl_callbacks_t *cb);   /* PL_ERR_AUTH if the 12.2 per-chip assertion fails: UART wait */
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
pl_err_t pl_maintenance_mode(pl_ctx_t *ctx, bool enter);                   /* set the RTC flag and reboot into / out of the BLE phone link (6.4) */
void     pl_task(void *ctx);                                               /* FreeRTOS task; stack 6144 as a start, measure */

typedef struct {
    uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail, seg_fail, bad_frame, bad_version,
             auth_fail, hop_tag_fail, hop_replay, replay_dropped, bundle_fail, fec_recovered, arq_retx, gaps,
             id_collisions, rx_queue_drop, relay_fwd, relay_drop_ttl, relay_drop_dedup, relay_drop_stale,
             relay_drop_noroute, relay_drop_mtu, relay_drop_rate, relay_drop_queue_data,
             relay_drop_queue_ctrl, relay_drop_loop, route_evictions, link_evictions, link_fail_drops,
             stack_hwm_words;                                              /* all u32 on the wire */
} pl_stats_t;                                                              /* MGMT section 1, this order */
```

Task layout, identical on both chips: transport callbacks (core 0) ->
`xQueueSend` (timeout 0) -> `pl_task` on core 1 (validation, pipeline,
FEC/ARQ, callbacks, framing, CCM, hop_tag, `send()`); the asynchronous
TX-status callback is queued the same way and feeds the 11.6 failover.
`pl_send_samples()` only enqueues. Stack 6144 is the ESP32 start value;
measure `uxTaskGetStackHighWaterMark()` on each chip (section 0 `stack_hwm`).

## Appendix C. Carrier notes

C.1 IR edge link (to be validated on hardware; indoor or shaded only)

- 38 kHz carrier via RMT, TSOP-style receiver. Pulse-distance cell: mark
  300 us, space 300 / 600 us, about 2 kbit/s (estimate); validate against the
  receiver's minimum burst and gap. Preamble 9 ms mark + 4.5 ms space; 10 ms
  trailing silence delimits a frame (no COBS; 0x00 is legal).
- On the original ESP32 RMT has 8 channels x 64 words with no RX ping-pong
  and no DMA, and an 80-byte frame is about 640 symbols: receive with a
  GPIO-capture ISR (edge timestamps from `esp_timer`, decode in `pl_task`) or
  MCPWM capture, and keep RMT for transmit (review J12). The S3 runs the
  same capture path (one code path); its RMT RX ping-pong / DMA mode MAY
  replace it once C.1 is validated (12.12). Pins: C.6.
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

C.4 WiFi UDP (LAN side only): port 40888; floods to multicast 239.255.40.88
with IP TTL 1 (IGMP join at start), unicast otherwise; static IPs or DHCP
reservations; `pl/udp_peers` unicast list where multicast or client isolation
blocks it, else the carrier is unusable.

C.5 nRF24L01+ over SPI

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
- Overhead: 9 packets per 250-byte frame, about 1.5x on the air, roughly
  3-4 ms per frame at 2 Mbps, 30-60 kbit/s of payload (estimate).
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

C.6 Pin plans (field boards; bench dev boards MAY differ; numbers are chip
GPIOs exposed on the module). Both plans keep the IO_MUX pins for SPI and
UART so no signal goes through the GPIO matrix at speed.

| Function | ESP32-WROOM-32E / -32UE | ESP32-S3-WROOM-1 / -1U |
|---|---|---|
| Never use | GPIO6-11 (flash); strapping GPIO0 / 2 / 5 / 12 / 15 as inputs at boot only (GPIO12 low, or the flash-voltage eFuse burnt, 12.2); GPIO34-39 are input only without pull-ups | GPIO26-32 (flash, not module pins); GPIO33-37 (octal PSRAM on R8: 35-37 are module pins and MUST stay free on N8R8, and are kept free on N8 / N8R2 so one PCB serves both); strapping GPIO0 / 3 / 45 / 46 at their defaults (GPIO46 input only and low at boot; GPIO45 selects the flash voltage, leave its pulldown); GPIO19 / 20 USB D- / D+ (USB-Serial-JTAG for bench flashing and monitor; plain GPIO after `DIS_USB_SERIAL_JTAG`, kept as test pads) |
| UART0: console, provisioning station | GPIO1 TX, GPIO3 RX | GPIO43 TX, GPIO44 RX |
| UART1 role: sensor UART on nodes (115200), inter-chip link on the gateway (921600 or more) | GPIO17 TX, GPIO16 RX (UART2 IO_MUX pins) | GPIO17 TX, GPIO18 RX (UART1 IO_MUX pins) |
| nRF24L01+ SPI (10 MHz or less) | VSPI IO_MUX: SCK GPIO18, MISO GPIO19, MOSI GPIO23; CSN GPIO5 (pull-up, idles high through the strap window), CE GPIO4, IRQ GPIO35 | SPI2 (FSPI) IO_MUX: SCK GPIO12, MISO GPIO13, MOSI GPIO11; CSN GPIO10, CE GPIO9, IRQ GPIO14 |
| W5500 SPI (gateway LAN chip, 12.4) | n/a (ESP32 gateway branch withdrawn) | same SPI2 bus; CS GPIO38, INT GPIO39, RST GPIO40 |
| IR edge (C.1) | TX (RMT) GPIO25, RX (TSOP, GPIO capture) GPIO26 | TX (RMT) GPIO41, RX GPIO42 (JTAG pads, plain GPIO at the default strap and after `DIS_PAD_JTAG`) |
| ADC1 analog inputs | VBAT divider GPIO34 (CH6); sensors GPIO32, 33 (CH4, CH5) | VBAT divider GPIO1 (CH0); sensors GPIO4, 5, 6 (CH3-5); GPIO9-14 (CH8-9, ADC2) are taken by SPI |
| Digital sensor inputs, ext1 wake (12.12) | RTC GPIOs 36, 39, 27, 14 | RTC GPIOs 7, 8, 21 |
| Case switch (8.7, section 0 bit6) | GPIO13 (RTC, ext1 source) | GPIO2 (RTC, ext1 source) |
| Maintenance button (6.4) | GPIO0 (boot button, read after boot) | GPIO0 (same) |
| Spare | GPIO21, 22 | GPIO15 / 16 (reserved for a 32 kHz crystal on leaves), GPIO47, 48 |

## Appendix D. Change history and review disposition

History: v0.2 CRC on all links, RS erasure code across frames, probe nonce,
ARQ, two-nonce keys; v0.3 mandatory mesh; v0.4 hop_tag, 48-bit index,
per-pair keys, epochs, validation table, leaves, nRF24L01+; v0.5 BLE as a
phone link, IR as an edge, one max_frame, CCM + HMAC hop_tag, unicast BIND,
MGMT_REQ/RESP, pulled bundles. Round-1 and round-2 dispositions are in
PROTOCOL.v0.4.md and PROTOCOL.v0.5.md; all round-2 items closed in v0.5
except those reopened by round 3 (G1/T3 -> H1/U5, G3/T10 -> H2/U3, G8/T8 ->
H3/U1, G6 -> H4, G10 -> H5/H7, G9 -> H6, T1 -> U2).

v0.6 (round-3 fixes): 32-bit `hop_seq`, clear `pre_ctr` prefix, `K_hop`,
`K_node` bundles, recovery-holder IDs, two live epochs plus a retired slot
with recovery through it, return-direction route refresh and send-failure
link deletion, MGMT pacing and flood fallback, leaf update window,
fail-closed boot and BLE. Round-3 disposition (H1-H21, U1-U19, all fixed,
H13 partial) is in PROTOCOL.v0.6.md.

v0.7 (round-4 fixes, ESP32-WROOM profile, application profiles):

- IR: `max_frame` 80 so every control frame fits the 74-byte edge path;
  SEEK at `E_prov` accepted on the edge link; MGMT section 0 paged; A.15
  (J1).
- Bundles are full snapshots (omission = retire or revoke); MGMT_REQ and
  section 0 carry `bundle_no`; `chunk` is its own field; the manager keeps
  only the newest bundle per node; lost-phone revocation is just a new
  snapshot (J2). A.12 recomputed.
- MGMT pacing: response timeout `max(BIND_TIMEOUT, 1100 ms)`, 1 s chain gap
  (J3). Streams held for the life of a bound session, sink streams from the
  manifest, heap-allocated context, ESP32 RAM budgets (J4). WROOM
  provisioning order with host-generated `nvs_keys` encrypted at first boot
  (J5).
- Deployment profile: ESP32-WROOM-32E/-32UE, `CONFIG_ESP32_REV_MIN_3`, 4 MB
  partition table, pin plan, Secure Boot v2 asserted specifically (V6),
  anti-rollback budget (V5), CVE-2019-17391 named; gateway silicon as an
  OPEN decision with S3 recommended and WROOM-32E allowed under conditions
  (V2, J4).
- Capture detection the node cannot author: gateway-side cadence and
  counter / epoch / bundle continuity record, hourly challenge (TLV 0x08,
  section 4), tamper-evident enclosures with a case bit (V1, R11).
- `KEY_RECOVERY_S` 7 days, persisted in MGMT periods (V3, J21); referenced
  link entries live with their routes (J6); manager trial-decrypts epochs
  (J7); unicast hop_tag default `E_old` (J8); gateway-outage airtime row
  (J9); asynchronous TX status callback and core layout (J10); BLE
  maintenance by reboot (J11); IR receive by GPIO capture on the ESP32
  (J12); RESUME unicast after short parks (perimeter profile).
- 12.11 corrected; section 13 application profiles (fixed network,
  vehicle / flight data, campsite perimeter).

v0.8 (two chip families; this document; wire bytes, Appendix A and
`tools/vectors.py` unchanged):

- USER-DECIDED: bench = any ESP32-WROOM (any revision) or S3-WROOM-1, nothing
  protected at rest; field gateway / manager / sink = ESP32-S3-WROOM-1U N8R8,
  closing 12.4 (V2, J4); field relays and leaves = S3-WROOM-1U N8 / N8R2 or
  WROOM-32E / -32UE v3.0+; WROOM-32 / -32D / -32U never in the field (12.1).
- 12.2 per-chip provisioning and `pl_init` assertion tables: S3 with three
  Secure Boot digest slots (field, escrow, revoked spare), XTS-AES flash
  encryption, HMAC-peripheral NVS scheme (no `nvs_keys`), JTAG and
  USB-Serial-JTAG off, Secure Download Mode or full disable; `chip_id` check
  on BULK images (12.7).
- 12.12 interop requirement (chip never on the wire), per-chip budgets, 4 MB
  and 8 MB partition tables (12.1), leaf sleep and wake sources; PSRAM rules
  for the sink (12.4, App. B `streams_in_psram`); 12.10 chip limitations on
  WROOM-32E field nodes only; 12.11 and 13.3 updated; C.6 pin plans; one IR
  receive path (C.1); BLE reboot rule on both chips (6.4).

Round 4 disposition. Field MEDIUM/LOW items had no IDs in ROAST-4-field.md;
they are numbered here J6-J16 (MEDIUM) and J17-J25 (LOW) in that file's order.

| ID | Sev | Disposition | Where / reason |
|---|---|---|---|
| J1 | CRITICAL | fixed | IR max_frame 80 (1.2, 6.1, 6.3); SEEK key_epoch = E_prov on edge links (3.6, 8.2, 8.5, 11.11); section 0 paged; A.15 with fit assertion |
| J2 | HIGH | fixed | 8.5 snapshot bundles, 8.6 serving rule and bundle_no in MGMT_REQ and section 0, chunk field (11.10); A.12 recomputed |
| J3 | HIGH | fixed | 11.10 pacing: timeout max(BIND_TIMEOUT, 1100 ms), MGMT_CHAIN_GAP_MS 1000, hops = seek_ttl when flooded |
| J4 | HIGH | fixed; silicon closed in v0.8 | 4.1.12 stream held for the session, FULL at HELLO only, streams from the manifest; heap allocation (11.9, App. B); S3 N8R8 gateway budget in 12.4, per-chip budgets in 12.12 |
| J5 | HIGH | fixed | 12.2 WROOM order: host nvs_keys flashed before release-mode first boot, NVS image written afterwards, download disable last |
| J6 | MEDIUM | fixed | referenced link entries live with their routes (11.6, 11.9, 9) |
| J7 | MEDIUM | fixed | manager trial-decrypts E_old, E_new, retired (8.5) |
| J8 | MEDIUM | fixed | unicast hop_tag defaults to E_old when the link entry is absent or retired (8.5) |
| J9 | MEDIUM | fixed (bounded) | gateway-outage row in the section 9 budget, about 5 %, failure pull capped per MGMT_PERIOD_S (4.1.8) |
| J10 | MEDIUM | fixed | set_tx_cb asynchronous status (1.2), core layout (App. B, 12.1) |
| J11 | MEDIUM | fixed | maintenance mode by reboot, NimBLE, BTDM reserve budgeted (6.4, App. B) |
| J12 | MEDIUM | fixed | GPIO / MCPWM capture for IR receive on the ESP32 (C.1) |
| J13 | MEDIUM | fixed | 4 MB partition table and 0xC000 table offset (12.1) |
| J14 | MEDIUM | fixed | SECURE_VERSION BLOCK3 app anti-rollback, security releases only (8.7) |
| J15 | MEDIUM | fixed (stated) | single Secure Boot key digest, no revocation, in 12.1 and 12.10 |
| J16 | MEDIUM | fixed | pin plan: GPIO12 / flash-voltage eFuse, GPIO6-11, ADC1 only (12.1, 12.2) |
| J17 | LOW | fixed | pre-v0.7 versions were never on the air; frozen prefix applies from v0.7 (reading guide) |
| J18 | LOW | fixed | header seq == low 16 bits of pre_ctr (3.6) |
| J19 | LOW | fixed | A.12 report bytes labelled illustrative; section 0 is 38 bytes |
| J20 | LOW | fixed | pl_stats_t all u32 (App. B) |
| J21 | LOW | fixed | KEY_RECOVERY_S counted in MGMT periods and persisted (8.5) |
| J22 | LOW | fixed | flooded MGMT timeout uses hops = seek_ttl (11.10) |
| J23 | LOW | fixed | tool persists bundle_no transactionally (8.6) |
| J24 | LOW | fixed | "beacons" removed from 8.7 |
| J25 | LOW | fixed | CVE-2019-17391 named (12.1) |
| V1 | HIGH | fixed | R11; 8.7 gateway-side cadence and continuity record, hourly challenge (TLV 0x08 / section 4), tamper-evident enclosures with a case bit |
| V2 | MEDIUM | closed v0.8 (USER-DECIDED) | 12.4: ESP32-S3-WROOM-1U N8R8 for gateway / manager / sink, WROOM-32E gateway branch withdrawn; role-to-silicon mapping in 12.1 |
| V3 | MEDIUM | fixed | KEY_RECOVERY_S 7 days, revocation cap 24 h, routine cap bounded by KEY_RECOVERY_S (8.5, 9) |
| V4 | LOW | accepted | IR edge key never rotates; cable rekey (12.6, 12.10) |
| V5 | LOW | fixed | anti-rollback budget: 32 increments, at most two per year (8.7) |
| V6 | LOW | fixed | Secure Boot v2 asserted specifically (ABS_DONE_1, CONFIG_SECURE_BOOT_V2_ENABLED); section 0 bit0 means v2 (12.1, 11.10) |
| V7 | LOW | accepted | pre_ctr and activity visible on the air, within the enumeration model (8.7, 12.10) |
