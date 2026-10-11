# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.5 (round-2 fixes, scope reduced; wire version 1, minor 0)

One protocol, four mesh carriers (ESP-NOW, WiFi UDP, nRF24L01+, UART) plus
an IR edge link. Every device has an ID. Every frame is integrity-checked and
carries enough redundancy to recover damaged or lost data. Payloads are
digital or analog 32-bit values, sent in HIGH or LOW resolution.

Reading guide: sections 1-10 keep the v0.1 numbering so the drafts can be
diffed. Section 11 is the mesh layer (mandatory). Section 12 holds the
deployment profile and every design decision with its alternative; two of
them (BLE, IR) are user decisions. Appendix D maps every review finding to
its disposition. Numbers marked "(estimate)" are not measurements.

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
In-frame RS is fixed at 0 on PACKET links (v0.5: one less knob).

Unified recovery model: the frame layer turns every kind of damage into an
erasure (a frame that is either fully correct or absent); FEC and ARQ only
ever deal with erasures. Recovery data per packet, stated precisely: DATA
frames carry recovery data (RS parity on RAW links, PARITY frames on every
link); control frames are protected by CRC plus repetition (floods are sent
`FLOOD_REPEAT` times on carriers without broadcast MAC retry, 11.5) and by
the handshake retries. A stricter reading is a knob in 12.3.

### 1.2 Transport adapter contract

```c
typedef enum { PL_LINK_PACKET = 0, PL_LINK_RAW = 1 } pl_link_class_t;

typedef struct {
    const char     *name;          /* "espnow", "udp", "nrf24", "uart", "ir" */
    pl_link_class_t link_class;
    uint16_t        max_frame;     /* 250 on mesh carriers; 64 on IR (incl. RS parity) */
    uint8_t         rs_nsym;       /* 0 PACKET, 8 UART, 6 IR */
    bool            can_broadcast; /* floods by broadcast (ESP-NOW, UDP multicast, nRF24) */
    bool            mac_retry;     /* carrier retries unicast (ESP-NOW, nRF24: yes) */
    bool            edge_only;     /* IR: frames are never forwarded to or from this transport */
    uint8_t         link_cost;     /* for carriers without RSSI (11.4): UART 1, nRF24 2 */
    uint8_t         addr_len;      /* carrier address bytes in the link table: 6 ESP-NOW, 5 nRF24, 4 UDP, 0 UART/IR */
    int  (*send)(const uint8_t *addr, const uint8_t *buf, uint16_t len);   /* addr NULL = broadcast */
    void (*set_rx_cb)(void (*cb)(const uint8_t *addr, const uint8_t *buf, uint16_t len, int8_t rssi));
} pl_transport_t;
```

| Carrier | Class | max_frame | Notes |
|---|---|---|---|
| ESP-NOW | PACKET | 250 | Broadcast FF:FF:FF:FF:FF:FF for floods, unicast to the `next_hop` MAC otherwise. One dedicated channel (`pl/channel`) for all mesh nodes; `esp_wifi_set_ps(WIFI_PS_NONE)`; WiFi STA and BT never run on a mesh node while the mesh is up (12.4, 12.5). `rssi` from `esp_now_recv_info_t` (ESP-IDF >= 5.0). |
| WiFi UDP | PACKET | 250 | LAN side of the gateway only (12.4). Port 40888, multicast 239.255.40.88 TTL 1 for floods, unicast otherwise; static IPs or DHCP reservations; a configured unicast peer list replaces multicast on isolated LANs (C.4). |
| nRF24L01+ (SPI) | PACKET | 250 (reassembled) | 32-byte packets, segmented and reassembled inside the adapter per hop (C.5). ESB CRC-16, auto-ACK unicast on unit-ID-derived addresses, NO_ACK broadcast address for floods. No RSSI: fixed `link_cost` 2; `rssi` reported as -128 (unknown). |
| UART | RAW | 250 (incl. 8 RS bytes) | COBS, 0x00 delimiter; COBS bytes are outside max_frame. Point to point. Also the carrier of the two-chip gateway and of the provisioning station (12.2). |
| IR (RMT) | RAW, edge | 64 (incl. 6 RS bytes) | One hop, point to point, between an IR leaf and one mesh node; never forwarded (user decision, 12.6). 38 kHz, half duplex, indoor or shaded. Both ends apply `IR_TIME_SCALE` (10) to the handshake timers of that link only. |

BLE is not a carrier. It is a phone link for commissioning and diagnostics
that runs only while the mesh radio is stopped (12.5).

---

## 2. Device IDs

16-bit IDs. Small enough for IR, large enough for a site of 50 nodes.

| Range | Meaning |
|---|---|
| 0x0000 | Unassigned. Never valid on the air. |
| 0x0001 - 0xFEFF | Unit ID. One per device. |
| 0xFF00 - 0xFFFE | Group (destination) ID. Several probes can subscribe to one group. |
| 0xFFFF | Flood. |

- Unit IDs come from the provisioning manifest (12.2), one row per device
  keyed by its eFuse base MAC, written to NVS (`pl/unit_id`) with the MAC it
  belongs to (`pl/unit_mac`). At boot, if `pl/unit_mac` differs from
  `esp_read_mac(ESP_MAC_BASE)` the image is a clone: the node ignores the ID,
  uses the fallback below, and reports the mismatch in its next MGMT report
  (11.10). A fallback node holds no pairwise keys, so it can report and do
  nothing else until re-provisioned; that is the intended outcome.
- Fallback ID: CRC-16/CCITT-FALSE (3.1) of the base MAC; if 0x0000 or
  >= 0xFF00, `(crc % 0xFEFF) + 1`.
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
11   2     hop_seq     low 16 bits of the transmitter's txseq (3.5)        per hop
[13  2     path_mtu    SEEK only: smallest (max_frame - rs_nsym) so far    per hop]
[15  1     path_cost   SEEK only: sum of link costs so far (11.4)          per hop]
..   1     session_id  0 in SEEK/HELLO/BIND/BIND_ACK/BIND_NAK/MGMT         end-to-end
..   2     seq         low 16 bits of the end-to-end index (3.5)           end-to-end
..   1     len         payload length 0..255                               end-to-end
..   len   payload     AES-CCM ciphertext (SEEK, RESUME: plaintext, 8.3)   end-to-end
..   8     auth_tag    if FLAG_AUTH: AES-CCM tag (section 8)               end-to-end
..   4     hop_tag     if FLAG_AUTH: HMAC(K_mesh) over bytes 0..auth_tag   per hop
..   2     crc16       CRC-16/CCITT-FALSE over byte 0 .. end of hop_tag    per hop
..   n     rs_parity   rs_nsym bytes on RAW links                          per hop
```

Header 17 bytes (20 in SEEK). Fixed overhead with CRC: 19 bytes, +12 with
FLAG_AUTH, +rs_nsym. Per-hop fields are rewritten by every forwarding node
(section 11); a direct link is a one-hop route with `prev_hop = src_id` and
`next_hop = dst_id`. End-to-end fields never change between origin and final
destination.

| Flag bit | Name | Meaning |
|---|---|---|
| 0 | FLAG_ACK_REQ | Receiver replies ACK immediately |
| 1 | FLAG_AUTH | `auth_tag` and `hop_tag` present. Mandatory in the field profile. |
| 2, 3 | reserved | 0 on send, ignored on receive |

Frozen prefix: bytes 0..12, the SEEK hop fields, the positions of
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
  other type inside a group (MODE, PING, CLOSE go between groups). A group may
  close early (`FEC_FLUSH_MS`, or before MODE/CLOSE). With `fec_m > 0` the
  DATA payload is capped at `max_payload - 9` so the PARITY frame fits.
  Retransmitted DATA keeps its seq and stays a valid member.
- Receiver: buffer the last `fec_k + fec_m` frames per stream, RAM
  `(k + m) x (max_payload + 1)` = 10 x 220 = 2200 bytes for k 8, m 2 on the
  mesh path. Decode when k blocks are reachable; deliver through the reorder
  buffer (section 7). Overhead `m / k`, latency up to `k + m` frame periods.

| k | m | Overhead | Recovers | Suits |
|---|---|---|---|---|
| 8 | 2 | 25 % | any 2 of 10 | default for radio streaming |
| 8 | 4 | 50 % | any 4 of 12 | noisy 2.4 GHz |
| 2 | 1 | 50 % | any 1 of 3 | IR edge, low-rate sensors |
| 16 | 2 | 12.5 % | any 2 of 18 | clean link, bandwidth matters |

### 3.4 Header budget

One header everywhere. The mesh fields cost 7 bytes (5 hop fields plus
hop_seq) and the field-profile tags 12: 8 % of a 250-byte frame and 33 % of a
64-byte IR frame. Compressing the header for IR or point-to-point links was
rejected: it saves at most 4 bytes, needs two parsers, and IR is a one-hop
edge where the bit rate, not the header, is the limit. The nRF24L01+ 32-byte
packet is handled by per-hop segmentation inside its adapter (C.5), never by
shrinking this header.

### 3.5 Counters and sequence numbers

Three counters, two of them persistent across reboots (reserve-ahead: the
NVS value is the next block boundary; at boot the node resumes from it; one
write per block):

| Counter | Scope | On the wire | Persistent | Block |
|---|---|---|---|---|
| `txseq` | per node, every transmission (own frames, forwarded frames, each FLOOD_REPEAT copy) | `hop_seq` = low 16 bits | NVS `pl/txseq` | 4096 (about 1000 writes/day at 50 frames/s) |
| `preseq` | per node, every originated pre-session frame (SEEK, HELLO, BIND, BIND_ACK, BIND_NAK, MGMT) and every RESUME | full 32 bits as `pre_ctr`, first payload field; header `seq` = low 16 bits for session_id 0 frames | NVS `pl/preseq` | 64 |
| session index | per session and direction: ROC u32 (implicit) << 16 \| `seq` u16, from 0 at BIND_ACK, +1 per frame of any type; retransmitted DATA reuses its index | `seq` | leaf RTC blob only (4.4) | - |

- The 48-bit session index is what the CCM nonce covers (section 8), so a
  frame recorded before a 16-bit wrap is never valid after it. The receiver
  estimates the sender's ROC as in SRTP (RFC 3711, 3.3.1): with `s_l` the
  highest seq received and `roc` the current estimate, a frame uses `roc - 1`
  if `s_l < 32768` and `seq - s_l > 32768`, `roc + 1` if `s_l >= 32768` and
  `s_l - 32768 > seq`, otherwise `roc`; the tag confirms the guess (A.10).
- `hop_seq` gives every transmission per-hop freshness: a neighbour keeps the
  32-bit reconstruction per (unit_id, transport) in its link table and drops
  anything not newer before learning or forwarding (11.4). `pre_ctr` gives
  floods and pre-session frames end-to-end freshness at relays (ORIGIN table,
  11.5) and at endpoints (8.4).
- Serial-number arithmetic (RFC 1982) compares 16-bit values; all windows
  are far below 32768. Receivers keep a 64-entry seen-bitmap below the highest
  index and drop duplicates.

### 3.6 Receiver validation (normative)

Checks run in this order before any other processing; a failure drops the
frame, increments the counter and sends nothing. Forwarding nodes apply the
Length, Header, SEEK hop field, Version and hop_tag rows; payload rows and the
CCM tag apply at the endpoint that holds the key.

| Stage | Check | Counter |
|---|---|---|
| Length | received length == header + len + (12 if FLAG_AUTH) + 2 + rs_nsym; len <= 231 - rs_nsym without AUTH, 219 - rs_nsym with AUTH | `bad_frame` |
| Header | ttl <= MAX_HOPS; hops < MAX_HOPS; prev_hop and src_id are unit IDs; next_hop is a unit ID or 0xFFFF; dst_id != 0 | `bad_frame` |
| SEEK hop fields | MIN_PATH_MTU (48) <= path_mtu <= (max_frame - rs_nsym) of the link it arrived on; path_cost <= 250 | `bad_frame` |
| Version | endpoints: version in {N, N-1}; forwarders: any version with the frozen prefix | `bad_version` |
| hop_tag | valid under a stored K_mesh epoch; hop_seq newer than the link-table value for (prev_hop, transport) | `hop_tag_fail`, `hop_replay` |
| CCM tag | valid under the key of section 8.3; for session_id 0 frames and RESUME, `pre_ctr` newer than the last seen from this peer under this key | `auth_fail`, `replay_dropped` |
| SEEK | len 18; caps reserved bits 0; max_frame >= MIN_PATH_MTU; key_epoch stored | `bad_frame` |
| HELLO | len 24; status 0..1; nonce_s matches an outstanding SEEK | `bad_frame` |
| BIND / BIND_ACK / BIND_NAK | len 13 / 12 / 9; nonces match an OFFERED or BINDING entry; session_id != 0 (BIND) | `bad_frame` |
| MODE | len 13 + descriptor bytes (mode 2: 13 + 40); ch_count 1..16 (mode 0/1); kind 0..1; fmt 0..2 analog, 1..32 digital; scale finite and non-zero, offset finite; period > 0; fec_m 0..4; fec_k 2..16 when fec_m > 0; arq 0..1; keepalive_ms 1000..60000; one full sample <= max_payload - 7 (- 9 more with FEC) | MODE_ACK status 3 or 2 |
| MODE_ACK / ACK / RESUME_ACK / PING / PONG / CLOSE / RESUME | len 2 / 6 / 6 / 4 / 8 / 3 / 5; cum_seq inside the ARQ window | `bad_frame` |
| DATA | config_id known; len == 7 + n_samples x sample bytes (mode 2: 7 + n_samples) | `bad_frame` |
| PARITY | idx < m == fec_m; k 1..fec_k; block_len <= max_payload + 1; first_seq inside the window | `bad_frame` |
| MGMT_REQ / MGMT_RESP | fixed part 16 / 29; TLVs (type u8, len u8) within len; section 0..3 | `bad_frame` |

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
  | SEEK flood (nonce_s) --------->|----------------->|      ttl SEEK_TTL, under Ke_mesh
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
   sender's caps, `max_frame`, `key_epoch`, `proto_minor` and `fw_build`.
   Its payload is plaintext but authenticated under `Ke_mesh(key_epoch)` so
   relays can read `pre_ctr` (8.3). SEEK carries no session authority. The
   first SEEK after a cold boot waits `rand(0..BOOT_SPREAD_MS)` with
   `BOOT_SPREAD_MS = 600 x pl/node_count` (30 s at 50 nodes); a deep-sleep
   wake is exempt.
2. Each probe subscribed to the group that holds a pairwise key for the
   sender waits `rand(0..HELLO_WINDOW_MS)` and sends HELLO unicast along the
   reverse route installed by the lowest-cost SEEK copy it received inside
   the window (11.4): `pre_ctr`, `nonce_s`, a fresh `nonce_p`, its caps,
   `max_frame` = min(own `max_frame - rs_nsym`, that copy's `path_mtu`),
   `rssi`, `status` (0 ok, 1 full), that copy's `path_cost`, `proto_minor`,
   `fw_build`, encrypted under `Ke_hello` (8.2). It enters OFFERED with a
   `BIND_TIMEOUT(hops)` timer (rule 10). One OFFERED entry per `src_id`; when
   `PROBE_OFFERS_MAX` (4) entries exist the oldest is replaced. A probe
   without a free stream (rule 12) still answers with `status` 1 and keeps no
   state.
3. A probe bound to sender X that receives a new SEEK from X answers HELLO
   like any other and keeps the existing session untouched. Only a BIND that
   decrypts under the new `Ke_hs` replaces the old session with X; a
   replayed or forged SEEK changes nothing.
4. Selection: the first valid HELLO with `status` 0 wins (the user's
   first-acknowledger-wins) and BIND is sent at once. Up to
   `HELLO_CANDIDATES` (4) further HELLOs are kept as fallbacks until the
   session is established; a candidate whose first hop (`prev_hop` of its
   HELLO) is on the penalty list (4.2) ranks last. If every HELLO says FULL
   the sender backs off to the 60 s cap of rule 8 at once.
5. BIND is unicast to the chosen probe along the route its HELLO installed,
   carrying `pre_ctr`, both nonces and the new `session_id`, encrypted under
   `Ke_hs`. The probe replies BIND_ACK (`Ke_hs`) and enters BOUND. Losing
   probes simply time out of OFFERED (rule 7); nothing on the air can cancel
   an offer early.
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
   A probe in OFFERED that hears the same `nonce_s` with a newer `pre_ctr`
   assumes its HELLO was lost and sends HELLO again (new delay, same
   `nonce_p`).
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
12. Capacity (review G9): a probe keeps `PL_MAX_SESSIONS` session records
    (keys, index state, replay bitmap, two configs, SRTT: about 600 bytes
    each; 32 by default) and `PL_MAX_STREAMS` stream buffers (FEC + reorder,
    about 4.7 KB each; 4 by default), taken only while frames are in
    flight. Parked sessions hold a record and no stream. "Full" (rule 2)
    means no free record, or no free stream for a non-leaf sender. Probes
    allocate no ARQ buffer; only senders retransmit. Leaves hold one record.
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

- Cadence is a session parameter, `keepalive_ms` in MODE (default 5000,
  review G2). The probe sends ACK every `ACK_EVERY` (8) frames, on
  FLAG_ACK_REQ, or when `keepalive_ms` has passed since its last own frame
  and it has received something; it never sends PING. The sender sends PING
  when no ACK has arrived for `keepalive_ms`. `SESSION_TIMEOUT =
  max(4 x keepalive_ms, 8 x SRTT)` on both ends. Airtime: 2 frames per
  keepalive per session, about 0.6 % of a 1 Mbps collision domain for 40
  two-hop sessions at the default (section 9 table).
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
  lost CLOSE.

### 4.3 Race catalogue

| Scenario | Rule |
|---|---|
| Two probes answer the same SEEK | BIND is unicast to one; the other times out (4.1.5, 4.1.7) |
| Two senders SEEK one group at once | Multi-session probes serve both; a full probe says FULL or BIND_NAKs (4.1.2, 4.1.6) |
| Bound probe hears a SEEK from its own sender (replay or reboot) | HELLO answered; the old session is replaced only by a BIND that decrypts under the new Ke_hs (4.1.3) |
| BIND or BIND_ACK lost | Retries inside BIND_TIMEOUT at every hop count; idempotent BIND_ACK (4.1.9-10) |
| HELLO lost | Same nonce_s with newer pre_ctr triggers a new HELLO (4.1.8) |
| Late BIND after BIND_TIMEOUT | Ignored by a LISTENING probe (4.1.7) |
| Sender or probe reboots mid-session | Timeouts on both ends; stale record replaced on the next BIND (4.1.3, 4.2) |
| seq wraps at 65535 | Serial arithmetic for ordering; 48-bit index with implicit ROC in the CCM nonce for replay (3.5, 8) |
| Two senders pick the same session_id | Sessions keyed by (src_id, session_id) (4.1.11) |
| Replayed SEEK / HELLO / BIND | pre_ctr freshness at relays and endpoints; transcript-bound keys (8.4) |
| 50 nodes reboot together | Boot holdoff, full-jitter backoff, jittered re-SEEK (4.1.1, 4.1.8, 4.2) |
| Probe hears SEEK copies via two paths | Dedup; lowest-cost copy inside the window sets route, path_mtu and HELLO fields (11.4) |
| Relay on the path dies | SESSION_TIMEOUT -> re-SEEK installs new routes; penalty list avoids the dead first hop; stale routes expire (4.2, 11.6) |
| Path MTU shrinks after failover | New session, new MODE, MODE_ACK status 2 if too big (11.3) |
| Origin hears its own flood echoed | Dropped by its own dedup entry, no alarm (11.5) |
| Leaf wakes after a park | RESUME flood re-installs routes both ways (4.4, 11.4) |

### 4.4 Parked sessions and leaves

Leaves are battery nodes that deep-sleep between reports. They are senders
only, never serve a group and never forward; non-leaf nodes MUST be mains or
solar powered (11.1).

- Park: the leaf sends CLOSE with reason 6 (PARK) and `park_s` (1..3600),
  with FLAG_ACK_REQ, up to 3 times until ACKed. The probe keeps the session
  record for `park_s + PARK_GRACE_S` (60) and stops expecting liveness; no
  stream buffer is held.
- RTC blob (`RTC_DATA_ATTR`, about 160 bytes, CRC32-protected): probe_id,
  session_id, route hops and first-hop address, `Ke_s2p`, `Ke_p2s`,
  `key_epoch`, ROC/seq reserved ahead by 64 (written before transmitting),
  `preseq` and `txseq` reserved ahead, config_id, SRTT, the last 8
  session_ids. The blob is used only when `esp_reset_reason() ==
  ESP_RST_DEEPSLEEP` and its CRC matches; otherwise the leaf does a full
  handshake. Reserving ahead means a reset can never reuse a CCM nonce.
- Wake: the leaf floods RESUME (type 0x31, plaintext `pre_ctr` and
  `config_id`, authenticated under `Ke_s2p`) with `ttl = min(hops + 1,
  MAX_HOPS)`. Relays treat it as a flood (ORIGIN freshness on its `pre_ctr`,
  dedup, budget) and it re-installs reverse routes; the probe verifies the
  tag and the session index, replies RESUME_ACK on the reverse route, which
  installs the forward routes (11.4), and the leaf sends DATA. Timeout
  `BIND_TIMEOUT(hops)`; one retry with a new `pre_ctr` and a new session
  seq (an identical retry would be a dedup hit), then a full SEEK.
- Management on wake: every `MGMT_EVERY_WAKES` (10) wakes the leaf sends
  MGMT_REQ to its manager after DATA and stays awake for the reply chain
  (11.10). This is how a leaf receives keys and time and reports its
  battery; nothing is pushed to a sleeping node, so a bundle waits at most
  10 wakes.
- Power: battery voltage is checked before the radio starts; below
  `VBAT_MIN` the wake is skipped and reported in the next MGMT section 0.
  `esp_wifi_set_max_tx_power()` at the lowest level that closes the link; a
  bulk capacitor for primary cells (C3 TX peaks exceed what bobbin cells
  deliver). Wake budget (estimate, measure on hardware): Secure Boot image
  check 100-300 ms + radio start 120 ms + RESUME round trip 100-500 ms +
  DATA 20 ms, 0.4-0.9 s at about 100 mA: roughly 0.02 mAh per wake, about
  2 months on 2000 mAh at one report per minute, over a year at one per
  five minutes.

---

## 5. Message types

| Type | Name | Dir | Key (8.3) | Payload (after the 4-byte `pre_ctr` where marked P) |
|---|---|---|---|---|
| 0x01 | SEEK | S -> group (flood) | Ke_mesh, plaintext | P, nonce_s u32, caps u16, max_frame u16, key_epoch u8, proto_minor u8, fw_build u32 (18) |
| 0x02 | HELLO | P -> S | Ke_hello | P, nonce_s u32, nonce_p u32, caps u16, max_frame u16, rssi i8 (-128 = unknown), status u8 (0 ok, 1 full), path_cost u8, proto_minor u8, fw_build u32 (24) |
| 0x03 | BIND | S -> P | Ke_hs | P, nonce_s u32, nonce_p u32, session_id u8 (13) |
| 0x04 | BIND_ACK | P -> S | Ke_hs | P, nonce_s u32, nonce_p u32 (12) |
| 0x07 | BIND_NAK | P -> S | Ke_hs | P, nonce_s u32, reason u8 (1 busy, 2 caps mismatch) (9) |
| 0x05 | MODE | S -> P | Ke_s2p | 6.1 |
| 0x06 | MODE_ACK | P -> S | Ke_p2s | config_id u8, status u8 (0 ok, 1 unsupported, 2 too big, 3 bad arg) |
| 0x10 | DATA | S -> P | Ke_s2p | 6.2 |
| 0x11 | PARITY | S -> P | Ke_s2p | 3.3 |
| 0x12 | ACK | P -> S | Ke_p2s | cum_seq u16, bitmap u32 (seqs cum_seq+1 .. +32, bit set = received) |
| 0x20 | PING | S -> P | Ke_s2p | t_tx_us u32 |
| 0x21 | PONG | P -> S | Ke_p2s | t_echo_us u32, t_local_us u32 |
| 0x30 | CLOSE | either | Ke dir | reason u8 (0 normal, 1 timeout, 2 unknown session, 3 application, 4 auth failure, 5 reboot, 6 park, 7 bulk complete), park_s u16 |
| 0x31 | RESUME | S -> P (flood) | Ke_s2p, plaintext | P, config_id u8 (5) |
| 0x32 | RESUME_ACK | P -> S | Ke_p2s | cum_seq u16, bitmap u32 |
| 0x40 | MGMT_REQ | node -> manager | K_mgmt | 11.10 |
| 0x41 | MGMT_RESP | manager -> node | K_mgmt | 11.10 |

"Ke dir" is the directional session key of whoever sends (`Ke_s2p` from the
sender, `Ke_p2s` from the probe). Every frame's `hop_tag` is under `K_mesh`.

caps (u16): 0 HIGH, 1 LOW, 2 ARQ, 3 AUTH, 4 group FEC, 5 RELAY (clear on
leaves), 6 MULTI (probe serves several sessions), 7-15 reserved. A session
uses the intersection of both ends' caps; the transcript (8.2) binds both
values, so neither end can be fooled about the other's. In the field profile
a probe drops SEEKs that fail the `Ke_mesh` tag and ignores senders whose
caps lack AUTH.

`max_frame` in SEEK is the sender's own; HELLO's is min(probe's own `max_frame
- rs_nsym`, the chosen SEEK copy's `path_mtu`); the session uses min(sender's
own `max_frame - rs_nsym`, HELLO `max_frame`) = the path MTU (11.3). SEEK and
RESUME are flooded; MGMT_REQ MAY be flooded when the node has no route to its
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
  212). On the IR edge link (max payload 20 with AUTH) MODE fits one digital
  or HIGH channel, or three channels without AUTH; IR leaves therefore use
  one channel, or send one channel per session.
- One complete sample must fit a DATA frame, else MODE_ACK status 2.
- MODE may be sent at any time after BIND_ACK; DATA keeps the old
  `config_id` until MODE_ACK; MODE is resent every `MODE_RETRY_MS` until
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

Data bytes per frame = path_mtu - 19 (header + CRC) - 7 (DATA header) - 12
(AUTH) (- 9 more with fec_m > 0). Example: 4 analog channels.

| Link / path | path_mtu | Data bytes (AUTH) | HIGH / LOW samples per frame | bench, no AUTH |
|---|---|---|---|---|
| ESP-NOW, nRF24, UDP, or any path of them | 250 | 212 | 13 / 26 | 224: 14 / 28 |
| Path with a UART hop (250 - 8) | 242 | 204 | 12 / 25 | 216: 13 / 27 |
| IR edge link (64 - 6) | 58 | 20 | 1 / 2 | 32: 2 / 4 |

Throughput (estimates): ESP-NOW at 1 Mbps gives about 100 kbit/s of goodput,
about 50 full frames per second per collision domain; nRF24 at 2 Mbps about
30-60 kbit/s per link after segmentation (C.5); IR about 3 frames per
second. Choose `period` and `n_samples` so the frame rate stays under the
carrier's limit with margin for PARITY and retransmissions.

### 6.4 BLE phone link

BLE is used only for commissioning and local diagnostics from a phone, and
only while the node is in maintenance mode: the mesh radio is stopped, BLE
starts, the phone connects and exchanges MGMT frames (11.10) over one GATT
characteristic pair under the node's `K_mgmt` with the phone acting as a
manager that holds the manifest's recovery key for that device. Leaving
maintenance mode stops BLE and restarts the mesh. BLE and ESP-NOW never run at
the same time on one chip, which removes the coexistence and power-save
conflict (review G13). Entering maintenance mode: a button, or a MGMT_RESP
command from the gateway, or the first boot of an unprovisioned node.

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

---

## 7. Reliability modes

| Setting | Use when | Behaviour |
|---|---|---|
| arq 0, fec_m 0 | UART, short cable | CRC + RS only; lost frames stay lost |
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
  expires is reported as `on_gap(first_seq, count)`.
- Queues: the transport RX queue (`RX_QUEUE_FRAMES` 16) is filled with
  timeout 0 and a full queue counts `rx_queue_drop`. The forwarding queue
  (`RELAY_QUEUE_FRAMES` 8) has two classes: when full, a control frame (any
  type but DATA/PARITY) evicts the oldest DATA/PARITY frame
  (`relay_drop_queue_data`); a control frame is dropped only when the queue
  holds nothing else (`relay_drop_queue_ctrl`).

---

## 8. Security

Requirements with their mechanism. Attacker classes: an outsider in radio
range or on the LAN (no keys); a thief who removes one node and reads its
flash; a node holding the mesh key (any node, or a captured one before it is
revoked). Reviews F2, F17, F22, S1-S20, G1, G3, G4, G8, T1-T24 are addressed
here and in 11.8.

### 8.1 Requirements

| Req | Statement | Mechanism |
|---|---|---|
| R1 | Keys at rest MUST be protected so that reading a node's flash costs a lab attack, not a cable. | Field profile MUSTs and the provisioning sequence (12.1, 12.2); `pl_init` verifies them. Revocation (8.5) bounds what a successful lab attack yields. |
| R2 | A captured node MUST NOT allow derivation of other pairs' session keys, nor impersonation of another unit ID at the session or management layer. | Per-pair keys derived offline from `K_site`; a node holds only its own pairs (8.2). Mesh-layer identity (routes, flood budgets) rests on the shared mesh key and is a stated limitation (11.8). |
| R3 | Every frame an endpoint acts on MUST be authenticated and encrypted end to end, including its sequence position. | AES-128-CCM over the end-to-end header, the 48-bit index and the payload (8.3). |
| R4 | A forwarding node MUST NOT change any table because of a frame it has not authenticated as fresh. | `hop_tag` under `K_mesh` plus `hop_seq` freshness, checked before any state change (8.4, 11.4). |
| R5 | A frame MUST NOT be accepted twice, and a recorded frame MUST NOT be accepted later, within or across sessions, at endpoints or relays. | 48-bit session index; 32-bit `pre_ctr` for pre-session frames and RESUME; `hop_seq` per hop; persistent counters (3.5, 8.4). |
| R6 | Session authority MUST NOT be obtainable from the mesh key. | HELLO under `Ke_hello`, BIND/BIND_ACK/NAK under `Ke_hs`, session frames under directional keys, all derived from the pair key and the handshake transcript (8.2). |
| R7 | Keys MUST be rotatable and a node MUST be revocable without a site visit to every other node, including leaves. | Epochs with a three-epoch accept window, bundles pulled by each node through MGMT, revocation items (8.5). |
| R8 | Management (keys, time, diagnostics) MUST be authenticated between a node and its listed managers only. | `K_mgmt` from the pair key of node and manager; manager list in NVS (11.10). |
| R9 | The field profile MUST NOT run unauthenticated, and test keys MUST NOT work in the field. | `pl_init` refuses a field build without keys or without the at-rest state of R1; the provisioning tool refuses the Appendix A `K_site`; firmware rejects all-zero or repeated-byte keys and the hashes of `K_mesh(E)` for all 256 epochs of the test `K_site` (12.1). |
| R10 | A node MUST NOT answer a frame that fails any check. | Drop, count, rate-limited log; no CLOSE, NAK or error (no oracle). |

### 8.2 Keys

HKDF-SHA256 (RFC 5869) throughout; `||` is concatenation; integers
little-endian as on the wire; S = sender unit ID, P = probe unit ID in every
label.

| Key | Formula | Held by |
|---|---|---|
| `K_site` | 32 random bytes, generated and kept by the offline provisioning tool | nobody in the field |
| `K_mesh(E)` | `HKDF(IKM = K_site, salt = "ProbeLink-mesh", info = E u8, L = 32)`; hop_tag key | every node, up to three epochs |
| `Ke_mesh(E)` | `Expand(Extract(salt = "ProbeLink-v1", IKM = K_mesh(E)), "mesh-enc", 16)`; SEEK CCM key | derived locally from K_mesh(E) |
| `K_pair(A, B, E)` | `HKDF(K_site, "ProbeLink-pair", min(A,B) u16 \|\| max(A,B) u16 \|\| E u8, 32)` | A and B only |
| `PRK` | `Extract(salt = "ProbeLink-v1", IKM = K_pair(S, P, E))` | S, P |
| `T0`, `T` | `T0 = SHA-256(SEEK e2e header \|\| SEEK payload)`; `T = SHA-256(SEEK e2e header \|\| SEEK payload \|\| HELLO e2e header \|\| HELLO payload)` | S, P |
| `Ke_hello` | `Expand(PRK, "hello" \|\| S \|\| P \|\| T0, 16)` | S, P (derivable before HELLO arrives) |
| `Ke_hs` | `Expand(PRK, "hs" \|\| S \|\| P \|\| T, 16)` | S, P |
| `Ke_s2p`, `Ke_p2s` | `Expand(PRK, "s2p" \|\| S \|\| P \|\| session_id u8 \|\| T, 16)`, same with "p2s" | S, P |
| `K_mgmt(N, M, E)` | `Expand(Extract("ProbeLink-v1", K_pair(N, M, E)), "mgmt" \|\| N \|\| M, 16)` | node N and manager M |

- The transcript binds caps, `max_frame`, `key_epoch`, `proto_minor`, both
  nonces and both `pre_ctr` values into every key, so the two ends either
  agree on all of them or derive different keys and the handshake fails
  closed (reviews T11, T17). The persistent `pre_ctr` values make key
  uniqueness deterministic, not probabilistic.
- The manifest lists each node's peers (default: all nodes, 49 x 32 bytes per
  epoch at 50 nodes) and its managers. A probe answers only senders it holds
  a pair key for; a node accepts MGMT only from listed managers.
- A captured node yields its stored `K_mesh` epochs and its own pair keys:
  it can impersonate itself, forward, drop and misroute as a node, originate
  floods within the budgets, and act under other IDs at the mesh layer
  (11.8). It cannot derive any other `K_pair`, hence no other session or
  management key (R2). Recovery is revocation plus an epoch bump (8.5).
- Bench profile: a single `pl/net_key` MAY stand in for `K_site` on the
  device, with everything derived locally. Not permitted in the field.

### 8.3 One construction: AES-CCM end to end, HMAC per hop

Every frame's end-to-end part is protected by AES-128-CCM with an 8-byte tag
(mbedtls, hardware AES on all ESP32 variants); every frame's hop part by
HMAC-SHA256 truncated to 4 bytes. HMAC-SHA256 is also the HKDF primitive, so
two primitives cover everything (review G14 cut 5).

- Nonce (13 bytes): `dir u8 || src_id u16 || dst_id u16 || session_id u8 ||
  ctr_hi u32 || seq u16 || 0x00`. `dir` is 0 for sender -> probe and node ->
  manager, 1 for the reverse. `ctr_hi` is the ROC for session frames and the
  high 16 bits of `pre_ctr` (zero-extended) for session_id 0 frames; for
  RESUME it is the session ROC. Every (key, nonce) pair is unique because the
  index never repeats under a key (3.5).
- AAD: `e2e_header || ctr_hi u32`, where `e2e_header` is bytes 0..5 of the
  header plus `session_id`, `seq`, `len` (10 bytes).
- Encrypted frames: the payload field is the ciphertext, `auth_tag` the CCM
  tag.
- Plaintext frames (SEEK, RESUME): relays must read `pre_ctr` and the probe
  must read SEEK before it has a session key, so their payload is carried in
  clear and appended to the AAD; the CCM tag over zero-length plaintext is
  the `auth_tag`.
- Keys per type are in the section 5 table. SEEK uses `Ke_mesh(key_epoch)`:
  it carries no authority and must be verifiable by a probe that shares no
  pair key yet. RESUME uses `Ke_s2p` of the parked session; relays verify
  only its hop_tag.
- `hop_tag = HMAC-SHA256(K_mesh(E), frame[0 .. end of auth_tag])[0..3]`,
  recomputed by every transmitter (the hop fields change). The receiver tries
  its stored epochs and records which one verified for that neighbour (8.5).
  32 bits is enough: a forged hop_tag gains at most one table entry and the
  attempt rate is bounded by airtime.

### 8.4 Freshness and replay windows

- Session frames: per session and direction the receiver keeps the highest
  48-bit index and a 64-entry seen-bitmap below it; accept iff newer than the
  highest or within the window and unseen. Retransmitted DATA (same index,
  byte-identical ciphertext) is dropped as a duplicate by the ARQ layer before
  this check. Across sessions a new key makes old frames fail; within a
  session the ROC makes frames from a previous 16-bit cycle fail.
- Pre-session frames and RESUME: endpoints keep the last `pre_ctr` per
  (peer, key) and drop non-newer values; relays apply the ORIGIN rule (11.5)
  to floods. Because `pre_ctr` is persistent and 32 bits wide on the wire, a
  recording never becomes "newer" again (reviews G3, T10).
- Hop freshness: every neighbour keeps the 32-bit reconstruction of
  `hop_seq` per (unit_id, transport) and drops any frame not newer than it
  before learning or forwarding (11.4). A recorded unicast frame therefore
  cannot be re-admitted while the neighbour's entry lives (reviews G4, T1).
  Known limitation: after `LINK_TTL_MS` expiry one recorded frame can be
  re-admitted once, until the real neighbour next transmits.
- Cost: two HMACs plus one CCM per forwarded frame, tens of microseconds each
  on ESP32 hardware (estimate).

### 8.5 Epochs, rotation and revocation

- A node stores up to three epochs of `K_mesh` and of its pair keys (`E-1`,
  `E`, `E+1`; NVS `pl/epoch`, `pl/mesh_key/<E>`, `pl/pair/<id>/<E>`) and
  accepts hop_tags and SEEKs under any stored epoch. The link table records,
  per neighbour, the newest epoch that verified. Unicast to a neighbour uses
  that epoch; floods use the oldest epoch any live neighbour still uses. The
  node's own `key_epoch` in SEEK is its newest epoch that at least one
  neighbour has been heard under, or its newest if none (reviews G1, T3).
- Bundles: the offline tool generates, per node and per epoch, a bundle of
  TLVs (8.3 of 11.10: `K_mesh(E+1)`, the node's pair keys for E+1,
  revocations) encrypted under that node's `K_mgmt(N, M, E)`. The gateway
  stores and relays opaque bundles and holds no other node's keys (review
  G8, T8). Each node pulls its bundle in MGMT_RESP chunks when its MGMT_REQ
  reports an older epoch; leaves do this on wake (4.4). There is no push and
  no activation message.
- Retiring: when a node holds `E+1` it erases `E-2`; `E-1` is erased when every
  live neighbour has been heard under `E` or newer, or after
  `KEY_RETIRE_S` (7 days). Operational rule, enforced by the tool: no bundle
  for `E+2` is issued while any non-revoked node's last MGMT report shows an
  epoch below `E`. This keeps every pair of communicating nodes within the
  three-epoch window without any synchronized switch.
- Revocation: a bundle marked REVOKE lists the revoked unit IDs; receiving
  nodes delete those pair keys at once and treat the bundle's `E+1` as a
  revocation epoch: they erase `E` as soon as all live neighbours have been
  heard under `E+1`, or after `KEY_REVOKE_GRACE_S` (24 h). The revoked node
  never receives `E+1` because its pair key with the manager is deleted
  first. Residual window: the revoked node keeps mesh-layer (not session)
  access for at most the grace period plus the time to reach every node.
- Adding a node: the tool issues one TLV with the new pair key to each of its
  peers in their next bundle.
- A node more than two epochs behind is re-provisioned over its UART by the
  provisioning station acting as a manager with the device's recovery key
  (12.2); "cable" in this document means exactly that.

---

## 9. Constants and budgets

Radio defaults; `hops` is the route hop count (1 on a direct link); the IR
edge link multiplies handshake timers by `IR_TIME_SCALE` on both ends.

| Name | Default | Note |
|---|---|---|
| HELLO_WINDOW_MS | 50 | probe random delay range |
| HELLO_CANDIDATES / PROBE_OFFERS_MAX | 4 / 4 | fallback probes kept / OFFERED entries per probe (one per src_id) |
| BIND_RETRY_MS / BIND_RETRIES | 50 / 3 | `BIND_RETRY(hops) = max(50, hops x HOP_DELAY_MS)` |
| BIND_TIMEOUT | formula 4.1.10 | 470 ms direct, 1730 ms at 4 hops |
| SEEK_BASE_MS | 50 + 2 x seek_ttl x 60 | 530 ms at ttl 4 |
| SEEK_TIMEOUT(n) | SEEK_BASE_MS + rand(0, min(60000, 600 x 2^n)) | never gives up |
| BOOT_SPREAD_MS | 600 x pl/node_count | first SEEK after a cold boot |
| RESEEK_JITTER_MS / PENALTY_MS | 1000 / 60000 | |
| MODE_RETRY_MS | 100 | |
| keepalive_ms | 5000 (1000..60000) | MODE field; SESSION_TIMEOUT = max(4 x keepalive_ms, 8 x SRTT) |
| ACK_EVERY | 8 frames | |
| FEC_K / FEC_M / FEC_FLUSH_MS | 8 / 2 / 100 | |
| ARQ_WINDOW / ARQ_RTO_MS / ARQ_MAX_RETRIES | 24 (4 on leaves) / 100 / 3 | RTO = max(100, 2 x SRTT) |
| REORDER_MS / REPLAY_WINDOW | 500 (x 4 SRTT) / 64 | |
| RX_QUEUE_FRAMES / RELAY_QUEUE_FRAMES | 16 / 8 | |
| PL_MAX_GROUPS / PL_MAX_SESSIONS / PL_MAX_STREAMS | 8 / 32 / 4 | |
| PARK_GRACE_S / MGMT_EVERY_WAKES | 60 / 10 | |
| MGMT_PERIOD_S / TIME_MAX_SLEW_PPM | 600 / 500 | |
| KEY_RETIRE_S / KEY_REVOKE_GRACE_S | 604800 / 86400 | |
| seek_ttl / MAX_HOPS / MIN_PATH_MTU | manifest (site diameter + 1, default 4) / 8 / 48 | |
| HOP_DELAY_MS / RELAY_JITTER_MS / FLOOD_REPEAT | 60 / 50 / 2 | |
| DEDUP_ENTRIES / DEDUP_TTL_MS | 64 / 5000 | |
| ORIGIN_ENTRIES / ORIGIN_TTL_S / ORIGIN_MAX_JUMP | 64 / 3600 / 2^20 | |
| ROUTE_ENTRIES / ROUTE_TTL_MS | 64 / 1200000 | 20 min, refreshed by any traffic |
| LINK_ENTRIES / LINK_TTL_MS | 32 / 60000 | |
| FLOOD_BUCKET_ORIGIN / FLOOD_BUCKET_TOTAL / FLOOD_BUCKETS | depth 6, 2/s / depth 20, 10/s / 64 | |
| IR_TIME_SCALE / IR_GUARD_MS / NRF_GUARD_MS | 10 / 20 / 2 | |
| VBAT_MIN | board-specific | leaf wake gate (4.4) |

Airtime budget at 1 Mbps ESP-NOW (estimates; a small unicast frame costs
about 1.5 ms of air per hop including preamble, 802.11 ACK and backoff; a
flood costs about `node_count x FLOOD_REPEAT x 1.1 ms`):

| Traffic | Per unit | 40 sessions, 2 hops, 50 nodes |
|---|---|---|
| Keepalive (ACK + PING) at 5 s | 2 x 1.5 ms x hops per keepalive | 0.6 % |
| DATA at 1 frame/s per session | 1.5 ms x hops per frame | 12 % |
| MGMT every 600 s per node | 2 x 1.5 ms x hops | 0.05 % |
| Floods (SEEK, RESUME, lost-route MGMT) | about 110 ms each | 20 leaves at one wake per 5 min: 0.7 % |

Rule: keepalive plus management traffic at the funnel node SHOULD stay under
10 % of airtime; data rate and `fec_m` are then chosen against the remainder.

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

Why not just PJON: it covers four carriers and gives IDs, CRC and ACK, but
none of forward error correction, the seek-a-group / first-acknowledger
handshake, forwarding, authentication or HIGH/LOW sample typing. Its
light-sampling code is a reasonable starting point for the IR PHY.

RS libraries for ESP32: Arduino-FEC (github.com/simonyipeter/Arduino-FEC),
libcorrect (C, decode-with-erasures), Schifra (C++ templates). A minimal
GF(2^8) encoder plus erasure decoder is about 300 lines of C.

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
| Gateway | 1 | mains | Bridge with a LAN side (12.4); manager: time source, bundle relay, report sink (11.10) |
| Leaf | 0 | battery | Sender only, parks sessions (4.4), forwards nothing, serves nothing |

Routes never pass through a leaf: routes are installed from the `prev_hop`
of transmitted frames and a leaf transmits only frames it originates.
"Relay" below means any non-leaf node in its forwarding role. A permanent-RX
node draws 80-100 mA (estimate): solar relays need a panel of at least
`daily Wh / (peak sun hours x 0.7)` (about 8 Wh/day) and three days of
battery, a low-voltage gate with hysteresis before WiFi start, and report
`vbat_mv` in MGMT section 0.

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
- `hop_seq`: per-transmission freshness (3.5, 8.4).
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
250, or 242 through a UART hop; the only smaller link, IR, is an edge and
never part of a path. Forwarders still check fit (`header + len + 12 + 2 <=
max_frame - rs_nsym`) and count `relay_drop_mtu`. Failover is a new SEEK and a
new MODE, so a smaller path is caught by MODE_ACK status 2.

Fragmentation at the mesh layer was rejected: it needs per-relay reassembly
state, fragments cannot be tag-verified alone, any lost fragment loses the
frame, and FEC groups are defined over whole frames. The nRF24 32-byte packet
is segmented inside its adapter only, with one reassembly buffer per frame in
flight and whole-frame drop on any missing segment (C.5).

### 11.4 Routing: AODV-lite on SEEK and HELLO

Route entry: `{dst_id u16, next_hop u16, transport u8, hops u8, cost u8,
expiry u32}`, `ROUTE_ENTRIES` 64, `ROUTE_TTL_MS` 20 minutes refreshed by any
admitted traffic to or from `dst_id` (review G2: routes are cheap to keep and
failures are detected end to end).

| Event (frame already admitted, step 5) | Route action |
|---|---|
| Flood (SEEK, RESUME, flooded MGMT_REQ) from `prev_hop` on T | Reverse route to `src_id` via `prev_hop`, `hops + 1`, `cost = path_cost + link cost`; inside the node's jitter window a lower-cost copy replaces it; afterwards only a fresher flood (newer `pre_ctr`) does |
| Unicast HELLO from `prev_hop` | Forward route to `src_id` (the probe) via `prev_hop` with the HELLO's cost; replaces an existing entry |
| Any other admitted frame that is for me or that I forward (not overheard) | Installs a route to `src_id` via `prev_hop` if none exists (this is how RESUME_ACK, BIND_ACK and MGMT_RESP install forward routes, review G6); refreshes expiry of the routes to `src_id` and `dst_id`; never changes an existing `next_hop` |

Pipeline run by every node on every received frame, in order; one counter
per drop. Nothing after step 5 runs for a frame that fails step 5.

| Step | Condition | Action |
|---|---|---|
| 1 | per-hop decode fails (COBS, RS, nRF24 reassembly, CRC) | drop, `crc_fail` / `rs_fail` / `seg_fail` |
| 2 | 3.6 length / header / SEEK hop-field checks fail | drop, `bad_frame` |
| 3 | version unknown and the frozen prefix does not parse | drop, `bad_version` (an unknown version with a valid prefix is forwarded, never delivered locally) |
| 4 | field profile and FLAG_AUTH clear, or AUTH set and `len` leaves no room for the tags | drop, `auth_fail` |
| 5 | hop_tag fails under every stored epoch, or `hop_seq` not newer than the link table's value for (prev_hop, transport) | drop, `hop_tag_fail` / `hop_replay`; nothing learned, nothing replied |
| 6 | admitted | learn or refresh link: (prev_hop, transport) -> address, hop_seq, epoch (11.9) |
| 7 | unicast with `dst_id` = me or a group of mine, and `next_hop` = me | deliver to the endpoint logic (CCM tag, pre_ctr / index windows); install route per the table above; stop |
| 8 | unicast, `next_hop` != me | overheard: drop silently, no route or table change |
| 9a | flood, `src_id` = me | echo of my own flood: drop silently, no alarm (11.5) |
| 9b | flood, `(src_id, pre_ctr)` in dedup | duplicate: update the entry's best cost and reverse route if this copy is cheaper (inside the jitter window); drop, `relay_drop_dedup` |
| 9c | flood, `pre_ctr` older than ORIGIN `last_ctr`, or more than `ORIGIN_MAX_JUMP` ahead of it | drop, `relay_drop_stale` |
| 9d | flood, per-origin or total bucket empty (11.5) | drop, `relay_drop_rate` |
| 9e | flood, otherwise | insert dedup and ORIGIN; install reverse route; deliver locally if `dst_id` is me or a group of mine; if `dst_id` = me (unicast destination), or node is a leaf, or `ttl <= 1`, or the frame arrived on an `edge_only` transport: stop (`relay_drop_ttl` for the ttl case) |
| 9f | flood, forwarding | after `rand(0..RELAY_JITTER_MS)` take the lowest-cost copy seen; ttl - 1, hops + 1, prev_hop = me, new hop_seq, path_mtu lowered, path_cost += that copy's link cost; recompute hop_tag and CRC; send on every transport except `edge_only` ones and the point-to-point one it arrived on, `FLOOD_REPEAT` copies where the carrier has no broadcast retry |
| 10a | unicast, no route to `dst_id`, or node is a leaf, or the frame arrived on an `edge_only` transport | drop, `relay_drop_noroute` (no RERR: a relay cannot verify the frame and is not an endpoint) |
| 10b | unicast, `route.next_hop == prev_hop` | drop, `relay_drop_loop` |
| 10c | unicast, `ttl <= 1`, or does not fit the outgoing link, or outgoing transport is `edge_only` | drop, `relay_drop_ttl` / `relay_drop_mtu` |
| 10d | unicast, forwarding queue full | class-aware drop (section 7) |
| 10e | unicast, otherwise | ttl - 1, hops + 1, prev_hop = me, next_hop = route.next_hop, new hop_seq; recompute hop_tag under the epoch last verified from next_hop, CRC; per-hop encode; send; install/refresh routes per the table; `relay_fwd` |

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
  `PL_EVT_ID_COLLISION` (one rule, review G26).
- Dedup: `DEDUP_ENTRIES` (64) x `(src_id, pre_ctr, timestamp, best_cost,
  pending copy)`, FIFO, `DEDUP_TTL_MS` 5 s. Sized so an entry outlives its TTL
  under full load (10 floods/s x 5 s = 50 < 64). `FLOOD_REPEAT` copies share
  one `pre_ctr` and are dropped after the first; they exist to survive a
  broadcast collision.
- ORIGIN: 64 x `(src_id, last_ctr u32, timestamp)`, `ORIGIN_TTL_S` 1 h. A
  flood is dropped if its `pre_ctr` is older than `last_ctr` or more than
  `ORIGIN_MAX_JUMP` (2^20) ahead of it; the bound is sized for the gateway,
  which originates thousands of unicast pre-session frames (MGMT_RESP, HELLO,
  BIND_ACK) between floods. Entries are checked after dedup, so equal copies
  reach 9b and can improve the route (reviews G5, T21). After expiry one
  recorded flood is forwarded once, costs one token, and can start no session
  (its keys are stale); this is accepted.
- Budget: token buckets after the freshness checks. Per origin depth 6,
  refill 2/s, 64 buckets hashed by `src_id`; per node depth 20, refill 10/s.
  A handshake is one SEEK flood (BIND is unicast), a wake one RESUME, a
  routeless report one MGMT_REQ.
- Jitter: `rand(0..RELAY_JITTER_MS)` before rebroadcast, keeping the
  lowest-cost copy; copies arriving during the wait improve the route and
  the forwarded copy. One pending frame buffer per flood in its jitter window
  (`FLOOD_PENDING` 4).
- TTL: `seek_ttl` from the manifest (site diameter + 1, default 4),
  `MAX_HOPS` 8. Counter-based suppression is gone (review F8/G8): the
  budgets bound flood load and suppression creates coverage holes.

### 11.6 Route lifetime

`ROUTE_TTL_MS` is 20 minutes, refreshed by any admitted frame to or from the
destination. Live sessions refresh continuously; sessions with
`keepalive_ms` up to 60 s refresh many times per TTL; MGMT traffic every 10
minutes keeps node-to-gateway routes alive, so the gateway's reports and
bundles rarely need a flood. A dead route is harmless until used: the sender
detects failure end to end (`SESSION_TIMEOUT`), re-SEEKs, and the new flood
and HELLO overwrite routes on the new path; stale entries elsewhere expire.
Loss of a relay is not signalled (no RERR). Full table: evict the earliest
expiry (`route_evictions`). 64 entries hold the two routes of 32 sessions.

### 11.7 Timers across hops

Handshake timers use hop counts (no RTT yet): `SEEK_BASE_MS`, `BIND_RETRY`
and `BIND_TIMEOUT` in 4.1.8-10, `HOP_DELAY_MS` 60 covering jitter plus
airtime. Session timers use measured RTT (section 7). The IR edge link
scales handshake timers by `IR_TIME_SCALE` on both ends; nothing else in the
mesh knows about IR.

### 11.8 Security in a mesh

| Attacker | Can | Cannot (mechanism) |
|---|---|---|
| Outsider (no key) | Jam; cost each node one HMAC per received frame | Enter any table, consume a budget, be forwarded, or trigger an alarm (hop_tag + hop_seq before any state, R4/R5); forge, alter or replay session or management frames (R3, R5) |
| Node holding K_mesh (any node, or a captured one before revocation) | Originate floods within the budgets; forward, drop, delay or misroute frames through it; at the mesh layer act under another unit ID: install routes toward itself, advance that ID's ORIGIN counter by up to ORIGIN_MAX_JUMP, spend that ID's flood budget | Derive any pair key it was not given, hence read, forge or alter any session or management exchange it is not party to, or impersonate another ID to that ID's peers (R2, R6, R8); raise `path_mtu` or ttl (3.6); push time or keys (K_mgmt) |
| Revoked node | The row above for at most `KEY_REVOKE_GRACE_S` plus reach time | Receive the new epoch |

Known limitation (reviews T6, G3 item 5): mesh-layer identity for route
installation and flood budgets rests on the shared mesh key. A compromised
node can misdirect routes until it is revoked; the penalty list (4.2) and the
MGMT link statistics (11.10) make the misbehaving first hop visible. Removing
this needs per-node signatures on SEEK and HELLO (12.8). Unkeyed relays cannot
exist in the field profile: without `K_mesh` nothing a node sends is admitted.

### 11.9 Tables and RAM

Link table: keyed `(unit_id, transport)`, entry `{address[6], hop_seq_hi
u16, hop_seq u16, epoch u8, rssi_ewma i8, expiry}`, `LINK_ENTRIES` 32,
`LINK_TTL_MS` 60 s. An entry referenced by a live route is never evicted. A
frame from a new address with a newer `hop_seq` replaces the address (node
swapped, DHCP renewed); the alarm fires only on `prev_hop` = own ID.

| Table | Entry | Count | Bytes |
|---|---|---|---|
| Route table | 12 | 64 | 768 |
| Dedup cache (+ pending copy pointers) | 12 | 64 | 768 |
| ORIGIN | 12 | 64 | 768 |
| Link table | 16 | 32 | 512 |
| Flood buckets | 8 | 64 | 512 |
| Pending flood copies | 250 | 4 | 1000 |
| Forwarding queue | 250 | 8 | 2000 |
| nRF24 reassembly (if present) | 258 | 4 | 1032 |
| HMAC / CCM contexts, preallocated | | | ~600 |
| Total, ESP-NOW node | | | ~6.9 KB (8 KB with nRF24) |

Minimum a conforming non-leaf node MUST provide: half of each count above.
Leaves keep a 2-entry route table, an 8-entry dedup cache and no queues
(about 200 bytes). Pair keys: 32 bytes per peer per stored epoch in NVS
(about 4.7 KB for 49 peers x 3 epochs).

### 11.10 Management (MGMT_REQ / MGMT_RESP)

One request/response pair, between a node and a manager from its NVS list
`pl/managers` (the gateway; the provisioning station over UART; a phone over
BLE in maintenance mode), encrypted under `K_mgmt(N, M, E)`. It replaces the
v0.4 DIAG, TIME and KEY_UPDATE frames and works for leaves because the node
always initiates (review G10, T5). A node sends MGMT_REQ every
`MGMT_PERIOD_S` (600 s), after boot, after a key epoch change, and (leaves)
every `MGMT_EVERY_WAKES` wakes.

```
MGMT_REQ   pre_ctr u32, t1 u64 (requester clock, us), key_epoch u8 (newest held),
           flags u8 (bit0 want_keys, bit1 more_follows), section u8, page u8, section bytes
MGMT_RESP  pre_ctr u32, t1 u64 (echo), t2 u64, t3 u64 (manager UTC rx/tx, us),
           flags u8 (bit0 TLVs present, bit1 more chunks pending),
           TLVs: type u8, len u8, value (may span responses; the node ACKs a chunk by its next MGMT_REQ)
```

Sections of the report, one per request, rotated by the node (review G17):
0 identity and health (`mac[6]`, unit_id, proto version and minor, fw_build,
key_epoch, role, power_src, vbat_mv, uptime_s, reset_reason, reset_count from
the RTC reset log, min_free_heap, stack_hwm, secure-state bits: secure boot,
flash encryption release, NVS encrypted; 34 bytes); 1 counters (`pl_stats_t`
as 4-byte values); 2 links (page of `{unit_id, transport, rssi_ewma, rx,
crc_fail}`); 3 routes (page of `{dst, next_hop, hops, cost}`). Pages are sized
to the path MTU.

TLVs in MGMT_RESP: 0x01 `K_mesh(E+1)` (epoch u8 + 32 bytes); 0x02 pair key
(unit_id u16, epoch u8, 32 bytes); 0x03 revoke (unit_id u16, flags u8 bit0
revocation epoch); 0x04 command (u8: 1 enter maintenance mode, 2 reboot, 3
accept BULK from manager). A bundle with `more` set keeps the node awake and
requesting until it is complete. Time: the requester computes offset and
round trip from t1..t4 as NTP does (6.5). A manager answers at most one
request per second per node and never answers an unverified one.

### 11.11 Carrier notes for mesh links

- ESP-NOW: unicast to the link table's MAC (MAC retries), broadcast for
  floods. 20 peers maximum: keep an LRU peer table of 16 plus broadcast; when
  all 16 are referenced by live routes evict the LRU anyway and re-add on the
  next send (add/del is cheap). Fixed channel, `WIFI_PS_NONE`, no STA, no BT
  while the mesh is up.
- nRF24L01+: unicast to the `next_hop` address derived from its unit ID with
  ESB auto-ACK; floods on the broadcast address with NO_ACK; per-hop
  segmentation (C.5). Fixed link cost 2.
- UART: point to point; a flood is never sent back on the transport it
  arrived on. `prev_hop` / `next_hop` are still carried so the format is
  uniform.
- WiFi UDP: LAN side of the gateway only; multicast for floods, unicast
  otherwise; peer list on isolated LANs (C.4).
- IR: `edge_only`. The IR leaf and its attached node form a two-node link;
  frames never cross between IR and any other transport (steps 9f, 10a, 10c).
  The attached node is the probe for its IR leaves and republishes their data
  as its own sender session if the site needs it elsewhere (application
  level, not protocol).

---

## 12. Deployment profile and decisions

Each item is a decision with its alternative so it can be flipped. Items
marked USER-DECIDED were set by the user in round 2.

### 12.1 Bench vs field profile

| | Bench | Field (default) |
|---|---|---|
| Keys | optional; `pl/net_key` MAY derive everything locally | MUST: pair keys and `K_mesh` from the offline `K_site` (8.2) |
| FLAG_AUTH | optional | MUST on every frame |
| At rest | development build | MUST: Secure Boot v2, flash encryption release mode, NVS encryption, JTAG and UART download disabled by eFuse; `pl_init` returns `PL_ERR_AUTH` unless `esp_secure_boot_enabled()`, `esp_get_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE` and the key partition is encrypted (review T9) |
| Chips | any | ESP32-C3, -S3, -C6 (HMAC-based NVS encryption); original ESP32 only at silicon revision 3.0 or later (review T20). R1 raises the cost of extraction; published fault-injection work shows it is not absolute, so revocation (8.5) is the control that bounds a captured node |
| Signing | any key | separate Secure Boot signing keys for bench and field images; a field image refuses to start without production eFuses and a bench image refuses to start with them (review T19) |
| Test keys | allowed | the tool refuses the Appendix A `K_site`; firmware rejects all-zero or repeated-byte keys and the 8-byte hash prefixes of `K_mesh(E)` for all 256 epochs of the test `K_site` (2 KB table) |
| Replies to unverified frames | CLOSE(2) allowed | never |
| Logging | anything | no key, nonce or tag bytes at any level |

### 12.2 Provisioning (decision)

A provisioning station (host script plus a UART cable) runs, per board and
in this order: read the base MAC and chip revision (refuse unsupported);
burn and verify the Secure Boot v2 digest and the JTAG / download-mode
eFuses; flash the signed bootloader and app; enable flash encryption in
release mode and wait for the first-boot encryption to finish on a stable
supply; provision the NVS encryption key (eFuse HMAC key on C3/S3/C6);
write the per-device encrypted NVS image generated from the manifest row
(`unit_id`, `unit_mac`, `role`, `groups`, `managers`, `channel`,
`nrf_channel`, `seek_ttl`, `node_count`, `epoch`, `mesh_key` x up to 3,
pair keys, `recovery_key`); verify by reading the node's MGMT section 0 over
the UART. Dry-run on two sacrificial boards; store the eFuse summary per MAC
in the manifest (reviews G24, T9). Later re-provisioning uses the same
station as a manager with the device's `recovery_key` (a pair key between
the device and the station's reserved unit ID 0x0002): that is the only
meaning of "cable" in the field profile (review G11).

### 12.3 Control-frame recovery (decision)

Repetition (`FLOOD_REPEAT` 2) and handshake retries satisfy "recovery data in
every packet" for control frames. Alternative: in-frame RS on control frames
on PACKET links, 4-8 bytes per frame against a failure mode (whole lost
frame) it cannot fix. Not chosen.

### 12.4 Radio channel, WiFi STA and co-located radios (decision)

All ESP-NOW nodes use one dedicated channel from the manifest, `WIFI_PS_NONE`,
never STA. The gateway is two chips joined by UART: the mesh chip, and a LAN
chip that SHOULD use Ethernet (W5500 over SPI, or LAN8720 on an ESP32). If
the LAN chip must use WiFi STA: external antennas at least 30 cm apart and
the mesh channel at least 5 channels from the AP channel, both written in the
manifest (review G12). WiFi UDP nodes live on the LAN side only. nRF24
sites: mesh channel 1-6, nRF channel 76-81, antennas separated or
cross-polarised, and a bridge never starts a transmission on one radio while
the other is mid-reception of a multi-segment frame. Commissioning test:
compare `crc_fail` / `seg_fail` / `rx_frames` at the gateway and bridges
with the co-located radio idle and loaded. Alternative not chosen:
channel-follow of the AP (leaves the mesh deaf during sweeps and fails
silently when the AP retunes).

### 12.5 BLE: phone link only (USER-DECIDED)

BLE never carries mesh traffic and is not a carrier. It is a commissioning
and diagnostics link to a phone, active only in maintenance mode while the
mesh radio is stopped (6.4). This removes the BLE/WiFi coexistence and
power-save conflict (review G13), the BLE bridge role and the 61-byte path
MTU. Alternative (v0.4): BLE as an optional carrier on a separate chip over
UART; not needed once BLE sensors are out of scope.

### 12.6 IR: one-hop edge only (USER-DECIDED)

IR connects a leaf to exactly one mesh node and is never forwarded. The
attached node terminates the session. This removes IR from every mesh
budget: no `time_scale` on mesh timers, no `path_mtu <= 58` heuristic, no
29-byte MODE limit on the mesh path (reviews G21, G16, G17). IR stays
indoor/shaded until its bit cell is validated on hardware (C.1). Alternative
(v0.4): IR as a mesh hop with scaled timers; rejected by the user.

### 12.7 Firmware update (decision, review G11)

In-mesh, minimal: the update server (the gateway's LAN chip, through the mesh
chip) SEEKs the node by unit ID, BINDs, and sends MODE mode 2 (BULK:
`bulk_size`, `sha256`, `fw_build`) with `arq` 1 and `fec_m` 0, then DATA
frames whose `t_first_us` is the byte offset; the node writes with
`esp_ota_write`, verifies the SHA-256 at CLOSE reason 7, lets Secure Boot
verify the signature at reboot, and marks the image valid
(`esp_ota_mark_app_valid_cancel_rollback`) only after it has verified a
neighbour's hop_tag and received one MGMT_RESP within 10 minutes of boot
(leaves: before their first park). Any final ARQ gap aborts the image. A 1 MB
image at 20-50 kbit/s over 2-3 hops takes 3-7 minutes per node (estimate).
Nodes accept BULK only from a listed manager (MGMT command 3 arms it).
Version transition: endpoints accept N and N-1 during a rollout; forwarders
forward any version with the frozen prefix. Alternative (v0.4): a
maintenance-WiFi window with `esp_https_ota`; rejected because meshed nodes
are the ones without WiFi coverage.

### 12.8 Key architecture (decision)

Pairwise symmetric keys from an offline site key, three-epoch acceptance,
pulled bundles, revocation (8.2, 8.5). Alternative: per-node X25519/Ed25519
identities with site-signed certificates: closes the mesh-layer identity
limitation (11.8) and removes per-peer key lists, at tens of ms of software
crypto per handshake (estimate) and a larger SEEK/HELLO. Not chosen for v0.5;
the SEEK/HELLO payloads have room for a 32-byte public key later.

### 12.9 Leaf model (decision)

Sender-only leaves that park and resume sessions and pull management on wake
(4.4). Alternatives: a sessionless REPORT frame (bypasses the seek/bind
handshake and MODE); a parent relay that buffers for the leaf (relays would
hold session state). Not chosen.

### 12.10 Cut list applied in v0.5 and known limitations

Cut (review G14): BLE carrier; IR as a mesh hop; ESP-NOW v2, FLAG_LEN16 and
UDP above 255 (one `max_frame` of 250); PL_SELECT_BEST; the HMAC-or-CCM dual
path (CCM end to end, HMAC per hop only); time stratum chaining (listed
managers only); KEY_UPDATE activation modes (three-epoch window instead);
in-frame RS on PACKET links; flooded BIND; counter-based suppression; DIAG,
TIME and KEY_UPDATE as separate types (one MGMT pair).

Known limitations, deliberate: mesh-layer identity rests on `K_mesh` (11.8);
one recorded unicast frame can be re-admitted at a relay after `LINK_TTL_MS`
until the real neighbour transmits (8.4); epoch pacing is an operational rule
of the tool, not a protocol mechanism (8.5); a revoked node keeps mesh-layer
access for up to the grace period (8.5); OFFERED denial is bounded to one
entry per `src_id`, not eliminated (4.1.2); IR outdoors and the IR bit cell
are unvalidated (C.1); R1 is a cost, not a guarantee, on some silicon (12.1);
no TRACE frame (route tables in MGMT section 3 give the path in two
reports); FEC/ARQ parameters are not auto-tuned to measured loss.

---

## Appendix A. Test vectors

Computed by `vectors_v05.py` (Python `hmac`/`hashlib` for HKDF and HMAC,
`cryptography` for AES-CCM, `reedsolo` cross-check for RS). Hex is wire
order. Key material is TEST ONLY and refused by field builds (12.1).

A.1 CRC-16/CCITT-FALSE: `"123456789"` -> 0x29B1

A.2 SEEK on ESP-NOW, bench profile (no tags)

```
src 0x1234, dst 0xFF01, prev 0x1234, next 0xFFFF, ttl 4 / hops 0, hop_seq 1, path_mtu 250, path_cost 0,
session 0, seq 1; payload: pre_ctr 1, nonce_s 0xA1B2C3D4, caps 0x0033 (HIGH|LOW|FEC|RELAY), max_frame 250,
key_epoch 0, proto_minor 0, fw_build 1
10 01 34 12 01 ff 34 12 ff ff 40 01 00 fa 00 00 00 01 00 12
01 00 00 00 d4 c3 b2 a1 33 00 fa 00 00 00 01 00 00 00  98 74        40 bytes, CRC16 = 0x7498
```

A.3 Same SEEK on UART: path_mtu 242, RS nsym 8, then COBS

```
frame (40): 10 01 34 12 01 ff 34 12 ff ff 40 01 00 f2 00 00 00 01 00 12
            01 00 00 00 d4 c3 b2 a1 33 00 fa 00 00 00 01 00 00 00 7a 79    CRC16 = 0x797A
RS parity:  3d f9 11 80 4d f4 a4 c9
COBS wire (50): 0d 10 01 34 12 01 ff 34 12 ff ff 40 01 02 f2 01 01 02 01 03 12 01 01 01 06 d4 c3 b2 a1
                33 02 fa 01 01 02 01 01 01 0b 7a 79 3d f9 11 80 4d f4 a4 c9 00
```

A.4 RS standalone: RS(6) of "ProbeLink" = 28 76 02 56 91 f1; RS(1) of 12 34 56 78 9a = 92 (= XOR)

A.5 Cross-frame FEC (unchanged since v0.2): k 2 / m 1 blocks `03 01 02 03 00`, `04 10 20 30 40`
-> parity `07 11 22 33 40`; k 4 / m 2 blocks `02 aa bb 00`, `03 11 22 33`, `01 ff 00 00`,
`03 01 02 03` -> parity `2d 01 2d 19`, `2e 44 b6 29`; erasing blocks 1 and 3 and decoding with
erasure positions {1, 3} reproduces them.

A.6 Keys (K_site TEST ONLY = bytes 0x00..0x1F; S 0x1234, P 0x0042, relay R 0x0099, manager M 0x0001)

```
K_mesh(1)  = 15e0339cd6e0d2252a7ba30c238e504c70c651eb217736caca7e54c1720c31c3
K_mesh(0)  = bbc1234f0bec88b75f0183243a63823dd512cff64fce168c0586601c263ebf4b
Ke_mesh(1) = cf6945811a150c490d9b97523507296f
K_pair(0042, 1234, 1) = 1427086608cb09c6cc10fa2d6ea68ddd3de5a73fbd9a0c10e7754a1a1bf31af5
PRK = Extract("ProbeLink-v1", K_pair) = 4a0e7d437c9d90f9dd777e602767a34b2049542478e05a938e39ecfbd571749f
```

A.7 DATA on a direct link (Ke_s2p from A.9), session 7, seq 5, ROC 0, one float32 1.5 at t = 1000 us

```
header: 12 10 34 12 42 00 34 12 42 00 30 09 00 07 05 00 0b   (prev = src, next = dst, ttl 3 / hops 0, hop_seq 9)
plaintext  = 01 00 e8 03 00 00 01 00 00 c0 3f
nonce      = 00 34 12 42 00 07 00 00 00 00 05 00 00     (dir 0, src, dst, sess, ROC 0, seq 5, 0)
AAD        = 12 10 34 12 42 00 07 05 00 0b 00 00 00 00  (e2e header || ROC)
ciphertext = f1 07 5e e6 5c 87 6e df ed 4b 4a ; ccm_tag = e1 0f 1d 3a 37 7a 77 21
hop_tag    = HMAC(K_mesh(1), frame[0..37])[0..3] = 60 dc 75 05
frame (42): 12 10 34 12 42 00 34 12 42 00 30 09 00 07 05 00 0b f1 07 5e e6 5c 87 6e df ed 4b 4a
            e1 0f 1d 3a 37 7a 77 21 60 dc 75 05 bd 06                                CRC16 = 0x06BD
```

A.8 Two hops: the A.7 frame via R, and a keyed SEEK flood

```
DATA hop 1 (S -> R): prev 0x1234, next 0x0099, ttl 4 / hops 0, hop_seq 9; ciphertext and ccm_tag as A.7
12 10 34 12 42 00 34 12 99 00 40 09 00 07 05 00 0b f1 07 5e e6 5c 87 6e df ed 4b 4a
e1 0f 1d 3a 37 7a 77 21 c2 1b 55 ad 97 f5                                            CRC16 = 0xF597
DATA hop 2 (R -> P): prev 0x0099, next 0x0042, ttl 3 / hops 1, hop_seq 0x0131
12 10 34 12 42 00 99 00 42 00 31 31 01 07 05 00 0b f1 07 5e e6 5c 87 6e df ed 4b 4a
e1 0f 1d 3a 37 7a 77 21 52 e9 90 58 ec 60                                            CRC16 = 0x60EC
Same hop 2 if R still transmits under epoch 0 (accepted by P, which stores E-1):
hop_tag 33 7e f2 b4, CRC16 = 0xE3C9

SEEK, field profile, pre_ctr 0x00010001 (header seq 0x0001), caps 0x003B (HIGH|LOW|AUTH|FEC|RELAY),
key_epoch 1: payload in clear, CCM tag over AAD = e2e header || pre_hi (1) || payload under Ke_mesh(1)
nonce = 00 34 12 01 ff 00 01 00 00 00 01 00 00 ; ccm_tag = 89 e7 25 07 07 1f d7 16
hop 1 (S, hop_seq 7, path_mtu 250, cost 0) (52):
12 01 34 12 01 ff 34 12 ff ff 40 07 00 fa 00 00 00 01 00 12 01 00 01 00 d4 c3 b2 a1 3b 00 fa 00 01 00
01 00 00 00 89 e7 25 07 07 1f d7 16 c9 b4 32 10 f3 f4                                CRC16 = 0xF4F3
hop 2 (R, hop_seq 0x0130, ttl 3 / hops 1, path_mtu 250, cost 1) (52):
12 01 34 12 01 ff 99 00 ff ff 31 30 01 fa 00 01 00 01 00 12 01 00 01 00 d4 c3 b2 a1 3b 00 fa 00 01 00
01 00 00 00 89 e7 25 07 07 1f d7 16 3f a3 04 36 37 c4                                CRC16 = 0xC437
```

A.9 Handshake keys, HELLO and BIND

```
T0 = SHA-256(SEEK e2e header || SEEK payload) = 87e4b0aba23b9b44a3cd96a5821c90a50bff4ba265353095e969132881f53f99
Ke_hello = Expand(PRK, "hello" || 34 12 || 42 00 || T0, 16) = 9239b60dae4214844f7a69dab1213e95
HELLO (P -> S via R): header 12 02 42 00 34 12 42 00 99 00 40 03 00 00 07 00 18, pre_ctr 7
plaintext = 07 00 00 00 d4 c3 b2 a1 0d f0 ad 0b 3b 00 fa 00 c3 00 01 00 02 00 00 00
            (pre_ctr, nonce_s, nonce_p 0x0BADF00D, caps, max_frame 250, rssi -61, status 0, path_cost 1, minor 0, fw 2)
nonce = 01 42 00 34 12 00 00 00 00 00 07 00 00
ciphertext = d6 27 dd 9f d5 3c 9d 28 e2 c9 c5 1b 91 6d da 52 56 ac 2d d5 fb 42 11 00 ; tag = d4 b5 38 e7 c4 db 22 c1
frame (55): header || ciphertext || tag || hop_tag 64 64 f9 d7 || b8 4f                 CRC16 = 0x4FB8
T  = SHA-256(SEEK e2e || SEEK payload || HELLO e2e || HELLO plaintext) = 23a631133b822e7b5b5f6d685beb22e4785a12baf3a30076332c3c561fd45723
Ke_hs  = a5c27a6eeceb91ecb0c98c6130ea9efc
Ke_s2p = df810284505046a3db3233d90f746f95 ; Ke_p2s = b62196e1cdc6b3a105133c8b9e1ece7b  (session 7)
BIND (S -> P via R, unicast): header 12 03 34 12 42 00 34 12 99 00 40 08 00 00 02 00 0d, pre_ctr 0x00010002
plaintext = 02 00 01 00 d4 c3 b2 a1 0d f0 ad 0b 07 ; ciphertext = b2 1c cb 1c b3 c1 a5 69 08 67 b8 e5 35 ; tag = d9 8a f2 58 d5 3b 2c f1
frame (44): header || ciphertext || tag || hop_tag bd 93 0d d2 || 03 2c                  CRC16 = 0x2C03
```

A.10 ROC: estimation cases and a second-cycle frame

```
(seq, highest, roc) -> roc used: (0x0005, 0xFFF0, 0) -> 1; (0xFFF0, 0x0005, 1) -> 0;
(0x8001, 0x0000, 3) -> 2; (0x7FFF, 0xFFFF, 3) -> 3
A.7 plaintext again at ROC 1, seq 5, hop_seq 0x2345: nonce 00 34 12 42 00 07 01 00 00 00 05 00 00
ciphertext = 42 d1 5a 04 31 8c 3f 08 bf c9 2f ; tag = 20 8b 57 6a ed b3 b9 be
frame (42): 12 10 34 12 42 00 34 12 42 00 30 45 23 07 05 00 0b 42 d1 5a 04 31 8c 3f 08 bf c9 2f
            20 8b 57 6a ed b3 b9 be 7c dc 49 d1 12 b2                                CRC16 = 0xB212
```

A.11 RESUME flood (plaintext, Ke_s2p), session 7 at seq 0x0042, ROC 0, pre_ctr 0x00010003, ttl 3

```
header 12 31 34 12 42 00 34 12 ff ff 30 00 40 07 42 00 05 ; payload 03 00 01 00 01 (pre_ctr, config_id 1)
nonce = 00 34 12 42 00 07 00 00 00 00 42 00 00 ; ccm_tag (AAD-only) = 4b 94 57 64 e9 db f3 5a
frame (36): header || payload || tag || hop_tag 24 e5 36 b7 || 6b dc                     CRC16 = 0xDC6B
```

A.12 MGMT_REQ from P (0x0042) to manager M (0x0001) via R

```
K_pair(0001, 0042, 1) = 6368f6bf23c97acb0b9c36574f0cc2981456ae5c71d335a5b07cd180b2607088
K_mgmt(0042 -> 0001) = Expand(Extract("ProbeLink-v1", K_pair), "mgmt" || 42 00 || 01 00, 16) = c7ccbdf12bd73a2f349cf415f666d987
header 12 40 42 00 01 00 42 00 99 00 40 04 00 00 08 00 18, pre_ctr 8
plaintext = 08 00 00 00 15 cd 5b 07 00 00 00 00 01 01 00 00 11 11 11 11 11 11 11 11
            (pre_ctr, t1 123456789, key_epoch 1, flags want_keys, section 0, page 0, 8 report bytes)
nonce = 00 42 00 01 00 00 00 00 00 00 08 00 00
ciphertext = 0e a6 10 31 b7 eb ee a2 dd 51 3c 99 92 bf 12 c3 fc 30 e5 4c c2 c7 35 a1 ; tag = 14 f8 da 6b 50 ec 39 06
frame (55): header || ciphertext || tag || hop_tag 61 11 73 af || 03 15                  CRC16 = 0x1503
```

A.13 LOW quantization, range 0..3.3 V: scale 5.0356e-5, offset 1.65; v 0.00 -> q -32767; 1.65 -> 0;
3.30 -> 32767; 4.00 -> 32767 with CLIP.

## Appendix B. Minimal C API

Rules: no heap after `pl_init()` (mbedtls HMAC and CCM contexts are
preallocated in the context); every call returns `pl_err_t`; transport RX
callbacks only copy into a queue with timeout 0; one `pl_task()` does all
protocol work; nothing blocks the caller longer than the Task Watchdog
period. Runtime NVS writes: `pl/txseq` and `pl/preseq` block boundaries, key
bundles, and `pl/boot_count` on power-on or external reset only (deep-sleep
wakes use an RTC counter).

```c
typedef enum { PL_OK = 0, PL_ERR_ARG, PL_ERR_STATE, PL_ERR_NO_PROBE /* event */, PL_ERR_TIMEOUT,
               PL_ERR_BUSY, PL_ERR_TOO_BIG, PL_ERR_AUTH, PL_ERR_QUEUE_FULL } pl_err_t;
typedef enum { PL_ROLE_NODE = 0, PL_ROLE_BRIDGE, PL_ROLE_GATEWAY, PL_ROLE_LEAF } pl_role_t;
typedef uint8_t pl_session_t;                 /* handle: index of a session record */

typedef struct {                              /* all from NVS (12.2) */
    uint16_t unit_id; pl_role_t role; uint8_t node_count, seek_ttl;
    uint8_t max_sessions, max_streams;        /* records / stream buffers (4.1.12) */
    pl_keystore_t *keys;                      /* K_mesh epochs, pair keys, managers; encrypted NVS backed */
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
    void (*on_event)(uint16_t event, uint32_t arg);                            /* PL_EVT_ID_COLLISION, PL_EVT_NO_PROBE, ... */
} pl_callbacks_t;

typedef struct { uint8_t blob[160]; uint32_t crc32; } pl_rtc_state_t;         /* 4.4, RTC_DATA_ATTR */
typedef struct pl_ctx pl_ctx_t;                                                /* opaque, PL_CTX_STATIC(...) */

/* RAM, approximately: session record ~600 B x max_sessions; stream buffer (FEC 2200 + reorder 2500)
 * x max_streams; sender ARQ buffer 24 x 250 = 6 KB per active sender session; forwarding tables ~7 KB
 * (11.9); rx queue 16 x 250. A C3 probe with 32 records and 4 streams: ~19 + 19 + 7 + 4 = ~49 KB. */
#define PL_CTX_STATIC(name, max_sessions, max_streams) ...

pl_err_t pl_init(pl_ctx_t *ctx, const pl_config_t *cfg, const pl_callbacks_t *cb);   /* PL_ERR_AUTH if 12.1 fails */
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
pl_err_t pl_mgmt_serve(pl_ctx_t *ctx, pl_mgmt_server_t *srv);              /* gateway: bundles, time, report sink */
pl_err_t pl_maintenance_mode(pl_ctx_t *ctx, bool enter);                   /* stop mesh, start BLE phone link (6.4) */
void     pl_task(void *ctx);                                               /* FreeRTOS task; stack 6144 as a start, measure */

typedef struct {
    uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail, seg_fail, bad_frame, bad_version,
             auth_fail, hop_tag_fail, hop_replay, replay_dropped, fec_recovered, arq_retx, gaps,
             id_collisions, rx_queue_drop, relay_fwd, relay_drop_ttl, relay_drop_dedup, relay_drop_stale,
             relay_drop_noroute, relay_drop_mtu, relay_drop_rate, relay_drop_queue_data,
             relay_drop_queue_ctrl, relay_drop_loop, route_evictions, link_evictions;
    uint16_t stack_hwm_words;
} pl_stats_t;                                                              /* MGMT section 1 */
```

Task layout: transport callbacks -> `xQueueSend` (timeout 0) -> `pl_task`
parses, validates (3.6), runs the pipeline (11.4), FEC/ARQ, and the
callbacks. `pl_send_samples()` only enqueues; framing, CCM, hop_tag and
`send()` run in `pl_task`.

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
  received frame. `rs_nsym` 6; `fec_k` 2, `fec_m` 1; `rssi` -128.

C.2 UART: 8N1, 115200 default; COBS with 0x00 delimiter, resynchronise on
any 0x00; FIFO-threshold or idle-line interrupt, frames processed in
`pl_task`. Also the gateway's inter-chip link and the provisioning station's
link (12.2).

C.3 ESP-NOW: register `next_hop` MACs as peers (LRU 16 + broadcast; evict
and re-add when full); unicast is retried by the MAC, broadcast is not, so
floods are sent `FLOOD_REPEAT` times. `WIFI_PS_NONE`, fixed channel, no STA,
no BT while the mesh is up; RSSI from `esp_now_recv_info_t`.

C.4 WiFi UDP (LAN side only): port 40888; floods to multicast 239.255.40.88,
IP TTL 1, IGMP join at start; unicast to the link table's address; static
IPs or DHCP reservations; `pl/udp_peers` unicast list where multicast or
client isolation blocks it; otherwise the UDP carrier is unusable and the
installation must say so.

C.5 nRF24L01+ over SPI

- Facts: 32-byte packets (dynamic length), Enhanced ShockBurst CRC-16,
  auto-ACK and auto-retransmit, 6 RX pipes, 5-byte addresses, 250 kbps / 1 /
  2 Mbps, channels 0-125 at 2400 + n MHz, no RSSI.
- Segmentation (adapter only): a frame of n bytes goes as `ceil(n / 30)`
  packets of `tag u8, idx:7 | LAST:1, up to 30 bytes`. `tag` is a per-node
  8-bit counter (not per neighbour: ESB packets carry no source address).
  Reassembly buffers are opened by segment 0, which carries `prev_hop` at
  frame offset 6, and keyed by `(prev_hop, tag)`; `NRF_REASM` (4) buffers of
  258 bytes; segments in order; a gap, a foreign tag before LAST, or
  `NRF_REASM_TIMEOUT_MS` (50) drops the frame (`seg_fail`). ESB retries
  (ARC 15, ARD 500 us) make a lost unicast segment rare. The adapter reports
  `max_frame` 250, so the path MTU never sees 32.
- Overhead: a 250-byte frame is 9 packets, about 1.46x on the air with ESB
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

v0.2 (from v0.1): CRC mandatory on all links, RS erasure code across frames,
probe nonce and BIND_NAK, race catalogue, DATA status byte, ARQ details,
two-nonce keys, 8-byte tag, prior art. v0.3: mandatory mesh with a 15-byte
header (prev_hop, next_hop, ttl_hops), floods, AODV-lite routing. v0.4:
round-1 fixes (hop_tag, 48-bit index, per-pair keys, epochs, validation
table, leaves, DIAG/TIME, nRF24L01+).

v0.5 (round-2 fixes, scope reduced; this document):

- Cuts (12.10): BLE is a phone link only, IR an edge link only (user
  decisions); one `max_frame` 250 (no ESP-NOW v2 / LEN16 / big UDP); no
  PL_SELECT_BEST; AES-CCM end to end plus HMAC hop_tag as the only
  construction; listed managers only for time; no key activation modes;
  rs_nsym 0 on PACKET links; BIND unicast instead of flooded; suppression
  removed; DIAG/TIME/KEY_UPDATE folded into MGMT_REQ/RESP.
- Header: `hop_seq` added (17 bytes, SEEK 20); `pre_ctr` u32 in every
  pre-session frame and RESUME; FLAG_LEN16 gone.
- Keys: transcript-bound handshake (`Ke_hello`, `Ke_hs`, directional
  session keys), three-epoch accept window with per-neighbour transmit
  epoch, pulled bundles encrypted to each node, revocation epochs, MGMT
  under `K_mgmt`.
- Mesh: dedup before ORIGIN with cost update, ORIGIN jump bound, hop_seq
  freshness before any table change, routes installed by any admitted
  frame, 20-minute route TTL, keepalive 5 s, airtime budget table.
- Leaves: pull-based management on wake, RTC reserve-ahead with CRC,
  CLOSE(PARK) acknowledged, RESUME retry rules, battery gate.
- Operations: provisioning sequence and `pl_init` at-rest checks, in-mesh
  BULK update with a connectivity-based rollback rule, UART recovery as the
  only "cable", co-located radio rules, session records vs streams.
- Appendix A recomputed (A.1-A.13) including ROC 1, E-1 hop_tag, RESUME and
  MGMT vectors.

Round 2 disposition (ROAST-2-field G1-G29, ROAST-2-security T1-T24):

| ID | Sev | Disposition | Where / reason |
|---|---|---|---|
| G1 | CRITICAL | fixed | 8.5 three-epoch accept window, per-neighbour transmit epoch, no activation message, pulled bundles reach leaves (4.4, 11.10), UART recovery (12.2) |
| G2 | CRITICAL | fixed | ROUTE_TTL 20 min refreshed by any traffic, 64 routes, keepalive 5 s with no probe PING, airtime table (4.2, 9, 11.6) |
| G3 | HIGH | fixed | 32-bit `pre_ctr` on the wire and in the CCM nonce, ORIGIN jump bound and 1 h TTL (3.5, 8.4, 11.5); insider variant stated as limitation (11.8) |
| G4 | HIGH | fixed | `hop_seq` in the header, checked before link learning; address replacement only with a newer hop_seq; alarm only on prev_hop = own ID (8.4, 11.4, 11.9) |
| G5 | HIGH | fixed | dedup (9b) before ORIGIN (9c); equal copies update cost and route; HELLO fields from the chosen copy (4.1.2, 11.4) |
| G6 | HIGH | fixed | any admitted frame for me or forwarded installs a route to src_id if none exists (11.4 table); leaf keeps first-hop address in RTC (4.4) |
| G7 | HIGH | removed by cut | PL_SELECT_BEST deleted |
| G8 | HIGH | fixed | revocation epochs erase E after neighbours are heard under E+1 or after the grace period; bundles encrypted per node by the tool, gateway holds opaque blobs (8.5) |
| G9 | HIGH | fixed | session records vs stream buffers, PL_MAX_SESSIONS 32 / PL_MAX_STREAMS 4, probes hold no ARQ buffer, capacity rule (4.1.12, App. B) |
| G10 | HIGH | fixed | leaves pull MGMT on wake: keys, time, health report (4.4, 11.10); a bundle waits at most MGMT_EVERY_WAKES wakes |
| G11 | HIGH | fixed | in-mesh BULK update, connectivity-based validity rule, UART recovery manager (12.2, 12.7) |
| G12 | HIGH | fixed | Ethernet LAN side preferred; antenna/channel separation rules; nRF24 channel plan; bridge TX arbitration; commissioning test (12.4) |
| G13 | HIGH | removed by cut | BLE only in maintenance mode with the mesh stopped (6.4, 12.5) |
| G14 | HIGH | fixed | cut list applied (12.10); document 2354 -> under 1700 lines |
| G15 | MEDIUM | fixed | SEEK_TIMEOUT(n) defined, BOOT_SPREAD 600 x nodes, seek_ttl from manifest, RESUME ttl min(hops + 1, MAX_HOPS) (4.1.1, 4.1.8, 4.4, 9) |
| G16 | MEDIUM | removed by redesign | key bundles arrive in MGMT_RESP chunks (TLV type u8, len u8, may span responses); no session, no FULL problem (11.10) |
| G17 | MEDIUM | fixed | paged MGMT report sections 0-3 sized to the path MTU (11.10) |
| G18 | MEDIUM | fixed | CLOSE(PARK) acknowledged with retries; SRTT in RTC; RESUME timeout BIND_TIMEOUT(hops) and one retry (4.4) |
| G19 | MEDIUM | fixed | RTC wake counter, boot_count on power-on only, deep-sleep wake exempt from holdoff, battery gate, budget restated with Secure Boot time (4.1.1, 4.4, App. B) |
| G20 | MEDIUM | removed by cut | listed managers only; time inside MGMT under the pair key with pre_ctr echo (6.5, 11.10) |
| G21 | MEDIUM | removed by cut | IR is an edge; no path_mtu heuristic (12.6) |
| G22 | MEDIUM | fixed | RMT partial-RX / GPIO capture note; nRF24 reassembly keyed by (prev_hop, tag) with a per-node tag; rssi -128 = unknown; ESP-NOW peer eviction rule (C.1, C.5, 11.11) |
| G23 | MEDIUM | fixed | solar sizing rule, low-voltage gate, vbat_mv in MGMT section 0 (11.1, 11.10) |
| G24 | MEDIUM | fixed | ordered provisioning sequence with verification (12.2) |
| G25 | LOW | fixed | session_id from esp_random, last 8 kept in RTC (4.1.11) |
| G26 | LOW | fixed | one echo/collision rule based on the dedup cache (11.5) |
| G27 | LOW | fixed | validation rows for all types; forwarder length bound is fixed (250); MODE fit minus 7 / 9; BIND_NAK reasons 3-4 removed; pipeline stops after local delivery (step 7) and at a unicast flood destination (9e); ARQ_WINDOW 24 fits the 32-bit bitmap |
| G28 | LOW | fixed | session handles, type sketches, pending-copy buffers and preallocated contexts in the RAM table (App. B, 11.9) |
| G29 | LOW | fixed | nRF24 channels 76-81 at 2 Mbps; 82-83 only at lower rates (C.5) |
| T1 | CRITICAL | fixed | = G4: hop_seq freshness before step 6; residual after LINK_TTL expiry stated (8.4) |
| T2 | CRITICAL | fixed | RESUME carries pre_ctr; ORIGIN, dedup and budget apply to it (4.4, 11.4, 11.5) |
| T3 | CRITICAL | fixed | = G1 |
| T4 | HIGH | fixed | = G8: revocation epochs erase E; residual window stated (8.5) |
| T5 | HIGH | fixed | = G10 |
| T6 | HIGH | fixed (partial) | R2 narrowed to session and management layers; ORIGIN jump bound; mesh-layer identity listed as a known limitation; signatures as the alternative (8.1, 11.8, 12.8) |
| T7 | HIGH | fixed | time only from listed managers under K_mgmt; time never drives key activation (6.5, 8.5, 11.10) |
| T8 | HIGH | fixed | = G8: per-node encrypted bundles; gateway holds no other node's keys (8.5) |
| T9 | HIGH | fixed | provisioning sequence; pl_init checks secure boot, flash encryption mode and NVS encryption (12.1, 12.2) |
| T10 | HIGH | fixed | = G3; endpoints keep last pre_ctr per (peer, key) for unicast pre-session frames (8.4) |
| T11 | HIGH | fixed | transcript hash T in every handshake and session key (8.2) |
| T12 | HIGH | fixed | RTC blob with reserve-ahead counters, CRC32, used only after ESP_RST_DEEPSLEEP (4.4) |
| T13 | HIGH | fixed | tool refuses the test K_site; firmware blacklists K_mesh(E) prefixes for all 256 test epochs and degenerate keys (12.1) |
| T14 | MEDIUM | removed by cut | BIND is unicast; no free-retry rule (11.5) |
| T15 | MEDIUM | fixed | one OFFERED entry per src_id, oldest replaced when full (4.1.2) |
| T16 | MEDIUM | removed by cut | BIND unicast; losers time out, nothing on the air cancels an offer (4.1.5) |
| T17 | MEDIUM | fixed | both pre_ctr values are in the transcript; key uniqueness deterministic (8.2) |
| T18 | MEDIUM | fixed | ARQ buffers hold the encoded frame; retransmissions are byte-identical (section 7) |
| T19 | MEDIUM | fixed | separate signing keys; images refuse the wrong eFuse state (12.1) |
| T20 | MEDIUM | fixed | supported chips and revisions listed; R1 reworded as cost, revocation as the control (8.1, 12.1) |
| T21 | LOW | fixed | = G5; step 5b removed (hop_tag suffices) (11.4) |
| T22 | LOW | fixed | PRK = Extract("ProbeLink-v1", K_pair); nonces and transcript in Expand info; no separate inner tag (8.2) |
| T23 | LOW | fixed (partial) | vectors for ROC 1, E-1 hop_tag, RESUME, MGMT added; LEN16 is gone; no KEY bundle vector (deferred: needs a full bundle fixture) |
| T24 | LOW | fixed | boot_count written on power-on / external reset only; nonces also mix preseq and txseq (4.1.14, App. B) |
