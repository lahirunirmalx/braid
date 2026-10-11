# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.4 (round-1 review fixes applied; wire version 1, minor 0)

One protocol, six carriers: ESP-NOW, BLE, WiFi (UDP), nRF24L01+, IR, and raw
UART TX/RX. Every device has an ID. Every frame is integrity-checked and
carries enough redundancy to recover damaged or lost data. Payloads are
digital or analog 32-bit values, sent in HIGH or LOW resolution.

Reading guide: sections 1-10 keep the v0.1 numbering so the drafts can be
diffed. Section 11 is the mesh layer (mandatory since v0.3). Section 12 is
new in v0.4: the deployment profile (bench vs field) and the design decisions
taken in response to the round-1 reviews, each with its alternative, so they
can be overridden. Appendix D maps every review finding to its disposition.
All numbers marked "(estimate)" are engineering estimates, not measurements.

Normative words: MUST, MUST NOT, SHOULD, MAY as in RFC 2119. "Field profile"
and "bench profile" are defined in 12.1; where the two differ the field rule
is the default and the bench relaxation is named explicitly.

---

## 1. Layer stack

```
+---------------------------------------------------------+
| Application   pl_send_samples(), on_samples()           |
+---------------------------------------------------------+
| Session       SEEK / HELLO / BIND / MODE / DATA / CLOSE |
|               RESUME (parked sessions), KEY_UPDATE      |
+---------------------------------------------------------+
| Mesh          flood SEEK/BIND, hop-by-hop unicast, s.11 |  every node
|               DIAG / TIME (sessionless, s.11.11)        |
+---------------------------------------------------------+
| Group FEC     RS erasure code across k DATA frames,     |  any link
|               m PARITY frames (m = 1 is plain XOR)      |
+---------------------------------------------------------+
| Frame         header + payload [+ tags] + CRC-16        |  CRC mandatory
|               [+ in-frame RS parity]                    |  RS per link
+---------------------------------------------------------+
| Transport     ESP-NOW | BLE | UDP | nRF24 | UART | IR   |  nRF24 segments
+---------------------------------------------------------+
```

### 1.1 Two kinds of link, two kinds of damage

This is the most important design point, and v0.1 overstated it.

| Link class | Carriers | What damage usually looks like | Mandatory | Optional |
|---|---|---|---|---|
| PACKET | ESP-NOW, BLE, WiFi UDP, nRF24L01+ | The radio MAC checks its own CRC and drops bad frames, so damage is mostly a missing frame. | CRC-16, cross-frame FEC and/or ARQ | In-frame RS (rs_nsym > 0) |
| RAW | UART, IR | Bytes arrive flipped, missing or inserted. | CRC-16, in-frame RS | Cross-frame FEC, ARQ |

Why the CRC is mandatory on PACKET links too: ESP-IDF issue #9575 (open,
ESP32-C3, IDF 4.4.2) reports ESP-NOW frames with an invalid 802.11 FCS being
accepted and acknowledged. "The app never sees a corrupted byte" is therefore
not a safe assumption on ESP-NOW, and the nRF24L01+ hardware CRC is only 8 or
16 bits over a 32-byte packet. The application CRC is the last line of
defence on every carrier, and in-frame RS is allowed (not forbidden) on
PACKET links for installations that observe corrupt frames. Default `rs_nsym`
is still 0 on PACKET links because in the normal case the corrupt frame is
dropped by the MAC before the RS decoder could see it.

Unified recovery model: the frame layer turns every kind of damage into an
erasure (a frame that is either fully correct or absent). The group FEC and ARQ
layers only ever deal with erasures. This is what makes one FEC design work on
all six carriers.

Recovery data per packet, stated precisely (review F27): DATA frames carry
recovery data in the form of in-frame RS parity (RAW links) and cross-frame
parity (PARITY frames). Control frames (SEEK, HELLO, BIND, ACK, ...) are
protected by CRC plus repetition: flooded frames are transmitted
`FLOOD_REPEAT` (2) times with independent jitter on carriers without MAC retry
(11.5), and unicast control frames are retried by the handshake rules (4.1) or
the carrier's MAC. The user requirement "every packet carries enough data to
recover damage" is met by FEC for data and by retry/repetition for control.
If a stricter reading is wanted, 12.3 names the knob.

### 1.2 Transport adapter contract

```c
typedef enum { PL_LINK_PACKET = 0, PL_LINK_RAW = 1 } pl_link_class_t;

typedef struct {
    const char     *name;          /* "espnow", "ble", "udp", "nrf24", "uart", "ir" */
    pl_link_class_t link_class;
    uint16_t        max_frame;     /* largest frame (incl. RS parity) delivered whole */
    uint8_t         rs_nsym;       /* in-frame RS parity bytes; 0 = none */
    bool            can_broadcast; /* floods by broadcast; else write to each neighbour */
    bool            mac_retry;     /* carrier retries unicast (ESP-NOW, nRF24 yes; IR no) */
    bool            half_duplex;   /* IR, nRF24: cannot receive while transmitting */
    uint8_t         time_scale;    /* multiplier for section 9 timers (1 radio, 10 IR) */
    uint8_t         link_cost;     /* fixed cost for carriers without RSSI (11.4): UART 1, BLE 2, nRF24 2, IR 20 */
    uint8_t         addr_len;      /* carrier address bytes kept in the link table: 6 ESP-NOW/BLE, 5 nRF24, 4 UDP, 0 UART/IR */
    int  (*send)(const uint8_t *addr, const uint8_t *buf, uint16_t len);   /* addr NULL = broadcast */
    void (*set_rx_cb)(void (*cb)(const uint8_t *addr, const uint8_t *buf, uint16_t len, int8_t rssi));
} pl_transport_t;
```

| Carrier | Class | max_frame | rs_nsym default | Notes |
|---|---|---|---|---|
| ESP-NOW v1 | PACKET | 250 | 0 (may be 2-8, see 1.1) | Broadcast FF:FF:FF:FF:FF:FF for floods, unicast to the `next_hop` MAC from the link table otherwise. All mesh nodes sit on one dedicated channel (`pl/channel`); WiFi STA is forbidden on mesh nodes and `esp_wifi_set_ps(WIFI_PS_NONE)` is mandatory (12.4, review F4). |
| ESP-NOW v2 | PACKET | up to 1470 | 0 | Needs ESP-IDF v5.4+ on both ends. A v1 peer limits the pair to 250. The usable size is negotiated as the path MTU (11.3). Frames above 255 bytes need FLAG_LEN16 (section 3). v2 frame sizes are limited to single-session probes or `arq_window` 8 (review F9). |
| BLE GATT | PACKET | ATT_MTU - 3 | 0 | Optional per node (`pl/ble`, default off; 12.5, review F5). Default ATT MTU 23 gives 20 bytes, which does not hold the header. MUST request MTU >= 64 and SHOULD request 247. Links are connections; advertising is a neighbour beacon only (6.4). |
| WiFi UDP | PACKET | 255 default, up to 1400 with FLAG_LEN16 | 0 | LAN side of a gateway only (12.4). UDP port 40888, multicast 239.255.40.88 TTL 1 for floods, unicast otherwise; static IPs or DHCP reservations required; a configured unicast peer list replaces multicast on isolated LANs (C.5, review F26). |
| nRF24L01+ (SPI) | PACKET | 255 (reassembled) | 0 | 32-byte radio packets; the adapter segments and reassembles every frame per hop (C.6), so the path-MTU logic never sees 32. Enhanced ShockBurst CRC-16, auto-ACK and auto-retransmit for unicast; NO_ACK broadcast pipe for floods. Channels 76-83 recommended (C.6). No RSSI, only a 1-bit carrier-detect: fixed link_cost 2. |
| UART | RAW | 255 incl. parity | 8 | COBS-encoded, 0x00 delimiter. COBS adds at most 1 + ceil(n / 254) bytes on the wire; that is outside max_frame. |
| IR (RMT) | RAW | 64 incl. parity | 6 | 38 kHz carrier, half duplex, line of sight, both ends need TX + RX. Indoor or shaded installations only (review F7). Realistic bit rate a few kbit/s (estimate), so one 64-byte frame takes roughly 0.2-0.5 s. LOW mode and small channel counts only. PHY sketch in appendix C. |

`rs_nsym` is a static per-link setting, configured identically on both ends
out of band (NVS `pl/rs_nsym`, or the adapter default above). It cannot be
negotiated in-band because RS decoding happens before the header can be
parsed. A mismatch shows up as 100 % CRC/RS failures on the first SEEK.

---

## 2. Device IDs

16-bit IDs. Small enough for IR, large enough for a site of 50 nodes.

| Range | Meaning |
|---|---|
| 0x0000 | Unassigned. Never valid on the air. |
| 0x0001 - 0xFEFF | Unit ID. One per device. |
| 0xFF00 - 0xFFEF | Group (destination) ID. Several probes can subscribe to one group. |
| 0xFFF0 - 0xFFFE | Reserved groups: 0xFFF0 update service, 0xFFF1 monitor, others reserved. |
| 0xFFFF | Broadcast / flood. |

- Unit IDs are assigned by the provisioning manifest (12.2), one row per
  device keyed by its eFuse base MAC, and written to NVS (`pl/unit_id`)
  together with the MAC it was assigned to (`pl/unit_mac`). At boot, if
  `pl/unit_mac` differs from `esp_read_mac(ESP_MAC_BASE)` the override is a
  cloned image: the node ignores it, falls back to the MAC-derived ID below,
  raises `PL_EVT_ID_COLLISION` and reports the mismatch in DIAG (11.11). This
  catches every flash clone (review F3). The fallback ID has no pairwise
  keys, so such a node can answer DIAG and nothing else until it is
  re-provisioned; that is the intended outcome.
- Fallback ID when no manifest entry exists: CRC-16/CCITT-FALSE (section 3.1)
  of the 6-byte base MAC; if the result is 0x0000 or >= 0xFF00, use
  `(crc % 0xFEFF) + 1`. CRC-16 cannot collide for MACs that differ only in the
  last two bytes, so one reel of modules is safe; a mix of module types
  behaves like random IDs, where 50 nodes collide with probability about
  1.9 %. The manifest, not the fallback, is the field mechanism; the
  provisioning tool rejects duplicate IDs before flashing.
- Collision detection: a node that receives a frame with `src_id` or
  `prev_hop` equal to its own unit ID, which is not an echo of its own flood
  (11.5), raises `PL_EVT_ID_COLLISION` and logs it with `ESP_LOGE`. DIAG_RESP
  reports (MAC, unit_id), so a gateway polling diagnostics sees two MACs for
  one ID anywhere in the mesh, including colliders that never hear each
  other.
- A "destination" is a group ID. Each probe that can serve it subscribes to it
  (up to `PL_MAX_GROUPS` = 8 per probe, from NVS `pl/groups`). A sender seeks
  the group, not a specific probe. A unit ID is also a valid SEEK destination
  ("group of one"); KEY_UPDATE and OTA commands use that.
- A device accepts a frame when `dst_id` is its unit ID, a group it subscribes
  to, or 0xFFFF. After BIND all session frames are unicast: `dst_id` is the
  peer's unit ID, never the group.

---

## 3. Frame format

All multi-byte fields little-endian. Float32 is IEEE-754 binary32, also
little-endian. Fields are packed with no alignment padding; read them with
`memcpy()` into a local, never by casting a `uint32_t *` into the buffer (Xtensa
LX6/LX7 raise a LoadStoreAlignment exception on unaligned 32-bit loads, and the
cast is undefined behaviour in C anyway).

```
Off  Size  Field                                                        scope
0    1     ver_flags   bits 7..4 version (=1), bits 3..0 flags           end-to-end
1    1     type        message type (section 5)                          end-to-end
2    2     src_id      origin unit ID                                    end-to-end
4    2     dst_id      final destination: unit ID, group, or 0xFFFF      end-to-end
6    2     prev_hop    unit ID of the node that transmitted this copy    per hop
8    2     next_hop    unit ID of the intended receiver; 0xFFFF = flood  per hop
10   1     ttl_hops    bits 7..4 ttl (hops remaining), 3..0 hops done   per hop
[11  2     path_mtu    SEEK only: smallest (max_frame - rs_nsym) so far  per hop]
[13  1     path_cost   SEEK only: sum of link costs so far (11.4)        per hop]
..   1     session_id  0 in SEEK/HELLO/BIND/BIND_ACK/BIND_NAK/DIAG/TIME  end-to-end
..   2     seq         per-session, per-direction; low 16 bits of a      end-to-end
                       48-bit index (3.5)
..   1|2   len         payload length: u8, or u16 if FLAG_LEN16          end-to-end
..   len   payload     (ciphertext if ENC, 8.5)                          end-to-end
..   8     auth_tag    if FLAG_AUTH: HMAC or AES-CCM tag (section 8)     end-to-end
..   4     hop_tag     if FLAG_AUTH: HMAC(K_mesh) over bytes 0..auth_tag  per hop
..   2     crc16       CRC-16/CCITT-FALSE over byte 0 .. end of hop_tag  per hop
..   n     rs_parity   rs_nsym bytes, if rs_nsym > 0 for this link      per hop
```

Header is 15 bytes (18 in SEEK). Fixed overhead with CRC: 17 bytes (18 with
FLAG_LEN16, +12 with FLAG_AUTH, +rs_nsym). The per-hop bytes are rewritten
by every forwarding node (section 11); a direct link is a one-hop route with
`prev_hop = src_id` and `next_hop = dst_id`. End-to-end fields are never
modified between origin and final destination.

Flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 | FLAG_ACK_REQ | Receiver must reply ACK immediately |
| 1 | FLAG_AUTH | `auth_tag` and `hop_tag` present. Mandatory in the field profile. |
| 2 | FLAG_LEN16 | `len` is 2 bytes. Only on PACKET links with path_mtu > 255. Never with rs_nsym > 0 (RS block limit, 3.2). |
| 3 | reserved | 0 on send, ignored on receive |

Frozen prefix (review F14): bytes 0..10, the SEEK hop fields, the position
and width of `session_id`, `seq` and `len`, the meaning of flag bits 1 and 2,
and the tag sizes are frozen across all future versions. A forwarding node
that sees an unknown version can therefore still locate `len`, the tags and
the CRC, verify the hop_tag and forward the frame (11.4 step 2). Only
endpoints reject unknown versions. Endpoints accept version N and N-1 during
a declared transition (12.6). Behaviour changes that keep the layout bump
`proto_minor`, carried in SEEK/HELLO and DIAG so that a field tool can see
which rules each node runs.

### 3.1 Why CRC-16 and not a parity bit

A single parity bit misses every even number of flipped bits (half of all
random errors). CRC-16/CCITT detects all 1-, 2- and 3-bit errors, all odd-bit
errors, and all bursts up to 16 bits in frames this size. It is the "parity
check" of this protocol.

Exact definition: CRC-16/CCITT-FALSE, polynomial 0x1021, init 0xFFFF, no input
or output reflection, xorout 0x0000. Check value: CRC("123456789") = 0x29B1.
Implement it as a 256-entry table (512 bytes of flash) or bitwise; both are
fast enough at these frame rates.

### 3.2 In-frame Reed-Solomon (RAW links; optional elsewhere)

- Code: RS over GF(2^8), primitive polynomial 0x11D (x^8+x^4+x^3+x^2+1),
  first consecutive root 0, generator element alpha = 2, systematic (parity
  appended). These are the defaults of the common libraries (Arduino-FEC,
  libcorrect, Python `reedsolo`), so test vectors are interchangeable.
- `rs_nsym` parity bytes correct up to `rs_nsym / 2` damaged bytes anywhere in
  the frame, header included, or up to `rs_nsym` bytes at known positions
  (erasures). On UART/IR the positions are unknown, so plan on `rs_nsym / 2`.
- Whole RS block (frame + parity) must be <= 255 bytes. This is why
  FLAG_LEN16 and rs_nsym > 0 are mutually exclusive.
- Transmit: build frame -> append CRC -> RS-encode -> (UART: COBS + 0x00).
- Receive: (UART: COBS-decode) -> RS-decode -> if uncorrectable drop -> check
  CRC -> if CRC fails drop (catches RS mis-correction). A dropped frame is an
  erasure for the layers above.

Burst errors and interleaving: an RS symbol is one byte, so a burst of up to 8
consecutive bit errors inside one byte costs one symbol. A burst spanning B
bytes costs B symbols. Byte interleaving does not help here: a frame of
<= 255 bytes is a single codeword and the decoder does not care where in the
codeword the bad symbols are. Interleaving only pays off when a frame is split
into several codewords, which this protocol never does. The right knob is
`rs_nsym`: choose `rs_nsym >= 2 * B_max + 2`, where B_max is the longest burst
in bytes you expect. Examples: a 5 ms dropout at 2 kbit/s on IR is 10 bits,
B_max = 2, nsym 6 is enough. A 1 ms glitch at 115200 baud on UART is 14 bytes,
far beyond nsym 8, and a flipped byte that becomes 0x00 breaks COBS framing
before RS can act. UART therefore relies on cross-frame FEC or ARQ for long
bursts, and on RS only for single-bit and short glitches.

### 3.3 Group FEC (cross-frame erasure code, any link)

v0.1 used a single XOR parity frame per group. XOR recovers exactly one loss
per group, but radio losses are bursty (interference, channel contention), and
one burst taking two frames out of a group of 4 leaves both unrecoverable. v0.2
uses a systematic Reed-Solomon erasure code across frames, the same idea as
wfb-ng (k = 8, n = 12 there), with the same GF(2^8) arithmetic as 3.2 so one
set of tables serves both layers.

Definitions (set in MODE, section 6.1):

- `fec_k` data frames per group, 2..16. `fec_m` parity frames per group, 0..4.
  `fec_m = 0` disables group FEC. Codeword length n = k + m <= 20, well under
  the 255-symbol limit.
- Every DATA frame in a group is mapped to a block of `block_len` bytes:
  `[len] [payload] [zero padding]`. The `len` prefix has the same width as the
  frame's `len` field: 1 byte, or 2 bytes (LE) in a session that uses
  FLAG_LEN16; the width is uniform within a session. `block_len` = longest
  DATA payload in the group + prefix width. With ENC (8.5) the block holds
  the plaintext payload; FEC runs below encryption at the sender and above
  decryption at the receiver, so recovered blocks are plaintext.
- Parity block j (j = 0..m-1) is computed column-wise: for each byte position i
  the k data bytes form a message, RS-encode it with nsym = m, and the j-th
  parity symbol goes to parity block j at position i.
- With `fec_m = 1` the RS parity of a message with generator (x + 1) is the sum
  of the message symbols, i.e. the XOR of the k bytes. So the v0.1 XOR scheme
  is exactly the m = 1 case, and there is no separate XOR code path.
- A receiver holding any k of the k + m blocks reconstructs the missing ones
  by RS erasure decoding (positions known). Every RS library listed in
  section 10 exposes a decode-with-erasures call.

Group membership is explicit, not derived from `seq / K` (that rule breaks at
the 65535 wrap for any K that does not divide 65536, and breaks completely once
PARITY frames consume sequence numbers, which they do, see 3.5). The PARITY
payload carries:

```
first_seq    u16   seq of the first DATA frame in the group
k            u8    actual number of DATA frames in this group (1..fec_k)
m            u8    number of PARITY frames in this group (= fec_m)
idx          u8    which parity block this is, 0..m-1
block_len    u16   bytes of parity data that follow
reserved     u8    0
parity       block_len bytes
```

Sender rules:

- Group members are the `k` consecutive seqs `first_seq .. first_seq + k - 1`,
  all of type DATA. The sender MUST NOT interleave other frame types inside a
  group. Control frames (MODE, PING, CLOSE) are sent between groups.
- A group may be closed early with `k` < `fec_k`: when `FEC_FLUSH_MS` passes
  without a new sample frame, or before MODE/CLOSE. A group with k = 1 and
  m = 1 is a plain duplicate of one frame, which is still useful on IR.
- When `fec_m > 0`, the DATA payload is capped at `max_payload - 9` bytes
  (`- 10` with FLAG_LEN16) so that the PARITY frame (8-byte header +
  `block_len` = payload + prefix width) still fits `max_frame`.
- Retransmitted DATA frames (ARQ, section 7) keep their original seq, so they
  stay valid group members and duplicates are detected.

Receiver rules:

- Buffer the last `fec_k + fec_m` frames per session. RAM:
  `(fec_k + fec_m) * (max_payload + 1)` bytes where
  `max_payload = path_mtu - 17 - 12` with AUTH, e.g. 10 x 222 = 2220 bytes
  for an ESP-NOW v1 path (max_payload 221) with k = 8, m = 2. Static
  allocation, sized at init.
- When a group has at least one PARITY frame and `k` data frames are
  reachable (received or recovered), decode. Recovered frames are delivered
  in order through the reorder buffer (section 7).
- Overhead is `m / k`, recovery latency is up to `k + m` frame periods.

| k | m | Overhead | Recovers | Suits |
|---|---|---|---|---|
| 4 | 1 | 25 % | any 1 of 5 | v0.1 behaviour, low latency |
| 8 | 2 | 25 % | any 2 of 10 | default for radio streaming |
| 8 | 4 | 50 % | any 4 of 12 | noisy 2.4 GHz, many WiFi neighbours |
| 2 | 1 | 50 % | any 1 of 3 | IR, where latency per frame is already large |
| 16 | 2 | 12.5 % | any 2 of 18 | clean link, bandwidth matters |

### 3.4 Header budget: why one header for all carriers

Compressions evaluated and rejected:

| Variant | Saves | IR data bytes (path_mtu 58, AUTH, DATA hdr 7) | Why rejected |
|---|---|---|---|
| Full header (this spec) | - | 22 | - |
| Omit prev_hop/next_hop on point-to-point links (UART, BLE) | 4 bytes on those links only | 22 (IR is shared, cannot omit) | Two parsers; a bridge re-frames every frame anyway; a UART bus with 3 nodes needs them |
| In-session compact header (drop src/dst, keep session_id + seq) | 4 bytes | 26 | Loses origin on a shared medium (IR room with two senders collides on 1-byte session_ids); forwarding nodes route on dst_id |
| Drop hop_tag (4) | 4 bytes | 26 | Outsiders could then poison link tables and routes (11.8) |
| BLE at default MTU 23 (20 bytes) | - | cannot hold the 15-byte header plus one sample | MTU negotiation is mandatory (1.2) |

Decision: one header, 15 bytes, everywhere; 12 bytes of tags in the field
profile. The mesh fields cost 5 bytes per frame, the tags 12: 7 % of an
ESP-NOW frame and 29 % of an IR frame. On IR the bottleneck is the bit rate,
not header bytes; use LOW mode and few channels there, and keep IR at the
edge of the mesh. The 32-byte nRF24L01+ packet is handled by per-hop
segmentation in its adapter (C.6), not by shrinking this header.

### 3.5 Sequence numbers

- `seq` is per session and per direction: the sender's frames and the probe's
  frames each have their own counter, starting at 0 at BIND_ACK, and
  incrementing on every frame of every type sent in the session (DATA, PARITY,
  MODE, PING, ACK, ...). Retransmitted DATA frames are the exception: they
  reuse their original seq.
- The wire carries the low 16 bits. Both ends also keep a 32-bit roll-over
  counter ROC that increments each time `seq` wraps; the 48-bit index
  `ROC << 16 | seq` is what the tags and the CCM nonce cover (section 8), so a
  frame recorded before a wrap is never valid after it (review F17 / S7).
  The receiver estimates the sender's ROC as in SRTP (RFC 3711, 3.3.1): with
  `s_l` the highest seq received and `roc` the current estimate, a frame
  with `seq` uses `roc - 1` if `s_l < 32768` and `seq - s_l > 32768`,
  `roc + 1` if `s_l >= 32768` and `s_l - 32768 > seq`, otherwise `roc`. The
  tag check then confirms the guess. Worked cases are in Appendix A.10.
- Pre-session frames (`session_id` = 0: SEEK, HELLO, BIND, BIND_ACK,
  BIND_NAK, DIAG_REQ/RESP, TIME_REQ/RESP) use one per-device 32-bit
  pre-session counter whose low 16 bits go on the wire; ROC is 0 in their tag
  input. The counter is persistent: NVS `pl/preseq` stores the next multiple
  of 64 ahead of the current value and is rewritten only when that boundary
  is crossed (one NVS write per 64 pre-session frames, bounded wear); at boot
  the node resumes from the stored value. Every transmission, including
  retries, increments it. When one logical transmission is copied to several
  transports (a bridge flooding SEEK on UART and ESP-NOW at once) all copies
  carry the same seq. Forwarding nodes key flood duplicate suppression on
  `(src_id, session_id, seq)` and the per-origin freshness filter on the
  pre-session `(src_id, seq)` (11.5).
- Compare seqs with serial-number arithmetic (RFC 1982): `a` is newer than `b`
  iff `(int16_t)(a - b) > 0`. All windows (ACK bitmap, FEC groups, replay
  window) are far smaller than 32768, so the comparison is unambiguous.
- Receivers keep a 64-entry "seen" bitmap below the highest index (section 8
  replay window) and drop duplicates.

### 3.6 Receiver validation (normative)

Every receiver applies these checks in this order before any other
processing: forwarding nodes apply the Length, Header, SEEK hop field,
Version and hop_tag / K_mesh rows; the payload rows and the K_s auth_tag
apply at the endpoint that holds the key. A failed check drops the frame and
increments the named counter; nothing is sent in reply. (Review F18: without
this table two implementations reject different sets of malformed frames and
a third crashes on `len`.)

| Stage | Check | Counter |
|---|---|---|
| Length | received length == header + len + (12 if FLAG_AUTH) + 2 + rs_nsym; FLAG_LEN16 only on links with max_frame > 255 and rs_nsym = 0; `len` <= max_payload | `bad_frame` |
| Header | ttl <= MAX_HOPS, hops < MAX_HOPS, prev_hop is a unit ID (not 0, not a group), next_hop is a unit ID or 0xFFFF, src_id is a unit ID, dst_id != 0 | `bad_frame` |
| SEEK hop fields | `MIN_PATH_MTU` (48) <= path_mtu <= (max_frame - rs_nsym) of the link it arrived on; path_cost <= 250 | `bad_frame` |
| Version | endpoints: version in {N, N-1}; forwarders: any version with the frozen prefix | `bad_version` |
| Type | known type for this version at an endpoint; forwarders do not care | `bad_frame` |
| Tags | hop_tag under K_mesh(E) then K_mesh(E-1); auth_tag per section 8 | `hop_tag_fail`, `auth_fail` |
| SEEK payload | len == 14; caps reserved bits 0; max_frame >= MIN_PATH_MTU; key_epoch in {E, E-1} when keyed | `bad_frame` |
| HELLO payload | len == 21; status in {0, 1}; nonce_s matches an outstanding SEEK | `bad_frame` |
| BIND payload | len == 19; probe_id is a unit ID; session_id != 0 | `bad_frame` |
| MODE | len == 13 + sum of descriptor sizes; ch_count 1..16; kind 0..1; fmt 0..2 for analog, 1..32 for digital; scale finite and non-zero, offset finite (LOW analog); period > 0; fec_m 0..4; fec_k 2..16 when fec_m > 0; arq 0..1; reserved flag bits 0; one full sample fits in max_payload | MODE_ACK status 3 (bad arg) or 2 (too big) |
| DATA | config_id known; len == 7 + n_samples x sample bytes; n_samples >= 1 | `bad_frame` |
| PARITY | idx < m; m == fec_m; k in 1..fec_k; block_len <= max_payload + 2; first_seq inside the receive window | `bad_frame` |
| ACK | len == 6; cum_seq inside the ARQ window | `bad_frame` |
| PING/PONG/CLOSE/RESUME/DIAG/TIME/KEY_UPDATE | exact payload sizes of section 5 and 11.11; TLV lengths within len | `bad_frame` |

Implementers SHOULD build the parser as a host-side library and fuzz it
(libFuzzer or AFL) with the Appendix A frames as seeds; the parser touches no
hardware, so this costs an afternoon.

---

## 4. Session state machine

```
Sender:   IDLE -> SEEKING -> BINDING -> CONFIGURING -> STREAMING -> (PARKED <-> STREAMING) -> CLOSED -> IDLE
Probe:    LISTENING -> OFFERED -> BOUND -> STREAMING -> (PARKED) -> LISTENING   (one instance per session, 4.1.12)
```

```
Sender                         Probe A           Probe B
  | SEEK flood (nonce_s) ------->|----------------->|      ttl SEEK_TTL, K_mesh tag
  |                              | wait rand(0..50ms)
  |<--- HELLO (nonce_s, nonce_p) |                  |      K_hs tag, reverse route
  |<-------------------------------------- HELLO    |      kept as candidate #2
  | BIND flood (probe=A, inner tag) ------------->  |      B stands down
  |<------------------ BIND_ACK  |                  |      K_hs tag
  | MODE (cfg 1, HIGH) --------->|                         K_s2p from here on
  |<------------------ MODE_ACK  |                         K_p2s
  | DATA x8, PARITY x2 --------->|                         one FEC group
  |<----------------------- ACK  |                         every keepalive, liveness
  | MODE (cfg 2, LOW) ---------->|                         switch any time
  |<------------------ MODE_ACK  |
  | DATA ... ------------------->|
  | CLOSE (PARK, 120 s) -------->|                         leaf goes to deep sleep
  | RESUME flood --------------->|                         wake: no new handshake
  |<---------------- RESUME_ACK  |
  | DATA ... ------------------->|
  | CLOSE (normal) ------------->|
```

### 4.1 Rules

1. SEEK is flooded (`next_hop` 0xFFFF, `ttl` = SEEK_TTL, section 11) with
   `dst_id` = target group (or a unit ID, "group of one"), a fresh 32-bit
   `nonce_s` (rule 15), the sender's caps, its `max_frame`, `key_epoch`,
   `proto_minor` and `fw_build`. In the field profile SEEK carries
   `auth_tag` under `K_mesh(key_epoch)` and every forwarding node verifies it
   before any state change (11.4). SEEK carries no session authority: only
   HELLO and BIND do.
   Boot holdoff: the first SEEK after boot waits `rand(0..BOOT_SPREAD_MS)`
   where `BOOT_SPREAD_MS = 200 x pl/node_count` (10 s for 50 nodes), so a
   site-wide power cycle does not produce 25 simultaneous floods (review F10).
2. Each probe subscribed to the group, with a free session slot (rule 12) or
   already bound to this sender (rule 3), waits a random delay in
   0..`HELLO_WINDOW_MS` and sends HELLO unicast along the reverse route the
   SEEK installed (11.4). HELLO carries `nonce_s`, a fresh `nonce_p`, caps,
   `max_frame` (= min of its own `max_frame - rs_nsym` and the SEEK's
   `path_mtu`), the RSSI at which it heard the SEEK, `path_cost` of the best
   SEEK copy it received inside the window, `status` 0, `key_epoch`,
   `proto_minor`, `fw_build`. HELLO is tagged under `K_hs` (section 8). The
   probe enters OFFERED and starts `BIND_TIMEOUT` (rule 10). A probe keeps
   at most `PROBE_OFFERS_MAX` (4) OFFERED entries and ignores further SEEKs
   until one expires (review S12). Further copies of the same SEEK (same
   `src_id`, same `seq`) are duplicates and ignored.
   A probe with no free slot still answers HELLO with `status` 1 (FULL) so
   the sender can tell "group full" from "group gone" (review F9); it keeps no
   OFFERED state for it.
3. A probe bound to sender X that receives a SEEK from X with a new
   `nonce_s` answers HELLO with a fresh `nonce_p` like any other SEEK, and
   keeps the existing session untouched. Only an authenticated BIND (rule 6)
   for the new nonces replaces the old session with that sender; a replayed
   or forged SEEK therefore changes nothing (review S3). The old session's
   frames keep flowing until then.
4. Sender selection policy. `PL_SELECT_FIRST` (default, the user's
   first-acknowledger-wins): the first valid HELLO with `status` 0 wins and
   BIND is sent at once. `PL_SELECT_BEST`: wait `SEEK_BASE_MS` (= HELLO_WINDOW_MS +
   SELECT_MARGIN_MS + 2 x SEEK_TTL x HOP_DELAY_MS; the hop count is unknown
   before the first HELLO), then pick
   the lowest `path_cost`, ties broken by RSSI. In both policies up to
   `HELLO_CANDIDATES` (4) further HELLOs are kept as fallbacks until the
   session is established, and a candidate whose first hop (`prev_hop` of the
   HELLO) is on the sender's penalty list (4.2) is ranked last.
   If every HELLO says FULL the sender treats the group as present but busy:
   it backs off to the 60 s cap of rule 8 at once.
5. The sender floods BIND (like SEEK) with `dst_id` = group, naming the chosen
   `probe_id`, both nonces, the new `session_id`, and an 8-byte `inner_tag`
   under `K_hs` over (`nonce_s`, `nonce_p`, `probe_id`, `session_id`). The
   outer `auth_tag` is under `K_mesh` so forwarding nodes can police the flood
   (review F24 / S8). The chosen probe verifies the inner tag, replies
   BIND_ACK (under `K_hs`) and enters BOUND. All other probes in OFFERED for
   this `nonce_s` return to LISTENING on the outer tag alone; a forged BIND
   therefore costs at most one re-SEEK.
6. A probe in OFFERED that receives a BIND naming it with an `inner_tag` that
   does not verify, or with nonces it does not know, ignores it silently. A
   probe in LISTENING (not OFFERED) that is named in a BIND ignores it
   (review F25). A probe in OFFERED that ran out of slots since its HELLO
   replies BIND_NAK (reason BUSY, under `K_hs`). The sender then tries its
   next candidate, and if none is left restarts SEEK.
7. A probe that sent HELLO and hears no valid BIND within `BIND_TIMEOUT`
   (rule 10) returns to LISTENING.
8. No usable HELLO within `SEEK_TIMEOUT(n)`: resend SEEK with the same
   `nonce_s` and a new pre-session seq. Backoff is full-jitter and never
   gives up (review F10): attempt n waits `rand(0, min(SEEK_CAP_MS,
   SEEK_BASE_MS x 2^n))` with SEEK_BASE_MS = 600 (section 9) and SEEK_CAP_MS
   = 60000, so a sender whose probe is offline floods about once a minute,
   not never and not continuously. `PL_EVT_NO_PROBE` is raised after the 5th
   attempt as an event; the application may call `pl_seek_cancel()`. The
   last two attempts before the cap MAY raise ttl to MAX_HOPS.
   A probe in OFFERED that hears the same `nonce_s` again with a newer `seq`
   (a retry, not a duplicate copy) assumes its HELLO was lost and sends HELLO
   again (new random delay, same `nonce_p`).
9. The session starts on BIND_ACK. Without BIND_ACK the sender resends BIND
   every `BIND_RETRY(hops) = max(BIND_RETRY_MS, hops x HOP_DELAY_MS)` up to
   `BIND_RETRIES` times, then falls to rule 6 (next candidate or re-SEEK).
   Retries are floods with new seqs; forwarding nodes do not charge them to
   the origin's flood budget (11.5). A probe that is already BOUND to this
   `(src_id, nonce_s, nonce_p)` and receives the BIND again resends BIND_ACK
   without changing state (idempotent, covers a lost BIND_ACK).
10. Timers scale with hops (the probe reads `hops` from the SEEK header, the
    sender from HELLO; a direct link is hops = 1):
    `BIND_TIMEOUT(hops) = HELLO_WINDOW_MS + SELECT_MARGIN_MS + (BIND_RETRIES + 2) x BIND_RETRY(hops) + 2 x hops x HOP_DELAY_MS`.
    The inequality it must satisfy is
    `BIND_TIMEOUT > HELLO_WINDOW_MS + SELECT_MARGIN_MS + hops x HOP_DELAY_MS + BIND_RETRIES x BIND_RETRY(hops) + hops x HOP_DELAY_MS`
    (HELLO travel, all retries, last BIND travel), and it holds with a margin
    of two retry intervals at every hop count:

    | hops | BIND_RETRY | BIND_TIMEOUT | needed |
    |---|---|---|---|
    | 1 | 60 | 490 | 370 |
    | 2 | 120 | 910 | 670 |
    | 4 | 240 | 1750 | 1270 |
    | 8 | 480 | 3430 | 2470 |

    On paths with an IR hop (`path_mtu <= 58`) both ends multiply by
    `time_scale` 10.
11. `session_id` is chosen by the sender: 1..255, never 0, never equal to the
    previous session_id it used with any probe; the counter is seeded from
    the low byte of `pl/preseq` at boot so it does not repeat across reboots.
    Sessions are matched on `(src_id, session_id)` everywhere; the transport
    a frame arrives on is irrelevant (review F25).
12. Multi-session is mandatory on non-leaf probes: `PL_MAX_SESSIONS >= 4` for
    frames up to 255 bytes (review F9). Each session has its own context
    (Appendix B). Probes that accept ESP-NOW v2 / UDP frames above 255 bytes
    either run one session or cap `arq_window` at 8. Leaves run one session.
13. Any frame with a `session_id` the receiver does not know, from a `src_id`
    it is not bound to, is dropped and counted. In the bench profile (no
    keys) the receiver MAY reply CLOSE (reason UNKNOWN_SESSION), rate limited
    to one per second per peer. In the field profile nothing is sent: the
    frame cannot be verified and section 8 forbids answering unverified
    frames. A sender that wants fast detection of a rebooted probe sets
    FLAG_ACK_REQ on one frame per keepalive interval and closes after
    `ARQ_MAX_RETRIES` unanswered requests.
14. Half-duplex carriers (IR, nRF24): a probe does not start its HELLO delay
    until the SEEK frame has fully ended plus `IR_GUARD_MS` (IR) or
    `NRF_GUARD_MS` (nRF24); IR multiplies all section 9 timers by
    `time_scale`.
15. Nonces and counters (review S9 / F28): `nonce_s`, `nonce_p` and the random
    delays come from `esp_random()` only while WiFi or BT is running, or
    with `bootloader_random_enable()` active on nodes without RF (it borrows
    the SAR ADC; do not sample the ADC meanwhile). Every nonce is additionally
    mixed with the persistent counters: `nonce = SHA-256(esp_random() ||
    pl/preseq || pl/boot_count || unit_id || esp_timer_get_time())[0..3]`,
    where `pl/boot_count` is an NVS counter incremented once per boot. Two
    nodes that reboot in the same millisecond therefore never repeat a nonce,
    and a node never reuses one across its own reboots.

Why three messages, not two: with SEEK + ACK only, two probes that both answer
both believe they own the session. BIND tells every probe who won.

### 4.2 Failover and liveness

- Liveness cadence is a session parameter: MODE carries `keepalive_ms`
  (6.1). The probe sends ACK every `ACK_EVERY` frames or `keepalive_ms`,
  whichever comes first; the sender sends PING after `keepalive_ms` of
  silence; both sides use `SESSION_TIMEOUT = max(SESSION_TIMEOUT_MS,
  8 x keepalive_ms, 8 x SRTT)`. A one-sample-per-minute session therefore
  runs at `keepalive_ms` = 30000 and costs two frames per minute instead of
  four per second (review F1).
- Sender side: when no ACK or PONG arrives for `SESSION_TIMEOUT` the sender
  closes the session (CLOSE twice, best effort), waits `rand(0..1000) ms`
  (review F10), and re-SEEKs the same group. Any other probe can take over.
  This is the payoff of seeking a group instead of a fixed device.
- Penalty list (review S13): on each such timeout the sender records the
  session's first hop (`next_hop` of its route) with a timestamp. For
  `PENALTY_MS` (60 s) HELLO candidates whose `prev_hop` is on the list rank
  last (rule 4); after 3 timeouts through the same first hop within 10 min
  that hop is excluded for 10 min. This breaks the loop in which a re-SEEK
  lands on the same black hole. An insider relay that forwards HELLOs but
  drops DATA is still detected only by this statistic; see 11.8.
- Probe side: if no frame from the sender arrives for `SESSION_TIMEOUT` the
  probe returns the slot to LISTENING. Without this a probe whose sender died
  keeps a slot busy forever.
- CLOSE carries a reason and is not acknowledged; the timeouts above cover a
  lost CLOSE. CLOSE reason 6 (PARK) is the exception described in 4.4.

### 4.3 Race catalogue

| Scenario | What goes wrong without a rule | Rule |
|---|---|---|
| Two probes answer the same SEEK | Both think they are bound | BIND names one probe, inner tag binds it (4.1.5) |
| Two senders SEEK the same group at once | A probe HELLOs both, both BIND it | Multi-session probes serve both; a full probe says FULL or BIND_NAKs (4.1.2, 4.1.6) |
| Probe already bound hears a new SEEK from its own sender | Replayed SEEK would kill the session | HELLO answered, old session replaced only by an authenticated BIND (4.1.3) |
| BIND lost | Probe times out, sender keeps retrying into the void | BIND retries finish inside BIND_TIMEOUT at every hop count (4.1.10) |
| BIND_ACK lost | Sender resends BIND, probe treats it as a new bind | Idempotent BIND_ACK (4.1.9) |
| HELLO lost | Sender re-SEEKs, probe sits in OFFERED | Same nonce_s with a newer seq triggers a new HELLO (4.1.8) |
| Late BIND after BIND_TIMEOUT | Undefined probe behaviour | LISTENING probe ignores it (4.1.6) |
| Sender reboots mid-session | Probe stays bound to a ghost | Probe-side timeout (4.2); the new SEEK is answered and the stale session replaced on BIND (4.1.3) |
| Probe reboots mid-session | Sender streams for one timeout into nothing | SESSION_TIMEOUT -> re-SEEK; FLAG_ACK_REQ probing for faster detection (4.1.13) |
| seq wraps at 65535 | FEC groups and ACK bitmaps misalign; recorded frames replay as "newer" | Serial arithmetic for ordering; 48-bit index with implicit ROC in the tags for replay (3.5, 8) |
| Two senders pick the same session_id | Frames mixed on a shared medium | Sessions keyed by (src_id, session_id) (4.1.11) |
| Replayed SEEK/HELLO | Old session key reused | Both nonces enter the key derivation; nonces never repeat (8, 4.1.15) |
| 50 nodes reboot together | Synchronized flood storm | Boot holdoff, full-jitter backoff, jittered re-SEEK (4.1.1, 4.1.8, 4.2) |
| Mesh: two relays rebroadcast the same SEEK at once | Collision, both copies lost | Relay jitter; FLOOD_REPEAT (11.5) |
| Mesh: probe hears SEEK via two paths | Two reverse routes, two HELLOs | Dedup; the lowest-cost copy inside the window sets the route (11.4) |
| Mesh: a relay on the path dies | Session streams into a hole | No RERR; SESSION_TIMEOUT -> re-SEEK installs new routes; stale routes expire in ROUTE_TTL_MS (11.6) |
| Mesh: re-SEEK lands on the same bad first hop | Black hole persists | Penalty list ranks that first hop last (4.2) |
| Mesh: path MTU shrinks after failover | Old MODE no longer fits | Failover is a new session; MODE is re-sent and re-validated (MODE_ACK status 2) (11.3) |
| Mesh: relay reboots mid-session | Frames arrive with no route | Relay drops and counts; it cannot send CLOSE; endpoint timeouts recover (11.4) |
| Mesh: asymmetric link | SEEK gets through, HELLO cannot return | No HELLO -> backoff; a path that completed HELLO has proven both directions once (11.4) |
| Mesh: duplicate unit IDs | Routes flap between two nodes | Manifest + clone check (2); DIAG reports (MAC, unit_id) mesh-wide (11.11) |
| Mesh: flooded BIND reaches the winner twice | Double bind | Idempotent BIND_ACK (4.1.9), dedup cache (11.5) |
| Mesh: BIND flood misses a losing probe | Loser stays in OFFERED | BIND_TIMEOUT returns it to LISTENING; harmless |
| Mesh: origin hears its own flood echoed | False collision alarm, self-route | Origin pre-inserts its floods into dedup; echoes dropped silently (11.5) |
| Leaf wakes after a park | Routes to it expired | RESUME floods with small ttl and re-installs routes (4.4) |

### 4.4 Parked sessions and leaves (review F1)

Leaves are battery nodes that deep-sleep between reports. The session model
is kept, and the handshake is paid once per route change instead of once per
wake:

- Leaves are senders only; they never serve a group (no listen window exists
  while asleep) and never forward. Non-leaf nodes MUST be mains or solar
  powered; a relay on a battery lasts about a day (estimate) and is a
  misconfiguration, reported by DIAG (`power_src` field).
- Before sleeping, the leaf sends CLOSE with reason 6 (PARK) and `park_s`,
  the maximum sleep time in seconds (1..3600). The probe keeps the session
  context (keys, ROC/seq state, config) for `park_s + PARK_GRACE_S` (60) and
  stops expecting liveness. The slot counts as occupied.
- The leaf keeps `{probe_id, session_id, K_s2p, K_p2s, Ke_*, ROC, seq,
  config_id, route hops, key_epoch}` in RTC slow memory (`RTC_DATA_ATTR`,
  about 120 bytes), never in flash. A brown-out that clears RTC memory simply
  costs one full handshake.
- On wake the leaf sends RESUME (type 0x31) under the parked `K_s2p`, with
  the session's next seq/ROC, flooded with `ttl = min(hops + 1, SEEK_TTL)`
  because every relay route to and from it expired while it slept (11.6).
  Forwarding nodes treat RESUME as a flood verified by its hop_tag (11.4),
  so it re-installs reverse routes; the probe verifies the auth_tag, replies
  RESUME_ACK (type 0x32, payload as ACK) on the reverse route, which installs
  the forward routes, and the leaf sends DATA at once. No MODE is needed
  unless the config changed. One flood per wake, no nonces, no key
  derivation.
- If RESUME_ACK does not arrive within `RTO x ARQ_MAX_RETRIES` the leaf falls
  back to a full SEEK. If the probe's park window has expired or the probe
  rebooted, the RESUME fails the tag or finds no session and is dropped
  silently; the fallback covers that.
- Wake budget (estimate, ESP32-C3, ESP-NOW): radio init 120 ms + RESUME /
  RESUME_ACK round trip 50-200 ms + DATA + CLOSE(PARK) 20 ms, about 0.3 s
  awake at about 100 mA, about 0.01 mAh per wake. One report per minute is
  about 15 mAh/day (4 months on 2000 mAh); one per five minutes about 1.5
  years. A full handshake per wake would cost 3-5x that and two network-wide
  floods per wake.
- A leaf uses the maximum `keepalive_ms` (60000) in MODE: it parks before
  any liveness frame would be due, requests ACKs with FLAG_ACK_REQ instead,
  and runs `arq` = 1 with a window of 4.

---

## 5. Message types

| Type | Name | Dir | Tag key | Payload |
|---|---|---|---|---|
| 0x01 | SEEK | S -> group (flood) | K_mesh | nonce_s u32, caps u16, max_frame u16, key_epoch u8, proto_minor u8, fw_build u32 (14 bytes; header also carries path_mtu, path_cost) |
| 0x02 | HELLO | P -> S | K_hs | nonce_s u32, nonce_p u32, caps u16, max_frame u16, rssi i8, status u8 (0 ok, 1 full), key_epoch u8, proto_minor u8, fw_build u32, path_cost u8 (21 bytes) |
| 0x03 | BIND | S -> group (flood) | K_mesh outer | nonce_s u32, nonce_p u32, probe_id u16, session_id u8, inner_tag[8] = HMAC(K_hs, nonce_s || nonce_p || probe_id || session_id)[0..7] (19 bytes) |
| 0x04 | BIND_ACK | P -> S | K_hs | nonce_s u32, nonce_p u32 |
| 0x05 | MODE | S -> P | K_s2p | see 6.1 |
| 0x06 | MODE_ACK | P -> S | K_p2s | config_id u8, status u8 (0 ok, 1 unsupported, 2 too big, 3 bad arg) |
| 0x07 | BIND_NAK | P -> S | K_hs | nonce_s u32, reason u8 (1 busy, 2 caps mismatch, 3 auth required, 4 key epoch unknown) |
| 0x10 | DATA | S -> P | K_s2p | see 6.2 |
| 0x11 | PARITY | S -> P | K_s2p | see 3.3 |
| 0x12 | ACK | P -> S | K_p2s | cum_seq u16, bitmap u32 (seqs cum_seq+1 .. cum_seq+32, bit set = received) |
| 0x20 | PING | either | K_s dir | t_tx_us u32 (sender's session clock) |
| 0x21 | PONG | either | K_s dir | t_echo_us u32, t_local_us u32, utc_us u64 (0 if unsynced, 6.5) |
| 0x30 | CLOSE | either | K_s dir | reason u8 (0 normal, 1 timeout, 2 unknown session, 3 application, 4 auth failure, 5 reboot, 6 park), park_s u16 (reason 6 only, else 0) |
| 0x31 | RESUME | S -> P (flood) | K_s2p | config_id u8 (4.4) |
| 0x32 | RESUME_ACK | P -> S | K_p2s | cum_seq u16, bitmap u32 |
| 0x40 | DIAG_REQ | any -> any | K_mesh | nonce u32, flags u8 (bit0 routes, bit1 links) |
| 0x41 | DIAG_RESP | any -> any | K_mesh | nonce u32, then the record of 11.11 |
| 0x42 | TIME_REQ | any -> master | K_mesh | t1 u64 (requester local us) |
| 0x43 | TIME_RESP | master -> any | K_mesh | t1 u64 echo, t2 u64 (rx, UTC us), t3 u64 (tx, UTC us), stratum u8 |
| 0x44 | KEY_UPDATE | S -> P (in session, ENC) | K_s2p + CCM | epoch u8, idx u8, total u8, TLV items (8.6) |
| 0x45 | KEY_UPDATE_ACK | P -> S | K_p2s | epoch u8, idx u8, status u8 |

"K_s dir" means the directional session key of whoever sends the frame
(`K_s2p` from the sender, `K_p2s` from the probe). The hop_tag on every frame
is under `K_mesh` regardless of type.

caps bits (u16): 0 HIGH, 1 LOW, 2 ARQ, 3 AUTH, 4 group FEC, 5 LEN16, 6 RELAY
(node forwards frames; clear on leaves, 11.1), 7 ENC (AES-CCM payload
encryption, 8.5), 8 MULTI (probe serves several sessions), 9-15 reserved
(0). In-frame RS is not a cap: it is fixed per link (1.2). A session uses the
intersection of both ends' caps. In the field profile a probe drops SEEKs
without a valid `K_mesh` tag and rejects (BIND_NAK reason 3) any sender
whose caps lack AUTH; a SEEK whose `key_epoch` is neither the current nor the
previous epoch gets BIND_NAK reason 4 only if the probe can derive `K_hs`
for it, which it cannot, so in practice it is dropped and counted
(`epoch_mismatch`), and DIAG shows the mismatch.

`max_frame` in SEEK is the sender's own value (transport adapter, 1.2).
HELLO's `max_frame` is `min(probe's own max_frame - rs_nsym, path_mtu from the
SEEK header)`. The session uses `min(sender's own max_frame - rs_nsym, HELLO
max_frame)`, which is the path MTU (11.3); on a direct link it is simply the
smaller end. SEEK, BIND and RESUME are flooded (11.5); DIAG_REQ and TIME_REQ
MAY be flooded when the origin has no route to `dst_id`; all other types are
unicast hop by hop.

Probes never send DATA. Only the sender chooses the resolution mode.

---

## 6. Data and resolution modes

### 6.1 MODE frame

```
config_id      u8    1..255 (never 0), increments on every change, wraps to 1
mode           u8    0 = HIGH, 1 = LOW
ch_count       u8    1..16
period         u32   nominal sample period, us (flags bit0 = 0) or ms (bit0 = 1)
fec_k          u8    2..16 (ignored if fec_m = 0)
fec_m          u8    0 = no group FEC, else 1..4
arq            u8    0 = fire-and-forget, 1 = retransmit on ACK gaps
flags          u8    bit0 period unit (0 us, 1 ms); bits 1-7 reserved, 0
keepalive_ms   u16   ACK / PING cadence, 0 = section 9 defaults (250 / 500); max 60000
then per channel:
  kind         u8    0 = digital, 1 = analog
  fmt          u8    analog: 0 uint32, 1 int32, 2 float32
                     digital: number of lines, 1..32
  [LOW analog only]
  scale        f32
  offset       f32
```

- MODE must fit in one frame (no fragmentation anywhere in this protocol).
  The fixed part is 13 bytes, so 16 LOW analog channels need 13 + 16 x 10 =
  173 payload bytes: fine on ESP-NOW/UDP/BLE-247/UART paths, not on IR.
  IR with AUTH has max payload 58 - 17 - 12 = 29: one LOW analog channel
  (13 + 10 = 23) or eight digital/HIGH descriptors (13 + 16 = 29). Without
  AUTH (bench) IR allows 41 bytes: two LOW analog or 14 descriptors. Paths
  through an IR hop inherit the same limit via `path_mtu`.
- At least one complete sample (all channels) must fit in a DATA frame,
  otherwise the probe replies MODE_ACK status 2 (too big).
- The sender may send MODE at any time after BIND_ACK. DATA keeps using the
  old `config_id` until MODE_ACK arrives. The sender resends MODE every
  `MODE_RETRY_MS` until MODE_ACK; the probe re-acks an already-active
  `config_id` without side effects.
- The probe keeps the last two configs, so frames in flight during a switch
  still decode. DATA with an unknown `config_id` is dropped and counted.
- The v0.3 flag "probe should send ACK even when arq = 0" is gone: ACKs are
  always sent at the keepalive cadence (section 7), which removes the 6.1 /
  7 contradiction of review F25. `period` in ms (bit0) covers sampling
  periods above 71 minutes (review F21).

### 6.2 DATA payload

```
config_id      u8
status         u8    bit0 CLIP (a LOW value saturated in this frame)
                     bit1 OVERRUN (samples were dropped before this frame)
                     bit2 INVALID (at least one INVALID code in this frame)
                     bit3 UNSYNCED (sender has no network time, 6.5)
                     bits 4-7 reserved, 0
t_first_us     u32   timestamp of first sample, sender session clock (6.5)
n_samples      u8    1..255
samples        n_samples x (all channels, in descriptor order)   sample-major
```

Sample-major means: sample 0 channel 0, sample 0 channel 1, ..., sample 1
channel 0, ... Sample i has nominal time `t_first_us + i * period`.

| Channel kind | HIGH | LOW |
|---|---|---|
| Analog uint32 / int32 | 4 bytes, raw value | 2 bytes, int16 q, value = offset + q * scale |
| Analog float32 | 4 bytes, IEEE-754 binary32 LE, NaN/Inf allowed | 2 bytes, int16 q as above; NaN/Inf become INVALID |
| Digital | 4 bytes, bitmap of 32 lines, line i = bit i | ceil(lines / 8) bytes, line i = byte i/8 bit i%8 |

Digital values are lossless in both modes; HIGH/LOW only changes packing.
"Resolution" applies to analog channels.

LOW quantization at the sender, computed in float32 (24-bit mantissa, more
than enough for a 16-bit result):

```
q = round((v - offset) / scale)
q = clamp(q, -32767, 32767)         -> if clamped, set status.CLIP
q = -32768 (INVALID) if v is NaN/Inf or the sample is missing
```

For a known range `[min, max]` choose `scale = (max - min) / 65534` and
`offset = (max + min) / 2`; the range then maps to exactly -32767..32767.
Example: 0..3.3 V gives scale = 50.36 uV per step (3.3 / 65534), q(0 V) = -32767,
q(1.65 V) = 0, q(3.3 V) = 32767, q(4.0 V) = 32767 with CLIP set. For uint32 /
int32 channels converting `v` to float32 first loses bits below 2^-24 of `v`,
which is far below one q step for any sane `scale`; exact integer math is not
required.

Range overflow policy: saturate, never wrap, and flag it. A receiver that sees
CLIP in a LOW session should switch the sender to HIGH or widen the range; the
protocol only guarantees the flag is set.

### 6.3 What fits in one frame

Data bytes per frame = path_mtu - 17 (header + CRC) - 7 (DATA header) - 12
(AUTH, field profile) (- 1 with FLAG_LEN16, - 9 or - 10 more when fec_m > 0,
see 3.3), where `path_mtu = max_frame - rs_nsym` of the smallest link on the
path (11.3); on a direct link that is the link itself.

Example: 4 analog channels, no group FEC.

| Link / path | path_mtu | Data bytes (AUTH) | HIGH / LOW samples per frame (16 / 8 B each) | bench, no AUTH |
|---|---|---|---|---|
| ESP-NOW v1 (250) | 250 | 214 | 13 / 26 | 226: 14 / 28 |
| ESP-NOW v2 (1470, LEN16) | 1470 | 1433 | 89 / 179 | 1445: 90 / 180 |
| WiFi UDP (255) | 255 | 219 | 13 / 27 | 231: 14 / 28 |
| BLE (MTU 247 -> 244) | 244 | 208 | 13 / 26 | 220: 13 / 27 |
| BLE (MTU 64 -> 61) | 61 | 25 | 1 / 3 | 37: 2 / 4 |
| nRF24L01+ (255 reassembled) | 255 | 219 | 13 / 27 | 231: 14 / 28 |
| UART (255, nsym 8) | 247 | 211 | 13 / 26 | 223: 13 / 27 |
| IR (64, nsym 6) | 58 | 22 | 1 / 2 | 34: 2 / 4 |
| ESP-NOW -> bridge -> IR | 58 | 22 | 1 / 2 | 34: 2 / 4 |
| ESP-NOW -> bridge -> nRF24 | 250 | 214 | 13 / 26 | 226: 14 / 28 |

Throughput context (estimates): ESP-NOW at its default 1 Mbps PHY rate gives
on the order of 100 kbit/s of goodput, roughly 50 full v1 frames per second;
`esp_wifi_config_espnow_rate()` can raise the PHY rate. nRF24L01+ at 2 Mbps
with 32-byte segments and ESB auto-ACK delivers roughly 30-60 kbit/s of frame
payload after segmentation overhead (C.6), i.e. about 15-25 full 250-byte
frames per second per link. IR at 2 kbit/s gives about 3 frames per second,
so 4 LOW channels stream at roughly 6 samples per second with AUTH. Choose
`period` and `n_samples` so the frame rate stays under the carrier's limit
with margin for PARITY and retransmissions.

### 6.4 BLE mapping

BLE is an optional, per-node carrier (`pl/ble` in NVS, default off; 12.5).
The radio is shared with WiFi, so ESP-NOW relays MUST NOT run BLE scanning;
BLE belongs on edge sensors and on the bridge that serves them.

BLE has no "broadcast a frame and get unicast replies" primitive, and the
legacy 31-byte advertisement cannot hold a SEEK frame (34 bytes plus AD
headers). So BLE links are connections, and advertising is only neighbour
discovery:

- A BLE edge node (peripheral only) advertises a "ProbeLink node" beacon: a
  manufacturer-specific AD (company ID 0xFFFF, the Bluetooth SIG test ID,
  until a real one is assigned) carrying `magic u16` = 0x504C ("PL"),
  `version u8`, `unit_id u16` and `caps u16`. Foreign 0xFFFF beacons fail the
  magic check and are ignored (review F5).
- A BLE bridge (central only) connects only to unit IDs on its NVS allowlist
  (`pl/ble_peers`), requests the ATT MTU (1.2), uses a connection interval of
  100 ms or more and `esp_coex_preference_set()` toward WiFi, and from then on
  treats the connection as a point-to-point link: every frame including
  flooded SEEK/BIND goes over one write-without-response characteristic
  (central -> peripheral) and one notify characteristic (peripheral ->
  central). A flood on BLE is a write to each connected neighbour (11.10).
- Fixed roles prevent two nodes from connecting to each other twice and
  prevent connection churn as neighbours appear. ESP32 supports only a few
  simultaneous connections (verify `CONFIG_BT_ACL_CONNECTIONS` /
  `CONFIG_BT_NIMBLE_MAX_CONNECTIONS` in menuconfig), so a bridge serves a
  handful of BLE edges, not a BLE-only mesh.
- The ESP-NOW "broadcast for floods" of 1.2 maps on BLE to "write to all
  connections"; nothing else in the handshake changes.

### 6.5 Timestamps, clock drift and network time

- Session clock: each end starts a 32-bit microsecond counter from its own
  `esp_timer_get_time()` at the moment it sends or receives BIND_ACK (or
  RESUME_ACK after a park). `t_first_us`, `t_tx_us`, `t_echo_us`,
  `t_local_us` are all in the owner's session clock.
- Wrap: 2^32 us = 71.6 minutes. Receivers extend to 64 bits by assuming
  consecutive DATA frames are less than 2^31 us (35.8 min) apart; a session
  with no DATA for longer than that must be re-anchored by a PING/PONG pair.
- Drift: two ESP32 crystals typically differ by 20-40 ppm, i.e. 1.2-2.4 ms per
  minute (estimate). The nominal `period` is the sender's intent; the actual
  ADC clock differs by the sender's crystal error. The receiver can (a) trust
  `t_first_us` per frame and resample, which is the recommended default, or
  (b) fit `t_local = a + b * t_sender` from PING/PONG pairs
  (`offset = t_local_us - t_echo_us - RTT / 2`) and convert to its own clock.
- Network time (review F16): the gateway (SNTP or GPS) is the time master.
  Every node syncs with TIME_REQ / TIME_RESP (NTP's four timestamps over the
  mesh, 11.11) every `TIME_SYNC_S` (600 s) against a master from its NVS
  list `pl/time_masters`; a node accepts time only from a listed master, or
  from a node whose TIME_RESP `stratum` is lower than its own and which is
  itself synced to a listed master (stratum = master's + 1). Accuracy over
  radio hops is a few ms, over an IR hop tens of ms (estimates), which is
  enough to align sensors across sessions and failovers. PONG carries
  `utc_us` so a probe can anchor the sender's session clock to UTC directly:
  `utc_of(t_sender) = pong.utc_us - (pong.t_local_us - fit(t_sender))`. A node
  without a sync in `3 x TIME_SYNC_S` sets DATA status bit 3 (UNSYNCED) and
  the probe stamps its records as relative. A 40 ppm crystal drifts about 2.4
  s per day; the 10-minute sync keeps the error under about 25 ms.
- Samples inside a frame have nominal times only. If the sender's sampler is
  not isochronous (e.g. a polled I2C sensor), use one sample per frame.

---

## 7. Reliability modes

| Setting | Use when | Behaviour |
|---|---|---|
| arq = 0, fec_m = 0 | Wired UART, short cable | CRC + RS only. Lost frames stay lost. |
| arq = 0, fec_m = 2, fec_k = 8 | Streaming telemetry over radio | Any 2 losses in 10 rebuilt, no added latency from retries |
| arq = 1, fec_m = 2, fec_k = 8 | Data that must arrive | FEC first; ACK bitmap gaps it could not fill get resent |
| arq = 1, fec_m = 0 | Low-rate commands, IR, leaves | Pure ARQ, cheapest in bandwidth |

ACK is sent every `ACK_EVERY` frames or `keepalive_ms`, whichever comes first,
and immediately on FLAG_ACK_REQ, in every session regardless of `arq`. It is
the liveness signal for the sender; with `arq = 0` the sender ignores the
bitmap.

ARQ details:

- Sender keeps the last `ARQ_WINDOW` (32; 8 for frames above 255 bytes; 4 on
  leaves) DATA frames: `ARQ_WINDOW * max_frame` bytes, 8 KB on ESP-NOW v1,
  static. The ACK bitmap covers exactly this window.
- A seq reported missing (bit clear, older than the RTO) is retransmitted
  with its original seq, at most `ARQ_MAX_RETRIES` (3) times, then abandoned
  and reported to the application as a gap.
- RTO: `RTO = max(ARQ_RTO_MS, 2 * SRTT)`. SRTT is seeded by the BIND ->
  BIND_ACK round trip and updated as `SRTT = 7/8 SRTT + 1/8 RTT` from every
  PING/PONG pair and every FLAG_ACK_REQ -> ACK pair. Single-hop radio sessions
  never leave the floor; multi-hop and IR paths scale automatically. Measured
  RTT is used rather than a hop count because an IR hop costs about ten radio
  hops. `SESSION_TIMEOUT = max(SESSION_TIMEOUT_MS, 8 * keepalive_ms, 8 * SRTT)`
  and `REORDER_MS = max(500, 4 * SRTT)` follow the same rule. The probe keeps
  its own SRTT: it seeds it with the HELLO -> BIND interval and sends a PING
  of its own whenever it has heard nothing for `keepalive_ms`, measuring the
  PONG.
- `cum_seq` is the highest seq such that every seq up to it is either
  received, recovered by FEC, or expired from the reorder buffer (reported as
  a gap). The receiver cannot know whether a missing seq was DATA, PARITY or
  PING, so the bitmap simply reports seqs; the sender retransmits only
  cleared-bit seqs it still holds as DATA and ignores the rest. The sender
  frees everything up to `cum_seq`. Consequence: `on_gap()` counts may include
  non-DATA seqs when a whole group and its PARITY frames are lost.
- Receiver delivery: in seq order through a reorder buffer of `fec_k + fec_m`
  frames (4 when FEC is off) or `REORDER_MS`, whichever fills first. A frame
  still missing when its slot expires is reported as `on_gap(first_seq,
  count)` and delivery continues. Late retransmissions for an already reported
  gap are dropped.
- Group FEC and ARQ compose: FEC removes most losses with no round trip, ARQ
  cleans up the rest. Retransmitted frames are also valid FEC group members.

Queues (review F19):

- The transport RX queue between the carrier callbacks and `pl_task` is
  `RX_QUEUE_FRAMES` (16) deep; callbacks use `xQueueSend` with timeout 0 and a
  full queue increments `rx_queue_drop`. Nothing in a WiFi/BT callback ever
  blocks.
- The relay forwarding queue has two classes. Control frames (every type
  except DATA and PARITY) are never dropped in favour of data: when the queue
  is full and a control frame arrives, the oldest DATA/PARITY frame is
  dropped (`relay_drop_queue_data`); a control frame is dropped only when the
  queue holds nothing but control frames (`relay_drop_queue_ctrl`). This
  stops the feedback loop in which congestion drops ACKs, sessions time out,
  and the re-SEEK floods add load.

---

## 8. Security

This section is written as requirements with their mechanism. The attacker
model is: an outsider in radio range or on the LAN (no keys); a thief who
removes one node and reads its flash; a malicious or buggy forwarding node
inside the mesh. Reviews F2, F17, F22, F24 and S1-S20 are addressed here and
in 11.8.

### 8.1 Requirements

| Req | Statement | Mechanism |
|---|---|---|
| R1 | Keys and firmware MUST be protected at rest. A node's flash dump MUST NOT yield usable key material. | Field profile MUSTs (12.1): Secure Boot v2, flash encryption in release mode, NVS encryption, JTAG and UART download mode disabled by eFuse. |
| R2 | A captured node MUST NOT allow derivation of other pairs' session keys or impersonation of any other unit ID. | No network-wide secret with session authority. Per-pair keys derived offline from `K_site` (8.2); a node holds only the pairs it is allowed to talk to. |
| R3 | Every frame an endpoint acts on MUST be authenticated end to end, including its sequence position. | `auth_tag` over the end-to-end header, the 48-bit index and the payload (8.4). |
| R4 | A forwarding node MUST NOT change any table (link, route, dedup, rate, suppression) because of a frame it has not authenticated. | `hop_tag` under `K_mesh` on every frame, verified before any state change (8.4, 11.4). |
| R5 | A frame MUST NOT be accepted twice, and a recorded frame MUST NOT be accepted later, within or across sessions. | 48-bit index with implicit ROC, replay bitmap, fresh nonces mixed with persistent counters, per-origin freshness for pre-session frames (8.4, 3.5, 4.1.15). |
| R6 | Session authority (who is bound to whom, with which session_id and mode) MUST NOT be obtainable from the mesh key. | HELLO, BIND inner tag, BIND_ACK/NAK under `K_hs`; MODE and all session frames under directional `K_s` (8.3). |
| R7 | Keys MUST be rotatable and a node MUST be revocable without visiting every other node. | Key epochs, KEY_UPDATE over authenticated encrypted sessions, revocation list (8.6). |
| R8 | Payload confidentiality MUST be available where readings are sensitive, and MUST be used for key material. | AES-128-CCM option (8.5), mandatory for KEY_UPDATE. |
| R9 | The field profile MUST NOT be able to run unauthenticated, and test keys MUST NOT work in the field. | `pl_init` refuses a field build without keys; Appendix A keys are blacklisted by hash (12.1). |
| R10 | A node MUST NOT answer a frame that failed any authentication check. | Drop, count, rate-limited log; no CLOSE, NAK or error of any kind (no oracle). |

### 8.2 Keys

All derivations use HKDF-SHA256 (RFC 5869). `||` is concatenation; integers
are little-endian as on the wire.

| Key | Derived by | Formula | Held by |
|---|---|---|---|
| `K_site` | provisioning tool | 32 random bytes, generated and stored offline | nobody in the field |
| `K_mesh(E)` | tool | `HKDF(IKM = K_site, salt = "ProbeLink-mesh", info = E u8, L = 32)` | every node, epochs E and E-1 |
| `K_pair(A, B, E)` | tool | `HKDF(IKM = K_site, salt = "ProbeLink-pair", info = min(A,B) u16 \|\| max(A,B) u16 \|\| E u8, L = 32)` | nodes A and B only |
| `PRK` | both ends at handshake | `HKDF-Extract(salt = nonce_s u32 \|\| nonce_p u32, IKM = K_pair(S, P, E))` | S, P |
| `K_hs` | both ends | `HKDF-Expand(PRK, "ProbeLink-v1 hs" \|\| S u16 \|\| P u16, 32)` | S, P |
| `K_s2p`, `K_p2s` | both ends after BIND | `HKDF-Expand(PRK, "ProbeLink-v1 s2p" \|\| S \|\| P \|\| session_id u8, 32)`, same with "p2s" | S, P |
| `Ke_s2p`, `Ke_p2s` | both ends, if ENC | `HKDF-Expand(PRK, "ProbeLink-v1 enc s2p" \|\| S \|\| P \|\| session_id, 16)`, same with "p2s" | S, P |

S is always the sender's unit ID and P the probe's, in every label.

- Pairwise provisioning: the manifest (12.2) lists, per node, the peers it
  may form sessions with (default: every node in the site, 49 keys x 32
  bytes = 1568 bytes of NVS at 50 nodes). A probe answers HELLO only to
  senders it holds a `K_pair` for; a sender BINDs only probes it holds one
  for. Group membership is therefore also an authorization list.
- What a captured node yields: `K_mesh(E)`, `K_mesh(E-1)` and its own
  pairwise keys. With these the holder can impersonate that one node to its
  peers, forward or drop frames (it is a node), and originate floods within
  the rate limits. It cannot derive any `K_pair` it was not given, hence no
  `K_s` of any session it is not an endpoint of, and it cannot claim another
  unit ID to any peer (R2). Recovery is revocation plus a mesh-key epoch
  bump (8.6).
- Bench profile only: a single `pl/net_key` MAY stand in for `K_site` on the
  device, with `K_mesh` and every `K_pair` derived locally. This is the v0.3
  model and is not permitted in the field (R9).

### 8.3 Which key protects which frame

| Frames | auth_tag key | Why |
|---|---|---|
| SEEK, RESUME-as-flood hop policing | `K_mesh(E)` for SEEK; RESUME's auth_tag is `K_s2p` | Before HELLO no pair is known; SEEK carries no authority. Forwarding nodes police floods on the K_mesh tags. |
| HELLO, BIND inner_tag, BIND_ACK, BIND_NAK | `K_hs` | Proves possession of `K_pair(S, P)` and freshness of both nonces; `session_id` does not exist yet. |
| BIND outer auth_tag | `K_mesh(E)` | Lets forwarding nodes verify the flood; authority is in the inner tag. |
| MODE, DATA, PARITY, PING, CLOSE, KEY_UPDATE (sender side) | `K_s2p` | Directional keys: a frame captured in one direction can never verify in the other (review S17). |
| MODE_ACK, ACK, PONG, CLOSE, RESUME_ACK, KEY_UPDATE_ACK (probe side) | `K_p2s` | |
| DIAG_REQ/RESP, TIME_REQ/RESP | `K_mesh(E)` | Sessionless, any node to any node; carry no session authority. Time is additionally gated by the master allowlist (6.5). |
| hop_tag on every frame | `K_mesh(E)` | Link-layer admission (R4). |

Key confirmation: HELLO proves the probe holds `K_pair`; the BIND inner tag
proves the sender does; BIND_ACK closes the loop. MODE/MODE_ACK then confirm
the directional keys.

### 8.4 Tags, index and replay window

- `tag_input = e2e_header || ROC u32 || payload`, where `e2e_header` is the
  header with the per-hop fields removed: bytes 0..5 (`ver_flags`, `type`,
  `src_id`, `dst_id`) then `session_id`, `seq`, `len` (4 or 5 bytes). ROC is
  the 32-bit roll-over counter of 3.5 (0 for pre-session frames).
  `auth_tag = HMAC-SHA256(key, tag_input)[0..7]`. 8 bytes (64 bits) rather
  than 4: BIND, MODE and CLOSE each take over a session with a single accepted
  frame, and a 32-bit tag at a few hundred frames per second falls to brute
  force in weeks.
- `hop_tag = HMAC-SHA256(K_mesh(E), frame[0 .. end of auth_tag])[0..3]`,
  recomputed by every transmitter because the hop fields change. The receiver
  verifies against the current epoch, then the previous one. 32 bits is
  enough here: a forged hop_tag only gains a link-table or dedup entry, and
  the attempt rate is bounded by airtime, not CPU.
- `ver_flags` is inside `tag_input`, so a forwarding node cannot add or strip
  FLAG_AUTH or FLAG_LEN16 without detection.
- Replay window: per session and direction the receiver keeps `highest_index`
  (ROC, seq) and a 64-bit bitmap of seen indices below it. Accept a frame iff
  its index is newer than `highest_index`, or within the last 64 and not yet
  seen; otherwise drop and count `replay_dropped`. Retransmitted DATA frames
  (same index) are handled before this check by the ARQ layer: a duplicate
  index that is already delivered is dropped as a duplicate, not as a replay,
  and either way it is not delivered twice. Across sessions a new `K_s`
  makes old frames fail the tag check; within a session the ROC makes frames
  from a previous 16-bit cycle fail (review F17).
- Pre-session frames: forwarding nodes keep a per-origin `last_seq` (11.5)
  and drop non-newer `(src_id, seq)`; the persistent counter of 3.5 makes
  this survive reboots. DIAG/TIME requests carry a 32-bit nonce echoed in the
  response, so a response can only answer one request.
- Sessions have no hard lifetime cap: the 48-bit index allows 2^48 frames.
  Policy MAY still re-BIND daily to rotate `K_s`; nothing in the protocol
  requires it.
- Cost: HMAC-SHA256 of a 250-byte frame on ESP32 with the mbedtls/hardware
  SHA path is tens of microseconds (estimate); two per forwarded frame is
  still negligible at these frame rates.

### 8.5 Confidentiality (caps bit 7, ENC)

- Cipher: AES-128-CCM, 8-byte tag (mbedtls `MBEDTLS_CCM_C`, hardware AES on
  all ESP32 variants). When ENC is negotiated, the payload field carries the
  ciphertext and `auth_tag` carries the CCM tag; there is no separate HMAC.
- Nonce (13 bytes): `dir u8 (0 s2p, 1 p2s) || src_id u16 || dst_id u16 ||
  session_id u8 || ROC u32 || seq u16 || 0x00`. Every (key, nonce) pair is
  unique because the index never repeats within a session.
- AAD: `e2e_header || ROC u32` (the same prefix as `tag_input`).
- Group FEC operates on plaintext blocks (3.3); PARITY payloads are encrypted
  like any other frame.
- ENC is optional for sensor data and mandatory for KEY_UPDATE. ESP-NOW CCMP
  (PMK/LMK) remains available per hop as defence in depth, within
  `CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM` (default 7, maximum 17; verify in
  menuconfig). Encrypted ESP-NOW frames cannot be broadcast, so floods stay
  CCMP-clear on the air (they are still tagged).

### 8.6 Key epochs, rotation and revocation

- Every node stores epochs E (current) and E-1 (previous) of `K_mesh` and of
  its pairwise keys (NVS `pl/epoch`, `pl/mesh_key/<E>`, `pl/pair/<id>/<E>`).
  Receivers accept either; senders use E. SEEK and HELLO carry `key_epoch`
  so the peers agree on which pair key feeds the handshake.
- KEY_UPDATE: the gateway (or any node holding the manifest role "key
  server") SEEKs each node by unit ID, negotiates ENC, and sends KEY_UPDATE
  frames (type 0x44) whose TLV items are:

  | TLV | Content |
  |---|---|
  | 0x01 | `K_mesh(E+1)` (32 bytes) |
  | 0x02 | `unit_id u16, K_pair(self, unit_id, E+1)` (34 bytes), repeated |
  | 0x03 | revoke `unit_id u16`: delete all pair keys for it, add to `pl/revoked` |
  | 0x04 | activate: `at_utc_s u32`, 0 = when every peer in the manifest has acknowledged, or after `KEY_ACTIVATE_FALLBACK_S` (86400) |
  | 0x10 | UPDATE_WINDOW (12.6): `ssid`, `psk`, `url`, `sha256[32]`, `deadline_s u32`, each string length-prefixed |

  The node acknowledges each chunk with KEY_UPDATE_ACK and writes the items
  to the E+1 slot. At activation E+1 becomes current and E-1 is erased.
  A node that missed the activation (asleep, out of range) is still accepted
  under E for one more epoch and receives the update when next reached.
- Revocation of a captured node: the key server sends TLV 0x03 to every
  peer that held a pair with it and bumps the mesh epoch. Peers stop
  answering it immediately; after E+1 activates and E is erased its
  `K_mesh` is useless too. The revoked node never receives E+1 because its
  own pair key with the key server is deleted first.
- Adding a node later: the manifest gains a row, and the key server pushes
  one TLV 0x02 to each peer of the new node. No other node is visited.
- Transition: during a rollout, nodes on E and E-1 interoperate. A node two
  epochs behind is unreachable and must be re-provisioned by cable; the
  gateway's DIAG sweep reports `key_epoch` per node so this is visible before
  it happens.

### 8.7 Other requirements

- Per-hop link encryption is optional (8.5).
- Logs MUST NOT print keys, nonces or tags at any level in a field build.
- `esp_random()` quality: rule 4.1.15.
- Security counters (`auth_fail`, `hop_tag_fail`, `replay_dropped`,
  `epoch_mismatch`, `relay_drop_meshtag`, `relay_drop_rate`) are part of
  DIAG_RESP (11.11), so a gateway sees attacks and misconfiguration without a
  cable (review S20).
- Enumeration: unit IDs, caps and beacons are visible to anyone in range.
  This is accepted; the protocol hides readings (with ENC), not topology.
  ID-collision alarms cannot be triggered by outsiders because the frames
  that raise them must pass the hop_tag (review S19).

---

## 9. Constants

One normative timer table (review F25). Radio defaults; multiply every *_MS
by `time_scale` (10 on IR) when an IR hop is involved; `hops` is the route
hop count, 1 on a direct link.

| Name | Default | Note |
|---|---|---|
| HELLO_WINDOW_MS | 50 | probe random delay range |
| SELECT_MARGIN_MS | 20 | extra wait for PL_SELECT_BEST |
| HELLO_CANDIDATES | 4 | fallback probes kept |
| PROBE_OFFERS_MAX | 4 | concurrent OFFERED entries per probe |
| BIND_RETRY_MS | 50 | floor; `BIND_RETRY(hops) = max(50, hops x HOP_DELAY_MS)` |
| BIND_RETRIES | 3 | |
| BIND_TIMEOUT | formula 4.1.10 | 490 ms direct, 1750 ms at 4 hops |
| SEEK_BASE_MS | 600 | = HELLO_WINDOW + SELECT_MARGIN + 2 x SEEK_TTL x HOP_DELAY_MS, rounded up |
| SEEK_CAP_MS | 60000 | full-jitter backoff cap; never give up |
| BOOT_SPREAD_MS | 200 x pl/node_count | first SEEK after boot waits rand(0..this) |
| MODE_RETRY_MS | 100 | |
| SESSION_TIMEOUT_MS | 2000 | floor; actual = max(2000, 8 x keepalive_ms, 8 x SRTT) |
| RESEEK_JITTER_MS | 1000 | wait rand(0..this) before re-SEEK after a timeout |
| PENALTY_MS | 60000 | first-hop penalty after a session timeout |
| ACK_EVERY | 8 frames | |
| keepalive_ms default | 250 (ACK) / 500 (PING) | MODE keepalive_ms = 0 |
| FEC_K / FEC_M | 8 / 2 | radio default; 2 / 1 on IR |
| FEC_FLUSH_MS | 100 | close a partial group |
| ARQ_WINDOW | 32 | frames; 8 above 255-byte frames; 4 on leaves |
| ARQ_RTO_MS | 100 | floor; actual = max(100, 2 x SRTT) |
| ARQ_MAX_RETRIES | 3 | |
| REORDER_MS | 500 | floor; actual = max(500, 4 x SRTT) |
| REPLAY_WINDOW | 64 | indices |
| RX_QUEUE_FRAMES | 16 | transport callback -> pl_task |
| IR_GUARD_MS / NRF_GUARD_MS | 20 / 2 | half-duplex turnaround |
| PL_MAX_GROUPS | 8 | subscriptions per probe |
| PL_MAX_SESSIONS | 4 minimum | per non-leaf probe |
| PARK_GRACE_S | 60 | added to park_s at the probe |
| TIME_SYNC_S | 600 | network time period |
| SEEK_TTL | 4 | initial ttl of flooded frames (11.5) |
| MAX_HOPS | 8 | hard cap on ttl; the 4-bit field allows 15 |
| MIN_PATH_MTU | 48 | smallest path_mtu a SEEK may carry |
| HOP_DELAY_MS | 60 | per-hop budget for handshake timer scaling (11.7) |
| RELAY_JITTER_MS | 50 | random delay before a node rebroadcasts a flood |
| FLOOD_REPEAT | 2 | copies per flood on carriers without MAC retry (11.5) |
| RELAY_SUPPRESS_COUNT | 0 (off) | counter-based suppression; see 11.5 for when to enable |
| DEDUP_ENTRIES / DEDUP_TTL_MS | 64 / 5000 | flood duplicate cache; 256 / 20000 on nodes with an IR transport |
| ORIGIN_ENTRIES / ORIGIN_TTL_S | 64 / 86400 | per-origin freshness (last_seq) |
| ROUTE_ENTRIES / ROUTE_TTL_MS | 32 / 6000 | route table size and idle expiry (11.6) |
| LINK_ENTRIES / LINK_TTL_MS | 32 / 60000 | (unit_id, transport) -> carrier address |
| RELAY_QUEUE_FRAMES | 8 | forwarding queue depth, two classes (section 7) |
| FLOOD_BUCKET_ORIGIN | depth 6, refill 2/s | per-origin flood budget; BIND retries free (11.5) |
| FLOOD_BUCKET_TOTAL | depth 20, refill 10/s | per-node flood budget |
| FLOOD_BUCKETS | 64 | hashed by src_id |
| DIAG_RATE | 1/s per requester | |

---

## 10. Prior art

Research summary (see the references at the end of this section). No existing
protocol covers the full requirement list; several cover parts of it well.

| Project | Carriers | Addressing | Integrity | FEC | Discovery / session | Typed samples | Verdict |
|---|---|---|---|---|---|---|---|
| PJON | ThroughSerial, ESPNOW, AnalogSampling (IR/LED), LocalUDP, SoftwareBitBang | 1-byte device IDs (+ bus ID) | CRC8 / CRC32, optional ACK | none | none (no seek, no first-ACK-wins) | none | Closest match; see below |
| MAVLink v2 | any byte stream | 1-byte system + component IDs | CRC-16/MCRF4XX, optional signing | none | heartbeat, no bind | fixed message set | Good signing model, no FEC, no group seek |
| RadioHead | radio chips via drivers (incl. nRF24) | node addresses, reliable datagram, RHMesh | CRC via radio | none | none | none | No ESP-NOW/BLE/IR |
| RF24Network / RF24Mesh | nRF24L01+ | 16-bit octal tree addresses; RF24Mesh assigns them from a master node | ESB hardware CRC only | none | tree join to a master, no group seek | none | nRF24-only; fragmentation of 24-byte payloads into up to 255 segments and a static tree topology; no multi-carrier bridging, no end-to-end auth, no sample typing |
| SerialTransfer | UART only | none | COBS + CRC-8 | none | none | none | Framing reference only |
| wfb-ng | raw 802.11 (Linux) | none | per-packet | RS erasure across packets (zfec, k=8 n=12) | none | none | Model for section 3.3; Linux only |
| BTHome v2 | BLE advertising | MAC | AES-CCM | none | advertising only | value encoding with factors | Model for LOW scale/offset idea |
| ESP-WIFI-MESH | WiFi | MAC | WiFi | none | mesh formation | none | WiFi only, heavier than needed |

Why not just PJON: PJON is the only project with strategies for four of the
carriers (serial, ESP-NOW, light/IR, UDP) and it already gives device IDs,
CRC and optional ACK. It lacks the things this protocol is actually about:
no forward error correction of either kind (in-frame RS or cross-frame), no
seek-a-group / first-acknowledger-wins session handshake, no BLE or nRF24
strategy, no multi-hop forwarding, no end-to-end authentication and no
HIGH/LOW typed sample payloads. Two realistic ways to use it anyway: (a) wrap
PJON strategies as ProbeLink transport adapters (1.2), paying one extra PJON
header per frame; or (b) borrow PJON's bit-banging and light-sampling code
for the IR PHY (appendix C) and keep everything above the transport native.
For an ESP-IDF project (b) is the cleaner path.

Why not RF24Network / RF24Mesh for the nRF24 carrier: they solve the
nRF24-only problem well (tree routing, address assignment from a master,
fragmentation of long messages) but assume every node is an nRF24 radio
with one master, so they cannot bridge to ESP-NOW or UART, and they have no
authentication at all. ProbeLink uses the radio the same way they do (ESB
auto-ACK unicast on per-node pipe addresses, a shared NO_ACK broadcast
address) and keeps its own routing above it. The RF24 driver itself
(nRF24/RF24 on GitHub, ESP-IDF port available) is the sensible SPI layer to
reuse.

RS libraries usable on ESP32: Arduino-FEC (github.com/simonyipeter/Arduino-FEC,
small, Arduino style), libcorrect (C, has decode-with-erasures, fits ESP-IDF
as a component), Schifra (C++ templates, heaviest). A minimal GF(2^8) RS
encoder plus erasure-only decoder is about 300 lines of C if you prefer no
dependency; the test vectors in appendix A are enough to validate it.

References: github.com/gioblu/PJON; MAVLink v2 protocol docs; RadioHead
library docs; nRF24/RF24, RF24Network and RF24Mesh (github.com/nRF24);
SerialTransfer (PowerBroker2); wfb-ng (svpcom); BTHome v2 format; ESP-IDF
ESP-WIFI-MESH docs; ESP-IDF issue #9575; RFC 5869 (HKDF); RFC 3711 (SRTP,
implicit ROC); RFC 1982 (serial number arithmetic).

---

## 11. Mesh layer

Forwarding is part of the base protocol: every frame carries origin/final
and hop fields (section 3), every conforming node runs the forwarding rules
below, and a direct link is a one-hop route. This section is separate only
for readability. Sessions (section 4) sit on top and never know how many hops
they cross; a node that bridges two carriers (UART <-> ESP-NOW, ESP-NOW <->
nRF24, ESP-NOW <-> IR) is the normal case, not a special one.

### 11.1 Roles and the per-hop / end-to-end split

| Role | caps RELAY | Power | Does |
|---|---|---|---|
| Node (default) | 1 | mains or solar, MUST | Originates and terminates its own sessions, forwards everyone else's frames, keeps the tables of 11.9, serves groups |
| Bridge | 1 | mains or solar, MUST | A node with 2+ transports; re-frames between carriers: strips the incoming per-hop layers and applies the outgoing ones |
| Gateway | 1 | mains | A bridge with a LAN side (12.4); time master, DIAG poller, key server |
| Leaf | 0 | battery | Speaks the full frame format, originates sessions as a sender, parks them while asleep (4.4), forwards nothing, serves no group |

Routes never pass through a leaf by construction: routes are installed from
the `prev_hop` of frames a node transmitted (11.4), and a leaf transmits only
frames it originates, so every route "via a leaf" ends at that leaf. The
RELAY caps bit is exchanged so endpoints can log topology. Below, "relay"
means any non-leaf node in its forwarding role; the `relay_*` counters in
Appendix B follow the same usage.

Power budget per role (estimates, ESP32-C3, ESP-NOW): a relay or probe keeps
the radio in RX permanently, 80-100 mA, mains only. A leaf as in 4.4 averages
well under 1 mA at one report per five minutes. There is no role between
these two: a node that sleeps cannot forward or serve.

What is per-hop and what is end-to-end is the heart of the design:

| Layer | Scope | Reason |
|---|---|---|
| COBS, in-frame RS parity, nRF24 segmentation | per hop | They belong to the carrier; a bridge strips them and applies the next carrier's |
| CRC-16 | per hop, recomputed by every forwarding node | The hop fields change at every hop. A node verifies the CRC before forwarding so a corrupt frame dies at the first hop instead of burning airtime downstream |
| hop_tag | per hop, recomputed | Admission: only keyed nodes can make another node learn, route or forward anything (R4) |
| Hop fields (`prev_hop`, `next_hop`, `ttl_hops`, SEEK `path_mtu` / `path_cost`) | per hop, rewritten | Link-layer facts |
| End-to-end header fields, payload, auth_tag | end to end, never modified | Forwarding nodes have no session key and no session state |
| Group FEC, ARQ, replay window, session timers | end to end | Forwarding nodes treat DATA, PARITY, ACK, PING, MODE, CLOSE as opaque unicast frames |

### 11.2 Hop fields

The per-hop fields are defined in section 3; this is why each exists.

- `src_id` / `dst_id` are origin / final destination. Session matching on
  `(src_id, session_id)` and tag coverage use them; forwarding nodes only
  read `dst_id` to look up a route.
- `prev_hop` is needed because not every carrier gives a usable link-layer
  address: IR and a UART bus have none, and on ESP-NOW/UDP/nRF24 the
  address-to-unit-ID mapping is not known in advance. Route learning (11.4)
  needs it.
- `next_hop` lets the intended node act on a frame heard by several nodes on
  a shared medium (IR room, ESP-NOW broadcast) and lets bridges pick the
  outgoing transport. 0xFFFF marks flooded frames.
- `ttl_hops`: `MAX_HOPS` is 8 and the 4-bit fields allow 15; receivers drop
  anything above 8 (3.6). `hops` feeds the handshake timers (11.7).
- `path_mtu` (SEEK only) is a hop field and not payload because forwarding
  nodes lower it hop by hop while the payload is covered by the K_mesh tag
  and must not change. A node clamps it to the incoming link's own value
  before use (3.6), so it can never be raised.
- `path_cost` (SEEK only, review F6): the sum of link costs along the path so
  far. The origin writes 0; each node adds the cost of the link the copy
  arrived on before forwarding. Link cost from RSSI where the carrier
  reports it: 1 at or above -75 dBm, 3 in -85..-75, 10 in -90..-85; copies
  below -90 dBm are ignored. Carriers without RSSI use `link_cost` from the
  adapter: UART 1, BLE 2, nRF24 2, IR 20.

Byte cost: 5 bytes per frame (8 on SEEK), plus 12 bytes of tags in the field
profile. The per-path data-bytes table is in 6.3.

### 11.3 Mixed carriers: path MTU, not fragmentation

Every session frame is sized by the sender to the smallest link on the path.

- SEEK leaves the origin with `path_mtu = max_frame - rs_nsym` of the
  transport it goes out on (a bridge floods one copy per transport, each with
  that transport's value and the same seq). Each forwarding node sets
  `path_mtu = min(path_mtu, max_frame - rs_nsym of the outgoing transport)`.
- The probe sets HELLO `max_frame = min(own max_frame - rs_nsym, path_mtu)`.
  HELLO returns over the same links, which are assumed symmetric per carrier,
  so no second pass is needed. The session rule of section 5 then yields the
  path MTU; on a direct link it degenerates to the smaller end.
- In-frame RS parity is excluded from `path_mtu` because it is re-applied per
  hop with the outgoing link's `rs_nsym`. The nRF24 adapter's segmentation is
  likewise invisible: it advertises `max_frame` 255 and splits per hop (C.6).
- Forwarding nodes still check that a unicast frame fits the outgoing link
  (`header (15, or 16 with FLAG_LEN16) + len + 12 + 2 <= max_frame - rs_nsym`)
  and drop + count `relay_drop_mtu` otherwise: a route can change after the
  negotiation.
- Failover (4.2) is a new SEEK, a new HELLO and a new MODE, so a smaller path
  after failover is caught by MODE_ACK status 2 and the sender shrinks
  `n_samples` or switches to LOW.

Why not hop-by-hop fragmentation at the mesh layer: (1) reassembly needs
per-relay buffers and state for frames in flight, exactly what 11.1 forbids;
(2) a fragment cannot be tag-verified on its own, so a relay could not drop a
corrupt or forged fragment early; (3) losing any fragment loses the frame,
multiplying the loss rate on the link that caused the fragmentation; (4) FEC
groups (3.3) are defined over whole frames. Path MTU costs airtime efficiency
on the fast links of a mixed path, but the slow link is the bottleneck
anyway, so throughput is unchanged. The one exception is the nRF24L01+,
whose 32-byte packet is below MIN_PATH_MTU: there the segmentation is
link-local, inside one adapter, with one reassembly buffer per neighbour and
the whole frame dropped on any missing segment, so none of the four
objections apply above the adapter (C.6).

### 11.4 Routing: AODV-lite on SEEK and HELLO

Route table entry: `{dst_id u16, next_hop u16, transport u8, hops u8,
cost u8, expiry u32}`. Only two events install or change `next_hop`;
everything else only refreshes `expiry`. Every event below happens only for
frames that passed 3.6 and the tag checks of step 5; nothing an unverified
frame carries ever reaches a table (review F22 / S4 / S5).

| Event | Installs |
|---|---|
| Flooded SEEK, BIND or RESUME received from `prev_hop` on transport T | Reverse route: `dst = src_id (origin)`, `next_hop = prev_hop`, `T`, `hops + 1`, `cost = path_cost + link cost`. Within the node's jitter window a copy with lower cost replaces the entry; afterwards only a fresher flood (newer `(src_id, seq)`) does. |
| Unicast HELLO received from `prev_hop` on T | Forward route: `dst = src_id (probe)`, `next_hop = prev_hop`, `T`, `hops + 1`, `cost` from the HELLO payload |
| Any forwarded unicast frame | Refreshes `expiry` of the routes to its `dst_id` and `src_id`; never changes `next_hop` |

Flow for a 2-hop session (S = sender, R = relay, P = probe):

```
S --SEEK flood (ttl 4, prev S, next FFFF, mtu 250, cost 0)--> R   R: route S via S (cost 1); dedup (S, seq)
R --SEEK flood (ttl 3, hops 1, prev R, mtu 58, cost 1)------> P   P: route S via R, hops 2, cost 21 (IR link)
P --HELLO unicast (next R, max_frame 58, cost 21)-----------> R   R: route P via P
R --HELLO (next S)------------------------------------------> S   S: route P via R, hops 2
S --BIND flood (ttl 4)--------------------------------------> R --> P (and every probe in the group within ttl)
P --BIND_ACK unicast----------------------------------------> R --> S
S --MODE / DATA / PARITY unicast (next R)-------------------> R --> P
P --ACK / PONG unicast--------------------------------------> R --> S
```

Forwarding pipeline run by every node on every received frame, in order;
each drop has its own counter (`pl_stats_t`). The order is the security
property: nothing after step 5 runs for a frame that fails step 5.

| Step | Condition | Action |
|---|---|---|
| 1 | per-hop decode fails (COBS, RS, nRF24 reassembly, CRC) | drop, `crc_fail` / `rs_fail` / `seg_fail` |
| 2 | length and header range checks of 3.6 fail | drop, `bad_frame` |
| 3 | version unknown and the frozen prefix does not parse | drop, `bad_version` (an unknown version with a valid prefix is forwarded but never delivered locally) |
| 4 | field profile and FLAG_AUTH clear, or FLAG_AUTH set and `len` leaves no room for the tags | drop, `auth_fail` |
| 5 | field profile: hop_tag fails under K_mesh(E) and K_mesh(E-1) | drop, `hop_tag_fail`; nothing learned, nothing replied |
| 5b | flood (next_hop 0xFFFF) of type SEEK or BIND: auth_tag fails under K_mesh | drop, `relay_drop_meshtag` |
| 6 | always (frame is now admitted) | learn link: `(prev_hop, transport)` -> carrier address, refresh `LINK_TTL_MS` (11.9) |
| 7 | unicast and `dst_id` is me or a group I subscribe to | hand a copy to the local endpoint logic. Flooded frames are delivered locally only at step 9e, after freshness, dedup and budget checks, so a replayed flood never reaches endpoint state (review S12) |
| 8 | `next_hop` is neither me nor 0xFFFF | overheard, drop silently (no counter) |
| 9a | flood: `src_id` is my own ID | echo of my own flood: drop silently (11.5); not a collision |
| 9b | flood with `session_id` 0: `(src_id, seq)` not newer than the origin's `last_seq` (ORIGIN table) | drop, `relay_drop_stale`. RESUME carries a session seq from an independent counter and is exempt; its replay protection is the probe's session window (8.4) |
| 9c | flood: `(src_id, session_id, seq)` in dedup cache | drop, `relay_drop_dedup` (a lower-cost copy still updates the reverse route inside the jitter window) |
| 9d | flood: per-origin or total flood bucket empty (11.5) | drop, `relay_drop_rate` |
| 9e | flood: insert into dedup (and, for `session_id` 0, ORIGIN); install or improve reverse route; now deliver locally if `dst_id` is me, a group I subscribe to, or 0xFFFF (step 7 deferred to here for floods); node is a leaf or `ttl <= 1` | stop here (`relay_drop_ttl` for the ttl case) |
| 9f | flood: otherwise | after `rand(0..RELAY_JITTER_MS)`: take the best copy seen so far; ttl - 1, hops + 1, prev_hop = me, path_mtu lowered, path_cost += link cost of the copy used; recompute hop_tag and CRC; send on every transport (skip a point-to-point transport the frame arrived on), `FLOOD_REPEAT` copies on carriers without MAC retry |
| 10a | unicast: type HELLO | install forward route to `src_id` via `prev_hop` |
| 10b | unicast: no route to `dst_id`, or node is a leaf | drop, `relay_drop_noroute` (no RERR, no CLOSE: a forwarding node is not an endpoint; the endpoints' timeouts recover) |
| 10c | unicast: `route.next_hop == prev_hop` | would send it back: drop, `relay_drop_loop` |
| 10d | unicast: `ttl <= 1` | drop, `relay_drop_ttl` |
| 10e | unicast: does not fit outgoing link | drop, `relay_drop_mtu` |
| 10f | unicast: forwarding queue full | class-aware drop (section 7), `relay_drop_queue_*` |
| 10g | unicast: otherwise | ttl - 1, hops + 1, prev_hop = me, next_hop = route.next_hop; recompute hop_tag and CRC; per-hop encode; send on `route.transport`; refresh both routes' expiry; `relay_fwd` |

Endpoints originate unicast frames with `ttl = min(MAX_HOPS, route.hops + 2)`
and `next_hop = route.next_hop` (direct link: hops 1, ttl 3, next_hop =
dst_id); flooded frames with `ttl = SEEK_TTL`, `prev_hop = own unit ID`,
`hops = 0`, `path_cost = 0`. An origin that has no route for a unicast
DIAG_REQ or TIME_REQ MAY flood it instead; the reply installs the route.

### 11.5 Flood control

Flooded frames are SEEK, BIND and RESUME (plus optional DIAG_REQ / TIME_REQ
without a route). BIND is flooded, not unicast to the winner, because losing
probes several hops away must hear who won; a loser that misses it only
wastes its BIND_TIMEOUT. The winner's delivery is protected by the BIND
retries of 4.1.9, each a new flood with a new seq.

- Origin bookkeeping (review F23): before transmitting a flood the origin
  inserts its own `(src_id, session_id, seq)` into its dedup cache and
  remembers the last 16 seqs it flooded. A frame with `src_id` = own ID whose seq is in that
  history is an echo and is dropped without an alarm; one whose seq is not in
  the history, or any frame with `prev_hop` = own ID from another carrier
  address, raises `PL_EVT_ID_COLLISION`.
- Dedup cache: `DEDUP_ENTRIES` (64) entries of `(src_id, session_id, seq,
  timestamp, best_cost)`, FIFO replacement, lifetime `DEDUP_TTL_MS` (5 s radio, 20 s on
  nodes with an IR transport). Sizing: `DEDUP_ENTRIES >= FLOOD_BUCKET_TOTAL
  refill x DEDUP_TTL_MS / 1000` so an entry outlives its TTL under full load
  (10/s x 5 s = 50 < 64; 256 for IR nodes). Key is `(src_id, session_id,
  seq)`, not `(src_id, nonce_s)`, because SEEK retries and BIND retries reuse
  the nonce and must be forwarded; `session_id` is in the key because a
  RESUME (session seq) and a SEEK (pre-session seq) from one node may carry
  the same 16-bit value. `FLOOD_REPEAT` copies of one flood carry the same
  seq and are dropped by dedup after the first; they exist only to survive a
  broadcast collision.
- Per-origin freshness (ORIGIN table, review S12): 64 entries of `(src_id,
  last_seq, timestamp)`, lifetime 24 h, applied to floods with `session_id`
  0 only (SEEK, BIND, flooded DIAG/TIME). A flood whose pre-session seq is
  not newer than `last_seq` (serial arithmetic) is dropped before it costs
  anything. RESUME uses the session's own counter and is covered by the
  probe's replay window instead. The
  persistent pre-session counter of 3.5 keeps rebooted senders ahead of
  their own history, so this filter never black-holes a legitimate node.
- Flood budget (review F11 / F22 (B)): token buckets run after the tag checks,
  so only authentic floods spend tokens. Per origin: depth 6, refill 2 per
  second, 64 buckets hashed by `src_id` (no LRU reset at 50 nodes). Per node:
  depth 20, refill 10 per second. A BIND whose `(src_id, nonce_s)` matches a
  BIND already forwarded within the last 2 s is a retry and is free, so a
  lossy handshake (SEEK + BIND + 3 retries) always fits. RESUME, DIAG and
  TIME floods cost one token each.
- Jitter: a node waits `rand(0..RELAY_JITTER_MS)` before rebroadcasting so
  nodes that heard the same copy do not collide; during the wait it keeps the
  lowest-cost copy and rebroadcasts that one (review F6).
- Repetition (review F27): on carriers without MAC retry for broadcast
  (ESP-NOW, nRF24 NO_ACK pipe) each flood copy is sent `FLOOD_REPEAT` (2)
  times with independent jitter. Receivers dedup the second copy. This is a
  repetition code for control traffic; it doubles flood airtime, which the
  budgets above already bound.
- Counter-based suppression is off by default (`RELAY_SUPPRESS_COUNT` 0,
  review F8): at 5-50 nodes the budgets bound flood load and suppression
  creates coverage holes at chokepoints. Dense installations (> 8 neighbours
  per node) MAY enable it with count 3 on nodes that are not chokepoints
  (NVS `pl/suppress`).
- TTL: `SEEK_TTL` = 4 by default, `MAX_HOPS` = 8 hard cap. A sender that
  gets no HELLO MAY raise ttl to MAX_HOPS for later attempts (4.1.8).
- Half-duplex carriers: the node's jitter starts after the incoming frame
  ends plus the carrier guard time, and IR flood timers use `time_scale`.

### 11.6 Route lifetime

Routes expire `ROUTE_TTL_MS` (6 s) after the last frame that used them.

- A live session sends in both directions at least every `keepalive_ms` (250
  ms ACK and 500 ms PING by default), so every relay on the path refreshes
  both routes several times per second. Sessions with a long `keepalive_ms`
  (slow sensors, 4.2) have `keepalive_ms` capped at 60 s and their routes do
  expire between frames; their next DATA then finds no route at the first
  relay and is dropped. Such senders MUST re-anchor before each DATA burst
  when `keepalive_ms > ROUTE_TTL_MS / 3` (2 s): the threshold is a third of
  the route lifetime so that one lost ACK or PING cannot let the route expire
  before the next frame. The sender
  floods RESUME first (one flood per burst, `ttl = hops + 1`), which re-installs
  the routes, then sends DATA. Leaves do exactly this on every wake (4.4).
- A dead session stops refreshing; the endpoints give up after
  `SESSION_TIMEOUT`, and 6 s = 3 x the floor means relay state evaporates
  shortly after. Shorter would risk expiring routes during a normal
  retransmission pause on a slow IR path; longer only keeps dead entries
  occupying a 32-entry table.
- Loss of a relay is not signalled (no RERR): the sender's SESSION_TIMEOUT
  triggers re-SEEK, the new flood overwrites reverse routes on every node it
  reaches, the new HELLO overwrites forward routes on the new path. Stale
  entries on nodes off the new path are never consulted and expire. The
  penalty list (4.2) stops the re-SEEK from choosing the same dead first hop.
- Full table: evict the entry with the earliest expiry (`route_evictions`
  counter). 32 entries hold 16 concurrent sessions passing through one relay,
  more than an IR or ESP-NOW relay can carry anyway.

### 11.7 Timers across hops

- Handshake timers (4.1) use hop counts, because no RTT exists yet:
  `SEEK_BASE_MS` = 600 covers HELLO_WINDOW + SELECT_MARGIN + 2 x SEEK_TTL x
  HOP_DELAY_MS (70 + 480); `BIND_RETRY(hops)` and `BIND_TIMEOUT(hops)` are in
  4.1.9-4.1.10 with their table. `HOP_DELAY_MS` = 60 covers the 50 ms relay
  jitter plus ESP-NOW airtime. If `path_mtu <= 58` (64 - 6; BLE at MTU 64
  gives 61) an IR hop is on the path and both ends apply `time_scale` 10 to
  these handshake timers.
- Session timers use measured RTT (section 7): `RTO = max(ARQ_RTO_MS,
  2 x SRTT)`, `SESSION_TIMEOUT = max(2000, 8 x keepalive_ms, 8 x SRTT)`,
  `REORDER_MS = max(500, 4 x SRTT)`. The BIND -> BIND_ACK round trip seeds
  SRTT, so a 2-hop radio path starts around 150-250 ms and an IR path around
  2 s (estimates).
- Group FEC is untouched: recovery latency is still `k + m` frame periods at
  the receiver, independent of hops.
- `keepalive_ms` bounds route refresh (11.6); above `ROUTE_TTL_MS / 3` the
  sender re-anchors with RESUME before each burst.

### 11.8 Security in a mesh

Requirements R2, R4, R5 and R6 of section 8 are what the forwarding pipeline
enforces. Stated for the three attacker classes:

| Attacker | Can | Cannot (mechanism) |
|---|---|---|
| Outsider (no key) | Jam. Make nodes spend CPU verifying hop_tags (bounded by airtime, tens of us each). | Enter any table, consume any flood budget, be forwarded, trigger a reply, or trigger a collision alarm (hop_tag before any state change, R4/R10). Forge or alter session frames (R3). Replay (R5). |
| Node holding K_mesh (any node, or a captured one before revocation) | Originate floods within the budgets; forward, drop, delay, reorder or misroute frames passing through it; read DIAG of any node; answer TIME_REQ (ignored unless it is a listed master or has a lower stratum chained to one); impersonate itself. | Derive any `K_pair` it was not provisioned with, hence read, forge or alter any session it is not an endpoint of, or claim another unit ID to its peers (R2, R6). Forge HELLO/BIND-inner/BIND_ACK for other pairs (K_hs). Raise `path_mtu` or ttl (3.6 clamps). Push time to nodes that do not list it (6.5). |
| Captured node after revocation and epoch bump | Nothing after E is erased on its peers; until then, the row above. | Receive the new epoch (its pair key with the key server is deleted first, 8.6). |

Mechanics specific to forwarding:

- Admission (R4): link learning, route installation, dedup and bucket
  accounting all run after step 5. An outsider frame therefore costs a node
  one HMAC and nothing else; it never changes the node's view of the
  network (reviews F22, S4, S5, S6, S14, S15).
- Floods (SEEK, BIND) are additionally verified on their K_mesh `auth_tag`
  (step 5b) so that a node cannot be made to forward a flood whose end-to-end
  part was altered in transit.
- Residual insider risk: a node holding K_mesh can forward HELLOs and then
  drop DATA (gray hole) or tunnel floods to a distant location (wormhole).
  The penalty list (4.2) steers re-SEEKs away from a first hop that keeps
  timing out, and DIAG link statistics (11.11) expose a node whose
  `relay_fwd` stays high while sessions through it fail. Full protection
  would need per-node asymmetric identities; see 12.7.
- Unkeyed ("open") relays cannot exist in the field profile: without K_mesh
  a node cannot produce a valid hop_tag and nothing it sends is admitted
  (R4), which closes review S16 by construction.
- SEEK amplification: an authentic SEEK is forwarded once per node per
  `(src_id, seq)`; a replayed one is dropped by the ORIGIN table (not newer)
  or, after 24 h, by dedup and the budgets. The budgets cap any origin at 2
  floods per second per node regardless of how it is reached.

### 11.9 Loop prevention and node RAM budget

Loops are prevented by three independent rules: `ttl` (hard bound on damage,
`MAX_HOPS` = 8), the dedup cache (a flood never passes the same node twice),
and step 10c (a unicast frame is never sent back to the node it came from).
Routes change only on SEEK/HELLO, so a transient loop can exist only between
a stale and a fresh route during re-SEEK and lives at most `ttl` hops.

Link table (review F12): keyed on `(unit_id, transport)` so a bridge
neighbour reachable over UART and ESP-NOW has two entries; `LINK_TTL_MS`
(60 s) idle expiry; an entry referenced by a live route is never evicted
(unreferenced entries go first, oldest first); 32 entries; a new carrier
address for an expired or absent entry is a replacement (node swapped,
DHCP renewed), a new address while the entry is live and recently refreshed
is a collision alarm. Entries are learned only at step 6, i.e. from frames
with a valid hop_tag.

RAM per node (static, allocated at init). The "minimum" column is what every
conforming non-leaf node MUST provide; "default" is the section 9 sizing for
a 50-node site.

| Table | Entry bytes | Minimum | Default | Default bytes |
|---|---|---|---|---|
| Route table | 12 | 16 | 32 | 384 |
| Dedup cache | 10 | 32 | 64 | 640 |
| ORIGIN freshness | 8 | 32 | 64 | 512 |
| Link table (unit_id, transport -> address) | 16 | 16 | 32 | 512 |
| Flood buckets | 8 | 32 | 64 | 512 |
| Forwarding queue | max_frame | 4 | 8 | 2000 (ESP-NOW v1), 11760 (v2 1470) |
| Per-hop re-encode scratch | 255 | 2 | 2 | 510 |
| nRF24 reassembly (if present) | 255 + 8 | per neighbour, 4 | 8 | 2104 |
| Total (ESP-NOW v1, no nRF24) | | ~2.8 KB | | ~5.1 KB |

A leaf keeps a 2-entry route table, an 8-entry dedup cache and no forwarding
queue: about 150 bytes. Keys: 32 bytes per pairwise peer per epoch in NVS
(about 3.2 KB for 49 peers x 2 epochs) and in RAM only the pairs of live
sessions. Flash: HMAC-SHA256 and AES-CCM are in mbedtls already.

### 11.10 Carrier notes for mesh links

- ESP-NOW: unicast to `next_hop` through the link table's MAC (link-layer
  retries help), broadcast only for floods. ESP-NOW allows 20 peers in total,
  so the adapter keeps an LRU peer table of 16 plus the broadcast peer and
  evicts the least recently used `next_hop` that no live route references.
  Encrypted peers are further limited (8.5). All mesh nodes on one channel,
  `WIFI_PS_NONE`, no STA (12.4).
- nRF24L01+: unicast to the `next_hop` pipe address derived from its unit ID,
  with ESB auto-ACK and auto-retransmit; floods on the shared NO_ACK
  broadcast address; every frame segmented per hop (C.6). No RSSI: fixed
  link cost 2.
- BLE: links are GATT connections discovered through the beacon of 6.4, on
  BLE-enabled nodes only. A flood is a write to each connected neighbour
  except the one the frame came from (a connection is point-to-point).
- UART: point-to-point, so a flood is never sent back on the transport it
  arrived on (step 9f). `prev_hop` / `next_hop` are still carried so the
  frame format is uniform and a UART bus with several nodes works.
- WiFi UDP: LAN side of the gateway only (12.4); multicast for floods,
  unicast otherwise; configured peer list on isolated LANs (C.5).
- IR: shared, half-duplex, slow, indoor. Keep IR at the edge of the mesh
  (one IR hop to a bridge), link cost 20 so radio paths win when one exists,
  `fec_k = 2, fec_m = 1` on sessions whose `path_mtu <= 58`. Expect the
  handshake to take 2-4 s (estimate) over an IR hop because of time_scale 10.

### 11.11 Diagnostics and time (sessionless frames)

DIAG_REQ / DIAG_RESP (review F15) and TIME_REQ / TIME_RESP (review F16) are
unicast frames between any two nodes, tagged under `K_mesh`, with
`session_id` 0 and the pre-session seq. Any node answers DIAG; only time
masters and synced nodes answer TIME. A node answers at most `DIAG_RATE` (1
per second) per requester and never answers an unverified request.

DIAG_RESP record (little-endian, fixed part then two counted lists):

```
nonce          u32   echo of the request
mac            6     eFuse base MAC
unit_id        u16
proto_ver      u8    major (header version)
proto_minor    u8
fw_build       u32
key_epoch      u8
role           u8    0 node, 1 bridge, 2 gateway, 3 leaf
power_src      u8    0 mains, 1 solar, 2 battery
uptime_s       u32
reset_reason   u8    esp_reset_reason()
reset_count    u16   from the RTC-memory reset log
min_free_heap  u32
stack_hwm      u16   words, pl_task
stats          pl_stats_t (Appendix B), 4-byte counters in declaration order
n_links        u8    then n_links x { unit_id u16, transport u8, rssi_ewma i8, rx u16, crc_fail u16 }   (flags bit1)
n_routes       u8    then n_routes x { dst u16, next_hop u16, hops u8, cost u8 }                         (flags bit0)
```

The record must fit one frame; a node truncates the lists to fit `path_mtu`
and sets `n_links` / `n_routes` accordingly. A gateway polls every node
round-robin (one DIAG_REQ per few seconds) and keeps the history; that
replaces ladders and cables for finding a gray-zone hop, a full queue, a
coexistence problem, a distant ID collision or a reboot loop. Each node also
keeps a 16-entry reset log (reason, uptime at reset) in RTC slow memory; it
survives soft resets and is reported as `reset_count`.

TIME: `t1` is the requester's local time at send, `t2`/`t3` the master's UTC
receive/transmit times, all in microseconds; the requester computes offset
and round trip as NTP does and applies the offset to its UTC estimate. It
accepts a response only from a listed master or a lower-stratum node (6.5),
and only if `t1` echoes an outstanding request.

---

## 12. Deployment profile and open decisions

Every item here is a decision taken in v0.4 that the user can override. Each
names the alternative and what changes if it is flipped.

### 12.1 Bench profile vs field profile

| | Bench | Field (default) |
|---|---|---|
| Keys | optional; a single `pl/net_key` MAY derive everything locally | MUST: per-pair keys and `K_mesh` from an offline `K_site` (8.2); `pl_init` returns `PL_ERR_AUTH` without them |
| FLAG_AUTH | optional | MUST on every frame |
| ENC | optional | optional for data, MUST for KEY_UPDATE |
| Flash | development build | MUST: Secure Boot v2, flash encryption (release mode), NVS encryption (`nvs_sec_provider` / encrypted partition), JTAG disabled, UART download mode disabled, all via eFuse |
| Test keys | allowed | the Appendix A key material is refused at `pl_init` (SHA-256 of `K_site` / `K_mesh` compared against a built-in blacklist) |
| Reply to unverified frames | CLOSE(UNKNOWN_SESSION) allowed | never |
| Logging | anything | no key, nonce or tag bytes at any level |
| Build flag | `CONFIG_PL_PROFILE_BENCH=y` | default; a field image cannot be switched to bench at runtime |

### 12.2 Provisioning (decision)

Per-device NVS partitions are generated from a CSV manifest keyed by base MAC
(`nvs_partition_gen.py`), one row per node: `unit_id`, `unit_mac`, `role`,
`groups`, `channel`, `rs_nsym`, `node_count`, `ble`, `ble_peers`,
`time_masters`, `epoch`, `mesh_key`, pairwise keys for its peer list,
`revoked`. The tool rejects duplicate unit IDs and never writes `K_site`
anywhere but its own encrypted store. Alternative: a commissioning session
over BLE or UART where the gateway pushes the manifest row via KEY_UPDATE;
not chosen for v0.4 because it needs a bootstrap key per device anyway, which
is the manifest again.

### 12.3 Control-frame recovery (decision)

Repetition (`FLOOD_REPEAT` 2) on carriers without broadcast MAC retry, plus
handshake retries, is taken as satisfying "recovery data in every packet"
for control frames (1.1). Alternative: in-frame RS parity on every control
frame on PACKET links (`rs_nsym` 4-8 on ESP-NOW). It costs 4-8 bytes per
frame and does nothing against the dominant failure, a whole lost frame.
Flip by setting `rs_nsym` on the ESP-NOW adapter; the spec allows it.

### 12.4 Radio channel and WiFi STA (decision, review F4)

Rule: all ESP-NOW mesh nodes use one dedicated channel from NVS
(`pl/channel`), run `esp_wifi_set_ps(WIFI_PS_NONE)` and never associate as a
WiFi station. The gateway is a two-chip design: a mesh ESP32 and a LAN
ESP32 joined by the UART carrier; the LAN side runs STA, SNTP, MQTT/HTTPS
OTA and the WiFi UDP carrier. WiFi UDP nodes therefore live on the LAN side
only. The installer picks a mesh channel away from the building AP
(deployment prerequisite); nothing in the mesh follows an AP.

Alternatives: (a) single-chip gateway with the AP pinned to the mesh
channel: works until the AP retunes, which enterprise controllers do on their
own; (b) channel-follow: the gateway announces its channel in a periodic
beacon and nodes that hear no neighbour for 60 s sweep channels 1-13 and store
the new one (rate-limited NVS write). (b) is specified well enough here to
implement if a single-chip gateway is unavoidable; it is not the default
because the sweep leaves the mesh deaf for about 3 s per node and the failure
mode is silent until the next AP reboot.

### 12.5 BLE as an optional carrier (decision, review F5)

BLE is off by default and enabled per node (`pl/ble`). Roles are fixed:
edge sensors are peripherals, bridges are centrals with an allowlist; ESP-NOW
relays never scan. Reason: one radio shared between BLE and WiFi costs
ESP-NOW broadcast reception during every scan window, and floods have no
MAC retry. Alternative: BLE on every node as in v0.3, with long connection
intervals and measured `fec_m`; rejected because the measured loss would
have to be re-done per site.

### 12.6 Firmware update and versions (decision, review F13 / F14)

OTA is out of the ProbeLink wire protocol. The path is: the gateway sends an
UPDATE_WINDOW command (a KEY_UPDATE TLV 0x10 `{ssid, psk, url, sha256,
deadline_s}`, ENC) to one node at a time, farthest first; the node leaves
the mesh, joins the maintenance WiFi, pulls the image with `esp_https_ota`,
verifies the Secure Boot v2 signature, and reboots. Rollback rule: the new
image calls `esp_ota_mark_app_valid_cancel_rollback()` only after it has
completed one session handshake or forwarded 100 frames within 10 minutes of
boot; otherwise it reboots and the bootloader rolls back. UART-only nodes
update through their UART host; IR-only nodes by cable. Version transition:
endpoints accept header version N and N-1 for the duration of a rollout
(configured in the manifest); forwarders forward any version with the frozen
prefix (section 3).

Alternative: an in-mesh chunked transfer (OTA_BEGIN / OTA_CHUNK with arq 1
and FEC / OTA_END over a session to group 0xFFF0). A 1 MB image is 80-90 s
per node direct at ESP-NOW rates and several minutes per extra hop
(estimate), and it needs the node to act as a probe for an image sender.
Not chosen for v0.4 because every mesh node has WiFi hardware; revisit if a
site has no maintenance WiFi at all.

### 12.7 Key architecture (decision, review F2 / S1)

Pairwise symmetric keys from an offline site key, with epochs, KEY_UPDATE
and revocation (8.2, 8.6). Alternative: per-device X25519 key pairs with
site-signed certificates and an ECDH at BIND (tens of ms on ESP32 in
software, estimate). It removes the per-peer key list and the "push one key
to every peer" step when adding a node, and it would also let forwarding
nodes verify HELLO/BIND end to end. Not chosen for v0.4 because the pairwise
scheme meets R2 at 5-50 nodes with no new primitives; the handshake messages
have room (SEEK/HELLO payload) to carry a 32-byte public key later without a
header change.

### 12.8 Leaf sleep model (decision, review F1)

Leaves are sender-only, park sessions with CLOSE(PARK) and resume with a
flooded RESUME (4.4). Alternative A: a sessionless REPORT frame (DATA to a
group with FLAG_ACK_REQ, first ACK wins); cheaper per wake but it bypasses
the seek/bind handshake and the MODE descriptor, so every REPORT would have
to carry its own descriptor. Alternative B: a parent relay that buffers for
the leaf and keeps its routes alive; rejected because it makes relays hold
session state. Also decided: non-leaf nodes MUST be mains or solar powered.

### 12.9 Items left open

- Asymmetric identities (12.7).
- In-mesh OTA (12.6).
- Channel-follow (12.4 b).
- IR bit cell validation on hardware (C.1); IR is scoped indoor/shaded until
  then.
- TRACE (relays appending their ID to a flagged flood) for path drawing: not
  specified because relays cannot append to a tagged payload; DIAG route
  tables give the same information in two polls.
- Health push (unsolicited DIAG_RESP to group 0xFFF1): the gateway poll
  covers it; add if a site has no gateway.

---

## Appendix A. Test vectors

All values computed with the reference script `vectors_v04.py` (Python,
`hmac`/`hashlib` for HKDF and HMAC, `cryptography` for AES-CCM, `reedsolo`
cross-check for RS). Hex is byte order on the wire. Key material here is
TEST ONLY and is refused by field builds (12.1).

A.1 CRC-16/CCITT-FALSE

```
"123456789" (ASCII)                       -> 0x29B1
```

A.2 SEEK frame on ESP-NOW v1, bench profile (no key)

```
src 0x1234, dst 0xFF01 (group), prev_hop 0x1234, next_hop 0xFFFF (flood),
ttl 4 / hops 0, path_mtu 250, path_cost 0, session 0, pre-session seq 1
payload: nonce_s 0xA1B2C3D4, caps 0x0053 (HIGH|LOW|FEC|RELAY), max_frame 250,
         key_epoch 0, proto_minor 0, fw_build 1

10 01 34 12 01 ff 34 12 ff ff 40 fa 00 00 00 01 00 0e
d4 c3 b2 a1 53 00 fa 00 00 00 01 00 00 00  18 3a
|header (18)                                      | |payload (14)               | |crc |
CRC16 = 0x3A18 (stored little-endian: 18 3a); 34 bytes
```

A.3 Same SEEK leaving on UART: path_mtu 247 (255 - 8), RS nsym = 8, then COBS

```
frame (34 bytes):
10 01 34 12 01 ff 34 12 ff ff 40 f7 00 00 00 01 00 0e
d4 c3 b2 a1 53 00 fa 00 00 00 01 00 00 00  23 47                 CRC16 = 0x4723
RS parity (appended): 45 52 50 57 f6 65 5a 46
COBS wire incl. 0x00 delimiter (44 bytes):
0d 10 01 34 12 01 ff 34 12 ff ff 40 f7 01 01 02 01 07 0e d4 c3 b2 a1 53 02 fa
01 01 02 01 01 01 0b 23 47 45 52 50 57 f6 65 5a 46 00
```

A.4 In-frame RS, standalone

```
RS(nsym=6) parity of ASCII "ProbeLink":   28 76 02 56 91 f1
RS(nsym=1) parity of 12 34 56 78 9a:       92   (= XOR of the bytes)
```

A.5 Cross-frame FEC (unchanged from v0.2)

```
k=2, m=1, block_len 5
block0 = 03 01 02 03 00     (len 3, payload 01 02 03, pad)
block1 = 04 10 20 30 40     (len 4, payload 10 20 30 40)
parity0 = 07 11 22 33 40    (= block0 XOR block1)

k=4, m=2, block_len 4
block0 = 02 aa bb 00
block1 = 03 11 22 33
block2 = 01 ff 00 00
block3 = 03 01 02 03
parity0 = 2d 01 2d 19
parity1 = 2e 44 b6 29
Erasing block1 and block3 and decoding with erasure positions {1, 3}
reproduces them exactly.
```

A.6 Keys and an authenticated DATA frame on a direct link

```
K_site (TEST ONLY) = 00 01 02 ... 1f (bytes 0x00..0x1F), epoch E = 1
sender S = 0x1234, probe P = 0x0042, nonce_s 0xA1B2C3D4, nonce_p 0x0BADF00D, session 7

K_mesh(1) = HKDF(K_site, salt "ProbeLink-mesh", info 01, 32)
          = 15e0339cd6e0d2252a7ba30c238e504c70c651eb217736caca7e54c1720c31c3
K_pair    = HKDF(K_site, salt "ProbeLink-pair", info 42 00 34 12 01, 32)
          = 1427086608cb09c6cc10fa2d6ea68ddd3de5a73fbd9a0c10e7754a1a1bf31af5
PRK       = HMAC-SHA256(key = d4 c3 b2 a1 0d f0 ad 0b, msg = K_pair)
          = 78cabd9ffa115f29b1d076f22d0a85a9374f4a0f2f0f678ae5e42914aafc2203
K_hs      = Expand(PRK, "ProbeLink-v1 hs" || 34 12 42 00, 32)
          = 4af7bd34b7897fb51a117cda1568326f1dd05bd3f6cc44e1aec6ab69d9dbbc0e
K_s2p     = Expand(PRK, "ProbeLink-v1 s2p" || 34 12 42 00 07, 32)
          = 4be97a49aa89c4a4886059f28e45d0cfbd9970036ef1270b80bab4b9e7eeb607
K_p2s     = Expand(PRK, "ProbeLink-v1 p2s" || 34 12 42 00 07, 32)
          = af6b0f4f89c0ff415e99017e259d2b4a869766f82ad5c0d84a4c664a96c32c13
Ke_s2p    = Expand(PRK, "ProbeLink-v1 enc s2p" || 34 12 42 00 07, 16)
          = dfd29dcd223a1c26c63ece526e93ce44

DATA, FLAG_AUTH, direct link (prev = src, next = dst, ttl 3 / hops 0),
seq 5, ROC 0, one float32 sample 1.5 at t = 1000 us (40 bytes):
12 10 34 12 42 00 34 12 42 00 30 07 05 00 0b
01 00 e8 03 00 00 01 00 00 c0 3f  b7 65 9d f9 3d 02 c2 9e  4a 5a 24 d8  92 27
|header (15)                                 | |payload (11)                    |
|auth_tag (8)            | |hop_tag  | |crc |
tag_input = e2e header || ROC || payload
          = 12 10 34 12 42 00 07 05 00 0b 00 00 00 00 01 00 e8 03 00 00 01 00 00 c0 3f
auth_tag  = HMAC-SHA256(K_s2p, tag_input)[0..7] = b7 65 9d f9 3d 02 c2 9e
hop_tag   = HMAC-SHA256(K_mesh, frame[0..33])[0..3] = 4a 5a 24 d8
CRC16     = 0x2792 over everything before it
float32 1.5 on the wire: 00 00 c0 3f
```

A.7 LOW quantization, range 0..3.3 V

```
scale = 3.3 / 65534 = 5.0356e-5, offset = 1.65
v = 0.00 -> q = -32767
v = 1.65 -> q = 0
v = 3.30 -> q = 32767
v = 4.00 -> q = 32767, status.CLIP = 1
```

A.8 The A.6 DATA frame relayed over two hops, and a keyed SEEK flood

```
Origin 0x1234 -> node 0x0099 -> final 0x0042. Route hops = 2, so ttl = 4.
tag_input is identical to A.6 (hop fields excluded): auth_tag b7 65 9d f9 3d 02 c2 9e.
hop_tag and CRC are recomputed by 0x0099.

Hop 1 (40 bytes): prev 0x1234, next 0x0099, ttl 4 / hops 0 = 0x40
12 10 34 12 42 00 34 12 99 00 40 07 05 00 0b 01 00 e8 03 00 00 01 00 00 c0 3f
b7 65 9d f9 3d 02 c2 9e  b3 43 21 1b  00 e5                      CRC16 = 0xE500
Hop 2 (40 bytes): prev 0x0099, next 0x0042, ttl 3 / hops 1 = 0x31
12 10 34 12 42 00 99 00 42 00 31 07 05 00 0b 01 00 e8 03 00 00 01 00 00 c0 3f
b7 65 9d f9 3d 02 c2 9e  58 fe fe 64  8d 7e                      CRC16 = 0x7E8D

SEEK flood, field profile, hop 1 on ESP-NOW v1, hop 2 forwarded onto IR:
payload: nonce_s, caps 0x005B (HIGH|LOW|AUTH|FEC|RELAY), max_frame 250, epoch 1, minor 0, fw_build 1
         d4 c3 b2 a1 5b 00 fa 00 01 00 01 00 00 00
auth_tag = HMAC-SHA256(K_mesh, e2e header || ROC 0 || payload)[0..7] = b7 19 12 da 31 e6 5f a9
Hop 1 (46 bytes): prev 0x1234, flood, ttl 4 / hops 0, path_mtu 250, path_cost 0
12 01 34 12 01 ff 34 12 ff ff 40 fa 00 00 00 01 00 0e d4 c3 b2 a1 5b 00 fa 00 01 00 01 00 00 00
b7 19 12 da 31 e6 5f a9  b3 84 77 02  e7 e3                      CRC16 = 0xE3E7
Hop 2 (46 bytes): prev 0x0099, flood, ttl 3 / hops 1, path_mtu 58 (= 64 - 6), path_cost 1 (ESP-NOW link at -60 dBm)
12 01 34 12 01 ff 99 00 ff ff 31 3a 00 01 00 01 00 0e d4 c3 b2 a1 5b 00 fa 00 01 00 01 00 00 00
b7 19 12 da 31 e6 5f a9  5e fb 58 2a  8a 0a                      CRC16 = 0x0A8A
On the IR link the node then appends 6 RS parity bytes (per hop, not shown).
```

A.9 HELLO under K_hs, BIND with outer K_mesh tag and inner K_hs tag

```
HELLO from P (0x0042) to S (0x1234) via 0x0099, ttl 4, pre-session seq 7:
payload: nonce_s, nonce_p, caps 0x005B, max_frame 58, rssi -61 (c3), status 0,
         epoch 1, minor 0, fw_build 2, path_cost 21
         d4 c3 b2 a1 0d f0 ad 0b 5b 00 3a 00 c3 00 01 00 02 00 00 00 15
auth_tag = HMAC-SHA256(K_hs, e2e header || ROC 0 || payload)[0..7] = e8 14 c2 cc 55 11 57 b8
frame (50 bytes):
12 02 42 00 34 12 42 00 99 00 40 00 07 00 15 d4 c3 b2 a1 0d f0 ad 0b 5b 00 3a 00 c3 00 01 00
02 00 00 00 15  e8 14 c2 cc 55 11 57 b8  81 77 09 db  b4 5d          CRC16 = 0x5DB4

BIND flood from S, pre-session seq 2, naming probe 0x0042, session 7:
inner_tag = HMAC-SHA256(K_hs, d4 c3 b2 a1 0d f0 ad 0b 42 00 07)[0..7] = 8d a0 03 ee cd 8c 71 eb
payload (19): d4 c3 b2 a1 0d f0 ad 0b 42 00 07 8d a0 03 ee cd 8c 71 eb
outer auth_tag = HMAC-SHA256(K_mesh, e2e header || ROC 0 || payload)[0..7] = 52 88 ff 24 aa 01 ef 7f
frame (48 bytes):
12 03 34 12 01 ff 34 12 ff ff 40 00 02 00 13 d4 c3 b2 a1 0d f0 ad 0b 42 00 07 8d a0 03 ee cd
8c 71 eb  52 88 ff 24 aa 01 ef 7f  b2 4e 3b 2a  d0 e7                CRC16 = 0xE7D0
```

A.10 ROC estimation and AES-CCM

```
ROC estimation (3.5), (seq, highest, roc) -> roc used:
(0x0005, 0xFFF0, 0) -> 1     wrapped forward
(0xFFF0, 0x0005, 1) -> 0     late frame from the previous cycle
(0x8001, 0x0000, 3) -> 2     late frame, highest just wrapped
(0x7FFF, 0xFFFF, 3) -> 3     in-cycle

AES-128-CCM, ENC negotiated, same frame as A.6:
Ke_s2p = dfd29dcd223a1c26c63ece526e93ce44
nonce (13) = dir 00 || src 34 12 || dst 42 00 || sess 07 || ROC 00 00 00 00 || seq 05 00 || 00
           = 00 34 12 42 00 07 00 00 00 00 05 00 00
AAD        = e2e header || ROC = 12 10 34 12 42 00 07 05 00 0b 00 00 00 00
plaintext  = 01 00 e8 03 00 00 01 00 00 c0 3f
ciphertext = 59 43 20 8c 03 4b 5c 76 66 c6 54
ccm_tag    = 7d bf 98 2c b7 03 3c ec       (goes in the auth_tag field)
frame (40 bytes):
12 10 34 12 42 00 34 12 42 00 30 07 05 00 0b 59 43 20 8c 03 4b 5c 76 66 c6 54
7d bf 98 2c b7 03 3c ec  44 33 6c 66  07 25                          CRC16 = 0x2507
```

## Appendix B. Minimal C API

Design rules: no heap after `pl_init()`, all buffers sized from the config
and placed in a caller-provided context; every call returns `pl_err_t`;
transport RX callbacks only copy into a queue (ESP-NOW and BLE callbacks run
in the WiFi/BT host tasks and must not block or parse there); one
`pl_task()` does all protocol work; nothing that can wait longer than the Task
Watchdog period blocks the caller (review F20).

```c
typedef enum {
    PL_OK = 0,
    PL_ERR_ARG,          /* bad parameter */
    PL_ERR_STATE,        /* call not valid in this state */
    PL_ERR_NO_PROBE,     /* (event) 5 SEEK attempts without HELLO; seeking continues */
    PL_ERR_TIMEOUT,      /* BIND/MODE not acknowledged */
    PL_ERR_BUSY,         /* all candidates FULL or BIND_NAK */
    PL_ERR_TOO_BIG,      /* MODE or sample set does not fit path_mtu */
    PL_ERR_AUTH,         /* field profile without keys, blacklisted test key, or peer key missing */
    PL_ERR_QUEUE_FULL,   /* send queue full, back off */
} pl_err_t;

typedef enum { PL_ROLE_NODE = 0, PL_ROLE_BRIDGE, PL_ROLE_GATEWAY, PL_ROLE_LEAF } pl_role_t;

typedef struct {
    uint16_t       unit_id;        /* from NVS pl/unit_id, checked against pl/unit_mac (2) */
    pl_role_t      role;
    uint8_t        select_policy;  /* PL_SELECT_FIRST | PL_SELECT_BEST */
    uint16_t       max_frame;      /* <= transport max_frame; 0 = transport value */
    uint8_t        fec_k_max;      /* sizes the RX FEC buffer, 2..16 */
    uint8_t        fec_m_max;      /* 0..4 */
    uint8_t        arq_window;     /* 0, 4, 8 or 32 */
    uint8_t        max_sessions;   /* >= 4 on non-leaf probes; 1 on leaves */
    uint8_t        node_count;     /* pl/node_count, sizes BOOT_SPREAD_MS and the tables */
    /* keys: field profile requires all three; bench profile may pass net_key only */
    const uint8_t *mesh_key[2];    /* K_mesh(E), K_mesh(E-1) or NULL */
    uint8_t        key_epoch;
    pl_keystore_t *keystore;       /* pairwise keys by (unit_id, epoch), backed by encrypted NVS */
    const uint8_t *net_key;        /* bench only: derive everything locally */
    /* table sizes, section 11.9 minimums enforced for PL_ROLE_NODE and above */
    uint8_t        route_entries, dedup_entries, origin_entries, link_entries, flood_buckets, relay_queue;
} pl_config_t;

typedef struct {
    uint8_t  config_id, mode, ch_count;
    uint32_t period;               /* us, or ms if flags bit0 */
    uint8_t  fec_k, fec_m, arq, flags;
    uint16_t keepalive_ms;
    struct { uint8_t kind, fmt; float scale, offset; } ch[16];
} pl_mode_t;

typedef struct {
    void (*on_seek_result)(pl_err_t result, uint16_t probe_id, uint8_t hops);  /* PL_OK on BIND_ACK */
    void (*on_bound)(uint16_t peer_id, uint8_t session_id);
    void (*on_mode)(uint8_t session, const pl_mode_t *mode);
    void (*on_samples)(uint8_t session, const pl_mode_t *mode, const uint8_t *samples,
                       uint8_t n_samples, uint32_t t_first_us, uint64_t utc_us, uint8_t status);
    void (*on_gap)(uint8_t session, uint16_t first_seq, uint16_t count);
    void (*on_closed)(uint8_t session, uint8_t reason);
    void (*on_event)(uint16_t event, uint32_t arg);     /* PL_EVT_ID_COLLISION, PL_EVT_NO_PROBE, PL_EVT_KEY_EPOCH, ... */
} pl_callbacks_t;

typedef struct pl_ctx pl_ctx_t;   /* opaque; allocate with the macro below */

/* Static context. RAM (bytes), approximately, per session slot:
 *   tx queue   : 4 * max_frame
 *   rx fec buf : (fec_k_max + fec_m_max) * (max_frame - 28 - rs_nsym)   (3.3, AUTH)
 *   arq buf    : arq_window * max_frame
 *   reorder    : (fec_k_max + fec_m_max) * max_frame
 *   state      : ~600 (keys, ROC, replay bitmap, SRTT)
 * plus per node: forwarding tables of 11.9 (~5.1 KB default), rx queue 16 * max_frame.
 * ESP-NOW v1 probe, 4 sessions, k 8, m 2, window 32:
 *   4 x (1000 + 2220 + 8000 + 2500 + 600) + 5100 + 4000 = ~66 KB.  Fits an ESP32-C3
 *   next to WiFi; with NimBLE as well, use 2 sessions or arq_window 8. */
#define PL_CTX_STATIC(name, max_frame, fec_n, arq_window, sessions) ...

pl_err_t pl_init(pl_ctx_t *ctx, const pl_config_t *cfg, const pl_callbacks_t *cb);
pl_err_t pl_add_transport(pl_ctx_t *ctx, const pl_transport_t *tr, uint8_t *index_out);

/* Sender side. Asynchronous: returns at once, result arrives in on_seek_result.
 * Seeking continues with the 4.1.8 backoff until pl_seek_cancel() or success. */
pl_err_t pl_seek(pl_ctx_t *ctx, uint16_t group_id);
pl_err_t pl_seek_cancel(pl_ctx_t *ctx);
pl_err_t pl_set_mode(pl_ctx_t *ctx, const pl_mode_t *mode);        /* result via on_mode */
pl_err_t pl_send_samples(pl_ctx_t *ctx, const void *samples, uint8_t n_samples,
                         uint32_t t_first_us, uint8_t status);
pl_err_t pl_park(pl_ctx_t *ctx, uint16_t park_s, pl_rtc_state_t *out); /* leaf: CLOSE(PARK), export RTC state */
pl_err_t pl_resume(pl_ctx_t *ctx, const pl_rtc_state_t *in);         /* leaf: RESUME flood on wake */
pl_err_t pl_close(pl_ctx_t *ctx, uint8_t reason);

/* Probe side. groups from NVS pl/groups. */
pl_err_t pl_listen(pl_ctx_t *ctx, const uint16_t *groups, uint8_t n_groups);

/* Gateway / tooling. */
pl_err_t pl_diag_request(pl_ctx_t *ctx, uint16_t unit_id, uint8_t flags, void (*cb)(const pl_diag_t *));
pl_err_t pl_time_master_set(pl_ctx_t *ctx, bool is_master, uint8_t stratum);
pl_err_t pl_key_update(pl_ctx_t *ctx, uint16_t unit_id, const pl_key_tlv_t *items, uint8_t n);

/* Both sides: FreeRTOS task body. Priority above the application, below the
 * WiFi/BT tasks. Stack: measure with uxTaskGetStackHighWaterMark(); 6144 is a
 * starting point with HMAC + CCM enabled. Subscribe it to the Task WDT. */
void pl_task(void *ctx);

typedef struct {
    uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail, seg_fail, bad_frame,
             fec_recovered, arq_retx, gaps, replay_dropped, auth_fail, hop_tag_fail,
             epoch_mismatch, bad_version, id_collisions, rx_queue_drop;
    /* forwarding (section 11), one counter per drop condition in 11.4 */
    uint32_t relay_fwd, relay_drop_ttl, relay_drop_dedup, relay_drop_stale, relay_drop_noroute,
             relay_drop_mtu, relay_drop_rate, relay_drop_meshtag, relay_drop_queue_data,
             relay_drop_queue_ctrl, relay_drop_loop, route_evictions, link_evictions;
    uint16_t stack_hwm_words;
} pl_stats_t;
pl_err_t pl_get_stats(const pl_ctx_t *ctx, pl_stats_t *out);
```

Task layout on a dual-core ESP32: transport callbacks -> `xQueueSendFromISR` /
`xQueueSend` (timeout 0) into `ctx->rx_queue` -> `pl_task` on core 1 parses,
validates (3.6), decodes RS, checks CRC, hop_tag and auth_tag, runs the
forwarding pipeline, FEC/ARQ, and calls the application callbacks. The
application's sampling task writes with `pl_send_samples()`, which only
enqueues; framing, tagging and the transport `send()` run in `pl_task`.
Nothing in the library writes NVS at runtime except `pl/preseq` (once per 64
pre-session frames), `pl/boot_count` (once per boot) and KEY_UPDATE results.

## Appendix C. Carrier notes

C.1 IR PHY (sketch, to be validated on hardware; indoor or shaded only)

- 38 kHz carrier from the RMT peripheral, standard TSOP-style receiver. Direct
  sunlight on the receiver window raises its noise floor; outdoor use needs
  a hood and an optical filter and is out of scope until measured.
- Bit coding: pulse-distance like NEC (mark 560 us, space 560 us = 0, space
  1690 us = 1) runs at about 290 bit/s for a 32-bit NEC frame in 110 ms. That
  is too slow: a 64-byte ProbeLink frame would take 1.7 s. A shorter custom
  cell (mark 300 us, space 300/600 us) gives about 2 kbit/s (estimate), still
  inside what a 38 kHz receiver's AGC tolerates. Validate the cell against
  the chosen receiver's minimum burst and gap figures on hardware.
- Preamble: 9 ms mark + 4.5 ms space before the frame so the receiver's AGC
  settles; 0x00 bytes are legal inside the frame (no COBS on IR; the preamble
  and a trailing 10 ms silence delimit the frame).
- Half duplex: a device never transmits while it is receiving a frame, and
  waits `IR_GUARD_MS` after the end of a received frame before replying.
- Keep `rs_nsym` at 6 (3 correctable bytes) and `fec_k = 2, fec_m = 1`. Report
  `rs_corrected` and `rs_fail` per hour through DIAG to see the daily pattern.

C.2 UART

- 8N1, 115200 baud default; higher is fine on short cables. COBS framing with
  0x00 delimiter; the receiver resynchronises on any 0x00. A frame longer than
  `max_frame` after COBS decoding is dropped.
- Enable the UART hardware FIFO threshold or idle-line interrupt and process
  frames in `pl_task`, never byte by byte in the ISR.
- The two-chip gateway (12.4) is a UART link between a mesh ESP32 and a LAN
  ESP32; both are ordinary nodes and the LAN one is a bridge to WiFi UDP.

C.3 ESP-NOW

- Register peers (`esp_now_add_peer`) for `next_hop` MACs from the link table
  (11.10), with the broadcast peer registered at init. The ESP-NOW send
  callback reports per-frame delivery status for unicast; the adapter may use
  it for link statistics but the protocol does not depend on it.
- Unicast ESP-NOW frames are retried by the WiFi MAC, broadcast frames are
  not; floods are sent `FLOOD_REPEAT` times (11.5).
- `esp_wifi_set_ps(WIFI_PS_NONE)`, fixed channel, no STA (12.4). With STA
  present ESP-IDF defaults to modem sleep and the radio is off between DTIM
  beacons, which drops broadcasts silently.

C.4 BLE

- GATT service with two characteristics: RX (write without response, central
  -> peripheral) and TX (notify, peripheral -> central). Request MTU 247 and
  2M PHY where available. Beacon layout and roles are in 6.4; enable per node
  with `pl/ble`.

C.5 WiFi UDP (review F26)

- UDP port 40888 on every node. Floods go to the administratively scoped
  multicast group 239.255.40.88 with IP TTL 1; unicast goes to the address in
  the link table. Nodes join the group with IGMP at start.
- Addresses: static IPs or DHCP reservations are required; a DHCP renewal
  that changes an address is handled as a link-table replacement (11.9) but
  costs one SESSION_TIMEOUT.
- Isolated LANs (client isolation, multicast filtering on IoT/guest SSIDs):
  configure `pl/udp_peers`, a list of unicast addresses; floods are then sent
  unicast to each peer and multicast is not used. Where neither multicast nor
  a peer list is possible the UDP carrier is unusable; say so during
  installation rather than discovering it from a mesh that never forms.

C.6 nRF24L01+ over SPI (sixth carrier)

Facts designed around: 32-byte maximum packet payload (static or dynamic
length), Enhanced ShockBurst with hardware CRC (1 or 2 bytes), auto-ACK and
auto-retransmit (ARD/ARC), 6 RX pipes, 3-5 byte addresses, 250 kbps / 1 /
2 Mbps, channels 0-125 at 2400 + n MHz, no RSSI (only a carrier-detect bit).

- Class: PACKET. The ESB CRC is per 32-byte packet; the ProbeLink CRC-16
  covers the reassembled frame and stays mandatory.
- Segmentation sublayer, inside the adapter only. A frame of n bytes is sent
  as `ceil(n / 30)` packets of 2-byte segment header + up to 30 bytes:

  ```
  byte 0   frame_tag  u8   per-neighbour counter, same for all segments of one frame
  byte 1   bits 7..1  idx  segment index 0..127; bit 0 LAST (1 on the final segment)
  bytes 2..31         up to 30 frame bytes
  ```

  The last segment's payload length gives the frame length (dynamic payload
  length, DPL, enabled). Receiver: one reassembly buffer per neighbour
  (`NRF_REASM_NEIGHBOURS` = 8, 263 bytes each: 255 + tag + bookkeeping);
  segments must arrive in order (ESB delivers in order per pipe); a missing
  or out-of-order index, a different `frame_tag` before LAST, or
  `NRF_REASM_TIMEOUT_MS` (50 ms) since the last segment drops the whole frame
  and counts `seg_fail`. ESB auto-retransmit (ARC 15, ARD 500 us) makes a
  lost unicast segment rare; the frame-level ARQ and FEC above cover the rest.
  The adapter advertises `max_frame` = 255, so path-MTU logic (11.3) never
  sees 32, and a frame never crosses the nRF24 link in pieces above the
  adapter.
- Overhead and throughput: a 250-byte frame is 9 packets of 32 bytes, 288
  bytes on the air plus 9 x (preamble 1 + address 5 + PCF 9 bits + CRC 2) of
  ESB framing, about 365 bytes, i.e. 1.46x the frame. At 2 Mbps with auto-ACK
  turnaround (about 130 us per packet for ACK plus 500 us ARD on a retry) one
  frame takes roughly 3-4 ms when clean (estimate): about 250 frames/s raw,
  30-60 kbit/s of usable frame payload after headers, tags and ACK gaps. At
  250 kbps (longest range) divide by about 6.
- Addresses from unit IDs. 5-byte addresses, high byte first on the radio:
  unicast pipe address of unit U = `0x50 0x4C U_hi U_lo 0xA5` ("PL", the ID,
  a fixed trailer chosen to avoid runs of 0s/1s and the 0x55/0xAA patterns ESB
  misreads as preamble). Broadcast address = `0x50 0x4C 0xFF 0xFF 0xA5`.
  Pipes 0 and 1 are the two pipes with fully independent 5-byte addresses
  (pipes 2-5 may differ from pipe 1 only in the last byte), so each node
  listens on pipe 0 with its own unicast address and on pipe 1 with the
  broadcast address. ESB requires pipe 0 to equal the TX address while a
  unicast with auto-ACK is in flight; the adapter (as the RF24 library does)
  reprograms pipe 0 to the destination address for the transmit and restores
  its own address afterwards. Floods are sent to the broadcast address with
  the NO_ACK bit (`W_TX_PAYLOAD_NOACK`, needs EN_DYN_ACK) and `FLOOD_REPEAT`
  copies; unicast uses auto-ACK. The link table stores the 5-byte address,
  derived from the unit ID rather than learned.
- Channel: avoid the WiFi/ESP-NOW channels. Recommended RF channels 76-83
  (2476-2483 MHz), above WiFi channel 13's upper edge (2483 MHz is the top of
  channel 13 only where 13 is allowed). Note the regional ISM limit of
  2483.5 MHz: channels above 83 are outside the band in most regions, and in
  North America (channels 1-11 only) 70-83 are all clear of WiFi. Store the
  channel in NVS `pl/nrf_channel`.
- Half duplex: the chip cannot receive while in PTX mode; the adapter
  switches to PRX between frames and waits `NRF_GUARD_MS` (2) after a
  transmit before expecting a reply.
- Link cost: no RSSI, so `link_cost` 2 (slightly worse than a good ESP-NOW
  link so that an equal-hop ESP-NOW path wins). The RPD/CD bit can be read
  during channel selection to pick a quiet channel.
- Driver: the nRF24/RF24 library has an ESP-IDF SPI port; ProbeLink uses
  only its raw packet send/receive, pipe and address setup, DPL and NO_ACK
  features, not RF24Network's addressing or fragmentation (section 10).

## Appendix D. Change history and review disposition

Changes since v0.1 (v0.2):

- 1.1: PACKET links can deliver corrupt frames (ESP-IDF #9575); CRC mandatory
  everywhere, in-frame RS optional on ESP-NOW. Unified erasure model.
- 3: FLAG_LEN16; version policy; memcpy rule; seq numbering (3.5); header
  budget analysis (3.4). 3.3: XOR replaced by RS erasure code across frames.
- 4: probe nonce, BIND_NAK, HELLO candidates, idempotent BIND_ACK, re-HELLO,
  probe-side timeout, race catalogue (4.3). 5-8: caps u16, ACK bitmap u32,
  DATA status byte, INVALID code, timestamps, ARQ details, two-nonce key
  derivation, 8-byte tag, replay window. 10: prior art. Appendices A-D.

Changes since v0.2 (v0.3, mandatory mesh):

- 3: header 15 bytes with prev_hop, next_hop, ttl_hops; SEEK adds path_mtu.
- 3.5: pre-session seq defined. 4.1: SEEK/BIND floods, HELLO on the reverse
  route. 8: tag input excludes hop fields; K_mesh for floods. 11: roles, hop
  fields, path MTU, AODV-lite routing, flood control, route lifetime, timers,
  security, RAM budget, carrier notes. 6.4: BLE connection-based.

Changes since v0.3 (v0.4, round-1 review fixes and nRF24L01+):

- 3: `path_cost` hop field in SEEK (header 18 there); `hop_tag` (4 bytes,
  K_mesh) after `auth_tag` whenever FLAG_AUTH is set; frozen prefix for
  version transitions; 3.5 48-bit index with implicit ROC and a persistent
  pre-session counter; 3.6 normative receiver validation table. Fixed
  overhead with AUTH is now 17 + 12.
- 4: boot holdoff, full-jitter backoff that never gives up, HELLO status
  FULL, multi-session MUST, SEEK from a bound sender no longer kills the
  session, BIND inner tag under K_hs, hop-scaled BIND timers with a worked
  table, nonce generation rule, penalty list, keepalive_ms, 4.4 parked
  sessions and leaves (RESUME / RESUME_ACK).
- 5: SEEK/HELLO carry key_epoch, proto_minor, fw_build; HELLO carries status
  and path_cost; BIND carries inner_tag; new types RESUME, RESUME_ACK,
  DIAG_REQ/RESP, TIME_REQ/RESP, KEY_UPDATE/ACK; caps ENC and MULTI; PONG
  carries utc_us; CLOSE carries park_s.
- 6: MODE fixed part 13 bytes (keepalive_ms, period unit flag), liveness flag
  removed; DATA status UNSYNCED; 6.3 recomputed with AUTH and nRF24 rows;
  6.4 BLE optional with fixed roles and beacon magic; 6.5 network time.
- 7: queues (RX queue depth and counter, two-class forwarding queue).
- 8: rewritten as requirements R1-R10 with mechanisms: offline K_site,
  per-pair keys, HKDF, handshake key, directional session keys, 48-bit index,
  AES-CCM option, key epochs, KEY_UPDATE, revocation, no-oracle rule.
- 9: one normative timer table including all mesh constants and 50-node
  table sizes. 10: RF24Network / RF24Mesh row and paragraph.
- 11: authenticate-before-state-change pipeline (steps 1-5 before any table),
  path_cost routing, ORIGIN freshness table, flood buckets with depth,
  FLOOD_REPEAT, suppression off by default, link table rules, minimum and
  default RAM, 11.11 DIAG and TIME.
- 12: new: deployment profile, provisioning, channel/STA rule, BLE optional,
  OTA path and rollback, key architecture alternative, leaf model, open items.
- Appendix A: all vectors recomputed for the 18-byte SEEK header and the
  tag pair; A.9 HELLO/BIND, A.10 ROC and AES-CCM added. Appendix B: async
  seek, park/resume, diag/time/key APIs, table sizes, counters. Appendix C:
  C.5 UDP, C.6 nRF24L01+.

Round 1 disposition (ROAST-1-field F1-F28, ROAST-1-security S1-S20):

| ID | Sev | Disposition | Where / reason |
|---|---|---|---|
| F1 | CRITICAL | fixed | 4.4 park/resume with RTC state, keepalive_ms in MODE, leaf = sender-only, non-leaf nodes MUST be mains/solar (11.1); alternative REPORT frame in 12.8 |
| F2 | CRITICAL | fixed | 8.2 per-pair keys from offline K_site, 8.6 epochs / KEY_UPDATE / revocation, 12.1 flash MUSTs; asymmetric identities left open (12.7) |
| F3 | HIGH | fixed | 2: manifest IDs, pl/unit_mac clone check, pl/groups; DIAG reports (MAC, unit_id) |
| F4 | CRITICAL | fixed | 12.4: dedicated channel, no STA on mesh nodes, WIFI_PS_NONE, two-chip gateway; channel-follow specified as alternative |
| F5 | HIGH | fixed | 6.4 / 12.5: BLE off by default, peripheral/central roles, allowlist, beacon magic, coex settings |
| F6 | HIGH | fixed | 11.2 path_cost from RSSI, 11.4 best copy inside the jitter window, HELLO carries cost |
| F7 | MEDIUM | fixed (scoped) | IR indoor/shaded only, link cost 20, RS counters in DIAG; bit-cell validation on hardware deferred (12.9) |
| F8 | MEDIUM | fixed | RELAY_SUPPRESS_COUNT default 0, FLOOD_REPEAT 2, per-node enable (11.5) |
| F9 | HIGH | fixed | 4.1.12 PL_MAX_SESSIONS >= 4, HELLO status FULL, v2 frames single-session or window 8, FULL backoff policy (4.1.4) |
| F10 | HIGH | fixed | boot holdoff, full-jitter backoff without give-up, RESEEK_JITTER, 64-entry dedup / 64 hashed buckets / ORIGIN table (4.1.1, 4.1.8, 9, 11.5) |
| F11 | HIGH | fixed | buckets depth 6 refill 2/s per origin, 20/10 total, BIND retries free, BIND_RETRY(hops) spacing with re-derived inequality (4.1.9-10, 11.5) |
| F12 | HIGH | fixed | 11.9 link table: (unit_id, transport) key, LINK_TTL 60 s, referenced entries never evicted, 32 entries, replacement vs collision rule, learn only after hop_tag |
| F13 | HIGH | fixed (scoped) | 12.6: UPDATE_WINDOW + esp_https_ota + Secure Boot v2 + rollback rule; in-mesh chunked OTA left open |
| F14 | HIGH | fixed | 3 frozen prefix, forwarders forward unknown versions, proto_minor + fw_build in SEEK/HELLO/DIAG, N/N-1 at endpoints, BIND_NAK reason 4 redefined |
| F15 | HIGH | fixed | 11.11 DIAG_REQ/RESP with identity, health, counters, links, routes; RTC reset log; TRACE and health push deferred (12.9) |
| F16 | HIGH | fixed | 6.5 TIME_REQ/RESP with master allowlist and stratum, PONG utc_us, DATA UNSYNCED |
| F17 | CRITICAL | fixed | 3.5 / 8.4 48-bit index (implicit ROC) in tags and CCM nonce; 4.3 row corrected |
| F18 | HIGH | fixed | 3.6 normative validation table, fuzzing recommendation |
| F19 | MEDIUM | fixed | section 7 queues: RX_QUEUE_FRAMES 16 + rx_queue_drop, two-class forwarding queue |
| F20 | MEDIUM | fixed | Appendix B: pl_seek asynchronous, pl_seek_cancel, TWDT note |
| F21 | LOW | fixed | MODE flags bit0 period unit (us/ms) |
| F22 | HIGH | fixed | 11.4 pipeline: validation, version, hop_tag, K_mesh tag before any table; hop_tag on every frame (8.4); 11.8 threat table corrected |
| F23 | MEDIUM | fixed | 11.5 origin bookkeeping: pre-insert own floods, echo rule, collision rule |
| F24 | MEDIUM | fixed | BIND inner_tag under K_hs, named probe binds only on it, LISTENING probe ignores BIND (4.1.5-6) |
| F25 | MEDIUM | fixed | one timer table (9) with hop scaling, session key (src_id, session_id) only, MODE liveness flag removed, late-BIND row |
| F26 | MEDIUM | fixed | C.5: port 40888, multicast 239.255.40.88 TTL 1, static/reserved addresses, unicast peer list |
| F27 | MEDIUM | fixed | 1.1 statement, FLOOD_REPEAT on carriers without MAC retry; stricter option named in 12.3 |
| F28 | LOW | fixed | 4.1.15 entropy rule, counters mixed into nonces |
| S1 | CRITICAL | fixed | = F2: pairwise keys; a captured node yields only its own pairs (8.2) |
| S2 | CRITICAL | fixed | 12.1 field profile MUSTs (Secure Boot v2, flash encryption release, NVS encryption, eFuse lockdown) |
| S3 | CRITICAL | fixed | 4.1.3: SEEK never closes a session; replacement only on an authenticated BIND |
| S4 | CRITICAL | fixed | 11.4: route installation only after hop_tag (and K_mesh tag for floods); HELLO under K_hs installs forward routes |
| S5 | CRITICAL | fixed | 11.4 step 6 (link learning) runs after step 5 (hop_tag) |
| S6 | CRITICAL | fixed | 11.4 steps 9b-9d (freshness, dedup, buckets) run after the tag checks |
| S7 | CRITICAL | fixed | = F17 |
| S8 | HIGH | fixed | = F24; SEEK carries no authority and is stated so (4.1.1); K_mesh confined to flood policing and sessionless DIAG/TIME (8.3) |
| S9 | HIGH | fixed | 4.1.15: esp_random with RF or bootloader_random_enable, mixed with persistent pl/preseq and pl/boot_count |
| S10 | HIGH | fixed | 8.6 key_epoch in SEEK/HELLO, E/E-1 acceptance, KEY_UPDATE, revocation list |
| S11 | HIGH | fixed | 3.6 clamps ttl/hops/path_mtu/path_cost; hop fields covered by hop_tag |
| S12 | HIGH | fixed | ORIGIN freshness table drops non-newer floods; PROBE_OFFERS_MAX caps OFFERED state (4.1.2, 11.5) |
| S13 | HIGH | fixed (partial) | 4.2 penalty list steers re-SEEK away from a failing first hop; residual insider gray-hole risk stated in 11.8, full fix needs asymmetric identities (12.7) |
| S14 | MEDIUM | fixed | liveness and route expiry refresh only from frames that passed step 5 (11.4) |
| S15 | MEDIUM | fixed | unicast forwarded only with a valid hop_tag; class-aware queue (7) |
| S16 | MEDIUM | fixed | 12.1: field build refuses to run without keys, test keys blacklisted; open relays impossible by construction (11.8) |
| S17 | MEDIUM | fixed | 8.2 HKDF-SHA256, directional K_s2p/K_p2s, AES-CCM option (8.5) |
| S18 | MEDIUM | fixed | BLE central allowlist + beacon magic (6.4); UDP peer list (C.5); every carrier gated by hop_tag |
| S19 | LOW | deferred (accepted) | topology and IDs stay visible by design; collision alarms now require a valid hop_tag (8.7) |
| S20 | MEDIUM | fixed | security counters in DIAG_RESP (8.7, 11.11) |
