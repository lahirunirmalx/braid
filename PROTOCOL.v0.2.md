# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.2 (review of v0.1 applied; wire version 1)

One protocol, five carriers: ESP-NOW, BLE, WiFi (UDP), IR, and raw UART TX/RX.
Every device has an ID. Every frame is integrity-checked and carries enough
redundancy to recover damaged or lost data. Payloads are digital or analog
32-bit values, sent in HIGH or LOW resolution.

Reading guide: sections 1-10 keep the v0.1 numbering so the two drafts can be
diffed. New material is in subsections 3.4-3.5, 4.3, 6.5 and appendices A-D.
All numbers marked "(estimate)" are engineering estimates, not measurements.

---

## 1. Layer stack

```
+---------------------------------------------------------+
| Application   pl_send_samples(), on_samples()           |
+---------------------------------------------------------+
| Session       SEEK / HELLO / BIND / MODE / DATA / CLOSE |
+---------------------------------------------------------+
| Group FEC     RS erasure code across k DATA frames,     |  any link
|               m PARITY frames (m = 1 is plain XOR)      |
+---------------------------------------------------------+
| Frame         header + payload [+ tag] + CRC-16         |  CRC mandatory
|               [+ in-frame RS parity]                    |  RS per link
+---------------------------------------------------------+
| Transport     ESP-NOW | BLE GATT | UDP | UART+COBS | IR |
+---------------------------------------------------------+
```

### 1.1 Two kinds of link, two kinds of damage

This is the most important design point, and v0.1 overstated it.

| Link class | Carriers | What damage usually looks like | Mandatory | Optional |
|---|---|---|---|---|
| PACKET | ESP-NOW, BLE, WiFi UDP | The radio MAC checks its own FCS and drops bad frames, so damage is mostly a missing frame. | CRC-16, cross-frame FEC and/or ARQ | In-frame RS (rs_nsym > 0) |
| RAW | UART, IR | Bytes arrive flipped, missing or inserted. | CRC-16, in-frame RS | Cross-frame FEC, ARQ |

Why the CRC is mandatory on PACKET links too: ESP-IDF issue #9575 (open,
ESP32-C3, IDF 4.4.2) reports ESP-NOW frames with an invalid 802.11 FCS being
accepted and acknowledged. "The app never sees a corrupted byte" is therefore
not a safe assumption on ESP-NOW. The application CRC is the last line of
defence on every carrier, and in-frame RS is allowed (not forbidden) on
ESP-NOW for installations that observe corrupt frames. Default `rs_nsym` is
still 0 on PACKET links because in the normal case the corrupt frame is dropped
by the MAC before the RS decoder could see it.

Unified recovery model: the frame layer turns every kind of damage into an
erasure (a frame that is either fully correct or absent). The group FEC and ARQ
layers only ever deal with erasures. This is what makes one FEC design work on
all five carriers.

### 1.2 Transport adapter contract

```c
typedef enum { PL_LINK_PACKET = 0, PL_LINK_RAW = 1 } pl_link_class_t;

typedef struct {
    const char     *name;          /* "espnow", "ble", "udp", "uart", "ir" */
    pl_link_class_t link_class;
    uint16_t        max_frame;     /* largest frame (incl. RS parity) delivered whole */
    uint8_t         rs_nsym;       /* in-frame RS parity bytes; 0 = none */
    bool            can_broadcast; /* SEEK by broadcast; else see 6.4 (BLE) */
    bool            half_duplex;   /* IR: cannot receive while transmitting */
    uint8_t         time_scale;    /* multiplier for section 9 timers (1 radio, 10 IR) */
    int  (*send)(const uint8_t *buf, uint16_t len);
    void (*set_rx_cb)(void (*cb)(const uint8_t *buf, uint16_t len, int8_t rssi));
} pl_transport_t;
```

| Carrier | Class | max_frame | rs_nsym default | Notes |
|---|---|---|---|---|
| ESP-NOW v1 | PACKET | 250 | 0 (may be 2-8, see 1.1) | Broadcast FF:FF:FF:FF:FF:FF for SEEK, unicast after BIND. `esp_now_add_peer()` must be called for the peer MAC before the first unicast. Both ends must be on the same WiFi channel; channel comes from NVS (`pl/channel`), scanning is out of scope. |
| ESP-NOW v2 | PACKET | up to 1470 | 0 | Needs ESP-IDF v5.4+ on both ends. A v1 peer limits the pair to 250. The usable size is negotiated: min(sender max_frame, probe max_frame) from SEEK/HELLO. Frames above 255 bytes need FLAG_LEN16 (section 3). |
| BLE GATT | PACKET | ATT_MTU - 3 | 0 | Default ATT MTU 23 gives 20 bytes, which does not fit one sample. MUST request MTU >= 64 (61-byte frames, IR-class capacity) and SHOULD request 247 (244-byte frames, fits one LL PDU with DLE). SEEK goes in advertising data, see 6.4. |
| WiFi UDP | PACKET | 255 default, up to 1400 with FLAG_LEN16 | 0 | Broadcast/multicast for SEEK, unicast after BIND. |
| UART | RAW | 255 incl. parity | 8 | COBS-encoded, 0x00 delimiter. COBS adds at most 1 + ceil(n / 254) bytes on the wire; that is outside max_frame. |
| IR (RMT) | RAW | 64 incl. parity | 6 | 38 kHz carrier, half duplex, line of sight, both ends need TX + RX. Realistic bit rate a few kbit/s (estimate), so one 64-byte frame takes roughly 0.2-0.5 s. LOW mode and small channel counts only. PHY sketch in appendix C. |

`rs_nsym` is a static per-link setting, configured identically on both ends
out of band (NVS `pl/rs_nsym`, or the adapter default above). It cannot be
negotiated in-band because RS decoding happens before the header can be
parsed. A mismatch shows up as 100 % CRC/RS failures on the first SEEK.

---

## 2. Device IDs

16-bit IDs. Small enough for IR, large enough for a bench network.

| Range | Meaning |
|---|---|
| 0x0000 | Unassigned. Never valid on the air. |
| 0x0001 - 0xFEFF | Unit ID. One per device. |
| 0xFF00 - 0xFFFE | Group (destination) ID. Several probes can subscribe to one group. |
| 0xFFFF | Broadcast. |

- Default unit ID = CRC-16/CCITT-FALSE (section 3.1) of the 6-byte base MAC
  (`esp_read_mac(..., ESP_MAC_BASE)`). If the result is 0x0000 or >= 0xFF00,
  use `(crc % 0xFEFF) + 1`. Override from NVS (`pl/unit_id`).
- Collision detection: a device that receives a frame whose `src_id` equals its
  own unit ID, and which it did not send (different carrier address, or any
  frame on a point-to-point link it did not emit), raises `PL_EVT_ID_COLLISION`
  and logs it with `ESP_LOGE`. The fix is manual: set `pl/unit_id` in NVS.
  With 20 devices on random 16-bit IDs the collision chance is about 0.3 %,
  so this is rare but must be visible when it happens.
- A "destination" is a group ID. Each probe that can serve it subscribes to it
  (up to `PL_MAX_GROUPS` = 8 per probe). A sender seeks the group, not a
  specific probe.
- A device accepts a frame when `dst_id` is its unit ID, a group it subscribes
  to, or 0xFFFF. After BIND all frames are unicast: `dst_id` is the peer's unit
  ID, never the group.

---

## 3. Frame format

All multi-byte fields little-endian. Float32 is IEEE-754 binary32, also
little-endian. Fields are packed with no alignment padding; read them with
`memcpy()` into a local, never by casting a `uint32_t *` into the buffer (Xtensa
LX6/LX7 raise a LoadStoreAlignment exception on unaligned 32-bit loads, and the
cast is undefined behaviour in C anyway).

```
Off  Size  Field
0    1     ver_flags   bits 7..4 version (=1), bits 3..0 flags
1    1     type        message type (section 5)
2    2     src_id
4    2     dst_id
6    1     session_id  0 in SEEK/HELLO/BIND/BIND_ACK/BIND_NAK
7    2     seq         per-session, per-direction, wraps at 65535 (3.5)
9    1|2   len         payload length: u8, or u16 if FLAG_LEN16
..   len   payload
..   8     auth_tag    only if FLAG_AUTH (section 8)
..   2     crc16       CRC-16/CCITT-FALSE over byte 0 .. end of auth_tag
..   n     rs_parity   rs_nsym bytes, if rs_nsym > 0 for this link
```

Fixed overhead: 12 bytes (13 with FLAG_LEN16, +8 with FLAG_AUTH, +rs_nsym).

Flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 | FLAG_ACK_REQ | Receiver must reply ACK immediately |
| 1 | FLAG_AUTH | auth_tag present |
| 2 | FLAG_LEN16 | `len` is 2 bytes. Only on PACKET links with max_frame > 255. Never with rs_nsym > 0 (RS block limit, 3.2). |
| 3 | reserved | 0 on send, ignored on receive |

Version: 1 = this document. v0.1 was never on the air, so no compatibility
shim exists. A receiver drops frames with an unknown version and counts them in
`pl_stats_t.bad_version`. Feature additions within version 1 use caps bits
(section 5) and the reserved flag; only a header layout change bumps the
version.

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
  DATA payload in the group + prefix width.
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
  `max_payload = max_frame - 12 - rs_nsym`, e.g. 10 x 239 = 2390 bytes for
  ESP-NOW v1 (max_payload 238) with k = 8, m = 2. Static allocation, sized at
  init.
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

A compact in-session header (drop src_id/dst_id, keep session_id + seq) was
evaluated for IR and BLE at default MTU. It saves 4 bytes per frame:

| Carrier | 12-byte header: data bytes | 8-byte header: data bytes | Gain |
|---|---|---|---|
| IR (64, nsym 6, DATA hdr 7) | 39 | 43 | 10 % |
| BLE MTU 23 (20) | 1 | 5 | still not one sample |

A 10 % gain on IR does not justify two header parsers, two CRC spans, and the
loss of `src_id` on a shared medium (two IR senders in one room would collide
on 1-byte session_ids). BLE at MTU 23 is unusable either way, so MTU
negotiation is mandatory (1.2). Decision: one header. The IR bottleneck is bit
rate, not header bytes; use LOW mode and few channels there.

The 1-byte `len` would have capped ESP-NOW v2 (1470 bytes) and UDP at 255-byte
frames, wasting most of the frame on the 2.4 GHz airtime budget. FLAG_LEN16
lifts that without costing a byte on carriers that do not need it.

### 3.5 Sequence numbers

- `seq` is per session and per direction: the sender's frames and the probe's
  frames each have their own 16-bit counter, starting at 0 at BIND_ACK, and
  incrementing on every frame of every type sent in the session (DATA, PARITY,
  MODE, PING, ACK, ...). Retransmitted DATA frames are the exception: they
  reuse their original seq.
- Compare seqs with serial-number arithmetic (RFC 1982): `a` is newer than `b`
  iff `(int16_t)(a - b) > 0`. All windows (ACK bitmap, FEC groups, replay
  window) are far smaller than 32768, so the comparison is unambiguous.
- Receivers keep a 64-entry "seen" bitmap below the highest seq (section 8
  replay window) and drop duplicates.

---

## 4. Session state machine

```
Sender:   IDLE -> SEEKING -> BINDING -> CONFIGURING -> STREAMING -> CLOSED -> IDLE
Probe:    LISTENING -> OFFERED -> BOUND -> STREAMING -> LISTENING
```

```
Sender                         Probe A           Probe B
  | SEEK (dst=group, nonce_s) -->|----------------->|      broadcast
  |                              | wait rand(0..50ms)
  |<--- HELLO (nonce_s, nonce_p) |                  |
  |<-------------------------------------- HELLO    |      kept as candidate #2
  | BIND (dst=group, probe=A) -->|----------------->|      B hears it, stands down
  |<------------------ BIND_ACK  |                  |
  | MODE (cfg 1, HIGH) --------->|
  |<------------------ MODE_ACK  |
  | DATA x8, PARITY x2 --------->|                         one FEC group
  |<----------------------- ACK  |                         periodic, liveness
  | MODE (cfg 2, LOW) ---------->|                         switch any time
  |<------------------ MODE_ACK  |
  | DATA ... ------------------->|
  | PING (idle) ---------------->|
  |<---------------------- PONG  |
  | CLOSE ---------------------->|
```

### 4.1 Rules

1. SEEK is broadcast with `dst_id` = target group, a fresh random 32-bit
   `nonce_s` (from `esp_random()`), the sender's caps and its `max_frame`.
   SEEK is never authenticated (the tag would not fit the BLE advertising
   budget, see 6.4, and it carries no authority: only HELLO/BIND do).
2. Each probe subscribed to the group and in LISTENING or OFFERED waits a
   random delay in 0..`HELLO_WINDOW_MS` and sends HELLO (unicast to the sender)
   with `nonce_s`, its own fresh `nonce_p`, caps, `max_frame` and the RSSI at
   which it heard the SEEK. The probe enters OFFERED and starts
   `BIND_TIMEOUT_MS`.
3. A probe in BOUND or STREAMING ignores SEEK from other senders. Exception: a
   SEEK from the `src_id` it is bound to, with a different `nonce_s`, means
   that sender rebooted; the probe closes the old session locally and answers
   HELLO.
4. Sender selection policy. `PL_SELECT_FIRST` (default): the first valid HELLO
   (matching `nonce_s`, compatible caps) wins and BIND is sent at once.
   `PL_SELECT_BEST_RSSI`: wait `HELLO_WINDOW_MS + SELECT_MARGIN_MS`, then pick
   the highest RSSI. In both policies up to `HELLO_CANDIDATES` (4) further
   HELLOs are kept as fallback candidates until the session is established.
5. The sender broadcasts BIND with `dst_id` = group, naming the chosen
   `probe_id`, both nonces and the new `session_id`. Every probe in the group
   hears it. The chosen probe replies BIND_ACK and enters BOUND. All other
   probes in OFFERED for this `nonce_s` return to LISTENING.
6. A probe in OFFERED that receives a BIND naming it but carrying a `nonce_s`
   or `nonce_p` it does not know ignores it. A probe already BOUND to another
   sender that is named in a BIND replies BIND_NAK (reason BUSY). The sender
   then tries its next candidate, and if none is left restarts SEEK.
7. A probe that sent HELLO and hears no BIND within `BIND_TIMEOUT_MS` returns
   to LISTENING.
8. No HELLO within `SEEK_TIMEOUT_MS`: resend SEEK with the same `nonce_s`,
   backoff 100, 200, 400, 800, 1600 ms, then give up (`PL_ERR_NO_PROBE`).
   A probe in OFFERED that hears the same `nonce_s` again assumes its HELLO
   was lost and sends HELLO again (new random delay, same `nonce_p`).
9. The session starts on BIND_ACK. Without BIND_ACK the sender resends BIND
   every `BIND_RETRY_MS` up to `BIND_RETRIES` times, then falls to rule 6
   (next candidate or re-SEEK). A probe that is already BOUND to this
   `(src_id, nonce_s, nonce_p)` and receives the BIND again resends BIND_ACK
   without changing state (idempotent, covers a lost BIND_ACK).
10. Timer inequality, which the constants in section 9 satisfy:
    `BIND_TIMEOUT_MS > HELLO_WINDOW_MS + SELECT_MARGIN_MS + BIND_RETRIES * BIND_RETRY_MS`
    (300 > 50 + 20 + 3 x 50 = 220). Otherwise the probe gives up on the
    sender before the sender has finished retrying.
11. `session_id` is chosen by the sender: 1..255, never 0, never equal to the
    previous session_id it used (counter kept in RAM, random start after
    boot). Frames are matched on `(transport, src_id, session_id)`, so two
    senders picking the same session_id do not collide.
12. A probe serves one session at a time. (An implementation may serve more by
    keeping one context per `(transport, src_id, session_id)`; the spec does
    not require it.)
13. Any frame with a `session_id` the receiver does not know, from a `src_id`
    it is not bound to, gets a CLOSE (reason UNKNOWN_SESSION) in reply, rate
    limited to one per second per peer. This lets a sender notice a rebooted
    probe immediately instead of after `SESSION_TIMEOUT_MS`. With AUTH
    negotiated the stray frame cannot be tag-verified (the probe has no
    `K_s` for it), and section 8 forbids answering unverified frames, so the
    CLOSE is not sent and the sender relies on `SESSION_TIMEOUT_MS`. A sender
    that wants faster detection under AUTH sets FLAG_ACK_REQ on one frame per
    `PING_IDLE_MS` and closes after `ARQ_MAX_RETRIES` unanswered requests.
14. Half-duplex carriers (IR): a probe does not start its HELLO delay until the
    SEEK frame has fully ended plus `IR_GUARD_MS`; all section 9 timers are
    multiplied by `time_scale`.

Why three messages, not two: with SEEK + ACK only, two probes that both answer
both believe they own the session. BIND tells every probe who won.

### 4.2 Failover and liveness

- Sender side: if no ACK or PONG arrives for `SESSION_TIMEOUT_MS` the sender
  closes the session (sends CLOSE twice, best effort) and re-SEEKs the same
  group. Any other probe can take over. This is the payoff of seeking a group
  instead of a fixed device.
- Probe side (new in v0.2): if no frame from the sender arrives for
  `SESSION_TIMEOUT_MS` the probe returns to LISTENING. Without this a probe
  whose sender died stays deaf to every other sender forever.
- Idle keepalive: a sender that has sent nothing for `PING_IDLE_MS` sends PING.
  The probe answers PONG. ACK frames (section 7) also count as liveness, so a
  streaming session never needs PINGs.
- CLOSE carries a reason and is not acknowledged; the timeouts above cover a
  lost CLOSE.

### 4.3 Race catalogue

| Scenario | What goes wrong without a rule | Rule |
|---|---|---|
| Two probes answer the same SEEK | Both think they are bound | BIND names one probe (4.1.5) |
| Two senders SEEK the same group at once | A probe HELLOs both, both BIND it | Probe accepts the first BIND, BIND_NAKs the second; loser tries next candidate (4.1.6) |
| Probe already bound hears a new SEEK | Would answer and get double-bound | Ignores it unless it is its own sender restarting (4.1.3) |
| BIND lost | Probe times out, sender keeps retrying into the void | BIND retries finish inside BIND_TIMEOUT (4.1.10) |
| BIND_ACK lost | Sender resends BIND, probe treats it as a new bind | Idempotent BIND_ACK (4.1.9) |
| HELLO lost | Sender re-SEEKs, probe sits in OFFERED | Same nonce_s triggers a new HELLO (4.1.8) |
| Sender reboots mid-session | Probe stays bound to a ghost | Probe-side timeout (4.2) and reboot detection (4.1.3) |
| Probe reboots mid-session | Sender streams for 2 s into nothing | CLOSE(UNKNOWN_SESSION) on the first stray frame (4.1.13) |
| seq wraps at 65535 | FEC groups and ACK bitmaps misalign | Serial arithmetic, explicit group membership (3.3, 3.5) |
| Two senders pick the same session_id | Frames mixed on a shared medium | Sessions keyed by (src_id, session_id) (4.1.11) |
| Replayed SEEK/HELLO | Old session key reused | Both nonces enter the key derivation (8) |

---

## 5. Message types

| Type | Name | Dir | Payload |
|---|---|---|---|
| 0x01 | SEEK | S -> group (bcast) | nonce_s u32, caps u16, max_frame u16 |
| 0x02 | HELLO | P -> S | nonce_s u32, nonce_p u32, caps u16, max_frame u16, rssi i8 |
| 0x03 | BIND | S -> group (bcast) | nonce_s u32, nonce_p u32, probe_id u16, session_id u8 |
| 0x04 | BIND_ACK | P -> S | nonce_s u32, nonce_p u32 |
| 0x05 | MODE | S -> P | see 6.1 |
| 0x06 | MODE_ACK | P -> S | config_id u8, status u8 (0 ok, 1 unsupported, 2 too big, 3 bad arg) |
| 0x07 | BIND_NAK | P -> S | nonce_s u32, reason u8 (1 busy, 2 caps mismatch, 3 auth required, 4 version) |
| 0x10 | DATA | S -> P | see 6.2 |
| 0x11 | PARITY | S -> P | see 3.3 |
| 0x12 | ACK | P -> S | cum_seq u16, bitmap u32 (seqs cum_seq+1 .. cum_seq+32, bit set = received) |
| 0x20 | PING | either | t_tx_us u32 (sender's session clock) |
| 0x21 | PONG | either | t_echo_us u32 (copied from PING), t_local_us u32 (responder's session clock) |
| 0x30 | CLOSE | either | reason u8 (0 normal, 1 timeout, 2 unknown session, 3 application, 4 auth failure, 5 reboot) |

caps bits (u16): 0 HIGH, 1 LOW, 2 ARQ, 3 AUTH, 4 group FEC, 5 LEN16,
6-15 reserved (0). In-frame RS is not a cap: it is fixed per link (1.2). A session uses the intersection
of both ends' caps. A probe with a network key set rejects (BIND_NAK reason 3)
any sender whose caps lack AUTH; this prevents a downgrade through the
unauthenticated SEEK.

`max_frame` in SEEK/HELLO is the value from the transport adapter (1.2). The
session uses `min(sender, probe)`.

Probes never send DATA. Only the sender chooses the resolution mode.

---

## 6. Data and resolution modes

### 6.1 MODE frame

```
config_id      u8    1..255 (never 0), increments on every change, wraps to 1
mode           u8    0 = HIGH, 1 = LOW
ch_count       u8    1..16
period_us      u32   nominal sample period, same for all channels
fec_k          u8    2..16 (ignored if fec_m = 0)
fec_m          u8    0 = no group FEC, else 1..4
arq            u8    0 = fire-and-forget, 1 = retransmit on ACK gaps
flags          u8    bit0 = probe should send ACK even when arq = 0 (liveness only); others 0
then per channel:
  kind         u8    0 = digital, 1 = analog
  fmt          u8    analog: 0 uint32, 1 int32, 2 float32
                     digital: number of lines, 1..32
  [LOW analog only]
  scale        f32
  offset       f32
```

- MODE must fit in one frame (no fragmentation anywhere in this protocol).
  The fixed part is 11 bytes, so 16 LOW analog channels need 11 + 16 x 10 =
  171 payload bytes: fine on ESP-NOW/UDP/BLE-247/UART, not on IR (max payload
  46 with nsym 6). IR is therefore limited to 3 LOW analog channels
  (11 + 30 = 41) or 16 digital/HIGH channel descriptors (11 + 32 = 43).
- At least one complete sample (all channels) must fit in a DATA frame,
  otherwise the probe replies MODE_ACK status 2 (too big).
- The sender may send MODE at any time after BIND_ACK. DATA keeps using the
  old `config_id` until MODE_ACK arrives. The sender resends MODE every
  `MODE_RETRY_MS` until MODE_ACK; the probe re-acks an already-active
  `config_id` without side effects.
- The probe keeps the last two configs, so frames in flight during a switch
  still decode. DATA with an unknown `config_id` is dropped and counted.

### 6.2 DATA payload

```
config_id      u8
status         u8    bit0 CLIP (a LOW value saturated in this frame)
                     bit1 OVERRUN (samples were dropped before this frame)
                     bit2 INVALID (at least one INVALID code in this frame)
                     bits 3-7 reserved, 0
t_first_us     u32   timestamp of first sample, sender session clock (6.5)
n_samples      u8    1..255
samples        n_samples x (all channels, in descriptor order)   sample-major
```

Sample-major means: sample 0 channel 0, sample 0 channel 1, ..., sample 1
channel 0, ... Sample i has nominal time `t_first_us + i * period_us`.

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

Data bytes per frame = max_frame - 12 (header + CRC) - 7 (DATA header) - rs_nsym
(- 1 with FLAG_LEN16, - 8 with FLAG_AUTH, - 9 or - 10 more when fec_m > 0,
see 3.3).

Example: 4 analog channels, no auth, no group FEC.

| Carrier | Data bytes | HIGH samples/frame (16 B each) | LOW samples/frame (8 B each) |
|---|---|---|---|
| ESP-NOW v1 (250) | 231 | 14 | 28 |
| ESP-NOW v2 (1470, LEN16) | 1450 | 90 | 181 |
| WiFi UDP (255) | 236 | 14 | 29 |
| BLE (MTU 247 -> 244) | 225 | 14 | 28 |
| BLE (MTU 64 -> 61) | 42 | 2 | 5 |
| UART (255, nsym 8) | 228 | 14 | 28 |
| IR (64, nsym 6) | 39 | 2 | 4 |

Throughput context (estimates): ESP-NOW at its default 1 Mbps PHY rate gives
on the order of 100 kbit/s of goodput, i.e. roughly 50 full v1 frames per
second; `esp_wifi_config_espnow_rate()` can raise the PHY rate. IR at 2 kbit/s
gives about 3 frames per second, so 4 LOW channels stream at roughly 12
samples per second. Choose `period_us` and `n_samples` so the frame rate stays
under the carrier's limit with margin for PARITY and retransmissions.

### 6.4 BLE mapping

BLE has no "broadcast a frame and get unicast replies" primitive, so:

- SEEK is placed in the sender's advertising data as a manufacturer-specific
  AD element (company ID 0xFFFF, the Bluetooth SIG test ID, until a real one
  is assigned). Budget: 31 bytes - 3 (Flags AD) - 4 (AD length, AD type,
  company ID) = 24 bytes. The SEEK frame is 20 bytes (10 header + 8 payload +
  2 CRC), so it fits with 4 bytes spare. An authenticated SEEK would be 28
  bytes and would not fit; this is one reason SEEK is never authenticated
  (4.1.1).
- A probe that hears it connects, requests the ATT MTU (1.2), and writes HELLO
  to the ProbeLink RX characteristic. The rest of the handshake runs over the
  connection; "broadcast" BIND is simply a write to the connected probe.
- After BIND_ACK, all frames go over one write-without-response characteristic
  (S -> P) and one notify characteristic (P -> S).
- If several probes connect in response to the same advertisement, the sender
  handles each connection as a HELLO candidate (4.1.4) and disconnects the
  losers after BIND.

### 6.5 Timestamps and clock drift

- Session clock: each end starts a 32-bit microsecond counter from its own
  `esp_timer_get_time()` at the moment it sends or receives BIND_ACK.
  `t_first_us`, `t_tx_us`, `t_echo_us`, `t_local_us` are all in the owner's
  session clock.
- Wrap: 2^32 us = 71.6 minutes. Receivers extend to 64 bits by assuming
  consecutive DATA frames are less than 2^31 us (35.8 min) apart; a session
  with no DATA for longer than that must be re-anchored by a PING/PONG pair.
- Drift: two ESP32 crystals typically differ by 20-40 ppm, i.e. 1.2-2.4 ms per
  minute (estimate). The nominal `period_us` is the sender's intent; the
  actual ADC clock differs by the sender's crystal error. The receiver can
  (a) trust `t_first_us` per frame and resample, which is the recommended
  default, or (b) fit `t_local = a + b * t_sender` from PING/PONG pairs
  (`offset = t_local_us - t_echo_us - RTT / 2`) and convert to its own clock.
  The protocol supplies the fields; the fit is the application's choice.
- Samples inside a frame have nominal times only. If the sender's sampler is
  not isochronous (e.g. a polled I2C sensor), use one sample per frame.

---

## 7. Reliability modes

| Setting | Use when | Behaviour |
|---|---|---|
| arq = 0, fec_m = 0 | Wired UART, short cable | CRC + RS only. Lost frames stay lost. |
| arq = 0, fec_m = 2, fec_k = 8 | Streaming telemetry over radio | Any 2 losses in 10 rebuilt, no added latency from retries |
| arq = 1, fec_m = 2, fec_k = 8 | Data that must arrive | FEC first; ACK bitmap gaps it could not fill get resent |
| arq = 1, fec_m = 0 | Low-rate commands, IR | Pure ARQ, cheapest in bandwidth |

ACK is sent every `ACK_EVERY` frames or `ACK_MS`, whichever comes first, and
immediately on FLAG_ACK_REQ. It doubles as the liveness signal for the sender.
With `arq = 0` and MODE flags bit0 clear, the probe still sends ACK at the
`ACK_MS` cadence (liveness) but the sender ignores the bitmap.

ARQ details:

- Sender keeps the last `ARQ_WINDOW` (32) DATA frames: `32 * max_frame` bytes,
  8 KB on ESP-NOW v1, static. The ACK bitmap covers exactly this window.
- A seq reported missing (bit clear, older than `ARQ_RTO_MS`) is retransmitted
  with its original seq, at most `ARQ_MAX_RETRIES` (3) times, then abandoned
  and reported to the application as a gap.
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

---

## 8. Security

Threat model: integrity and authenticity only. Payloads are in the clear
unless the carrier encrypts (ESP-NOW CCMP, BLE LE Secure Connections). An
attacker in radio range can still jam, and can still make probes send HELLO by
replaying SEEK (a DoS equivalent to jamming, nothing more).

- Without auth, anyone in radio range can send BIND, MODE or CLOSE and take
  over or kill a session. Fine on a bench, not in deployment.
- Network key: 32 bytes `K_net`, stored in NVS (`pl/net_key`), ideally with NVS
  encryption + flash encryption enabled. Never hardcoded, never logged.
- Session key:
  `K_s = HMAC-SHA256(K_net, "ProbeLink-v1" || src_id || dst_id || nonce_s || nonce_p)`
  with the integers little-endian as on the wire, `src_id` = sender unit ID,
  `dst_id` = probe unit ID. Both nonces are needed: with only the sender's
  nonce (v0.1) an attacker could replay a recorded SEEK and the whole recorded
  session after it. With `nonce_p` fresh per HELLO, the recorded BIND/BIND_ACK
  tags no longer verify.
- Tag: `auth_tag = HMAC-SHA256(K_s, header || payload)[0..7]`, 8 bytes, over
  everything before the tag, which includes `src_id`, `dst_id`, `session_id`,
  `seq`, `type` and `len`. 8 bytes (64 bits) rather than the 4 of v0.1: a
  4-byte tag gives one forged frame per 2^32 attempts on average, and at a
  few hundred frames per second on ESP-NOW that is weeks, not years; BIND, MODE
  and CLOSE each take over the session with a single accepted frame, so they
  need the stronger tag. 8 bytes costs 4 more bytes per frame, 10 % on IR and
  under 2 % elsewhere.
- Which frames carry the tag when AUTH is negotiated: every frame except
  SEEK. HELLO, BIND, BIND_ACK, BIND_NAK are tagged with `K_s` derived from the
  nonces they carry; BIND/BIND_ACK thus double as key confirmation. A probe
  with `K_net` set drops untagged frames of every type except SEEK.
- Replay window: per session and direction the receiver keeps `highest_seq`
  and a 64-bit bitmap of seen seqs below it. Accept a frame iff its seq is
  newer than `highest_seq`, or within the last 64 and not yet seen; otherwise
  drop and count `replay_dropped`. Retransmitted DATA frames (same seq) are
  handled before this check by the ARQ layer: a duplicate seq that is already
  delivered is dropped as a duplicate, not as a replay, and either way it is
  not delivered twice. Across sessions, a new `K_s` makes old frames fail
  the tag check.
- Cost: HMAC-SHA256 of a 250-byte frame on ESP32 with the mbedtls/hardware SHA
  path is tens of microseconds (estimate); negligible at these frame rates.
- ESP-NOW can additionally use its own CCMP encryption (PMK/LMK) for unicast
  peers after BIND, which adds confidentiality. The number of encrypted peers
  is limited by `CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM` (default 7, maximum
  17; verify in menuconfig for your IDF version). Encrypted ESP-NOW frames also
  cannot be broadcast, so SEEK/BIND stay unencrypted.
- Failed tag or replay: drop silently, increment the counter, log at
  `ESP_LOGW` with rate limiting. Never answer a frame that failed
  authentication (no CLOSE, no NAK): that would give an attacker an oracle.

---

## 9. Constants

Radio defaults; multiply every *_MS by `time_scale` (10 on IR).

| Name | Default | Note |
|---|---|---|
| HELLO_WINDOW_MS | 50 | probe random delay range |
| SELECT_MARGIN_MS | 20 | extra wait for PL_SELECT_BEST_RSSI |
| HELLO_CANDIDATES | 4 | fallback probes kept |
| BIND_RETRY_MS | 50 | |
| BIND_RETRIES | 3 | |
| BIND_TIMEOUT_MS | 300 | probe gives up on OFFERED; see inequality 4.1.10 |
| SEEK_TIMEOUT_MS | 100 (first try) | then x2 up to 1600 |
| MODE_RETRY_MS | 100 | |
| SESSION_TIMEOUT_MS | 2000 | both sides |
| PING_IDLE_MS | 500 | sender keepalive when no DATA |
| ACK_EVERY | 8 frames | |
| ACK_MS | 250 | |
| FEC_K / FEC_M | 8 / 2 | radio default; 2 / 1 on IR |
| FEC_FLUSH_MS | 100 | close a partial group |
| ARQ_WINDOW | 32 | frames, matches ACK bitmap |
| ARQ_RTO_MS | 100 | |
| ARQ_MAX_RETRIES | 3 | |
| REORDER_MS | 500 | |
| REPLAY_WINDOW | 64 | seqs |
| IR_GUARD_MS | 20 | half-duplex turnaround |
| PL_MAX_GROUPS | 8 | subscriptions per probe |

---

## 10. Prior art

Research summary (see the references at the end of this section). No existing
protocol covers the full requirement list; several cover parts of it well.

| Project | Carriers | Addressing | Integrity | FEC | Discovery / session | Typed samples | Verdict |
|---|---|---|---|---|---|---|---|
| PJON | ThroughSerial, ESPNOW, AnalogSampling (IR/LED), LocalUDP, SoftwareBitBang | 1-byte device IDs (+ bus ID) | CRC8 / CRC32, optional ACK | none | none (no seek, no first-ACK-wins) | none | Closest match; see below |
| MAVLink v2 | any byte stream | 1-byte system + component IDs | CRC-16/MCRF4XX, optional signing | none | heartbeat, no bind | fixed message set | Good signing model, no FEC, no group seek |
| RadioHead | radio chips via drivers | node addresses, reliable datagram | CRC via radio | none | none | none | No ESP-NOW/BLE/IR |
| SerialTransfer | UART only | none | COBS + CRC-8 | none | none | none | Framing reference only |
| wfb-ng | raw 802.11 (Linux) | none | per-packet | RS erasure across packets (zfec, k=8 n=12) | none | none | Model for section 3.3; Linux only |
| BTHome v2 | BLE advertising | MAC | AES-CCM | none | advertising only | value encoding with factors | Model for LOW scale/offset idea |
| ESP-WIFI-MESH | WiFi | MAC | WiFi | none | mesh formation | none | WiFi only, heavier than needed |

Why not just PJON: PJON is the only project with strategies for four of the
five carriers (serial, ESP-NOW, light/IR, UDP) and it already gives device IDs,
CRC and optional ACK. It lacks the four things this protocol is actually about:
no forward error correction of either kind (in-frame RS or cross-frame), no
seek-a-group / first-acknowledger-wins session handshake, no BLE strategy, and
no notion of HIGH/LOW typed sample payloads. Its 1-byte device IDs are also
tight for a lab with several groups. Two realistic ways to use it anyway:
(a) wrap PJON strategies as ProbeLink transport adapters (1.2), paying one
extra PJON header per frame and writing a BLE adapter by hand; or (b) borrow
PJON's bit-banging and light-sampling code for the IR PHY (appendix C) and
keep everything above the transport native. For an ESP-IDF project (b) is the
cleaner path; (a) is attractive if you need PJON's SoftwareBitBang single-wire
bus as a sixth carrier.

RS libraries usable on ESP32: Arduino-FEC (github.com/simonyipeter/Arduino-FEC,
small, Arduino style), libcorrect (C, has decode-with-erasures, fits ESP-IDF
as a component), Schifra (C++ templates, heaviest). A minimal GF(2^8) RS
encoder plus erasure-only decoder is about 300 lines of C if you prefer no
dependency; the test vectors in appendix A are enough to validate it.

References: github.com/gioblu/PJON; MAVLink v2 protocol docs; RadioHead
library docs; SerialTransfer (PowerBroker2); wfb-ng (svpcom); BTHome v2 format;
ESP-IDF ESP-WIFI-MESH docs; ESP-IDF issue #9575.

---

## Appendix A. Test vectors

All values computed with a reference implementation and cross-checked against
Python `reedsolo` (RS) and `hmac` (HMAC). Hex is byte order on the wire.

A.1 CRC-16/CCITT-FALSE

```
"123456789" (ASCII)                       -> 0x29B1
```

A.2 SEEK frame, no flags, no RS

```
src_id 0x1234, dst_id 0xFF01 (group), session 0, seq 0
payload: nonce_s 0xA1B2C3D4, caps 0x0013 (HIGH|LOW|FEC), max_frame 250

10 01 34 12 01 ff 00 00 00 08  d4 c3 b2 a1 13 00 fa 00  fe 1d
|header (10)                 | |payload (8)            | |crc |
CRC16 = 0x1DFE  (stored little-endian: fe 1d)
```

A.3 Same SEEK on UART: RS nsym = 8, then COBS

```
RS parity (appended to the 20 bytes above):
ef 22 22 d4 c2 3f f3 fa
COBS-encoded wire bytes incl. 0x00 delimiter (30 bytes):
07 10 01 34 12 01 ff 01 01 07 08 d4 c3 b2 a1 13 02 fa 0b fe 1d
ef 22 22 d4 c2 3f f3 fa 00
```

A.4 In-frame RS, standalone

```
RS(nsym=6) parity of ASCII "ProbeLink":   28 76 02 56 91 f1
RS(nsym=1) parity of 12 34 56 78 9a:       92   (= XOR of the bytes)
```

A.5 Cross-frame FEC

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

A.6 Session key and authenticated DATA frame

```
K_net   = 00 01 02 ... 1f  (bytes 0x00..0x1F)
src_id 0x1234, dst_id 0x0042, nonce_s 0xA1B2C3D4, nonce_p 0x0BADF00D
K_s = HMAC-SHA256(K_net, "ProbeLink-v1" || 34 12 || 42 00 || d4 c3 b2 a1 || 0d f0 ad 0b)
    = f71f9e683fc82b40fb4b9c484199b8d8b153fcfd33eba88988590a9792c3fb7a

DATA frame, FLAG_AUTH, session 7, seq 5, one float32 sample 1.5 at t=1000 us:
12 10 34 12 42 00 07 05 00 0b  01 00 e8 03 00 00 01 00 00 c0 3f
3d d8 e3 1f 15 c0 d3 c4  87 de
|header (10)                 | |payload (11)                    |
|tag (8)                 | |crc |
tag = HMAC-SHA256(K_s, header || payload)[0..7]
CRC16 = 0xDE87 over header || payload || tag
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

## Appendix B. Minimal C API

Design rules: no heap after `pl_init()`, all buffers sized from the config
and placed in a caller-provided context; every call returns `pl_err_t`;
transport RX callbacks only copy into a queue (ESP-NOW and BLE callbacks run
in the WiFi/BT host tasks and must not block or parse there); one
`pl_task()` does all protocol work.

```c
typedef enum {
    PL_OK = 0,
    PL_ERR_ARG,          /* bad parameter */
    PL_ERR_STATE,        /* call not valid in this state */
    PL_ERR_NO_PROBE,     /* SEEK exhausted its backoff */
    PL_ERR_TIMEOUT,      /* BIND/MODE not acknowledged */
    PL_ERR_BUSY,         /* all candidates replied BIND_NAK */
    PL_ERR_TOO_BIG,      /* MODE or sample set does not fit max_frame */
    PL_ERR_AUTH,         /* peer requires AUTH and we have no key, or vice versa */
    PL_ERR_QUEUE_FULL,   /* send queue full, back off */
} pl_err_t;

typedef struct {
    uint16_t       unit_id;        /* 0 = derive from MAC (section 2) */
    const uint8_t *net_key;        /* 32 bytes, or NULL for no AUTH */
    uint8_t        select_policy;  /* PL_SELECT_FIRST | PL_SELECT_BEST_RSSI */
    uint16_t       max_frame;      /* <= transport max_frame; 0 = transport value */
    uint8_t        fec_k_max;      /* sizes the RX FEC buffer, 2..16 */
    uint8_t        fec_m_max;      /* 0..4 */
    uint8_t        arq_window;     /* 0 or 32 */
} pl_config_t;

typedef struct {
    uint8_t  config_id, mode, ch_count;
    uint32_t period_us;
    uint8_t  fec_k, fec_m, arq, flags;
    struct { uint8_t kind, fmt; float scale, offset; } ch[16];
} pl_mode_t;

typedef struct {
    void (*on_bound)(uint16_t peer_id, uint8_t session_id);
    void (*on_mode)(const pl_mode_t *mode);
    void (*on_samples)(const pl_mode_t *mode, const uint8_t *samples,
                       uint8_t n_samples, uint32_t t_first_us, uint8_t status);
    void (*on_gap)(uint16_t first_seq, uint16_t count);
    void (*on_closed)(uint8_t reason);
} pl_callbacks_t;

typedef struct pl_ctx pl_ctx_t;   /* opaque; allocate with the macro below */

/* Static context sized for one session. RAM (bytes), approximately:
 *   tx queue   : 4 * max_frame
 *   rx fec buf : (fec_k_max + fec_m_max) * (max_frame - 11 - rs_nsym)   (3.3)
 *   arq buf    : arq_window * max_frame
 *   reorder    : (fec_k_max + fec_m_max) * max_frame
 *   state      : ~512
 * ESP-NOW v1, k 8, m 2, window 32: 1000 + 2390 + 8000 + 2500 + 512 = ~14.4 KB */
#define PL_CTX_STATIC(name, max_frame, fec_n, arq_window) ...

pl_err_t pl_init(pl_ctx_t *ctx, const pl_config_t *cfg,
                 const pl_transport_t *tr, const pl_callbacks_t *cb);

/* Sender side. pl_seek blocks the calling task up to timeout_ms and runs
 * SEEK / HELLO / BIND. */
pl_err_t pl_seek(pl_ctx_t *ctx, uint16_t group_id, uint32_t timeout_ms);
pl_err_t pl_set_mode(pl_ctx_t *ctx, const pl_mode_t *mode, uint32_t timeout_ms);
pl_err_t pl_send_samples(pl_ctx_t *ctx, const void *samples, uint8_t n_samples,
                         uint32_t t_first_us, uint8_t status);
pl_err_t pl_close(pl_ctx_t *ctx, uint8_t reason);

/* Probe side. */
pl_err_t pl_listen(pl_ctx_t *ctx, const uint16_t *groups, uint8_t n_groups);

/* Both sides: FreeRTOS task body. Priority above the application, below the
 * WiFi/BT tasks. Stack: measure with uxTaskGetStackHighWaterMark(); 4096 is a
 * starting point with HMAC enabled. */
void pl_task(void *ctx);

typedef struct {
    uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail,
             fec_recovered, arq_retx, gaps, replay_dropped, auth_fail,
             bad_version, id_collisions;
    uint16_t stack_hwm_words;
} pl_stats_t;
pl_err_t pl_get_stats(const pl_ctx_t *ctx, pl_stats_t *out);
```

Task layout on a dual-core ESP32: transport callbacks -> `xQueueSendFromISR` /
`xQueueSend` into `ctx->rx_queue` -> `pl_task` on core 1 parses, decodes RS,
checks CRC and tag, runs FEC/ARQ, calls the application callbacks. The
application's sampling task writes with `pl_send_samples()`, which only
enqueues; framing and the transport `send()` run in `pl_task`.

## Appendix C. Carrier notes

C.1 IR PHY (sketch, to be validated on hardware)

- 38 kHz carrier from the RMT peripheral, standard TSOP-style receiver.
- Bit coding: pulse-distance like NEC (mark 560 us, space 560 us = 0, space
  1690 us = 1) runs at about 290 bit/s for a 32-bit NEC frame in 110 ms. That
  is too slow: a 64-byte ProbeLink frame would take 1.7 s. A shorter custom
  cell (mark 300 us, space 300/600 us) gives about 2 kbit/s (estimate), still
  inside what a 38 kHz receiver's AGC tolerates. Expect to tune this.
- Preamble: 9 ms mark + 4.5 ms space before the frame so the receiver's AGC
  settles; 0x00 bytes are legal inside the frame (no COBS on IR; the preamble
  and a trailing 10 ms silence delimit the frame).
- Half duplex: a device never transmits while it is receiving a frame, and
  waits `IR_GUARD_MS` after the end of a received frame before replying.
- Keep `rs_nsym` at 6 (3 correctable bytes) and `fec_k = 2, fec_m = 1`.

C.2 UART

- 8N1, 115200 baud default; higher is fine on short cables. COBS framing with
  0x00 delimiter; the receiver resynchronises on any 0x00. A frame longer than
  `max_frame` after COBS decoding is dropped.
- Enable the UART hardware FIFO threshold or idle-line interrupt and process
  frames in `pl_task`, never byte by byte in the ISR.

C.3 ESP-NOW

- Register the peer (`esp_now_add_peer`) for the probe MAC when BIND_ACK
  arrives, with the broadcast peer registered at init. The ESP-NOW send
  callback reports per-frame delivery status for unicast; the adapter may use
  it for statistics but the protocol does not depend on it.
- Unicast ESP-NOW frames are retried by the WiFi MAC, broadcast frames are not.
  SEEK/BIND are broadcast and rely on the retry rules in 4.1.

C.4 BLE

- GATT service with two characteristics: RX (write without response, S -> P)
  and TX (notify, P -> S). Request MTU 247 and 2M PHY where available. The
  advertising payload layout is in 6.4.

## Appendix D. Changes since v0.1

- 1.1: PACKET links can deliver corrupt frames (ESP-IDF #9575); CRC mandatory
  everywhere, in-frame RS optional on ESP-NOW. Unified erasure model.
- 3: FLAG_LEN16 for ESP-NOW v2 / UDP; FLAG_FEC_GROUP removed; version policy;
  memcpy rule; seq numbering made explicit (3.5); header budget analysis (3.4).
- 3.3: XOR parity replaced by RS erasure code across frames with k/m; explicit
  group membership in PARITY; payload cap when FEC is on.
- 4: probe nonce, BIND_NAK, HELLO candidates, idempotent BIND_ACK, re-HELLO on
  repeated SEEK, probe-side timeout, sender-reboot detection, UNKNOWN_SESSION
  CLOSE, timer inequality, session keying, race catalogue (4.3).
- 5: caps widened to u16, BIND_NAK, ACK bitmap u32, PING/PONG carry timestamps.
- 6: DATA status byte, INVALID code, scale denominator 65534, MODE size limits,
  fec_m, timestamps and drift (6.5), BLE advertising budget, throughput notes.
- 7: ARQ window, RTO, retries, reorder/gap delivery defined.
- 8: threat model, two-nonce key derivation, 8-byte tag, replay window, no
  oracle responses.
- 10: prior art table and PJON discussion. Appendices A-D added.
