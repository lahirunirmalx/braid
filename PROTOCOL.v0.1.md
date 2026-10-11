# ProbeLink - transport-agnostic data link for ESP32

Status: DRAFT v0.1 (pre-review)

One protocol, five carriers: ESP-NOW, BLE, WiFi (UDP), IR, and raw UART TX/RX.
Every device has an ID. Every frame is integrity-checked and carries enough
redundancy to recover damaged or lost data. Payloads are digital or analog
32-bit values, sent in HIGH or LOW resolution.

---

## 1. Layer stack

```
+---------------------------------------------------------+
| Application   pl_send_samples(), pl_on_samples()        |
+---------------------------------------------------------+
| Session       SEEK / HELLO / BIND / MODE / DATA / CLOSE |
+---------------------------------------------------------+
| Group FEC     XOR parity frame every K data frames      |  packet links
+---------------------------------------------------------+
| Frame         header + payload + CRC-16 + RS parity     |  RS on raw links
+---------------------------------------------------------+
| Transport     ESP-NOW | BLE GATT | UDP | UART+COBS | IR |
+---------------------------------------------------------+
```

### 1.1 Two kinds of link, two kinds of damage

This is the most important design point.

| Link class | Carriers | What damage looks like | Recovery used |
|---|---|---|---|
| PACKET | ESP-NOW, BLE, WiFi UDP | Radio hardware checks its own CRC and drops bad frames. The app never sees a corrupted byte, only a missing frame. | Group FEC (XOR parity across frames) + optional ARQ |
| RAW | UART, IR | Bytes arrive flipped or missing. | In-frame Reed-Solomon + CRC |

In-frame Reed-Solomon on a PACKET link is pure overhead: the corrupted frame
never reaches the code that could repair it. So the transport adapter declares
its class and the frame layer picks the recovery method.

### 1.2 Transport adapter contract

```c
typedef enum { PL_LINK_PACKET = 0, PL_LINK_RAW = 1 } pl_link_class_t;

typedef struct {
    const char     *name;          /* "espnow", "ble", "udp", "uart", "ir" */
    pl_link_class_t link_class;
    uint16_t        max_frame;     /* largest frame the carrier delivers whole */
    uint8_t         rs_nsym;       /* RS parity bytes, 0 on PACKET links */
    bool            can_broadcast;
    int  (*send)(const uint8_t *buf, uint16_t len);
    void (*set_rx_cb)(void (*cb)(const uint8_t *buf, uint16_t len, int8_t rssi));
} pl_transport_t;
```

| Carrier | Class | max_frame | rs_nsym default | Notes |
|---|---|---|---|---|
| ESP-NOW | PACKET | 250 | 0 | Broadcast to FF:FF:FF:FF:FF:FF for SEEK, unicast after BIND |
| BLE GATT | PACKET | ATT_MTU - 3 | 0 | Must negotiate MTU >= 64. SEEK goes in advertising data, see 6.4 |
| WiFi UDP | PACKET | 255 | 0 | Broadcast/multicast for SEEK, unicast after BIND |
| UART | RAW | 255 | 8 | COBS-encoded, 0x00 delimiter |
| IR (RMT) | RAW | 64 | 6 | Half-duplex, line of sight. Both ends need TX + RX. LOW mode only in practice |

---

## 2. Device IDs

16-bit IDs. Small enough for IR, large enough for a bench network.

| Range | Meaning |
|---|---|
| 0x0000 | Unassigned. Never valid on the air. |
| 0x0001 - 0xFEFF | Unit ID. One per device. |
| 0xFF00 - 0xFFFE | Group (destination) ID. Several probes can subscribe to one group. |
| 0xFFFF | Broadcast. |

- Default unit ID = CRC-16 of the 6-byte base MAC, remapped if it lands in a
  reserved range. Override from NVS (`pl/unit_id`).
- A "destination" is a group ID. Each probe that can serve it subscribes to it.
  A sender seeks the group, not a specific probe.
- A device accepts a frame when `dst_id` is its unit ID, a group it subscribes
  to, or 0xFFFF.

---

## 3. Frame format

All multi-byte fields little-endian.

```
Off  Size  Field
0    1     ver_flags   bits 7..4 version (=1), bits 3..0 flags
1    1     type        message type (section 5)
2    2     src_id
4    2     dst_id
6    1     session_id  0 before BIND
7    2     seq         per-session, wraps at 65535
9    1     len         payload length, 0..max
10   len   payload
..   4     auth_tag    only if FLAG_AUTH
..   2     crc16       CRC-16/CCITT-FALSE over bytes 0 .. end of auth_tag
..   n     rs_parity   rs_nsym bytes, RAW links only
```

Fixed overhead: 12 bytes (+4 with auth, +rs_nsym on RAW links).

Flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 | FLAG_ACK_REQ | Receiver must reply ACK |
| 1 | FLAG_AUTH | auth_tag present |
| 2 | FLAG_FEC_GROUP | Frame belongs to a group-FEC group |
| 3 | reserved | 0 |

### 3.1 Why CRC-16 and not a parity bit

A single parity bit misses every even number of flipped bits (half of all
random errors). CRC-16/CCITT detects all 1-, 2- and 3-bit errors, all odd-bit
errors, and all bursts up to 16 bits in frames this size. It is the "parity
check" of this protocol.

### 3.2 In-frame Reed-Solomon (RAW links)

- Code: RS over GF(2^8), primitive poly 0x11D, first consecutive root 0,
  systematic (parity appended).
- `rs_nsym` parity bytes correct up to `rs_nsym / 2` damaged bytes anywhere in
  the frame, header included.
- Whole RS block (frame + parity) must be <= 255 bytes.
- Transmit: build frame -> append CRC -> RS-encode -> (UART: COBS + 0x00).
- Receive: (UART: COBS-decode) -> RS-decode -> if uncorrectable drop -> check
  CRC -> if CRC fails drop (catches RS mis-correction).

### 3.3 Group FEC (PACKET links)

- DATA frames are grouped by `seq / K`. K is set in MODE (default 4, range 2..16).
- After the K-th DATA frame of a group the sender emits one PARITY frame.
- PARITY payload = XOR of the K DATA payloads, each zero-padded to the longest,
  plus XOR of their `len` bytes.
- A receiver missing exactly one DATA frame of a group rebuilds it:
  payload = PARITY XOR (all received payloads); len = len_xor XOR (all received lens).
- Overhead = 1/K. K=4 costs 25 % and recovers 1 lost frame in 5.

---

## 4. Session state machine

```
Sender:   IDLE -> SEEKING -> BINDING -> CONFIGURING -> STREAMING -> CLOSED
Probe:    LISTENING -> OFFERED -> BOUND -> STREAMING -> LISTENING
```

```
Sender                         Probe A           Probe B
  | SEEK (dst=group, nonce) ---->|----------------->|      broadcast
  |                              | wait rand(0..50ms)
  |<--------------------- HELLO  |                  |
  |<-------------------------------------- HELLO    |      later, ignored
  | BIND (dst=group, probe=A) -->|----------------->|      B hears it, stands down
  |<------------------ BIND_ACK  |                  |
  | MODE (cfg 1, HIGH) --------->|
  |<------------------ MODE_ACK  |
  | DATA, DATA, DATA, DATA ----->|
  | PARITY --------------------->|
  |<----------------------- ACK  |                         periodic
  | MODE (cfg 2, LOW) ---------->|                         switch any time
  |<------------------ MODE_ACK  |
  | DATA ... ------------------->|
  | CLOSE ---------------------->|
```

### 4.1 Rules

1. SEEK is broadcast with `dst_id` = target group, a fresh 32-bit nonce, and
   the sender's capabilities.
2. Each probe subscribed to the group and not already BOUND waits a random
   delay in 0..`HELLO_WINDOW_MS` and sends HELLO (unicast to sender).
3. The sender takes the first valid HELLO whose nonce matches.
4. The sender broadcasts BIND with `dst_id` = group, naming the chosen probe
   and the new `session_id`. Every probe in the group hears it. The chosen probe
   replies BIND_ACK. All others return to LISTENING.
5. A probe that sent HELLO and hears no BIND within `BIND_TIMEOUT_MS` returns
   to LISTENING.
6. No HELLO within `SEEK_TIMEOUT_MS`: resend SEEK with the same nonce, backoff
   100, 200, 400, 800, 1600 ms, then give up (`PL_ERR_NO_PROBE`).
7. The session starts on BIND_ACK. Without BIND_ACK the sender resends BIND
   up to 3 times, then restarts SEEK.

Why three messages, not two: with SEEK + ACK only, two probes that both answer
both believe they own the session. BIND tells every probe who won.

### 4.2 Failover

If a session goes silent for `SESSION_TIMEOUT_MS` the sender closes it and
re-SEEKs the same group. Any other probe can take over. This is the payoff of
seeking a group instead of a fixed device.

---

## 5. Message types

| Type | Name | Dir | Payload |
|---|---|---|---|
| 0x01 | SEEK | S -> group (bcast) | nonce u32, caps u8, max_frame u16 |
| 0x02 | HELLO | P -> S | nonce u32, caps u8, max_frame u16, rssi i8 |
| 0x03 | BIND | S -> group | nonce u32, probe_id u16, new session_id u8 |
| 0x04 | BIND_ACK | P -> S | nonce u32 |
| 0x05 | MODE | S -> P | see 6.1 |
| 0x06 | MODE_ACK | P -> S | config_id u8, status u8 (0 ok, 1 unsupported, 2 too big) |
| 0x10 | DATA | S -> P | see 6.2 |
| 0x11 | PARITY | S -> P | group_first_seq u16, len_xor u8, xor bytes |
| 0x12 | ACK | P -> S | cum_seq u16, bitmap u16 (next 16 seqs) |
| 0x20 | PING | either | none |
| 0x21 | PONG | either | none |
| 0x30 | CLOSE | either | reason u8 |

caps bits: 0 HIGH, 1 LOW, 2 ARQ, 3 AUTH, 4 group FEC.

Probes never send DATA. Only the sender chooses the resolution mode.

---

## 6. Data and resolution modes

### 6.1 MODE frame

```
config_id      u8    1..255, increments on every change
mode           u8    0 = HIGH, 1 = LOW
ch_count       u8    1..16
period_us      u32   sample period
fec_k          u8    0 = no group FEC, else 2..16
arq            u8    0 = fire-and-forget, 1 = retransmit on ACK gaps
then per channel:
  kind         u8    0 = digital, 1 = analog
  fmt          u8    analog: 0 uint32, 1 int32, 2 float32
                     digital: number of lines, 1..32
  [LOW analog only]
  scale        f32
  offset       f32
```

- The sender may send MODE at any time after BIND_ACK.
- DATA keeps using the old `config_id` until MODE_ACK arrives.
- The probe keeps the last two configs, so frames in flight during a switch
  still decode.

### 6.2 DATA payload

```
config_id      u8
t_first_us     u32   timestamp of first sample, sender clock, since BIND_ACK
n_samples      u8
samples        n_samples x (all channels, in descriptor order)
```

| Channel kind | HIGH | LOW |
|---|---|---|
| Analog | 4 bytes, raw uint32 / int32 / float32 | 2 bytes, int16 q, value = offset + q * scale |
| Digital | 4 bytes, bitmap of 32 lines | ceil(lines / 8) bytes, bit-packed |

LOW quantization at the sender: `q = clamp(round((v - offset) / scale), -32768, 32767)`.
Choose `scale = (max - min) / 65535` and `offset = (max + min) / 2` for a known
range. 16 bits gives 65536 steps; e.g. 0..3.3 V -> 50 uV per step.

### 6.3 What fits in one frame

Data bytes per frame = max_frame - 12 (header + CRC) - 6 (DATA header) - rs_nsym.

Example: 4 analog channels.

| Carrier | Data bytes | HIGH samples/frame (16 B each) | LOW samples/frame (8 B each) |
|---|---|---|---|
| ESP-NOW (250) | 232 | 14 | 29 |
| WiFi UDP (255) | 237 | 14 | 29 |
| BLE (MTU 247 -> 244) | 226 | 14 | 28 |
| UART (255, nsym 8) | 229 | 14 | 28 |
| IR (64, nsym 6) | 40 | 2 | 5 |

### 6.4 BLE mapping

BLE has no "broadcast a frame and get unicast replies" primitive, so:

- SEEK is placed in the sender's advertising data (manufacturer-specific, legacy
  31 bytes is enough for a 19-byte SEEK).
- A probe that hears it connects and writes HELLO to the ProbeLink RX
  characteristic.
- After BIND_ACK, all frames go over one write-without-response characteristic
  (S -> P) and one notify characteristic (P -> S).

---

## 7. Reliability modes

| Setting | Use when | Behaviour |
|---|---|---|
| arq = 0, fec_k = 0 | Wired UART, short cable | CRC + RS only. Lost frames stay lost. |
| arq = 0, fec_k = 4 | Streaming telemetry over radio | 1 loss in 5 rebuilt, no added latency from retries |
| arq = 1, fec_k = 4 | Data that must arrive | FEC first; ACK bitmap gaps it could not fill get resent |

ACK is sent every `ACK_EVERY` frames or `ACK_MS`, whichever comes first.
It doubles as the liveness signal for the sender.

---

## 8. Security

- Without auth, anyone in radio range can send BIND or MODE and take over a
  session. Fine on a bench, not in deployment.
- FLAG_AUTH adds a 4-byte truncated HMAC-SHA256 over the frame before CRC,
  keyed with a pre-shared network key from NVS (`pl/net_key`). Never hardcode it.
- Replay protection: tag covers `session_id` + `seq`; the nonce from SEEK is
  mixed into the session key so old sessions cannot be replayed.
- ESP-NOW can also use its own CCMP encryption (PMK/LMK) for unicast peers
  after BIND; the number of encrypted peers is limited.

---

## 9. Constants

| Name | Default |
|---|---|
| HELLO_WINDOW_MS | 50 |
| BIND_TIMEOUT_MS | 200 |
| SEEK_TIMEOUT_MS | 100 (first try) |
| SESSION_TIMEOUT_MS | 2000 |
| ACK_EVERY | 8 frames |
| ACK_MS | 250 |
| FEC_K | 4 |

---

## 10. Prior art

TBD after research.
