# ROAST-4: ProbeLink v0.6 vs field deployment on ESP32-WROOM

Target: PROTOCOL.md, DRAFT v0.6 (wire version 1, minor 0), 1848 lines.
Question: is v0.6 ready to start implementation for a field deployment
(one engineer, ESP-IDF, 5-50 nodes unattended for months), now that the
target module is the original ESP32 (ESP32-WROOM, dual-core LX6, 520 KB
SRAM, typically 4 MB flash)?
Scope: deploy-blockers and likely field failures. Mesh, BLE phone-only, IR
one-hop edge and nRF24 as a mesh carrier are USER-DECIDED and not reopened;
findings about them are missing or broken rules inside those decisions.
"(estimate)" marks reviewer estimates.

What was run:

- `tools/vectors.py`: prints ALL OK and reproduces A.2-A.14. That is still
  self-consistency only (the script generates Appendix A).
- Independent scratch check on the A.9 HELLO frame (pre_ctr 0x00010007):
  header seq equals the low 16 bits of the clear pre_ctr; CCM decrypt with
  ctr_hi 0 fails (InvalidTag), with ctr_hi 1 from the clear prefix it
  passes. A.12 MGMT_RESP uses gateway pre_ctr 0x00020005. H2 holds.
- Independent size table for every session_id 0 frame and RESUME against
  the IR frame budget (64 - 6 RS = 58 bytes): see J1.
- Arithmetic re-checks: header 19 / SEEK 22, overhead 21 + 12, max payload
  217 - rs_nsym; section 5 payload sizes against the 3.6 len column; 6.3
  samples-per-frame table; MGMT fixed parts 17 / 33; section 0 = 34 bytes;
  A.7-A.14 header bytes, AAD and nonce composition; A.14 TLV lengths. All
  agree except where noted.
- ESP-IDF v5.5 tree (`~/esp/esp-idf-v5.5`) for ESP32 facts:
  - `bootloader/Kconfig.projbuild:467`: Secure Boot v2 RSA on ESP32
    depends on `ESP32_REV_MIN_FULL >= 300`;
  - `soc/esp32/include/soc/soc_caps.h`: RMT 8 channels x 64 words, no
    `SOC_RMT_SUPPORT_RX_PINGPONG`, no `SOC_RMT_SUPPORT_DMA` (both present
    on C3 / S3);
  - `bt/controller/esp32/Kconfig.in:544`: `BTDM_RESERVE_DRAM` 0xdb5c
    (about 55 KB) whenever BT is built;
  - `esp_system/ld/esp32/memory.ld.in:81-82`: static DRAM segment
    `0x2c200 - BTDM_RESERVE_DRAM`, about 122 KB with BT built in;
  - `efuse/esp32/esp_efuse_table.csv:122`: `SECURE_VERSION` is BLOCK3
    bits 128..159 (32 bits);
  - `docs/en/security/flash-encryption.rst:194`: release mode burns
    `DISABLE_DL_ENCRYPT`, `DISABLE_DL_DECRYPT`, `DISABLE_DL_CACHE` at first
    boot;
  - `docs/en/api-guides/wifi.rst:2172`: in coexistence mode WiFi sleeps
    outside its time slice even with `WIFI_PS_NONE`.

---

## 1. Round-3 CRITICAL / HIGH and security U1-U7 verification

SOUND = specified and consistent. PARTIAL = specified with a gap.
REGRESSED = the fix created a new failure.

| ID | Sev | Verdict | Evidence |
|---|---|---|---|
| H1 / U5 | CRIT | SOUND, residual | Everything transmits under E_old; RETIRE only by TLV 0x06; retired slot admits MGMT_REQ; no timers. The straggler path depends on the manager serving the right bundle, which is undefined (J2). Epoch selection at the manager is not on the wire (MEDIUM). The post-RETIRE mixed window is a stated limitation (12.10), accepted. |
| H2 / U3 | CRIT | SOUND | Clear pre_ctr prefix in the AAD on every session_id 0 frame and RESUME; nonce formed with no receiver state; independent decrypt check above; A.12 MGMT_RESP above 0x10000; req_ctr echo binds MGMT_RESP. |
| H3 / U1 | HIGH | PARTIAL | `K_node` / `Kb` bundles, wire format, nonce, AAD, chunk index and A.14 are sound; managers cannot read bundles. Which bundle a manager serves, and how it learns a bundle was applied, is undefined (J2). |
| H4 | HIGH | PARTIAL, REGRESSED in part | Return-direction refresh, send-failure deletion, MGMT timeout and flood fallback, boot spread and the 3 x MGMT_PERIOD_S window are all present. New failure: the manager rate limit defeats the retries (J3). Also 60 s link expiry now deletes routes and nothing but traffic keeps links alive (MEDIUM; severe only on a quiet mesh). |
| H5 | HIGH | REGRESSED | Attached node as manager, edge pair key, station for rekey: written. But HELLO and MGMT_RESP no longer fit an IR frame, and the IR leaf's SEEK fails the live-epoch check after the first RETIRE (J1). |
| H6 | HIGH | PARTIAL | Sink named, node_count records, 921600 baud, FULL backoff 1 h cap, stream release rule. Re-acquiring a stream for a bound session is undefined, 8 streams do not cover the round-3 scenario, and the sink context is likely to overflow WROOM static DRAM with BT built (J4). |
| H7 | HIGH | SOUND | Command 3 opens a probe window on the leaf's own unit ID; image marked valid by one MGMT_RESP before the first park (which matches IDF rollback: a deep-sleep wake is a boot). Depends on J3 for the MGMT_RESP. |
| U2 | CRIT | SOUND | 32-bit hop_seq under the hop_tag; txseq block 4096 per reboot stays below HOP_MAX_JUMP 2^16 even for a boot loop of about 12 boots per minute. |
| U4 | HIGH | PARTIAL | req_ctr matching and command rate limits are sound. The manager-side 1/s rate limit interacts badly with the retry timer (J3). |
| U6 | HIGH | PARTIAL | Holders 0x0003..0x000F with own pair keys: sound. A lost-phone revocation is a bundle that changes no epoch, so nothing triggers its delivery (J2). |
| U7 | HIGH | SOUND | No-key field node waits for UART only; BLE needs a stored holder key; no automatic NVS erase. On the original ESP32 the BLE start itself needs rules (MEDIUM list). |

---

## 2. Findings (CRITICAL / HIGH)

### J1 [CRITICAL, IR only] The IR edge link can neither bind nor manage: HELLO and MGMT_RESP exceed the IR frame, and the IR leaf is rejected after the first retirement

Section: 1.2 (IR max_frame 64 incl. 6 RS), 3 (header 19), 5 (HELLO 28,
MGMT_RESP 33), 3.6 (SEEK row: "key_epoch is a live epoch"), 8.2 (edge
keys), 8.5 (Accept), 11.11 IR edge, 12.6, A.9 ("frame (61)"), A.12
("frame (66)").

Byte budget on IR: 64 - 6 RS = 58 bytes per frame.

| Frame (AUTH) | Bytes | IR (58) |
|---|---|---|
| SEEK | 54 | fits |
| HELLO | 61 | does not fit |
| BIND / BIND_ACK / BIND_NAK | 50 / 45 / 42 | fit |
| RESUME / RESUME_ACK | 38 / 39 | fit |
| MGMT_REQ fixed / with section 0 | 50 / 84 | fits / needs paging |
| MGMT_RESP fixed / with one command TLV | 66 / 69 | does not fit |

In v0.5, HELLO was 17 + 24 + 14 = 55 bytes and fitted. v0.6 added 2 header
bytes and `seek_ctr`, so this is a v0.6 regression.

Failure in the field:

1. An IR leaf SEEKs its attached node over IR (54 bytes, fits).
2. The attached node must answer with HELLO over IR: 61 bytes. Its adapter
   or the 10c / MTU check drops it. The leaf never binds, retries SEEK with
   backoff forever, and its data never arrives.
3. Even with a bound session, the leaf's MGMT_REQ gets no reply. The
   smallest MGMT_RESP is 66 bytes, so the leaf has no time, no commands and
   no health path, which is what review H5 was meant to fix.
4. Separately, the leaf's SEEK carries `key_epoch` = its E_old = E_prov
   forever, because IR leaves never receive bundles. After the first
   RETIRE, E_prov is no longer a live epoch at the attached node. 3.6 then
   drops the SEEK as `bad_frame`. 8.2 exempts only `K_hop` / `Ke_mesh` on
   the edge link and the pair key's storage, not this check. So "an IR leaf
   never goes deaf" (12.6) is false after the first rotation.

Minimal fix:

1. Raise IR `max_frame` to 80 (incl. 6 RS): 74 bytes carries HELLO (61) and
   MGMT_RESP with a command TLV (69). RS block <= 255 still holds. At about
   2 kbit/s that is about 0.3 s per frame (estimate).
2. State that MGMT section bytes are paged to the path MTU on IR (section 0
   in two pages).
3. In 3.6 and 8.5: on an `edge_only` link the SEEK key_epoch MUST equal
   E_prov and the handshake uses the edge pair key, whatever the live
   epochs are.
4. Add an IR-sized HELLO and MGMT_RESP vector, with an assertion that
   every session_id 0 frame type fits min(max_frame - rs_nsym) on every
   transport.

Scope: IR is already gated before field use (12.11), so this does not
block phase 1 (ESP-NOW plus UART gateway). It blocks any IR code.

### J2 [HIGH] Bundle selection and acknowledgement are undefined: a manager can serve bundles out of order and lose one for good, and non-epoch bundles are never triggered

Section: 8.5 (Receive E+1, Retire, Recover), 8.6 (`bundle_no` strictly
increasing, transport, managers store bundles as bytes), 11.10 (MGMT_REQ
fields; "a node whose e_new is behind, or whose request sets want_bundle,
receives TLV 0x05 chunks"; `page`), Appendix B `on_bundle`.

What is missing:

- MGMT_REQ and section 0 carry `e_new` and `e_old`, but no `bundle_no`.
  The manager cannot tell which bundle the node last applied.
- No rule says which stored bundle the manager serves when it holds
  several for a node.
- `want_bundle` has no trigger: nothing says when a node sets it.
- `page` is used both as the report-section page (sections 2 and 3 take
  several pages) and as the bundle chunk index. One request cannot carry
  both.

Failure in the field:

1. Rotation to epoch 2 is bundle #4 for leaf L. L is below VBAT_MIN for a
   week. After the operator cap the tool issues RETIRE(1) as bundle #5.
   The gateway now stores #4 and #5 for L.
2. L returns at {1, 1}. The gateway sees `e_new` behind and serves the
   newest, #5:
   - its tag verifies and 5 > 3, so L accepts it and writes
     `pl/bundle_no` = 5;
   - RETIRE(1) names L's E_old, so it applies;
   - L ends with E_old = E_new = 1 and 1 also in the retired slot, and no
     epoch 2.
3. The gateway then serves #4. L rejects it forever as a lower number
   (`bundle_fail`). L is a UART station visit, which is exactly what the
   retired slot was meant to avoid (H1 / U5).
4. Bundles that change no epoch: a lost-phone revocation (8.6, U6), a
   holder key added later, or a manager list (TLV 0x07). For these
   `e_new` is never behind, and `want_bundle` has no trigger. Either the
   manager never offers them, and a lost phone keeps its holder key on
   every node, or it re-sends them forever with no confirmation.

Minimal fix (wire change to MGMT_REQ, so it blocks MGMT code):

1. Add `bundle_no u32` (last accepted) to the MGMT_REQ fixed part
   (17 -> 21 bytes) and to section 0. Recompute A.12.
2. The manager serves the lowest stored bundle with a number above it,
   chunk by chunk, until the node reports that number. The tool marks a
   bundle delivered only when a section 0 shows it.
3. Make every bundle cumulative for its node: it carries every TLV needed
   from the previous bundle's state, so a skipped bundle cannot strand a
   node. Also reject RETIRE when E_new == E_old.
4. Give bundle chunks their own field (`chunk u8`) and keep `page` for
   report pages.

### J3 [HIGH] The manager's one-response-per-second limit defeats MGMT retries for 1-hop nodes and stalls every bundle chunk chain

Section: 11.10 Freshness ("answers at most one request per second per
node"), 11.10 Failure (retry after `BIND_TIMEOUT(hops)`, `MGMT_RETRIES`
2, then delete the route), 8.6 / 11.10 (one chunk per response,
"requesting each with page"), 4.4 (the chain keeps a leaf awake), 9
(BIND_TIMEOUT 470 ms at 1 hop, 890 ms at 2).

Failure in the field:

1. A 1-hop node sends MGMT_REQ at t = 0. The gateway answers, and the
   MGMT_RESP is lost.
2. The retries at 470 ms and 940 ms both fall inside the gateway's 1 s
   window, so neither is answered. The node deletes its route and waits
   600 s, then floods. The retry rule (review H4) never helps a 1-hop
   node.
3. Bundle chains. The node asks for chunk i + 1 as soon as chunk i arrives
   (tens of ms later):
   - the request is rate-limited, and so are both retries;
   - the route is deleted;
   - the next attempt is 600 s later (mains) or 10 wakes later (leaves).
   A 2.0-2.4 KB rotation bundle (pair keys for peers, managers and
   holders) is 12-14 chunks of 176 bytes. At 14 chunks that takes about
   2.3 h for a mains node next to the gateway, and 140 wakes for a leaf
   (11.7 h at 5-min parks, 5.8 days at 1 h). Leaves near the gateway
   miss the 24 h revocation cap and become stragglers. The retired-slot
   recovery uses the same throttled path.
4. At 2 hops a chain still crawls (one chunk per about 1.8 s) and pays a
   failed request per chunk.
5. A leaf after an update boot needs one MGMT_RESP before its first park
   (12.7). A single lost reply at 1 hop rolls the image back.

Minimal fix:

1. The node waits at least 1 s after the previous MGMT_RESP before the
   next request in a chain.
2. Set the MGMT response timeout to `max(BIND_TIMEOUT(hops), 1100 ms)`.
3. Or exempt from the rate limit a request that asks for the chunk
   following the one just served.
4. Add the chain to the simulator scenarios.

### J4 [HIGH] Sink stream pool: re-acquiring a stream for a bound session is undefined, 8 streams do not cover the round-3 scenario, and the sink context is likely to overflow WROOM static DRAM with BT built in

Section: 4.1.12 (a stream is taken "when its first DATA arrives" and
released between groups; sink `PL_MAX_STREAMS` 8; sizing "streams >=
senders with ARQ/FEC streaming at the same time"), 4.1.2 / 4.1.4 (FULL
only at HELLO time), 7 (FEC k 8 / m 2 is the default for radio
streaming), 12.4 ("about 30 KB of records plus 38 KB of streams on a C3 or
S3"), Appendix B (`PL_CTX_STATIC`, about 79 KB for the sink).

Failure in the field:

1. Round-3 scenario: 25 mains sensors streaming with the default FEC and
   20 leaves send to the sink. Each FEC sender at 1 frame/s keeps a group
   open for about 10 s, then releases its stream for about 0.5 s
   (REORDER_MS) before its next DATA.
2. In those gaps other sessions take the free streams. When an already
   BOUND sender's next group starts, no stream may be free. The spec only
   defines FULL at HELLO time. For a bound session it says nothing: drop
   the DATA, deliver it without FEC, or close? Implementations will
   differ, and with 25 senders on 8 streams the case occurs constantly.
3. The fixed 8 contradicts the 4.1.12 sizing rule. Senders 9..25 either
   get FULL and back off up to 1 h, or hit the undefined case above.
4. WROOM fit (original ESP32):
   - with BT compiled in (every node needs it for 6.4), the static DRAM
     segment is `0x2c200 - 0xdb5c`, about 122 KB, shared with all IDF and
     WiFi statics;
   - `PL_CTX_STATIC` for the sink (about 79 KB, plus 7 KB tables and 4 KB
     rx queue) is likely to overflow `dram0_0_seg` next to them on a WROOM
     (estimate; the IDF static total is not measured here);
   - from heap, a WROOM sink holds about 20 stream buffers of 4.7 KB
     after WiFi, BT reserve and records (estimate, measure), not 45.
   12.4 sizes this role only for C3 / S3.

Minimal fix:

1. In 4.1.12, a bound session holds its stream from its first DATA until
   CLOSE, PARK or SESSION_TIMEOUT (no release between groups). FULL is
   then decided once, at HELLO.
2. Sink `PL_MAX_STREAMS` = the number of manifest senders with ARQ or FEC.
   The provisioning tool refuses a manifest whose sink does not fit the
   chip's budget, and points to a second sink probe (re-origination, 12.4).
3. Allocate `pl_ctx_t` from heap inside `pl_init` (Appendix B forbids heap
   only after init), or build the gateway mesh chip without BT.
4. Size stream buffers from MODE (k + m and the session max_payload)
   instead of a fixed 4.7 KB slot. Restate 12.4 for ESP32.

### J5 [HIGH, WROOM] The 12.2 provisioning order cannot produce an encrypted NVS on the original ESP32

Section: 12.1 (Chips: original ESP32 at rev 3.0+ "with a flash-encrypted
`nvs_keys` partition"; `pl_init` refuses unless the key partition is
encrypted), 12.2 (order: enable flash encryption in release mode and wait
for first-boot encryption; then provision the NVS key; then write the
per-device encrypted NVS image; verify over UART; burn UART download
last), 6.4 / 12.1 (a no-key node waits for "UART provisioning").

Mechanism:

- On the original ESP32 there is no eFuse-HMAC NVS key. The NVS XTS keys
  live in the `nvs_keys` partition, which MUST itself be flash-encrypted.
- In release mode the second-stage bootloader burns `DISABLE_DL_ENCRYPT`,
  `DISABLE_DL_DECRYPT` and `DISABLE_DL_CACHE` at first boot. After that,
  esptool can no longer write flash-encrypted data through the ROM loader.
- With a device-generated flash-encryption key (the 12.2 order), the host
  cannot write `nvs_keys`. If the app generates `nvs_keys` on first boot,
  the host does not know the NVS key, so it cannot generate the
  "per-device encrypted NVS image".
- The only remaining path is the running app writing the keys itself. It
  would need a plaintext UART provisioning command set for a node that
  holds no `K_pair(node, 0x0002)`, and the spec defines none. The station
  speaks MGMT under a pair key the blank node does not have.

Failure: the dry run on the two sacrificial boards ends with release-mode
flash encryption, no usable NVS keys, and an app that waits forever for an
undefined UART provisioning protocol. Every field-profile WROOM node is
blocked the same way. The C3 / S3 HMAC path does not have this problem,
which is why it was not caught.

Minimal fix (pick one, state it in 12.2 for ESP32):

1. Reorder two steps (simplest). First-boot encryption encrypts in place
   every partition flagged `encrypted`, `nvs_keys` included:
   - the host generates `nvs_keys` (`nvs_partition_gen.py generate-key`)
     and flashes it in plaintext before the first boot;
   - the release-mode first boot encrypts it with the device-generated key;
   - the host then writes the NVS image it encrypted with that key file, in
     plaintext through download mode. This still works: the NVS data
     partition is XTS-encrypted by the NVS library, not flash-encrypted;
   - `UART_DOWNLOAD_DIS` is burned last, as 12.2 already says.
2. Host-generated flash-encryption key per device:
   - burn it with espefuse;
   - pre-encrypt bootloader, app and the host-generated `nvs_keys` with
     `espsecure encrypt_flash_data`;
   - write the NVS image produced by `nvs_partition_gen.py` with that
     key file;
   - only then burn `FLASH_CRYPT_CNT` and the release-mode bits;
   - destroy the host copy of the flash-encryption key after the
     verification step, and record that in the manifest.
3. Or define a bench-only plaintext UART provisioning frame set that the
   app accepts only while it holds no keys and only before the
   download-mode eFuse is burned. The app writes NVS itself under
   on-device `nvs_keys`.

---

## 3. WROOM fit

### 3.1 Which module the deployment profile should require

Require ESP32-WROOM-32E (PCB antenna) or ESP32-WROOM-32UE (U.FL), chip
ESP32-D0WD-V3 / D0WDR2-V3, silicon revision v3.0 or later. The firmware
is built with `CONFIG_ESP32_REV_MIN_3` (or `_3_1`), so it refuses older
silicon. Flash: N4 (4 MB) minimum; N8 if the image with BLE exceeds about
1.8 MB. No PSRAM (WROVER) is needed.

- Exclude WROOM-32, -32D and -32U. They carry revision 1.x silicon, and
  IDF exposes Secure Boot v2 on ESP32 only when `ESP32_REV_MIN_FULL >=
  300`. `UART_DOWNLOAD_DIS`, which the 12.1 eFuse row relies on, is also
  revision 3 only. 12.1 already says "revision 3.0 or later"; the profile
  should name the module so procurement cannot get it wrong.
- Use -32UE for the gateway mesh chip and for any ESP-NOW / nRF24 bridge.
  12.4's antenna separation and cross-polarisation rule cannot be met with
  two PCB antennas on one board.
- 4 MB layout (estimate, check against the built image):
  - bootloader at 0x1000. Secure Boot v2 plus flash encryption can push it
    past the default 0x8000 partition table offset; move
    `CONFIG_PARTITION_TABLE_OFFSET` if so;
  - nvs 64 KB (about 300 entries of pair keys over 3 epochs, plus counter
    churn);
  - nvs_keys 4 KB (encrypted);
  - otadata 8 KB;
  - phy_init 4 KB;
  - two OTA slots of about 1.9 MB.
  The 12.7 "1 MB image" is optimistic once WiFi, BLE and mbedtls are
  linked: expect 1.2-1.5 MB with NimBLE (estimate).

### 3.2 Checks against the original ESP32

| Item | Spec assumption | ESP32-WROOM reality | Verdict |
|---|---|---|---|
| Secure Boot v2 | 12.1 field MUST | Rev v3.0+ only; RSA-3072, one key digest, no key revocation (C3 / S3 allow 3 keys and revocation) | OK with 3.1; the single key goes into 12.10 (MEDIUM) |
| Anti-rollback | 8.7 "Secure Boot v2 secure version eFuse" | `SECURE_VERSION` is BLOCK3 bits 128..159 (32 bits), app anti-rollback, one burned bit per bump | Wording and budget (MEDIUM) |
| NVS encryption | 12.1 `nvs_keys` path for ESP32 | Correct scheme; the 12.2 order does not work | J5 |
| Fault injection | 12.1 "R1 is a cost" | Original ESP32 has published eFuse key readout by voltage glitching (CVE-2019-17391); a thief with a rig gets that node's K_node and pair keys | Accept; name it (LOW). Revocation is the control, and J2 decides whether revocation works |
| DRAM | App. B / 12.4 sized for C3 / S3 | About 122 KB static with BT built; about 55 KB `BTDM_RESERVE_DRAM` cannot be released if BLE must start later | Normal nodes fit (about 49 KB at 32 records / 4 streams); sink J4 |
| BT controller | 6.4 "mesh stopped, BLE starts" | Coexistence time-slices WiFi even with `WIFI_PS_NONE` while the controller is enabled | Spec must order controller disable and deinit around `esp_wifi_start` (MEDIUM) |
| Cores | App. B: one `pl_task`, no affinity | Dual core; WiFi and ESP-NOW callbacks run in the WiFi task on core 0 | No C3-only assumption. Pin `pl_task` to core 1; ESP-NOW send status is asynchronous (MEDIUM) |
| WiFi + ESP-NOW + nRF24 | 12.4 channel plan, bridge TX arbitration | SPI2 / SPI3 free; WiFi and nRF24 share 2.4 GHz on one board | OK with -32UE; GPIO12 strap and ADC2 caveats (MEDIUM) |
| IR RX | C.1: C3 partial receive or S3 DMA | No RX ping-pong, no DMA; 64 words per channel, 512 words in all, and a 64-byte frame is about 512 symbols | Needs all 8 blocks (no TX channel left) or GPIO / MCPWM capture (MEDIUM); J1 makes frames longer |
| Leaf wake | 4.4 0.4-0.9 s | Secure Boot v2 verifies the app on every deep-sleep wake | Plausible; measure (already gated) |
| Hardware crypto | 8.3 "hardware AES on all variants" | AES and SHA accelerators present (AES without DMA) | OK |

---

## 4. MEDIUM and LOW (titles only)

MEDIUM, protocol:

- 60 s link expiry deletes the routes through the link and no beacon exists: on a quiet mesh (no leaf floods), keepalive_ms >= 60 s sessions over 2+ hops break every cycle and MGMT_REQ mostly floods; elsewhere, ACK churn at a slow sender's first hop. Keep referenced entries until their route expires (11.6, 11.9, 9)
- The manager's K_mgmt epoch is not on the wire; "the epoch it arrived in" must mean trial-decrypt E_old, E_new, retired and answer under the one that verified (8.5, 11.10)
- Unicast hop_tag epoch when the link entry has expired or names the retired slot (non-MGMT frames) is undefined; default to E_old (8.5, 11.4 step 10e)
- Gateway outage: SEEK floods plus failure-triggered MGMT_REQ floods from every sender, about 12 % airtime (estimate), above the 10 % rule (4.1.8, 9)
- Adapter `send()` returns delivery status synchronously, while ESP-NOW reports it asynchronously from the WiFi task; no task / core layout given (1.2, 11.6, App. B)

MEDIUM, WROOM:

- BLE maintenance on ESP32: about 55 KB BTDM DRAM reserved whenever BT is built; controller disable / deinit order around WiFi start; recommend reboot-into-maintenance and NimBLE; IRAM budget with WiFi + BLE + SPI ISR (6.4, 12.5)
- IR RX on the original ESP32: no RMT RX ping-pong or DMA; C.1 gives only C3 / S3 paths (C.1)
- No partition table or minimum flash in the deployment profile; partition-table offset with a Secure Boot v2 bootloader; NVS size (12.1, 12.7)
- Anti-rollback on ESP32 is the 32-bit BLOCK3 `SECURE_VERSION` app field, not a Secure Boot v2 eFuse; bump only on security releases (8.7)
- ESP32 Secure Boot v2 has one key digest and no key revocation; not in 12.10 (12.1, 12.10)
- WROOM pin plan: GPIO12 strap and the flash-voltage eFuse (burn before UART download is disabled), GPIO6-11 reserved, ADC2 unusable while WiFi runs (12.2, 4.4 VBAT)

LOW:

- Header layout changed under unchanged wire version 1.0, while section 3 calls the prefix frozen (3, D)
- 3.6 does not require header `seq` == low 16 bits of the clear `pre_ctr` (3.6)
- A.12 MGMT_REQ labels 8 bytes as section 0, which is 34 bytes (A.12, 11.10)
- `pl_stats_t` ends in a u16, while section 1 says all u32 (App. B, 11.10)
- KEY_RECOVERY_S "uptime" persistence across reboots undefined (8.5)
- The MGMT response timeout `BIND_TIMEOUT(hops)` has no hops value for a flooded request (11.10)
- The tool must persist `bundle_no` transactionally: a reuse is CCM nonce reuse under the never-rotated `Kb`, and a captured gateway sees both ciphertexts (8.6)
- 8.7 mentions "beacons"; no beacon frame exists (8.7)
- Name the original-ESP32 eFuse key readout (CVE-2019-17391) in 12.1 for WROOM (12.1)

---

Counts: CRITICAL 1, HIGH 4, MEDIUM 11, LOW 9

Verdict: READY WITH CONDITIONS

The frame, crypto and session core is consistent: H2 is verified
independently, the vectors agree with the text, and the 19-byte header,
pre_ctr AAD prefix, K_node bundles and epoch slots match byte for byte.
Implementation can start now on:

- frame codec, the 3.6 validator and fuzz harness, CRC / COBS / RS /
  group FEC;
- ARQ and reorder;
- HKDF / CCM / hop_tag / transcript and the keystore;
- sender and probe session machines, park and resume;
- the forwarding pipeline;
- the ESP-NOW and UART adapters and the host simulator.

Conditions, each before the named work:

1. Before any MGMT or bundle code: fix J2 (adds `bundle_no` to MGMT_REQ and
   section 0, recompute A.12, cumulative bundles, separate chunk field) and
   J3 (chain pacing or timeout >= 1.1 s).
2. Before the gateway build: fix J4 (stream held per bound session, sink
   streams sized from the manifest, heap-allocated context or no BT on the
   mesh chip, ESP32 budget in 12.4).
3. Before the provisioning tool and the first sacrificial-board dry run:
   fix J5 (an ESP32 path in 12.2). The profile also names ESP32-WROOM-32E /
   -32UE at revision v3.0+, `CONFIG_ESP32_REV_MIN_3`, N4 minimum and a
   partition table.
4. Before any IR code: fix J1 (IR max_frame 80, edge key_epoch rule, IR
   vectors). IR stays out of phase 1, as 12.11 already says.

12.11 overstates readiness. Its "buildable now" list includes MGMT with
bundles, the provisioning and bundle tool, and the two-chip gateway with
the LAN sink. Those are not buildable as written until J2, J3, J4 and J5
are fixed. The rest of that list stands.

Before field deployment the 12.11 soak list stands, plus:

- one bundle chain to a 1-hop leaf;
- a straggler that returns after two bundles were issued;
- a 60 s keepalive session over 2 hops;
- 25 FEC senders to the sink.
