# Braid 3-board demo - flash sheet

Boards: 3 x ESP32-WROOM (original ESP32). Dev build only (no secure boot / encryption).
Frames travel A -> B -> C. Allowlists force it.
Variant: let A and C also talk directly, so the demo keeps working with B
off (section 6a).

Run the `pio` commands below from this directory
(`firmware/examples/demo-3board`), except the self-test in section 2,
which builds from `firmware/`.

## Quick start (repeat runs)

1. Plug in ONE board. `pio device list` -> note port (e.g. /dev/ttyUSB0).
2. `cd ~/esp32-link-protocol/firmware/examples/demo-3board && pio run -e esp32_dev -t upload --upload-port /dev/ttyUSB0`
3. `pio device monitor -p /dev/ttyUSB0 -b 115200 --echo`, type that board's `br set` line (section 4).
4. Order: B, then C, then A. Unplug/replug the next board between each.
5. Power all three. Wait for `BRREADY` on A.
6. Press BOOT on A. C's LED flashes 5 times.

## Roles

| Board | Role | id | Config line |
|-------|------|----|-------------|
| A | sender (BOOT button, GPIO0, nothing to wire) | 0x0101 | see 4 |
| B | relay | 0x0102 | see 4 |
| C | probe (LED, GPIO2) | 0x0103 | see 4 |

C LED: onboard LED is GPIO2 on most WROOM devkits. No LED on yours:
external LED + 330 ohm from GPIO2 to GND, active-high. Other pin: `led=<pin>`.

Radio: ESP-NOW, channel 1 (default `chan=1`), all three boards the same.

## 1. Toolchain check (once)

```
cd ~/esp32-link-protocol/firmware/examples/demo-3board && pio run -e esp32_dev
```
Expect: ends with `[SUCCESS]`.
Fails with `No module named 'idf_component_manager'`: see "Machine note" in ../../README-BUILD.txt.

## 2. Selftest on ONE board (optional, recommended)

```
cd ~/esp32-link-protocol/firmware && pio run -e esp32_selftest -t upload -t monitor
```
Expect, repeating every 10 s:
```
app: BR_SELFTEST RESULT: PASS 826/826
```
Ctrl+C to leave the monitor. Press RST to rerun.

If FAIL, crash, or no RESULT line within 15 s of reset, copy back:
- board / devkit model
- full serial log from first `rst:` line to first `BR_SELFTEST RESULT`
- every line containing `FAIL [`, `selftest heap`, `selftest stack`
- crash: the `Guru Meditation` block + decoded backtrace
- build failed: `pio run -e esp32_selftest -v 2>&1 | tail -40`

Do not retry with other settings first.
Selftest image stays on the board; step 3 overwrites it.

## 3. Flash the demo image (each board)

1. Plug in one board only (or name ports explicitly if several are plugged in).
2. `pio device list` -> port.
3. Flash:
```
pio run -e esp32_dev -t upload --upload-port /dev/ttyUSB0
```
Expect: `Hard resetting via RTS pin...` then `[SUCCESS]`.

Do NOT add `-t erase`. Full erase resets the frame counters (see Warning).

## 4. Configure each board (order B, C, A)

Open the monitor with echo (without `--echo` you see nothing you type):
```
pio device monitor -p /dev/ttyUSB0 -b 115200 --echo
```
Lines end with Enter. An unconfigured board waits indefinitely, so no rush:
```
BRCFG boot role=unset id=unset grp=0xFF10 nbr=none led=2 btn=0 chan=1 (incomplete: ...)
BRBOOT waiting for configuration, e.g.: br set role=probe id=0x0103 grp=0xFF10 nbr=0x0102
```
Type the line for this board:

- B: `br set role=node id=0x0102 nbr=0x0101,0x0103`
- C: `br set role=probe id=0x0103 grp=0xFF10 nbr=0x0102 led=2`
- A: `br set role=sender id=0x0101 grp=0xFF10 nbr=0x0102 led=2 btn=0 chan=1`

Expect: `BRCFG saved role=... (ready)`.
First valid config on an unconfigured board starts it at once.
If the board was already configured, it starts 3 s after boot:
type within that window, then `br reboot` (or power-cycle) to apply.

Console:
- `br show` stored config + running id/mac
- `br stats` one BRSTAT line now (also auto every 5 s)
- `br erase` clears config, keeps counters
- `br reboot` restart (needed after `br set` on a running board)

Other carriers (not part of this demo; all off by default): `uart=on`
(../../UART-LINK.txt), `udp=on` with `espnow=off` (../../UDP-LINK.txt), `nrf=on`
(../../NRF24-LINK.txt). The full key list is in
`components/app_node/src/node_console.h`.

Any bad token rejects the whole line (`BRCFG error: ...`). Retype it.
Start order: B, C, A. Keep B and C powered and running, then reset A last.

## 5. Expected serial lines on success

Prefix `I (ms) node_app:` omitted below. Counts and values will differ.

All boards, at start:
```
BRBOOT starting in 3 s; send br commands now to change the configuration
BRRADIO espnow chan=1 mac=xx:xx:xx:xx:xx:xx
BROLED ssd1306 128x64 at 0x3C sda=GPIO21 scl=GPIO22   <- or "BROLED none at 0x3C/0x3D ..." without a display
BRBOOT started role=<role> id=0x01nn grp=0xFF10 tasks: br@core.. led=<yes|no> btn=<yes|no> con@core.. uart=no udp=no nrf=no wifi=no oled=<yes|no>
BRSTART node 0x01nn txseq=... preseq=... allowlist=on transports=espnow
```
B adds: `BRRELAY forwarding only`
C adds: `BRLISTEN group 0xFF10 rc=0` (LED task `led=yes`)
A adds: `BRSEEKING group 0xFF10 (s=..)` and `btn=yes`

In this demo every board says `uart=no udp=no nrf=no` and `transports=espnow`.

Status display (optional): an SSD1306 128x64 I2C module on SDA GPIO21 /
SCL GPIO22 (ESP32; S3: GPIO8 / GPIO9), address 0x3C or 0x3D, is found at
start; nothing to configure. It shows role and id, session state, `HOP n`
with the peer and next hop (`direct` or `via 0102`), counters, live
neighbours (`nb`) and the last event, and inverts while C's LED flashes.
Skipped when led, btn or an enabled carrier already uses GPIO21 / GPIO22.
SH1106 panels (picture shifted 2 px): set `kOledColOffset = 2` in
`components/app_node/src/node_app.cpp`.
Boards with another carrier on also print a `BRUART ...`, `BRWIFI ...` /
`BRUDP ...` or `BRNRF ...` line here and list it in `transports=` (joined
by `+`, e.g. `transports=espnow+uart`); see the carrier's own notes file.

Links (each board, once per neighbour):
```
BRLINK neighbour 0x0102 mac=... rssi=-nn      <- on A and C
BRLINK neighbour 0x0101 / 0x0103 ...          <- on B (both)
```
A neighbour reached over another carrier is logged as `BRLINK neighbour
0x.... via=uart2 ...`, `via=udp a.b.c.d:port ...` or `via=nrf24 50:4c:..`
instead of `mac=`. Not in this demo.

A, within about 1.8 s of start (first SEEK wait), then:
```
BRSEEK s=.. result=0 probe=0x0103 hops=2
BRSTATE sender SEEKING -> BINDING
BRBOUND s=0x.. peer=0x0103
BRSTATE sender BINDING -> CONFIGURING
BRMODE s=0x.. config_id=1 mode=HIGH ch=1 arq=1 fec_m=0 keepalive=5000
BRSTATE sender CONFIGURING -> STREAMING
BRREADY streaming to group 0xFF10: press BOOT (GPIO0)
```
(state lines may differ in order or skip a step; `BRREADY` is the gate.)
C: `BRSTATE probe rec=0 LISTENING -> OFFERED -> BOUND -> STREAMING` (one line per step).

Not seen = problem. Look for BRRESEEK, BREVT, BRCLOSED (section 7).

## 6. Press test

Press and release BOOT on A (do not hold it during reset: GPIO0 low at reset = download mode).

A prints (value 1, then 0 = two frames per press):
```
BRPRESS n=1 sent value 1 rc=0, value 0 rc=0
BRACK s=.. seq=.. acked=1
BRACK s=.. seq=.. acked=2
```
C prints:
```
BRRX src=0x0101 hops=2 seq=.. value=1 rssi=-nn
BREDGE src=0x0101 hops=2 0->1: LED x5
BRRX src=0x0101 hops=2 seq=.. value=0 rssi=-nn
```
C's LED flashes 5 times.

BRSTAT proof (type `br stats` or wait 5 s):
- B: `BRSTAT role=node ... relay_fwd=N ...` N rises after each press
- C: `hops=2` in every BRRX (src A, via B)
- A: `delivered=` +2 per press, `auth_fail=0`, `drops=none`

BRSTAT format: `BRSTAT role= uid= sess= relay_fwd= delivered= retx= auth_fail=
tx= rx= routes= hwm= heap= drops=<name:count,...|none>`. Boards with another
carrier on insert its fields before `hwm=`: `uart_tx= uart_rx= rs_fixed=`
(uart), `udp_tx= udp_rx=` (udp), `nrf_tx= nrf_rx= nrf_seg=tx/rx nrf_maxrt=`
(nrf), and their drop names (`u_*`, `ud_*`, `n_*`) appear in `drops=` only
when non-zero. With every carrier off the line is the phase 1c line.

BRPRESS `ignored: session SEEKING` = A not streaming yet. Wait for `BRREADY`.

`relay_fwd=1` on C is normal: a probe is not a leaf, so it re-floods A's
group SEEK once in case more group members sit beyond it.

## 6a. Variant: direct A - C, B optional

The section 4 allowlists only admit B, so every frame takes two hops. To let
A and C also reach each other directly (and keep working with B off), add
each one to the other's list, then reboot:

- A: `br set nbr=0x0102,0x0103` then `br reboot`
- C: `br set nbr=0x0101,0x0102` then `br reboot`

B is unchanged. The mesh takes the cheapest path, so while A and C hear each
other they bind directly and B carries nothing:
```
BRRX src=0x0101 hops=1 seq=.. value=1 rssi=-nn <- on C
```
B is used only when A and C are out of each other's range (different rooms):
then C shows `hops=2` again. Both cases (B unplugged, and the fallback through
B out of range) were checked on hardware on 2026-10-18. If the active path dies, A's session closes and
re-SEEKs (backoff 1 s up to 30 s) over whichever path still works.

Unplug B and press BOOT on A: with A and C in range the LED still flashes,
and B (`0102`) drops out of the `nb` line on the status displays after the
link times out.

## 6b. Range test (board C mobile)

Board C on a laptop USB port, A fixed, BOOT pressed on A while walking:
```
~/.platformio/penv/bin/python tools/range_log.py      (from this directory)
```
One CSV row per press with hops and `rssi=` (last hop), plus state changes
and the 5 s BRSTAT line; type a note + Enter to mark a position.

First run (2026-10-18, ESP32 devkits, ESP-NOW channel 1):
- A - C direct, B off: presses arrived down to about -94 dBm; the session
  timed out about 20 s after the last one. Treat about -85 dBm as the
  reliable edge.
- B placed between them: when the direct path failed, A re-SEEKed and C
  re-bound through B within the same second (`hops=2`); presses then
  arrived at -88 to -91 dBm on the B - C hop. A relay too close to the edge
  of A's range stays silent (it only re-sends what it hears), so place B
  where both sides see better than about -85 dBm.

## 7. Troubleshooting

| Symptom | Likely cause | Try / copy back |
|---------|--------------|-----------------|
| Nothing you type appears | monitor started without `--echo` | restart monitor with `--echo` |
| Board prints "waiting for configuration" forever | no role set | `br set ...` (section 4), then `br show` |
| `BRCFG error: ...` | bad token; whole line rejected | read message, retype the full line |
| `br set` has no effect | board already running | `br reboot` |
| No `BRLINK` lines | allowlist or channel mismatch, boards off, antenna | `br show` on all three: same `chan`, nbr as in table. Copy back the three `br show` |
| A stuck `SEEKING`, `BRRESEEK in .. ms`, `BREVT no probe answered` | B or C not started, or wrong `nbr` | start B and C first, then reset A. Check `br show` nbr/id/grp (grp must match on A and C) |
| `auth_fail` rising in BRSTAT | a board was fully erased: counters restarted | power-cycle all three. Wait; neighbours may reject its frames up to 1 h. Copy back `br stats` x3 |
| `BREVT ID collision` | two boards same id | fix id on one, `br reboot` |
| LED never flashes but `BRRX ... value=1` and `BREDGE` shown | LED pin or polarity | `br set led=<pin>` + `br reboot`; check wiring (active-high, 330 ohm to GND). `BRLED GPIO.. init failed` = pin refused |
| `BRPRESS ignored` | session not STREAMING | wait for `BRREADY` |
| A `BRCLOSED`, then `BRRESEEK` | link lost; re-SEEK backoff 1 s up to 30 s | check B/C still powered; copy back logs |
| Flash fails to connect | wrong port, or board needs BOOT held at `Connecting...` | `pio device list`; hold BOOT while `Connecting....` shows |
| Reboot loop: `E BOD: Brownout detector was triggered` right after `phy_init` | supply sags when the radio starts (`sdkconfig.defaults` uses brownout level 7, about 2.8 V) | another USB cable / port, 100 uF across 3V3-GND, or use another board |
| Board restarts each time the monitor opens | CH340 boards: opening the port toggles EN | expected; that board re-binds (A re-SEEKs). Keep one monitor open instead of reopening |
| `BROLED none at 0x3C/0x3D` with a display wired | SDA/SCL swapped, no power, or the panel does not ACK at 400 kHz | check GPIO21 = SDA, GPIO22 = SCL, VCC, GND; else lower `kOledHz` in `node_app.cpp` |
| Display picture shifted by 2 px | SH1106 controller, not SSD1306 | `kOledColOffset = 2` in `node_app.cpp` |
| Display shows only the top half, or doubled rows | 128x32 panel | the driver is 128x64 only (`k_init` in `oled.c`: `0xA8 0x1F`, `0xDA 0x02`) |

## 8. If it fails: send back

1. Full monitor log of all three boards, from boot through two presses (use `| tee a.log`, `b.log`, `c.log`).
2. `br show` and `br stats` output from each board.
3. Board / devkit model, and whether C's LED is onboard or external.

## Warning: full erase

`-t erase` (full flash erase) wipes the frame counters. After erasing ANY board:
1. Power-cycle all three.
2. Neighbours may reject the erased board's frames for up to 1 h.

`br erase` is safe: clears config only, keeps counters.
