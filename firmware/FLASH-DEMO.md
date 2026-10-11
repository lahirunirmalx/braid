# Braid 3-board demo - flash sheet

Boards: 3 x ESP32-WROOM (original ESP32). Dev build only (no secure boot / encryption).
Frames travel A -> B -> C. Allowlists force it.

## Quick start (repeat runs)

1. Plug in ONE board. `pio device list` -> note port (e.g. /dev/ttyUSB0).
2. `cd ~/esp32-link-protocol/firmware && pio run -e esp32_dev -t upload --upload-port /dev/ttyUSB0`
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
cd ~/esp32-link-protocol/firmware && pio run -e esp32_dev
```
Expect: ends with `[SUCCESS]`.
Fails with `No module named 'idf_component_manager'`: see "Machine note" in README-BUILD.txt.

## 2. Selftest on ONE board (optional, recommended)

```
pio run -e esp32_selftest -t upload -t monitor
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
(UART-LINK.txt), `udp=on` with `espnow=off` (UDP-LINK.txt), `nrf=on`
(NRF24-LINK.txt). The full key list is in
`components/app_node/src/node_console.h`.

Any bad token rejects the whole line (`BRCFG error: ...`). Retype it.
Start order: B, C, A. Keep B and C powered and running, then reset A last.

## 5. Expected serial lines on success

Prefix `I (ms) node_app:` omitted below. Counts and values will differ.

All boards, at start:
```
BRBOOT starting in 3 s; send br commands now to change the configuration
BRRADIO espnow chan=1 mac=xx:xx:xx:xx:xx:xx
BRBOOT started role=<role> id=0x01nn grp=0xFF10 tasks: br@core.. led=<yes|no> btn=<yes|no> con@core.. uart=no udp=no nrf=no
BRSTART node 0x01nn txseq=... preseq=... allowlist=on transports=espnow
```
B adds: `BRRELAY forwarding only`
C adds: `BRLISTEN group 0xFF10 rc=0` (LED task `led=yes`)
A adds: `BRSEEKING group 0xFF10 (s=..)` and `btn=yes`

In this demo every board says `uart=no udp=no nrf=no` and `transports=espnow`.
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
BRRX src=0x0101 hops=2 seq=.. value=1
BREDGE src=0x0101 hops=2 0->1: LED x5
BRRX src=0x0101 hops=2 seq=.. value=0
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

## 8. If it fails: send back

1. Full monitor log of all three boards, from boot through two presses (use `| tee a.log`, `b.log`, `c.log`).
2. `br show` and `br stats` output from each board.
3. Board / devkit model, and whether C's LED is onboard or external.

## Warning: full erase

`-t erase` (full flash erase) wipes the frame counters. After erasing ANY board:
1. Power-cycle all three.
2. Neighbours may reject the erased board's frames for up to 1 h.

`br erase` is safe: clears config only, keeps counters.
