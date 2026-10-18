# Braid example: 3-board demo

A button on board A reaches an LED on board C over ESP-NOW, relayed by board
B. Optional SSD1306 status displays show the session, hop count and route.
This is an application built on the Braid stack in `firmware/components`;
nothing here is part of the stack.

## Build and flash

From this directory:

```
pio run -e esp32_dev                                         # ESP32-WROOM-32E
pio run -e esp32s3_dev                                       # ESP32-S3-WROOM-1 N8
pio run -e esp32_dev -t upload --upload-port /dev/ttyUSB0    # flash one board
```

Then configure each board over the serial console (`br set ...`). The full
flash sheet, the expected serial lines and troubleshooting are in
[FLASH-DEMO.md](FLASH-DEMO.md).

## Contents

```
platformio.ini        envs esp32_dev / esp32s3_dev
CMakeLists.txt        ESP-IDF project file: adds ../../components (the stack)
sdkconfig.defaults*   copies of firmware/sdkconfig.defaults* (keep in sync)
main/                 app_main: NVS, platform bridge, then node_app_run()
components/app_node/  roles (sender, relay, probe), serial console + NVS
                      config, ESP-NOW and UART link adapters, radio
                      arbitration, SSD1306 status display (oled.c)
tools/range_log.py    range-test logger for board C (CSV with timestamp,
                      hops and RSSI per press)
FLASH-DEMO.md         flash sheet
```

Partition tables (`../../partitions*.csv`) and `../../version.txt` are
shared with the self-test image in `firmware/`.

## Status display

An SSD1306 128x64 I2C module on SDA GPIO21 / SCL GPIO22 (ESP32; S3: GPIO8 /
GPIO9), address 0x3C or 0x3D, is found at start. It shows role and id,
session state, `HOP n` with peer and next hop (`direct` or `via 0102`),
counters, live neighbours and the last event. Boards without one log
`BROLED none` and run unchanged.

## Range test

With board C on USB, from this directory:

```
~/.platformio/penv/bin/python tools/range_log.py
```

Writes `range-logs/range-<time>.csv` (one row per press, state change and
5 s status line) and a raw log. Type a note and Enter to mark your position.
Procedure and first results: FLASH-DEMO.md section 6b.

## Tests

The portable parts of `app_node` (console, UART link, radio arbitration,
ESP-NOW deferral, display driver) are host-tested from
`firmware/test/host/` (`test_console*.c`, `test_uart_link.c`,
`test_radio_arb.c`, `test_oled.c`), which compile these sources directly.
