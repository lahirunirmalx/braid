<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/braid-logo-dark.svg">
    <img alt="Braid - one mesh, many carriers" src="docs/assets/braid-logo-light.svg" width="560">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/lahirunirmalx/braid/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lahirunirmalx/braid/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: AGPL-3.0-or-later" src="https://img.shields.io/badge/license-AGPL--3.0--or--later-blue"></a>
</p>

# Braid

A multi-carrier mesh data-link stack for ESP32: one protocol over ESP-NOW, UART, WiFi UDP and nRF24L01+, with integrity, error recovery and encryption built in.

> ## Status
>
> - Protocol specification: **v0.9 (draft)**. Wire version 1, minor 0.
> - Stack and demo are **host-verified**: 27 test suites (about 1M frames of fuzzing, ASan/UBSan runs, mesh simulator scenarios, RFC 3610 CCM vectors).
> - Builds for **ESP32** and **ESP32-S3** with ESP-IDF 5.5.3.
> - **Run on hardware (2026-10-18):** ESP32 on-chip self-test PASS 826/826; ESP-NOW demo works over 2 hops, directly between A and C, and falls back to the relay when out of range; an ESP32-S3 (M5Stack Cardputer) joined as a fourth node and relayed.
> - UART, WiFi UDP and nRF24 carriers have **not been run on hardware**. The **nRF24 register driver has never touched a chip.**
> - Do not deploy this yet. Treat it as a reviewable design plus a tested core.

## What it is

- Transport-agnostic mesh over ESP-NOW, UART, WiFi UDP and nRF24L01+ (an IR edge link is specified, not built). Device IDs, and sessions formed by seeking a group (first probe to answer wins).
- Integrity and recovery on every frame: CRC-16, Reed-Solomon (in-frame on wired links, cross-frame FEC on packet links) and ARQ.
- Security: AES-128-CCM end-to-end plus a per-hop HMAC tag, key epochs and revocation.
- Payloads are digital or analog samples in HIGH (32-bit) or LOW (16-bit quantised) resolution.
- Pure C11 protocol core with a small HAL, so the same code runs on the host for testing.

## Carriers

| Carrier | Role | Status |
|---|---|---|
| ESP-NOW | Primary mesh radio | Implemented, host-verified, run on ESP32 (demo, range test) |
| UART | Wired point-to-point, RAW framing (COBS) | Implemented, host-verified, not run on hardware |
| WiFi UDP | LAN carrier, gateway side | Implemented, host-verified, not run on hardware |
| nRF24L01+ | Second mesh radio / bridge | Implemented; register driver never touched a chip |
| IR | Edge link (leaf devices) | Specified only |

The ESP-NOW and UART link adapters and the radio arbitration currently live in the demo example (`app_node`); the UDP and nRF24 carriers are stack components.

## Use cases

Details in PROTOCOL.md section 13.

- Fixed sensor networks: 5-50 nodes over 1-4 hops, one gateway as sink and manager.
- Campsite perimeter monitoring: battery sensors (PIR, beam-break, tripwire, reed) watched from a base.
- Vehicle and flight-data links: sensors to an onboard recorder over UART or direct ESP-NOW. The recorder must store data locally (the protocol is transport, not storage). Not certified aviation.

## Stack and examples

- **Stack** (`firmware/components`): protocol core, HAL, ESP-IDF port and the UDP / nRF24 carriers. `firmware/` itself builds only the on-chip self-test image.
- **Examples** (`firmware/examples/`): applications built on the stack, each a PlatformIO project of its own that pulls the stack from `../../components`.

| Example | What it shows |
|---|---|
| [demo-3board](firmware/examples/demo-3board/README.md) | Button on board A to LED on board C over ESP-NOW, relayed by B (or a 4th board such as an M5Stack Cardputer); serial console config, SSD1306 or ST7789 status display, range-test logger |

## Quick start

Prerequisites: [PlatformIO](https://platformio.org/) (platform `espressif32@6.13.0`, which brings ESP-IDF 5.5.3), CMake 3.16 or newer, a C compiler for the host build. Python 3 with `reedsolo` and `cryptography` is needed only to regenerate test vectors.

1. Host tests (from the repo root; add `-DBR_SANITIZE=ON` in a separate build dir for ASan/UBSan):

   ```
   cmake -S firmware/host -B firmware/host/build
   cmake --build firmware/host/build
   ctest --test-dir firmware/host/build
   ```

2. On-chip self-test (from `firmware/`; see [SELFTEST.txt](firmware/SELFTEST.txt)). Prints `BR_SELFTEST RESULT: PASS n/n`:

   ```
   pio run -e esp32_selftest -t upload -t monitor
   ```

3. 3-board demo (from `firmware/examples/demo-3board/`; flash and configure with [FLASH-DEMO.md](firmware/examples/demo-3board/FLASH-DEMO.md)):

   ```
   pio run -e esp32_dev -t upload --upload-port /dev/ttyUSB0
   ```

All builds are development builds: no Secure Boot, flash encryption or anti-rollback.

## Repository layout

```
PROTOCOL.md            the specification (v0.9); PROTOCOL.v0.*.md are frozen earlier drafts
SPEC-NOTES.md          implementation decisions on spec ambiguities
LICENSE, LICENSE-DOCS  AGPL-3.0 (code), CC BY-SA 4.0 (spec)
NOTICE                 test-key warning
roast/                 design review history (field and security reviews, rounds 1-4)
tools/vectors.py       oracle that generates and checks all test vectors
firmware/
  components/          the stack
    app_braid/         protocol core: CRC, COBS, RS, FEC, ARQ, crypto, sessions, mesh
    app_hal/           HAL headers (GPIO, UART, SPI, I2C, LCD, USB serial, UDP, radio, KV, time)
    port_esp_idf/      HAL implementation on ESP-IDF
    app_udp_link/      WiFi UDP carrier
    app_nrf24_link/    nRF24L01+ carrier and register driver
  main/                on-chip self-test image
  examples/
    demo-3board/       3-board demo (own platformio.ini, components/app_node, tools/)
  host/                host CMake build and CTest hook
  sim/                 host mesh simulator (virtual medium and clock)
  test/host/           unit, fuzz and scenario tests, generated vectors
```

## Documentation

Stack:

- [PROTOCOL.md](PROTOCOL.md): full specification.
- [SPEC-NOTES.md](SPEC-NOTES.md): implementation decisions and spec errata.
- [firmware/README-BUILD.txt](firmware/README-BUILD.txt): toolchain, builds, host tests.
- [firmware/SELFTEST.txt](firmware/SELFTEST.txt): on-chip self-test.
- [firmware/UART-LINK.txt](firmware/UART-LINK.txt), [UDP-LINK.txt](firmware/UDP-LINK.txt), [NRF24-LINK.txt](firmware/NRF24-LINK.txt): carrier notes.
- [firmware/GATEWAY-NRF24.txt](firmware/GATEWAY-NRF24.txt), [RADIO-ARB.txt](firmware/RADIO-ARB.txt): single-chip gateway and radio arbitration.
- [roast/](roast/): design review history.

Examples:

- [firmware/examples/demo-3board/README.md](firmware/examples/demo-3board/README.md): what the demo contains and how to build it.
- [firmware/examples/demo-3board/FLASH-DEMO.md](firmware/examples/demo-3board/FLASH-DEMO.md): flash sheet, expected output, direct and relayed variants, range test, troubleshooting.

## Licence

Code: **AGPL-3.0-or-later** (see [LICENSE](LICENSE)). Specification text: **CC BY-SA 4.0** (see [LICENSE-DOCS](LICENSE-DOCS)). Three points to know before you build on it:

1. **Network clause (AGPL section 13).** If you run a modified Braid gateway or host node that other people interact with over a network, you must offer those users the corresponding source.
2. **Installation Information (GPLv3 section 6, applies through AGPL).** If you ship a consumer device whose Secure Boot is locked to your key, buyers must still have a way to install modified firmware. Consider this before using the field profile's Secure Boot on consumer products.
3. **Dependencies.** ESP-IDF and mbedtls are Apache-2.0, which is compatible with (A)GPLv3.

This is not legal advice. See also [NOTICE](NOTICE) about the published test keys.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
