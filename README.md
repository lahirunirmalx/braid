# Braid

A multi-carrier mesh data-link stack for ESP32: one protocol over ESP-NOW, UART, WiFi UDP and nRF24L01+, with integrity, error recovery and encryption built in.

> ## Status
>
> - Protocol specification: **v0.9 (draft)**. Wire version 1, minor 0.
> - Firmware is **host-verified**: 25 test suites (including about 1M frames of fuzzing, ASan/UBSan runs, mesh simulator scenarios and RFC 3610 CCM vectors).
> - Builds for **ESP32** and **ESP32-S3** with ESP-IDF 5.5.3.
> - **NOT YET RUN ON HARDWARE.** The first 3-board demo is documented but has not been flashed.
> - The **nRF24 register driver has never touched a chip.**
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
| ESP-NOW | Primary mesh radio | Implemented, host-verified, not run on hardware |
| UART | Wired point-to-point, RAW framing (COBS) | Implemented, host-verified, not run on hardware |
| WiFi UDP | LAN carrier, gateway side | Implemented, host-verified, not run on hardware |
| nRF24L01+ | Second mesh radio / bridge | Implemented; register driver never touched a chip |
| IR | Edge link (leaf devices) | Specified only |

## Use cases

Details in PROTOCOL.md section 13.

- Fixed sensor networks: 5-50 nodes over 1-4 hops, one gateway as sink and manager.
- Campsite perimeter monitoring: battery sensors (PIR, beam-break, tripwire, reed) watched from a base.
- Vehicle and flight-data links: sensors to an onboard recorder over UART or direct ESP-NOW. The recorder must store data locally (the protocol is transport, not storage). Not certified aviation.

## Quick start

Prerequisites: [PlatformIO](https://platformio.org/) (platform `espressif32@6.13.0`, which brings ESP-IDF 5.5.3), CMake 3.16 or newer, a C compiler for the host build. Python 3 with `reedsolo` and `cryptography` is needed only to regenerate test vectors.

Host tests (from the repo root):

```
cmake -S firmware/host -B firmware/host/build
cmake --build firmware/host/build
ctest --test-dir firmware/host/build
```

Sanitizers: add `-DBR_SANITIZE=ON` and use a separate build dir, for example `firmware/host/build-asan`.

Device build (from `firmware/`):

```
pio run -e esp32_dev        # ESP32-WROOM-32E
pio run -e esp32s3_dev      # ESP32-S3-WROOM-1
```

On-chip self-test (replays the Appendix A vectors on the chip, see `firmware/SELFTEST.txt`):

```
pio run -e esp32_selftest -t upload -t monitor
```

It prints `BR_SELFTEST RESULT: PASS n/n` on success.

3-board demo (button on board A, relay B, LED on board C): see [firmware/FLASH-DEMO.md](firmware/FLASH-DEMO.md).

Builds here are development builds only: no Secure Boot, flash encryption or anti-rollback.

## Repository layout

```
PROTOCOL.md            the specification (v0.9); PROTOCOL.v0.*.md are frozen earlier drafts
SPEC-NOTES.md          implementation decisions on spec ambiguities
LICENSE, LICENSE-DOCS  AGPL-3.0 (code), CC BY-SA 4.0 (spec)
NOTICE                 test-key warning
roast/                 design review history (field and security reviews, rounds 1-4)
tools/vectors.py       oracle that generates and checks all test vectors
firmware/
  components/
    app_braid/         protocol core: CRC, COBS, RS, FEC, ARQ, crypto, sessions, mesh
    app_hal/           HAL headers (GPIO, UART, SPI, UDP, radio, KV, time)
    port_esp_idf/      HAL implementation on ESP-IDF
    app_node/          node app, console, ESP-NOW and UART links, radio arbitration
    app_udp_link/      WiFi UDP carrier
    app_nrf24_link/    nRF24L01+ carrier and register driver
  main/                app_main
  host/                host CMake build and CTest hook
  sim/                 host mesh simulator (virtual medium and clock)
  test/host/           unit, fuzz and scenario tests, generated vectors
```

## Documentation

- [PROTOCOL.md](PROTOCOL.md): full specification.
- [SPEC-NOTES.md](SPEC-NOTES.md): implementation decisions and spec errata.
- [firmware/README-BUILD.txt](firmware/README-BUILD.txt): toolchain, build, host tests.
- [firmware/FLASH-DEMO.md](firmware/FLASH-DEMO.md): 3-board demo.
- [firmware/SELFTEST.txt](firmware/SELFTEST.txt): on-chip self-test.
- [firmware/UART-LINK.txt](firmware/UART-LINK.txt), [UDP-LINK.txt](firmware/UDP-LINK.txt), [NRF24-LINK.txt](firmware/NRF24-LINK.txt): carrier notes.
- [firmware/GATEWAY-NRF24.txt](firmware/GATEWAY-NRF24.txt), [RADIO-ARB.txt](firmware/RADIO-ARB.txt): single-chip gateway and radio arbitration.
- [roast/](roast/): design review history.

## Licence

Code: **AGPL-3.0-or-later** (see [LICENSE](LICENSE)). Specification text: **CC BY-SA 4.0** (see [LICENSE-DOCS](LICENSE-DOCS)). Three points to know before you build on it:

1. **Network clause (AGPL section 13).** If you run a modified Braid gateway or host node that other people interact with over a network, you must offer those users the corresponding source.
2. **Installation Information (GPLv3 section 6, applies through AGPL).** If you ship a consumer device whose Secure Boot is locked to your key, buyers must still have a way to install modified firmware. Consider this before using the field profile's Secure Boot on consumer products.
3. **Dependencies.** ESP-IDF and mbedtls are Apache-2.0, which is compatible with (A)GPLv3.

This is not legal advice. See also [NOTICE](NOTICE) about the published test keys.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
