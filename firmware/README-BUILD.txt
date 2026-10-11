Braid firmware - build notes (core, sessions, mesh; carriers: ESP-NOW, UART, WiFi UDP, nRF24L01+, all wired into the node app; host-verified only, nRF24 register driver build-only)

Toolchain (verified 2026-10-08)
  PlatformIO platform   espressif32@6.13.0 (pinned exactly in platformio.ini)
  ESP-IDF               5.5.3 (framework-espidf 3.50503.0)
  Xtensa GCC            14.2.0 (toolchain-xtensa-esp-elf 14.2.0+20251107)
  mbedtls               3.6.5 (the copy inside ESP-IDF; also used by the host build)
  Host                  GCC 15.2, CMake 4.2 (needs >= 3.16)

Device builds (from firmware/)
  pio run -e esp32_dev      board esp32dev, ESP32-WROOM-32E, 4 MB, partitions.csv
  pio run -e esp32s3_dev    board esp32-s3-devkitc-1, S3-WROOM-1 N8, 8 MB, partitions_8mb.csv
  Development posture only: no secure boot, flash encryption, anti-rollback
  or NVS encryption.

Host build of the protocol core (from the repo root)
  cmake -S firmware/host -B firmware/host/build
  cmake --build firmware/host/build
  ctest --test-dir firmware/host/build          (runs firmware/test/host/test_*.c)
  ASan + UBSan: add -DBR_SANITIZE=ON (use a separate dir, e.g. firmware/host/build-asan)
  Other mbedtls tree: -DMBEDTLS_SRC=/path/to/mbedtls

Host mesh simulator (phase 1b)
  The same host build also builds library `brsim` (firmware/sim: virtual
  medium, clock and trace driving real br_node_t instances) and registers
  every firmware/sim/test/test_*.c in CTest (test_sim_self today; the
  scenario tests listed in firmware/test/host/README-SCENARIOS.txt later).
  Field-profile compile check: -DCMAKE_C_FLAGS=-DBR_FIELD_BUILD (compiles
  out the bench neighbour allowlist, SPEC-NOTES N22).

Rename note (2026-10-11, project renamed to Braid): the console command word is
  now `br` (br set|show|stats|erase|reboot) and the NVS namespace is "br"
  (was "pl"). Only dev boards exist and nothing is deployed, so there is no
  migration: a board flashed with an older image boots unconfigured; enter
  its `br set ...` line again (optionally `pio run -t erase` first to drop
  the stale "pl" namespace). Host CMake options are BR_SANITIZE and
  BR_SELFTEST, targets braid / brsim / br_selftest.

Device build note: after adding a source to components/app_braid
  (explicit BR_SRCS list), delete .pio/build/<env> once; PlatformIO does not
  always re-run CMake, and the new file is then silently left out.

Files the build generates in firmware/ (ignored by firmware/.gitignore)
  CMakeLists.txt           written by PlatformIO on the first build; not kept in git
  sdkconfig.esp32_dev, sdkconfig.esp32s3_dev
  .pio/, host/build*/

version.txt sets the app version (0.1.0-dev); without it ESP-IDF runs
`git describe`, which fails while the repo has no commits.

Machine note: PlatformIO's Python here is 3.14, but the espressif32@6.13.0
builder (builder/frameworks/espidf.py, install_python_deps) pins
pydantic < 2.12, whose pydantic-core has no Python 3.14 wheel. The IDF venv
~/.platformio/penv/.espidf-5.5.3 was therefore created with
/usr/bin/python3.12. If PlatformIO ever recreates it with 3.14, the build
fails with "No module named 'idf_component_manager'"; recreate it:
  V=~/.platformio/penv/.espidf-5.5.3
  /usr/bin/python3.12 -m venv --clear $V
  $V/bin/python -m pip install "urllib3<2" "cryptography~=44.0.0" \
      "pyparsing>=3.1.0,<4" "idf-component-manager~=2.2" \
      "esp-idf-kconfig~=2.5.0" "pydantic<2.12.0"
  then write $V/pio-idf-venv.json:
      {"version": "1.0.0", "python_version": "<output of the line below>"}
  $V/bin/python -c "import sys;print('{0}.{1}.{2}-{3}.{4}'.format(*sys.version_info))"
