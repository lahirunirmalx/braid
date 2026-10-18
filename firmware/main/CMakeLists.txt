# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# main - self-test supervisor only: boot, wire platform services, run
# br_selftest_run(). The demo application is firmware/examples/demo-3board.
idf_component_register(
    SRCS "app_main.cpp"
    REQUIRES app_hal port_esp_idf app_braid log freertos esp_system
)

# Strict, but no -Wpedantic here: ESP-IDF include dirs are not -isystem and
# IDF headers use GCC extensions (newlib platform_include/stdio.h has
# #include_next), so -Wpedantic -Werror fails inside IDF's own headers.
# The ESP-IDF-free core (app_braid) does build with -Wpedantic -Werror.
#
# C++: IDF 5.5 default gnu++2b (code is C++17; see platformio.ini).
# Set per SOURCE, not per target: PlatformIO places main's target options
# before IDF's global ones (-Wno-error=extra, -Wno-unused-parameter,
# -Wno-sign-compare), which would cancel them.
set_source_files_properties(app_main.cpp PROPERTIES COMPILE_OPTIONS
    "-Wall;-Wextra;-Werror;-Werror=extra;-Wunused-parameter;-Wsign-compare;-Wshadow")
