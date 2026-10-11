# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# app_braid - Braid protocol core (ESP-IDF component).
#
# C11 on purpose (deviation from the project's C++17 rule): the spec's API
# (Appendix B) is C and the same sources build on the host
# (firmware/host/CMakeLists.txt). No ESP-IDF or FreeRTOS headers in here;
# the only dependency is mbedtls.
#
# BR_SELFTEST (CMake cache variable, e.g. PlatformIO
# board_build.cmake_extra_args = -DBR_SELFTEST=1 or idf.py -DBR_SELFTEST=1):
# adds src/br_selftest.c (Appendix A replay, include/braid/br_selftest.h),
# which includes the generated vectors from firmware/test/host as-is, and
# defines BR_SELFTEST=1 for this component and everything that requires it.
# Without it, normal builds carry none of the self-test code or vectors.
set(BR_SRCS
    "src/br_arq.c"
    "src/br_cobs.c"
    "src/br_crc16.c"
    "src/br_crypto.c"
    "src/br_fec.c"
    "src/br_frame.c"
    "src/br_node.c"
    "src/br_platform.c"
    "src/br_rs.c"
    "src/br_sample.c"
    "src/br_session.c"
    "src/br_tables.c")
set(BR_PRIV_INCLUDES "src")
if(BR_SELFTEST)
    list(APPEND BR_SRCS "src/br_selftest.c")
    list(APPEND BR_PRIV_INCLUDES "../../test/host")
endif()

idf_component_register(
    SRCS ${BR_SRCS}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS ${BR_PRIV_INCLUDES}
    REQUIRES mbedtls
)

if(BR_SELFTEST)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC BR_SELFTEST=1)
endif()

target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-std=c11>
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Werror=extra            # IDF globally sets -Wno-error=extra
    -Wunused-parameter       # IDF globally sets -Wno-unused-parameter
    -Wsign-compare           # IDF globally sets -Wno-sign-compare
    -Wshadow
    -Wcast-align
    -Wstrict-prototypes
)
