# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# app_udp_link - Braid WiFi UDP transport adapter (PACKET link, spec 1.2
# "WiFi UDP" row, 11.11, 12.4, C.4). LAN side only (12.4): never on a chip
# that also runs ESP-NOW.
#
# src/udp_link.c is portable C11 and HAL-free (the socket is an injected
# ops table); src/udp_link_hal.c binds that table to app_hal's hal_udp.h
# (implemented by port_esp_idf/port_udp.cpp on the device and by
# host/udp_posix.c on the host). Host test: firmware/test/host/test_udp_link.c
# compiles both files directly.
#
# Used by applications that REQUIRE this component, e.g. the demo's app_node
# (examples/demo-3board, udp=on, firmware/UDP-LINK.txt section 3).
idf_component_register(
    SRCS
        "src/udp_link.c"
        "src/udp_link_hal.c"
    INCLUDE_DIRS "include"
    REQUIRES app_braid
    PRIV_REQUIRES app_hal
)

# Same strict set as app_braid (plain C, no IDF headers in udp_link.c;
# udp_link_hal.c includes only app_hal's hal_udp.h / hal_result.h).
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
    -Wconversion
    -Wsign-conversion
    -Wstrict-prototypes
)
