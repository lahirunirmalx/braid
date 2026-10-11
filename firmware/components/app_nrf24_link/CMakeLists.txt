# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# app_nrf24_link - Braid nRF24L01+ transport adapter (spec 1.2 nRF24 row,
# Appendix C.5): link-local segmentation (src/nrf24_seg.c), the transport
# adapter implementing br_transport_t (src/nrf24_link.c), the portable
# register-level chip driver (src/nrf24_regs.c, driven by port_nrf24.cpp over
# hal_spi / hal_gpio) and the device glue that maps the adapter's radio ops
# onto hal_nrf24.h (src/nrf24_link_hal.c).
#
# Everything except nrf24_link_hal.c is portable C11 with no ESP-IDF,
# FreeRTOS or HAL header and is host-tested by
# firmware/test/host/test_nrf24_link.c (which includes the .c files directly).
# Wired into node_app (nrf=on, firmware/NRF24-LINK.txt section 6); app_node
# REQUIRES this component and port_esp_idf PRIV_REQUIRES it (nrf24_regs.h).
idf_component_register(
    SRCS
        "src/nrf24_seg.c"
        "src/nrf24_regs.c"
        "src/nrf24_link.c"
        "src/nrf24_link_hal.c"
    INCLUDE_DIRS "src"
    REQUIRES app_braid
    PRIV_REQUIRES app_hal
)

# Same strict set the host build applies (firmware/host/CMakeLists.txt);
# IDF globally relaxes some of these, re-enable them here.
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
    -Wconversion
    -Wsign-conversion
)
