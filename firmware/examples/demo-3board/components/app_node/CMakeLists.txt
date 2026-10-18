# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# app_node - phase 1c demo application: serial console + NVS configuration,
# the Braid protocol task (br_task) with the ESP-NOW transport adapter,
# the optional UART link adapter (src/uart_link.c, RAW link, COBS), the
# optional WiFi UDP link (app_udp_link, LAN side, spec 12.4) and the optional
# nRF24L01+ link (app_nrf24_link), and the sender / relay / probe roles
# (button, LED, BRSTAT line), and the optional status display (src/oled.c,
# SSD1306 over hal_i2c, autodetected; portable C11, test_oled.c) or, in the
# cardputer env, the ST7789 LCD over hal_lcd (src/st7789.c, test_st7789.c),
# coloured through src/disp_theme.c.
#
# Talks to hardware only through app_hal (hal_radio, hal_gpio, hal_uart,
# hal_kv, hal_sys, hal_uart_link, hal_udp, hal_nrf24, hal_i2c, hal_lcd, hal_usb_serial); no driver, Wi-Fi,
# ESP-NOW or lwIP headers here. src/node_console.c and src/uart_link.c are
# portable C11 and host-tested (firmware/test/host/test_console*.c and
# test_uart_link.c compile them directly).
# 12.4 bridge radio arbitration (firmware/RADIO-ARB.txt): src/radio_arb.c and
# src/espnow_link.c are portable C11 (test_radio_arb.c); src/radio_arb_hal.c
# is the device glue (hal_radio_tx_inflight, nrf24_link_radio_busy).
idf_component_register(
    SRCS
        "src/node_app.cpp"
        "src/node_console.c"
        "src/uart_link.c"
        "src/radio_arb.c"
        "src/radio_arb_hal.c"
        "src/espnow_link.c"
        "src/oled.c"
        "src/st7789.c"
        "src/disp_theme.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES app_braid app_udp_link app_nrf24_link
    PRIV_REQUIRES app_hal freertos log
)

# Same strict set as port_esp_idf (no -Wpedantic for C++: IDF headers use
# GCC extensions). The portable C files additionally get -Wpedantic and the
# conversion warnings it is held to on the host.
target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-std=c11>
    -Wall
    -Wextra
    -Werror
    -Werror=extra            # IDF globally sets -Wno-error=extra
    -Wunused-parameter       # IDF globally sets -Wno-unused-parameter
    -Wsign-compare           # IDF globally sets -Wno-sign-compare
    -Wshadow
)
set_source_files_properties(src/node_console.c src/uart_link.c src/radio_arb.c src/radio_arb_hal.c src/espnow_link.c src/oled.c src/st7789.c src/disp_theme.c PROPERTIES COMPILE_OPTIONS
    "-Wpedantic;-Wconversion;-Wsign-conversion;-Wstrict-prototypes")
