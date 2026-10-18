# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# port_esp_idf - the ONLY component that includes ESP-IDF driver headers
# (GPIO, UART console and UART link, SPI master, I2C master), the Wi-Fi / ESP-NOW radio
# headers, the lwIP sockets (WiFi UDP link, esp_wifi STA) and the lwIP SNTP
# client (port_sntp.cpp, esp_netif_sntp; hal_time.h). Implements the
# app_hal interfaces. port_nrf24.cpp drives the portable register sequence
# of app_nrf24_link (nrf24_regs.h), hence that PRIV_REQUIRES.
idf_component_register(
    SRCS
        "port_espnow.cpp"
        "port_gpio.cpp"
        "port_i2c.cpp"
        "port_kv.cpp"
        "port_nrf24.cpp"
        "port_result.cpp"
        "port_sntp.cpp"
        "port_spi.cpp"
        "port_sys.cpp"
        "port_uart.cpp"
        "port_uart_link.cpp"
        "port_udp.cpp"
    REQUIRES app_hal
    PRIV_REQUIRES esp_driver_gpio esp_driver_i2c esp_driver_uart esp_driver_spi esp_timer esp_hw_support esp_system log
                  esp_wifi esp_netif esp_event nvs_flash heap freertos lwip app_nrf24_link
)

# Strict, but no -Wpedantic here: ESP-IDF include dirs are not -isystem and
# IDF headers use GCC extensions (newlib platform_include/stdio.h has
# #include_next), so -Wpedantic -Werror fails inside IDF's own headers.
# The ESP-IDF-free core (app_braid) does build with -Wpedantic -Werror.
# C++: IDF 5.5 default gnu++2b (code is C++17; see platformio.ini).
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -Werror=extra            # IDF globally sets -Wno-error=extra
    -Wunused-parameter       # IDF globally sets -Wno-unused-parameter
    -Wsign-compare           # IDF globally sets -Wno-sign-compare
    -Wshadow
)
