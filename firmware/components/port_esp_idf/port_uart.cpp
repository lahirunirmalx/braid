// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_uart.cpp - ESP-IDF implementation of hal_uart.h.
// Only translation unit (with port_gpio.cpp) that includes ESP-IDF drivers.
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"

#include "hal_uart.h"
#include "port_err.h"

namespace {

bool valid_port(uint8_t port) { return port < SOC_UART_NUM; }

TickType_t to_ticks(uint32_t ms) {
    TickType_t t = pdMS_TO_TICKS(ms);
    return (ms > 0 && t == 0) ? 1 : t;  // never round a real wait down to a poll
}

}  // namespace

extern "C" hal_result_t hal_uart_init(const hal_uart_cfg_t *cfg) {
    if (cfg == nullptr || !valid_port(cfg->port) || cfg->baud == 0 || cfg->rx_buf_len <= 128) {
        return HAL_ERR_INVALID_ARG;
    }
    const auto port = static_cast<uart_port_t>(cfg->port);

    uart_config_t uc = {};
    uc.baud_rate  = static_cast<int>(cfg->baud);
    uc.data_bits  = UART_DATA_8_BITS;
    uc.parity     = UART_PARITY_DISABLE;
    uc.stop_bits  = UART_STOP_BITS_1;
    uc.flow_ctrl  = UART_HW_FLOWCTRL_DISABLE;
    uc.source_clk = UART_SCLK_DEFAULT;

    esp_err_t e = uart_driver_install(port, cfg->rx_buf_len, 0, 0, nullptr, 0);
    if (e != ESP_OK) return port::map_err(e);
    e = uart_param_config(port, &uc);
    if (e == ESP_OK) {
        e = uart_set_pin(port,
                         cfg->tx_pin < 0 ? UART_PIN_NO_CHANGE : cfg->tx_pin,
                         cfg->rx_pin < 0 ? UART_PIN_NO_CHANGE : cfg->rx_pin,
                         UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    }
    if (e != ESP_OK) {
        (void)uart_driver_delete(port);
    }
    return port::map_err(e);
}

extern "C" hal_result_t hal_uart_deinit(uint8_t port) {
    if (!valid_port(port)) return HAL_ERR_INVALID_ARG;
    return port::map_err(uart_driver_delete(static_cast<uart_port_t>(port)));
}

extern "C" hal_result_t hal_uart_write(uint8_t port, const uint8_t *data, size_t len,
                                       uint32_t timeout_ms, size_t *written) {
    if (!valid_port(port) || written == nullptr || (data == nullptr && len > 0)) {
        return HAL_ERR_INVALID_ARG;
    }
    *written = 0;
    if (len == 0) return HAL_OK;
    const int n = uart_write_bytes(static_cast<uart_port_t>(port), data, len);
    if (n < 0) return HAL_ERR_INTERNAL;
    *written = static_cast<size_t>(n);
    const esp_err_t e = uart_wait_tx_done(static_cast<uart_port_t>(port), to_ticks(timeout_ms));
    return port::map_err(e);
}

extern "C" hal_result_t hal_uart_read(uint8_t port, uint8_t *buf, size_t cap,
                                      uint32_t timeout_ms, size_t *got) {
    if (!valid_port(port) || buf == nullptr || got == nullptr || cap == 0 || cap > UINT32_MAX) {
        return HAL_ERR_INVALID_ARG;
    }
    *got = 0;
    const int n = uart_read_bytes(static_cast<uart_port_t>(port), buf,
                                  static_cast<uint32_t>(cap), to_ticks(timeout_ms));
    if (n < 0) return HAL_ERR_INTERNAL;
    *got = static_cast<size_t>(n);
    return HAL_OK;
}
