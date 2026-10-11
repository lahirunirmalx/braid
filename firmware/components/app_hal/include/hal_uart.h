// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_uart.h - vendor-neutral UART interface (Braid RAW carrier, spec 1.2).
//
// Implemented in components/port_esp_idf/port_uart.cpp. Every call is bounded
// by timeout_ms; nothing blocks forever.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  port;        // UART controller index (0..2 on ESP32, 0..2 on S3)
    uint32_t baud;        // e.g. 921600 for the two-chip gateway (spec 12.4)
    int16_t  tx_pin;      // GPIO number, or -1 to keep the default
    int16_t  rx_pin;      // GPIO number, or -1 to keep the default
    uint16_t rx_buf_len;  // driver RX ring size in bytes (> 128)
} hal_uart_cfg_t;

hal_result_t hal_uart_init(const hal_uart_cfg_t *cfg);
hal_result_t hal_uart_deinit(uint8_t port);

// Queue up to len bytes for transmit; waits at most timeout_ms for space.
// *written receives the number of bytes queued.
hal_result_t hal_uart_write(uint8_t port, const uint8_t *data, size_t len,
                            uint32_t timeout_ms, size_t *written);

// Read up to cap bytes; returns after timeout_ms or when cap bytes arrived.
// *got receives the count (0 on timeout is HAL_OK).
hal_result_t hal_uart_read(uint8_t port, uint8_t *buf, size_t cap,
                           uint32_t timeout_ms, size_t *got);

#ifdef __cplusplus
}
#endif
