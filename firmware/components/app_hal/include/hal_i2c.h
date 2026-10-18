// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_i2c.h - vendor-neutral I2C master interface (one bus, 7-bit addresses).
//
// Application code (main/, components/app_*) MUST include this header and
// never <driver/i2c_master.h>. The translation to ESP-IDF lives in
// components/port_esp_idf/port_i2c.cpp. Used by the status display
// (app_node oled.c); not thread-safe: one task owns the bus.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create the bus on @p sda / @p scl (internal pull-ups on) at @p hz.
 * HAL_ERR_BUSY if already initialised.
 */
hal_result_t hal_i2c_init(uint8_t sda, uint8_t scl, uint32_t hz);

/** HAL_OK if a device ACKs @p addr7, HAL_ERR_NOT_FOUND if nobody answers. */
hal_result_t hal_i2c_probe(uint8_t addr7, uint32_t timeout_ms);

/** One write transaction of @p len bytes to @p addr7. */
hal_result_t hal_i2c_write(uint8_t addr7, const uint8_t *buf, size_t len, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
