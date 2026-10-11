// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_sys.h - vendor-neutral system services: monotonic time, CSPRNG, base MAC.
//
// Implemented in components/port_esp_idf/port_sys.cpp. main/ bridges these
// into the Braid core's br_platform_t (the core itself never includes HAL
// or ESP-IDF headers).

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

// Monotonic microseconds since boot. Never goes backwards. Task context only.
uint64_t hal_sys_time_us(void);

// Fill buf with len bytes from the hardware RNG. HAL_ERR_INVALID_ARG if buf is
// NULL and len > 0. Entropy note: true random only while the RF subsystem or
// bootloader_random is enabled (spec 12.12).
hal_result_t hal_sys_random_fill(uint8_t *buf, size_t len);

// Factory base MAC from eFuse (6 bytes). Used for the unit_id clone check and
// the fallback ID (spec section 2).
hal_result_t hal_sys_base_mac(uint8_t mac_out[6]);

// Software reset. Does not return.
void hal_sys_restart(void);

// Free heap in bytes (default capabilities) right now.
uint32_t hal_sys_free_heap(void);

// Lowest free heap seen since boot.
uint32_t hal_sys_min_free_heap(void);

// Task watchdog: subscribe the calling task / feed it. The task must call
// feed at least once per watchdog period (sdkconfig CONFIG_ESP_TASK_WDT_TIMEOUT_S).
hal_result_t hal_sys_wdt_subscribe_self(void);
hal_result_t hal_sys_wdt_feed(void);

#ifdef __cplusplus
}
#endif
