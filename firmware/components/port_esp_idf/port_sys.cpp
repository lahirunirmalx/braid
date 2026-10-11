// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_sys.cpp - ESP-IDF implementation of hal_sys.h.
#include "esp_heap_caps.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"

#include "hal_sys.h"
#include "port_err.h"

extern "C" uint64_t hal_sys_time_us(void) {
    // esp_timer_get_time() is int64_t microseconds since boot, never negative.
    return static_cast<uint64_t>(esp_timer_get_time());
}

extern "C" hal_result_t hal_sys_random_fill(uint8_t *buf, size_t len) {
    if (len == 0) return HAL_OK;
    if (buf == nullptr) return HAL_ERR_INVALID_ARG;
    esp_fill_random(buf, len);
    return HAL_OK;
}

extern "C" hal_result_t hal_sys_base_mac(uint8_t mac_out[6]) {
    if (mac_out == nullptr) return HAL_ERR_INVALID_ARG;
    return port::map_err(esp_read_mac(mac_out, ESP_MAC_BASE));
}

extern "C" void hal_sys_restart(void) {
    esp_restart();
}

extern "C" uint32_t hal_sys_free_heap(void) {
    return static_cast<uint32_t>(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
}

extern "C" uint32_t hal_sys_min_free_heap(void) {
    return static_cast<uint32_t>(heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
}

extern "C" hal_result_t hal_sys_wdt_subscribe_self(void) {
    return port::map_err(esp_task_wdt_add(nullptr));
}

extern "C" hal_result_t hal_sys_wdt_feed(void) {
    return port::map_err(esp_task_wdt_reset());
}
