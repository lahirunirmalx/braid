// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_i2c.cpp - ESP-IDF implementation of hal_i2c.h.
//
// This is the ONLY translation unit in the project that includes
// <driver/i2c_master.h> (the IDF 5.x master driver; the legacy driver/i2c.h
// warns under -Werror). One bus, I2C port chosen by the driver; devices are
// added on first use and kept (a status display: one device).

#include "driver/i2c_master.h"
#include "esp_log.h"

#include "hal_i2c.h"
#include "hal_result.h"
#include "port_err.h"

namespace {
constexpr char TAG[] = "port_i2c";

constexpr size_t kMaxDevs = 4;

i2c_master_bus_handle_t g_bus = nullptr;
uint32_t g_hz = 0;

struct Dev { uint8_t addr; i2c_master_dev_handle_t h; };
Dev g_devs[kMaxDevs] = {};

int timeout_arg(uint32_t timeout_ms) {
    return timeout_ms > 0x7FFFFFFFu ? -1 : static_cast<int>(timeout_ms);
}

hal_result_t dev_for(uint8_t addr7, i2c_master_dev_handle_t *out) {
    for (const auto &d : g_devs) {
        if (d.h != nullptr && d.addr == addr7) {
            *out = d.h;
            return HAL_OK;
        }
    }
    for (auto &d : g_devs) {
        if (d.h != nullptr) continue;
        i2c_device_config_t dc = {};
        dc.dev_addr_length = I2C_ADDR_BIT_LEN_7;
        dc.device_address = addr7;
        dc.scl_speed_hz = g_hz;
        const esp_err_t e = i2c_master_bus_add_device(g_bus, &dc, &d.h);
        if (e != ESP_OK) {
            d.h = nullptr;
            return port::map_err(e);
        }
        d.addr = addr7;
        *out = d.h;
        return HAL_OK;
    }
    return HAL_ERR_NO_MEM;
}
}  // namespace

extern "C" hal_result_t hal_i2c_init(uint8_t sda, uint8_t scl, uint32_t hz) {
    if (g_bus != nullptr) return HAL_ERR_BUSY;
    if (hz == 0) return HAL_ERR_INVALID_ARG;
    i2c_master_bus_config_t bc = {};
    bc.i2c_port = -1;  // any free controller
    bc.sda_io_num = static_cast<gpio_num_t>(sda);
    bc.scl_io_num = static_cast<gpio_num_t>(scl);
    bc.clk_source = I2C_CLK_SRC_DEFAULT;
    bc.glitch_ignore_cnt = 7;
    bc.flags.enable_internal_pullup = true;
    const esp_err_t e = i2c_new_master_bus(&bc, &g_bus);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "bus init sda=%u scl=%u failed: %s", sda, scl, esp_err_to_name(e));
        g_bus = nullptr;
        return port::map_err(e);
    }
    g_hz = hz;
    return HAL_OK;
}

extern "C" hal_result_t hal_i2c_probe(uint8_t addr7, uint32_t timeout_ms) {
    if (g_bus == nullptr) return HAL_ERR_BUSY;
    return port::map_err(i2c_master_probe(g_bus, addr7, timeout_arg(timeout_ms)));
}

extern "C" hal_result_t hal_i2c_write(uint8_t addr7, const uint8_t *buf, size_t len, uint32_t timeout_ms) {
    if (g_bus == nullptr) return HAL_ERR_BUSY;
    if (buf == nullptr || len == 0) return HAL_ERR_INVALID_ARG;
    i2c_master_dev_handle_t h = nullptr;
    const hal_result_t r = dev_for(addr7, &h);
    if (r != HAL_OK) return r;
    return port::map_err(i2c_master_transmit(h, buf, len, timeout_arg(timeout_ms)));
}
