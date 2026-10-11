// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_gpio.cpp - ESP-IDF implementation of hal_gpio.h.
//
// This is the ONLY translation unit in the project that includes
// <driver/gpio.h>. Application code talks to hal_gpio_*; this file
// translates to ESP-IDF.

#include "driver/gpio.h"
#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"

#include "hal_gpio.h"
#include "hal_result.h"

namespace {
constexpr char TAG[] = "port_gpio";

hal_result_t map_err(esp_err_t e) {
    switch (e) {
        case ESP_OK:                return HAL_OK;
        case ESP_ERR_INVALID_ARG:   return HAL_ERR_INVALID_ARG;
        case ESP_ERR_NO_MEM:        return HAL_ERR_NO_MEM;
        case ESP_ERR_TIMEOUT:       return HAL_ERR_TIMEOUT;
        case ESP_ERR_NOT_FOUND:     return HAL_ERR_NOT_FOUND;
        case ESP_ERR_INVALID_STATE: return HAL_ERR_BUSY;
        case ESP_ERR_NOT_SUPPORTED: return HAL_ERR_UNSUPPORTED;
        default:                    return HAL_ERR_INTERNAL;
    }
}

gpio_int_type_t map_intr(hal_gpio_int_t i) {
    switch (i) {
        case HAL_GPIO_INT_RISING:     return GPIO_INTR_POSEDGE;
        case HAL_GPIO_INT_FALLING:    return GPIO_INTR_NEGEDGE;
        case HAL_GPIO_INT_BOTH:       return GPIO_INTR_ANYEDGE;
        case HAL_GPIO_INT_LOW_LEVEL:  return GPIO_INTR_LOW_LEVEL;
        case HAL_GPIO_INT_HIGH_LEVEL: return GPIO_INTR_HIGH_LEVEL;
        case HAL_GPIO_INT_NONE:
        default:                      return GPIO_INTR_DISABLE;
    }
}

gpio_mode_t map_dir(hal_gpio_dir_t d) {
    switch (d) {
        case HAL_GPIO_DIR_OUT:    return GPIO_MODE_OUTPUT;
        case HAL_GPIO_DIR_OUT_OD: return GPIO_MODE_OUTPUT_OD;
        case HAL_GPIO_DIR_IN:
        default:                  return GPIO_MODE_INPUT;
    }
}

bool isr_service_installed = false;

struct CbSlot { hal_gpio_isr_cb cb; void *user; };
CbSlot slots[GPIO_NUM_MAX] = {};

void IRAM_ATTR shared_isr(void *arg) {
    auto pin = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));
    if (pin >= GPIO_NUM_MAX) return;
    auto &s = slots[pin];
    if (s.cb) s.cb(static_cast<uint8_t>(pin), s.user);
}
}  // namespace

extern "C" hal_result_t hal_gpio_init(const hal_gpio_cfg_t *cfg) {
    if (cfg == nullptr) return HAL_ERR_INVALID_ARG;
    if (cfg->pin >= GPIO_NUM_MAX) return HAL_ERR_INVALID_ARG;

    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << cfg->pin;
    io.mode         = map_dir(cfg->dir);
    io.pull_up_en   = (cfg->pull == HAL_GPIO_PULL_UP)   ? GPIO_PULLUP_ENABLE   : GPIO_PULLUP_DISABLE;
    io.pull_down_en = (cfg->pull == HAL_GPIO_PULL_DOWN) ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE;
    io.intr_type    = map_intr(cfg->intr);

    return map_err(gpio_config(&io));
}

extern "C" hal_result_t hal_gpio_set(uint8_t pin, bool level) {
    if (pin >= GPIO_NUM_MAX) return HAL_ERR_INVALID_ARG;
    return map_err(gpio_set_level(static_cast<gpio_num_t>(pin), level ? 1 : 0));
}

extern "C" hal_result_t hal_gpio_get(uint8_t pin, bool *level_out) {
    if (level_out == nullptr || pin >= GPIO_NUM_MAX) return HAL_ERR_INVALID_ARG;
    *level_out = gpio_get_level(static_cast<gpio_num_t>(pin)) != 0;
    return HAL_OK;
}

extern "C" hal_result_t hal_gpio_attach_isr(uint8_t pin, hal_gpio_isr_cb cb, void *user) {
    if (cb == nullptr || pin >= GPIO_NUM_MAX) return HAL_ERR_INVALID_ARG;
    if (!isr_service_installed) {
        esp_err_t e = gpio_install_isr_service(0);
        if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return map_err(e);
        isr_service_installed = true;
    }
    slots[pin] = { cb, user };
    return map_err(gpio_isr_handler_add(
        static_cast<gpio_num_t>(pin),
        shared_isr,
        reinterpret_cast<void*>(static_cast<uintptr_t>(pin))));
}

extern "C" hal_result_t hal_gpio_detach_isr(uint8_t pin) {
    if (pin >= GPIO_NUM_MAX) return HAL_ERR_INVALID_ARG;
    slots[pin] = {};
    return map_err(gpio_isr_handler_remove(static_cast<gpio_num_t>(pin)));
}
