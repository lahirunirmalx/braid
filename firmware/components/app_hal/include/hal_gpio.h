// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_gpio.h - vendor-neutral GPIO interface.
//
// Application code (main/, components/app_*) MUST include this header
// and never <driver/gpio.h>. The translation to ESP-IDF lives in
// components/port_esp_idf/port_gpio.cpp.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HAL_GPIO_DIR_IN,
    HAL_GPIO_DIR_OUT,
    HAL_GPIO_DIR_OUT_OD     // open-drain output
} hal_gpio_dir_t;

typedef enum {
    HAL_GPIO_PULL_NONE,
    HAL_GPIO_PULL_UP,
    HAL_GPIO_PULL_DOWN
} hal_gpio_pull_t;

typedef enum {
    HAL_GPIO_INT_NONE,
    HAL_GPIO_INT_RISING,
    HAL_GPIO_INT_FALLING,
    HAL_GPIO_INT_BOTH,
    HAL_GPIO_INT_LOW_LEVEL,
    HAL_GPIO_INT_HIGH_LEVEL
} hal_gpio_int_t;

typedef struct {
    uint8_t          pin;       // logical pin number (matches GPIO num on ESP32)
    hal_gpio_dir_t   dir;
    hal_gpio_pull_t  pull;
    hal_gpio_int_t   intr;      // HAL_GPIO_INT_NONE if not used
} hal_gpio_cfg_t;

typedef void (*hal_gpio_isr_cb)(uint8_t pin, void *user);

hal_result_t hal_gpio_init(const hal_gpio_cfg_t *cfg);
hal_result_t hal_gpio_set(uint8_t pin, bool level);
hal_result_t hal_gpio_get(uint8_t pin, bool *level_out);
hal_result_t hal_gpio_attach_isr(uint8_t pin, hal_gpio_isr_cb cb, void *user);
hal_result_t hal_gpio_detach_isr(uint8_t pin);

#ifdef __cplusplus
}
#endif
