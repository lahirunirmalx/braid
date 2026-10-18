// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_lcd.h - vendor-neutral write-only bus for a small SPI LCD controller
// (ST7789 class): command byte with D/C low, parameters / pixels with D/C
// high, optional reset and backlight pins.
//
// Implemented in components/port_esp_idf/port_lcd.cpp (its own SPI host
// with DMA, separate from hal_spi.h, which is register-sized and DMA-less).
// Every call blocks until the bytes are on the wire, so the caller may reuse
// its buffer at once. One task owns the panel.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_LCD_MAX_CHUNK  8192u   /**< bytes per hal_lcd_data() call */

typedef struct {
    int16_t  sck_pin;
    int16_t  mosi_pin;
    int16_t  cs_pin;
    int16_t  dc_pin;
    int16_t  rst_pin;       /**< -1 = not wired */
    int16_t  bl_pin;        /**< -1 = not wired; active high */
    uint32_t clock_hz;      /**< e.g. 40000000 */
} hal_lcd_cfg_t;

/** Create the bus and device, drive RST / BL as outputs (BL off). */
hal_result_t hal_lcd_init(const hal_lcd_cfg_t *cfg);

/** Pulse RST low (no-op without an RST pin), then wait for the controller. */
hal_result_t hal_lcd_reset(void);

/** Command byte, then @p len parameter bytes (may be 0). */
hal_result_t hal_lcd_cmd(uint8_t cmd, const uint8_t *params, size_t len);

/** Data bytes (pixels) after a memory-write command; len <= HAL_LCD_MAX_CHUNK. */
hal_result_t hal_lcd_data(const uint8_t *data, size_t len);

hal_result_t hal_lcd_backlight(bool on);

#ifdef __cplusplus
}
#endif
