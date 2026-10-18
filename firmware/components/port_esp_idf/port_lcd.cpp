// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_lcd.cpp - ESP-IDF implementation of hal_lcd.h.
//
// SPI3 with DMA, write-only (no MISO), one device, polling transactions
// (spi_device_polling_transmit blocks until the DMA is done, so callers may
// reuse their buffers). D/C is a plain GPIO set before each transaction.
// SPI3 keeps the panel off SPI2, which hal_spi.h gives the nRF24 on the S3.

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "hal_lcd.h"
#include "port_err.h"

namespace {
constexpr char TAG[] = "port_lcd";

spi_device_handle_t g_dev = nullptr;
int16_t g_dc = -1;
int16_t g_rst = -1;
int16_t g_bl = -1;

hal_result_t out_pin(int16_t pin, int level) {
    if (pin < 0) return HAL_OK;
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << pin;
    io.mode = GPIO_MODE_OUTPUT;
    esp_err_t e = gpio_config(&io);
    if (e == ESP_OK) e = gpio_set_level(static_cast<gpio_num_t>(pin), level);
    return port::map_err(e);
}

hal_result_t send(bool data, const uint8_t *buf, size_t len) {
    if (len == 0) return HAL_OK;
    (void)gpio_set_level(static_cast<gpio_num_t>(g_dc), data ? 1 : 0);
    spi_transaction_t t = {};
    t.length = len * 8;
    t.tx_buffer = buf;
    return port::map_err(spi_device_polling_transmit(g_dev, &t));
}
}  // namespace

extern "C" hal_result_t hal_lcd_init(const hal_lcd_cfg_t *cfg) {
    if (g_dev != nullptr) return HAL_ERR_BUSY;
    if (cfg == nullptr || cfg->sck_pin < 0 || cfg->mosi_pin < 0 || cfg->cs_pin < 0 || cfg->dc_pin < 0 ||
        cfg->clock_hz == 0) {
        return HAL_ERR_INVALID_ARG;
    }
    hal_result_t r = out_pin(cfg->dc_pin, 1);
    if (r == HAL_OK) r = out_pin(cfg->rst_pin, 1);
    if (r == HAL_OK) r = out_pin(cfg->bl_pin, 0);
    if (r != HAL_OK) return r;

    spi_bus_config_t bc = {};
    bc.mosi_io_num = cfg->mosi_pin;
    bc.miso_io_num = -1;
    bc.sclk_io_num = cfg->sck_pin;
    bc.quadwp_io_num = -1;
    bc.quadhd_io_num = -1;
    bc.max_transfer_sz = HAL_LCD_MAX_CHUNK;
    esp_err_t e = spi_bus_initialize(SPI3_HOST, &bc, SPI_DMA_CH_AUTO);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_initialize(SPI3) failed: %s", esp_err_to_name(e));
        return port::map_err(e);
    }
    spi_device_interface_config_t dc = {};
    dc.clock_speed_hz = static_cast<int>(cfg->clock_hz);
    dc.mode = 0;
    dc.spics_io_num = cfg->cs_pin;
    dc.queue_size = 1;
    dc.flags = SPI_DEVICE_HALFDUPLEX;
    e = spi_bus_add_device(SPI3_HOST, &dc, &g_dev);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(e));
        (void)spi_bus_free(SPI3_HOST);
        g_dev = nullptr;
        return port::map_err(e);
    }
    g_dc = cfg->dc_pin;
    g_rst = cfg->rst_pin;
    g_bl = cfg->bl_pin;
    return HAL_OK;
}

extern "C" hal_result_t hal_lcd_reset(void) {
    if (g_dev == nullptr) return HAL_ERR_BUSY;
    if (g_rst < 0) return HAL_OK;
    (void)gpio_set_level(static_cast<gpio_num_t>(g_rst), 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    (void)gpio_set_level(static_cast<gpio_num_t>(g_rst), 1);
    vTaskDelay(pdMS_TO_TICKS(120));
    return HAL_OK;
}

extern "C" hal_result_t hal_lcd_cmd(uint8_t cmd, const uint8_t *params, size_t len) {
    if (g_dev == nullptr) return HAL_ERR_BUSY;
    if ((params == nullptr && len > 0) || len > HAL_LCD_MAX_CHUNK) return HAL_ERR_INVALID_ARG;
    hal_result_t r = send(false, &cmd, 1);
    if (r == HAL_OK) r = send(true, params, len);
    return r;
}

extern "C" hal_result_t hal_lcd_data(const uint8_t *data, size_t len) {
    if (g_dev == nullptr) return HAL_ERR_BUSY;
    if (data == nullptr || len == 0 || len > HAL_LCD_MAX_CHUNK) return HAL_ERR_INVALID_ARG;
    return send(true, data, len);
}

extern "C" hal_result_t hal_lcd_backlight(bool on) {
    if (g_dev == nullptr) return HAL_ERR_BUSY;
    if (g_bl < 0) return HAL_OK;
    return port::map_err(gpio_set_level(static_cast<gpio_num_t>(g_bl), on ? 1 : 0));
}
