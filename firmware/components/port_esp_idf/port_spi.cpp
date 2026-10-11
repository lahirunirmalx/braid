// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_spi.cpp - ESP-IDF implementation of hal_spi.h over the SPI master
// driver (esp_driver_spi).
//
// The only translation unit that includes driver/spi_master.h.
//
// Buses: HAL_SPI_BUS_DEFAULT maps to the controller whose IO_MUX pins the
// C.6 pin plans use: SPI3 (VSPI) on ESP32 (SCK 18, MISO 19, MOSI 23, CS 5),
// SPI2 (FSPI) on ESP32-S3 (SCK 12, MISO 13, MOSI 11, CS 10). The driver
// routes through IO_MUX when the configured pins are the native ones and
// through the GPIO matrix otherwise (fine at <= 10 MHz either way).
//
// Transfers: no DMA (SPI_DMA_DISABLED), so one transaction is limited to the
// 64-byte hardware FIFO = HAL_SPI_MAX_TRANSFER; spi_device_polling_transmit()
// blocks the caller for the few tens of microseconds a 33-byte nRF24 command
// takes at 8 MHz. CS is asserted by the controller for the whole transaction
// and released between transactions, which is what the nRF24L01+ (CSN low
// per command, high between commands) and the W5500 expect.
//
// NOT YET RUN ON HARDWARE (no module attached when written). Not listed in
// this component's CMakeLists.txt yet: see firmware/NRF24-LINK.txt,
// Integration TODO.

#include <atomic>
#include <cstring>

#include "driver/spi_master.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "sdkconfig.h"

#include "hal_spi.h"
#include "port_err.h"

namespace {

constexpr char TAG[] = "port_spi";
constexpr TickType_t kLockWait = pdMS_TO_TICKS(50);

struct Bus {
    bool             up = false;
    spi_host_device_t host = SPI2_HOST;
    int16_t          sck = -1;
    int16_t          miso = -1;
    int16_t          mosi = -1;
};

struct Dev {
    bool                 used = false;
    uint8_t              bus = 0;
    spi_device_handle_t  handle = nullptr;
    std::atomic<uint32_t> transfers{0};
    std::atomic<uint32_t> errors{0};
};

// Index: 0 = default, 2 = SPI2, 3 = SPI3 (HAL_SPI_BUS_*). Slot 1 unused.
Bus g_bus[4];
Dev g_dev[HAL_SPI_MAX_DEVICES];
StaticSemaphore_t g_lock_buf;
SemaphoreHandle_t g_lock = nullptr;

bool host_for(uint8_t bus, spi_host_device_t *out) {
    switch (bus) {
        case HAL_SPI_BUS_DEFAULT:
#if CONFIG_IDF_TARGET_ESP32
            *out = SPI3_HOST;   // VSPI: IO_MUX 18 / 19 / 23 / 5
#else
            *out = SPI2_HOST;   // S3 FSPI: IO_MUX 12 / 13 / 11 / 10
#endif
            return true;
        case HAL_SPI_BUS_2:
            *out = SPI2_HOST;
            return true;
        case HAL_SPI_BUS_3:
#if SOC_SPI_PERIPH_NUM > 2
            *out = SPI3_HOST;
            return true;
#else
            return false;
#endif
        default:
            return false;
    }
}

bool pin_ok(int16_t p) { return p >= 0 && p < SOC_GPIO_PIN_COUNT; }

bool lock() {
    if (g_lock == nullptr) {
        g_lock = xSemaphoreCreateMutexStatic(&g_lock_buf);
    }
    return g_lock != nullptr && xSemaphoreTake(g_lock, kLockWait) == pdTRUE;
}

void unlock() { xSemaphoreGive(g_lock); }

}  // namespace

extern "C" hal_result_t hal_spi_bus_init(const hal_spi_bus_cfg_t *cfg) {
    if (cfg == nullptr || cfg->bus >= 4 || cfg->bus == 1 || !pin_ok(cfg->sck_pin) || !pin_ok(cfg->miso_pin) ||
        !pin_ok(cfg->mosi_pin)) {
        return HAL_ERR_INVALID_ARG;
    }
    spi_host_device_t host;
    if (!host_for(cfg->bus, &host)) return HAL_ERR_UNSUPPORTED;
    if (!lock()) return HAL_ERR_BUSY;
    Bus &b = g_bus[cfg->bus];
    hal_result_t r = HAL_OK;
    if (b.up) {
        r = (b.sck == cfg->sck_pin && b.miso == cfg->miso_pin && b.mosi == cfg->mosi_pin) ? HAL_OK : HAL_ERR_BUSY;
    } else {
        spi_bus_config_t bc = {};
        bc.mosi_io_num = cfg->mosi_pin;
        bc.miso_io_num = cfg->miso_pin;
        bc.sclk_io_num = cfg->sck_pin;
        bc.quadwp_io_num = -1;
        bc.quadhd_io_num = -1;
        bc.max_transfer_sz = HAL_SPI_MAX_TRANSFER;
        const esp_err_t e = spi_bus_initialize(host, &bc, SPI_DMA_DISABLED);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "spi_bus_initialize(host %d) failed: %s", static_cast<int>(host), esp_err_to_name(e));
            r = port::map_err(e);
        } else {
            b.up = true;
            b.host = host;
            b.sck = cfg->sck_pin;
            b.miso = cfg->miso_pin;
            b.mosi = cfg->mosi_pin;
        }
    }
    unlock();
    return r;
}

extern "C" hal_result_t hal_spi_dev_add(const hal_spi_dev_cfg_t *cfg, hal_spi_dev_t *dev_out) {
    if (cfg == nullptr || dev_out == nullptr || cfg->bus >= 4 || cfg->bus == 1 || !pin_ok(cfg->cs_pin) ||
        cfg->mode > 3 || cfg->clock_hz == 0) {
        return HAL_ERR_INVALID_ARG;
    }
    if (!lock()) return HAL_ERR_BUSY;
    Bus &b = g_bus[cfg->bus];
    hal_result_t r = HAL_OK;
    if (!b.up) {
        r = HAL_ERR_BUSY;
    } else {
        Dev *slot = nullptr;
        uint8_t idx = 0;
        for (uint8_t i = 0; i < HAL_SPI_MAX_DEVICES; i++) {
            if (!g_dev[i].used) {
                slot = &g_dev[i];
                idx = i;
                break;
            }
        }
        if (slot == nullptr) {
            r = HAL_ERR_NO_MEM;
        } else {
            spi_device_interface_config_t dc = {};
            dc.clock_speed_hz = static_cast<int>(cfg->clock_hz);
            dc.mode = cfg->mode;
            dc.spics_io_num = cfg->cs_pin;
            dc.queue_size = 1;   // polling transactions only
            const esp_err_t e = spi_bus_add_device(b.host, &dc, &slot->handle);
            if (e != ESP_OK) {
                ESP_LOGE(TAG, "spi_bus_add_device(cs GPIO%d) failed: %s", cfg->cs_pin, esp_err_to_name(e));
                r = port::map_err(e);
            } else {
                slot->used = true;
                slot->bus = cfg->bus;
                slot->transfers.store(0);
                slot->errors.store(0);
                *dev_out = idx;
            }
        }
    }
    unlock();
    return r;
}

extern "C" hal_result_t hal_spi_transfer(hal_spi_dev_t dev, const uint8_t *tx, uint8_t *rx, size_t len) {
    if (dev >= HAL_SPI_MAX_DEVICES || !g_dev[dev].used || tx == nullptr || len == 0 || len > HAL_SPI_MAX_TRANSFER) {
        return HAL_ERR_INVALID_ARG;
    }
    Dev &d = g_dev[dev];
    spi_transaction_t t = {};
    t.length = len * 8;
    t.rxlength = rx != nullptr ? len * 8 : 0;
    t.tx_buffer = tx;
    t.rx_buffer = rx;
    const esp_err_t e = spi_device_polling_transmit(d.handle, &t);
    if (e != ESP_OK) {
        d.errors.fetch_add(1, std::memory_order_relaxed);
        return port::map_err(e);
    }
    d.transfers.fetch_add(1, std::memory_order_relaxed);
    return HAL_OK;
}

extern "C" hal_result_t hal_spi_get_stats(hal_spi_dev_t dev, hal_spi_stats_t *out) {
    if (out == nullptr || dev >= HAL_SPI_MAX_DEVICES || !g_dev[dev].used) return HAL_ERR_INVALID_ARG;
    out->transfers = g_dev[dev].transfers.load(std::memory_order_relaxed);
    out->errors = g_dev[dev].errors.load(std::memory_order_relaxed);
    return HAL_OK;
}
