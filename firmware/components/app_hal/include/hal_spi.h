// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_spi.h - vendor-neutral SPI master: one bus per controller, up to
// HAL_SPI_MAX_DEVICES chip-selected devices, blocking full-duplex transfers
// with the chip select held low for the whole transfer. Implemented in
// components/port_esp_idf/port_spi.cpp, the only translation unit that
// includes the vendor SPI master driver.
//
// Scope: short register-style transactions (<= HAL_SPI_MAX_TRANSFER bytes,
// no DMA) for radios and peripherals such as the nRF24L01+ (33 bytes max)
// and the W5500. Not a bulk-transfer API.
//
// Thread safety: hal_spi_transfer() on one device may be called from one
// task at a time (Braid: the protocol task for the nRF24); different
// devices on the same bus may be used from different tasks (the port
// serialises at the driver). Init functions are called once at boot.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_SPI_MAX_TRANSFER   64u    // bytes per transfer (no-DMA hardware FIFO on ESP32 / S3)
#define HAL_SPI_MAX_DEVICES    4u
#define HAL_SPI_BUS_DEFAULT    0u     // chip default: ESP32 VSPI (SPI3), ESP32-S3 SPI2 (FSPI)
#define HAL_SPI_BUS_2          2u     // SPI2 (HSPI on ESP32, FSPI on S3)
#define HAL_SPI_BUS_3          3u     // SPI3 (VSPI on ESP32; S3 SPI3 has no IO_MUX pins)

typedef uint8_t hal_spi_dev_t;        // device handle, 0..HAL_SPI_MAX_DEVICES-1

typedef struct {
    uint8_t  bus;           // HAL_SPI_BUS_DEFAULT / _2 / _3
    int16_t  sck_pin;       // GPIO numbers; IO_MUX routing when they are the controller's native pins
    int16_t  miso_pin;
    int16_t  mosi_pin;
} hal_spi_bus_cfg_t;

typedef struct {
    uint8_t  bus;           // the bus from hal_spi_bus_init()
    int16_t  cs_pin;        // GPIO, driven by the controller: low during a transfer, high between
    uint32_t clock_hz;      // e.g. 8000000; the port rounds down to a reachable divider
    uint8_t  mode;          // SPI mode 0..3 (CPOL << 1 | CPHA)
} hal_spi_dev_cfg_t;

typedef struct {
    uint32_t transfers;     // completed transfers
    uint32_t errors;        // transfers refused or failed by the driver
} hal_spi_stats_t;

// Initialise a bus (idempotent per bus: a second call with the same pins
// returns HAL_OK, with different pins HAL_ERR_BUSY). HAL_ERR_INVALID_ARG on
// a bad bus or pin.
hal_result_t hal_spi_bus_init(const hal_spi_bus_cfg_t *cfg);

// Attach a device to an initialised bus. HAL_ERR_NO_MEM when
// HAL_SPI_MAX_DEVICES are in use; HAL_ERR_BUSY if the bus is not up.
hal_result_t hal_spi_dev_add(const hal_spi_dev_cfg_t *cfg, hal_spi_dev_t *dev_out);

// Full-duplex transfer of len bytes (1..HAL_SPI_MAX_TRANSFER): tx is
// shifted out, rx (may be NULL) receives what came in, CS low throughout.
// Blocking (polling transaction, tens of microseconds). HAL_ERR_INVALID_ARG
// on a bad handle / len / NULL tx.
hal_result_t hal_spi_transfer(hal_spi_dev_t dev, const uint8_t *tx, uint8_t *rx, size_t len);

// Counters of one device.
hal_result_t hal_spi_get_stats(hal_spi_dev_t dev, hal_spi_stats_t *out);

#ifdef __cplusplus
}
#endif
