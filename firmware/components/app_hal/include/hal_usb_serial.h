// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_usb_serial.h - receive side of the chip's native USB serial port
// (ESP32-S3 USB Serial/JTAG), for a serial console on boards whose only USB
// connector is the native one (no USB-UART bridge on UART0).
//
// Implemented in components/port_esp_idf/port_usb_serial.cpp. Transmit is
// not covered: log output already reaches the native port through the
// ESP-IDF secondary console. Non-blocking; one reader task.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/** True when the chip has a native USB serial port. */
bool hal_usb_serial_present(void);

/**
 * Copy up to @p cap received bytes into @p buf without waiting.
 * *got = 0 when nothing is pending. HAL_ERR_UNSUPPORTED without the port.
 */
hal_result_t hal_usb_serial_read(uint8_t *buf, size_t cap, size_t *got);

#ifdef __cplusplus
}
#endif
