// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_usb_serial.cpp - ESP-IDF implementation of hal_usb_serial.h.
//
// Reads the USB Serial/JTAG receive FIFO directly (hal/usb_serial_jtag_ll.h)
// instead of installing the usb_serial_jtag driver: the ESP-IDF secondary
// console (CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG) keeps writing the
// log to the same port, and nothing else reads it.

#include "soc/soc_caps.h"

#include "hal_usb_serial.h"

#if SOC_USB_SERIAL_JTAG_SUPPORTED
#include "hal/usb_serial_jtag_ll.h"
#endif

extern "C" bool hal_usb_serial_present(void) {
#if SOC_USB_SERIAL_JTAG_SUPPORTED
    return true;
#else
    return false;
#endif
}

extern "C" hal_result_t hal_usb_serial_read(uint8_t *buf, size_t cap, size_t *got) {
    if (buf == nullptr || got == nullptr || cap == 0) return HAL_ERR_INVALID_ARG;
    *got = 0;
#if SOC_USB_SERIAL_JTAG_SUPPORTED
    while (*got < cap && usb_serial_jtag_ll_rxfifo_data_available()) {
        *got += usb_serial_jtag_ll_read_rxfifo(buf + *got, static_cast<uint32_t>(cap - *got));
    }
    return HAL_OK;
#else
    return HAL_ERR_UNSUPPORTED;
#endif
}
