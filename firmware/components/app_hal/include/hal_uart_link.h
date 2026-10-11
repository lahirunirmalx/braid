// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_uart_link.h - vendor-neutral point-to-point serial link (Braid RAW
// carrier, spec 1.2 UART row, Appendix C.2). Implemented in
// components/port_esp_idf/port_uart_link.cpp, the only translation unit that
// includes the vendor UART driver for this link.
//
// Separate from hal_uart.h on purpose: hal_uart.h is the blocking,
// timeout-bounded API of the serial console (UART0); this one is an
// interrupt / event driven byte pipe for a protocol carrier:
//   - 8N1, no flow control, one link per UART controller.
//   - RX: the port runs one receive task per link (pinned to core 0, the
//     same core as the Wi-Fi task; priority tskIDLE_PRIORITY + 6, 3072 B
//     stack). It blocks on the driver's event queue (FIFO-threshold and
//     idle-line timeout interrupts, C.2), copies the received bytes out of
//     the driver ring buffer and hands them to the rx callback in chunks of
//     at most HAL_UART_LINK_RX_CHUNK bytes. No byte is interpreted here: no
//     framing, no COBS (that is the transport adapter's job).
//   - Loss: when the hardware FIFO or the driver ring overflowed, the port
//     discards what is buffered and calls the callback once with data NULL,
//     len 0 and HAL_UART_LINK_RX_LOST, so the adapter can drop a partial
//     frame and resynchronise on the next delimiter.
//   - The rx callback runs in the port's receive task: copy and enqueue with
//     a zero timeout, return. No blocking, no protocol work, no logging.
//   - TX: hal_uart_link_write() is all-or-nothing and never blocks: the
//     bytes go into the driver's TX ring buffer (drained by the UART
//     interrupt) or, when the ring lacks room, nothing is queued and
//     HAL_ERR_BUSY is returned (the caller counts the loss).
//   - RX pin: the internal pull-up is enabled, so an unconnected or not yet
//     driven line idles high (UART idle level) instead of producing noise.
//
// Thread safety: hal_uart_link_write() and hal_uart_link_flush() may be
// called from one task at a time per link (Braid: the protocol task).
// hal_uart_link_init() is called once at boot; there is no deinit (the link
// lives as long as the firmware runs).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_UART_LINK_RX_CHUNK        250u    // largest chunk handed to the rx callback
#define HAL_UART_LINK_RX_BUF_DEFAULT  2048u   // driver RX ring: about 22 ms at 921600 baud
#define HAL_UART_LINK_TX_BUF_DEFAULT  2048u   // driver TX ring: about 8 COBS frames of 252 bytes

#define HAL_UART_LINK_RX_LOST         0x01u   // bytes were discarded before this callback

typedef struct {
    uint8_t  port;          // UART controller (1 or 2; 0 is the console)
    int16_t  tx_pin;        // GPIO number (>= 0)
    int16_t  rx_pin;        // GPIO number (>= 0), internal pull-up enabled
    uint32_t baud;          // e.g. 921600 (spec 12.4 gateway figure) or 115200 (C.2 sensors)
    uint16_t rx_buf_len;    // driver RX ring in bytes, 0 = HAL_UART_LINK_RX_BUF_DEFAULT
    uint16_t tx_buf_len;    // driver TX ring in bytes, 0 = HAL_UART_LINK_TX_BUF_DEFAULT
} hal_uart_link_cfg_t;

// Receive-task context: copy what you need, enqueue with timeout 0, return.
// data is NULL and len 0 when only flags are reported.
typedef void (*hal_uart_link_rx_cb)(void *user, const uint8_t *data, size_t len, uint32_t flags);

typedef struct {
    uint32_t rx_bytes;      // bytes handed to the rx callback
    uint32_t tx_bytes;      // bytes accepted by hal_uart_link_write()
    uint32_t tx_busy;       // writes refused: TX ring had no room (nothing queued)
    uint32_t fifo_ovf;      // hardware RX FIFO overflows (input flushed, LOST reported)
    uint32_t buf_full;      // driver RX ring overflows (input flushed, LOST reported)
    uint32_t frame_err;     // 8N1 framing errors (wrong baud, noise, peer reset)
    uint32_t breaks;        // line breaks seen (peer reset or unplugged cable)
} hal_uart_link_stats_t;

// Install the driver on cfg->port, route the pins (IO_MUX when they are the
// controller's native pins, else the GPIO matrix), enable the RX pull-up and
// start the receive task. HAL_ERR_INVALID_ARG on a bad port, pin, baud or a
// NULL callback; HAL_ERR_BUSY if the port is already a link; driver errors
// otherwise (nothing is left installed on failure).
hal_result_t hal_uart_link_init(const hal_uart_link_cfg_t *cfg, hal_uart_link_rx_cb rx_cb, void *user);

// Queue len bytes for transmission and return at once. All-or-nothing:
// HAL_OK all queued; HAL_ERR_BUSY none queued (TX ring full);
// HAL_ERR_INVALID_ARG len 0, NULL data or a port that is not a link.
hal_result_t hal_uart_link_write(uint8_t port, const uint8_t *data, size_t len);

// Wait until every queued byte has left the TX shift register, at most
// timeout_ms. HAL_OK or HAL_ERR_TIMEOUT.
hal_result_t hal_uart_link_flush(uint8_t port, uint32_t timeout_ms);

// Snapshot of the port counters of one link.
hal_result_t hal_uart_link_get_stats(uint8_t port, hal_uart_link_stats_t *out);

#ifdef __cplusplus
}
#endif
