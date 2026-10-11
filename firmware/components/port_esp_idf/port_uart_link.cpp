// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_uart_link.cpp - ESP-IDF implementation of hal_uart_link.h.
//
// One link per UART controller (1..SOC_UART_NUM-1; UART0 is the console).
//
// Driver set-up: uart_driver_install() with an RX ring, a TX ring and the
// driver's event queue; 8N1, no flow control; uart_set_pin() picks IO_MUX
// when the pins are the controller's native ones (C.6: ESP32 UART2 on
// GPIO17 TX / GPIO16 RX, ESP32-S3 UART1 on GPIO17 TX / GPIO18 RX) and the
// GPIO matrix otherwise. The driver's defaults stay: RX FIFO-full threshold
// 120 bytes and an idle-line timeout of 10 symbol times, which is the
// "FIFO-threshold or idle-line interrupt" of Appendix C.2.
//
// Receive task ("ulrx<n>", core 0, priority tskIDLE_PRIORITY + 6, 3072 B):
// blocks on the event queue with a 1 s timeout (never polls). UART_DATA:
// copy ev.size bytes out of the ring with uart_read_bytes(timeout 0) in
// chunks of <= HAL_UART_LINK_RX_CHUNK and pass each to the callback.
// UART_FIFO_OVF / UART_BUFFER_FULL: flush input, reset the event queue,
// report HAL_UART_LINK_RX_LOST. UART_FRAME_ERR / UART_BREAK: counted only
// (the garbled byte is still in the stream; COBS + RS + CRC above decide).
// Core 0 keeps the priority-5 protocol task on core 1 free; the Wi-Fi task
// (priority 23) preempts this one, which the 2 KB RX ring absorbs (22 ms at
// 921600 baud, 178 ms at 115200).
//
// Transmit never blocks: uart_write_bytes() waits with portMAX_DELAY when
// its ring is full, so hal_uart_link_write() first asks the driver for the
// free TX ring space (uart_get_tx_buffer_free_size, a conservative bound)
// and refuses the whole write with HAL_ERR_BUSY unless len + kTxSlack bytes
// fit. kTxSlack covers the per-transaction descriptor item and the ring's
// item headers. Single writer per link (the protocol task), so the free
// space can only grow between the check and the write.

#include <atomic>
#include <cstring>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "soc/soc_caps.h"

#include "hal_uart_link.h"
#include "port_err.h"

namespace {

constexpr char TAG[] = "port_ulink";

constexpr BaseType_t  kRxCore      = 0;                      // PRO_CPU, with the Wi-Fi task
constexpr UBaseType_t kRxPrio      = tskIDLE_PRIORITY + 6;
constexpr uint32_t    kRxStack     = 3072;
constexpr int         kEvtQueueLen = 20;
constexpr TickType_t  kEvtWait     = pdMS_TO_TICKS(1000);    // bounded wait, loop again
constexpr size_t      kTxSlack     = 64;
constexpr uint32_t    kMaxBaud     = 5000000;

struct Link {
    std::atomic<bool>      up{false};
    uint8_t                port = 0;
    QueueHandle_t          evq = nullptr;
    TaskHandle_t           task = nullptr;
    hal_uart_link_rx_cb    cb = nullptr;
    void                  *user = nullptr;
    uint8_t                chunk[HAL_UART_LINK_RX_CHUNK] = {};
    std::atomic<uint32_t>  rx_bytes{0};
    std::atomic<uint32_t>  tx_bytes{0};
    std::atomic<uint32_t>  tx_busy{0};
    std::atomic<uint32_t>  fifo_ovf{0};
    std::atomic<uint32_t>  buf_full{0};
    std::atomic<uint32_t>  frame_err{0};
    std::atomic<uint32_t>  breaks{0};
};

Link g_links[SOC_UART_NUM];

bool valid_link_port(uint8_t port) { return port >= 1 && port < SOC_UART_NUM; }

Link *link_for(uint8_t port) {
    if (!valid_link_port(port)) return nullptr;
    Link *l = &g_links[port];
    return l->up.load() ? l : nullptr;
}

// ---- receive task ------------------------------------------------------------

void drain(Link &l, size_t pending) {
    const auto port = static_cast<uart_port_t>(l.port);
    while (pending > 0) {
        const size_t want = pending < sizeof l.chunk ? pending : sizeof l.chunk;
        const int got = uart_read_bytes(port, l.chunk, static_cast<uint32_t>(want), 0);
        if (got <= 0) return;  // already consumed (e.g. after a flush)
        l.rx_bytes.fetch_add(static_cast<uint32_t>(got), std::memory_order_relaxed);
        l.cb(l.user, l.chunk, static_cast<size_t>(got), 0);
        pending -= static_cast<size_t>(got);
    }
}

void report_lost(Link &l) {
    (void)uart_flush_input(static_cast<uart_port_t>(l.port));
    (void)xQueueReset(l.evq);
    l.cb(l.user, nullptr, 0, HAL_UART_LINK_RX_LOST);
}

void rx_task(void *arg) {
    Link &l = *static_cast<Link *>(arg);
    for (;;) {
        uart_event_t ev;
        if (xQueueReceive(l.evq, &ev, kEvtWait) != pdTRUE) continue;
        switch (ev.type) {
            case UART_DATA:
                drain(l, ev.size);
                break;
            case UART_FIFO_OVF:
                l.fifo_ovf.fetch_add(1, std::memory_order_relaxed);
                report_lost(l);
                break;
            case UART_BUFFER_FULL:
                l.buf_full.fetch_add(1, std::memory_order_relaxed);
                report_lost(l);
                break;
            case UART_FRAME_ERR:
            case UART_PARITY_ERR:
                l.frame_err.fetch_add(1, std::memory_order_relaxed);
                break;
            case UART_BREAK:
                l.breaks.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }
    }
}

}  // namespace

extern "C" hal_result_t hal_uart_link_init(const hal_uart_link_cfg_t *cfg, hal_uart_link_rx_cb rx_cb, void *user) {
    if (cfg == nullptr || rx_cb == nullptr || !valid_link_port(cfg->port) || cfg->baud == 0 ||
        cfg->baud > kMaxBaud || cfg->tx_pin < 0 || cfg->rx_pin < 0 || cfg->tx_pin == cfg->rx_pin ||
        !GPIO_IS_VALID_OUTPUT_GPIO(cfg->tx_pin) || !GPIO_IS_VALID_GPIO(cfg->rx_pin)) {
        return HAL_ERR_INVALID_ARG;
    }
    Link &l = g_links[cfg->port];
    if (l.up.load()) return HAL_ERR_BUSY;
    const auto port = static_cast<uart_port_t>(cfg->port);
    const int rx_len = cfg->rx_buf_len != 0 ? cfg->rx_buf_len : static_cast<int>(HAL_UART_LINK_RX_BUF_DEFAULT);
    const int tx_len = cfg->tx_buf_len != 0 ? cfg->tx_buf_len : static_cast<int>(HAL_UART_LINK_TX_BUF_DEFAULT);
    if (rx_len <= SOC_UART_FIFO_LEN || tx_len <= SOC_UART_FIFO_LEN) return HAL_ERR_INVALID_ARG;

    uart_config_t uc = {};
    uc.baud_rate  = static_cast<int>(cfg->baud);
    uc.data_bits  = UART_DATA_8_BITS;
    uc.parity     = UART_PARITY_DISABLE;
    uc.stop_bits  = UART_STOP_BITS_1;
    uc.flow_ctrl  = UART_HW_FLOWCTRL_DISABLE;
    uc.source_clk = UART_SCLK_DEFAULT;

    QueueHandle_t evq = nullptr;
    esp_err_t e = uart_driver_install(port, rx_len, tx_len, kEvtQueueLen, &evq, 0);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "uart%u driver install failed: %s", cfg->port, esp_err_to_name(e));
        return port::map_err(e);
    }
    e = uart_param_config(port, &uc);
    if (e == ESP_OK) e = uart_set_pin(port, cfg->tx_pin, cfg->rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (e == ESP_OK) e = gpio_pullup_en(static_cast<gpio_num_t>(cfg->rx_pin));
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "uart%u config failed: %s", cfg->port, esp_err_to_name(e));
        (void)uart_driver_delete(port);
        return port::map_err(e);
    }

    l.port = cfg->port;
    l.evq = evq;
    l.cb = rx_cb;
    l.user = user;
    char name[8] = {'u', 'l', 'r', 'x', static_cast<char>('0' + cfg->port), '\0'};
    // Created at boot (init), never deleted: no allocation after init.
    if (xTaskCreatePinnedToCore(rx_task, name, kRxStack, &l, kRxPrio, &l.task, kRxCore) != pdPASS) {
        ESP_LOGE(TAG, "uart%u receive task create failed", cfg->port);
        l.task = nullptr;
        (void)uart_driver_delete(port);
        return HAL_ERR_NO_MEM;
    }
    l.up.store(true);
    return HAL_OK;
}

extern "C" hal_result_t hal_uart_link_write(uint8_t port, const uint8_t *data, size_t len) {
    Link *l = link_for(port);
    if (l == nullptr || data == nullptr || len == 0) return HAL_ERR_INVALID_ARG;
    const auto p = static_cast<uart_port_t>(port);
    size_t free_bytes = 0;
    const esp_err_t e = uart_get_tx_buffer_free_size(p, &free_bytes);
    if (e != ESP_OK) return port::map_err(e);
    if (free_bytes < len + kTxSlack) {
        l->tx_busy.fetch_add(1, std::memory_order_relaxed);
        return HAL_ERR_BUSY;
    }
    const int n = uart_write_bytes(p, data, len);
    if (n < 0 || static_cast<size_t>(n) != len) return HAL_ERR_INTERNAL;
    l->tx_bytes.fetch_add(static_cast<uint32_t>(len), std::memory_order_relaxed);
    return HAL_OK;
}

extern "C" hal_result_t hal_uart_link_flush(uint8_t port, uint32_t timeout_ms) {
    if (link_for(port) == nullptr) return HAL_ERR_INVALID_ARG;
    TickType_t t = pdMS_TO_TICKS(timeout_ms);
    if (timeout_ms > 0 && t == 0) t = 1;
    return port::map_err(uart_wait_tx_done(static_cast<uart_port_t>(port), t));
}

extern "C" hal_result_t hal_uart_link_get_stats(uint8_t port, hal_uart_link_stats_t *out) {
    const Link *l = link_for(port);
    if (l == nullptr || out == nullptr) return HAL_ERR_INVALID_ARG;
    out->rx_bytes = l->rx_bytes.load(std::memory_order_relaxed);
    out->tx_bytes = l->tx_bytes.load(std::memory_order_relaxed);
    out->tx_busy = l->tx_busy.load(std::memory_order_relaxed);
    out->fifo_ovf = l->fifo_ovf.load(std::memory_order_relaxed);
    out->buf_full = l->buf_full.load(std::memory_order_relaxed);
    out->frame_err = l->frame_err.load(std::memory_order_relaxed);
    out->breaks = l->breaks.load(std::memory_order_relaxed);
    return HAL_OK;
}
