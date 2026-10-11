// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_radio.h - vendor-neutral connectionless packet radio (Braid PACKET
// carrier, spec 1.2). On ESP32 / ESP32-S3 this is ESP-NOW over the Wi-Fi PHY;
// the implementation is components/port_esp_idf/port_espnow.cpp, the only
// translation unit that includes the vendor radio headers.
//
// Model:
//   - 6-byte station addresses; broadcast is "dst NULL" in hal_radio_send().
//   - Unicast is acknowledged and retried by the radio MAC; the verdict comes
//     back once per unicast through the tx-done callback (broadcasts report
//     nothing).
//   - Callbacks run in the radio driver's task (core 0 on ESP32 / S3). They
//     must only copy and enqueue with a zero timeout: no blocking, no
//     protocol work, no logging in the hot path.
//   - Peers are managed inside the port: the broadcast peer is added at init,
//     unicast peers lazily before the first send to an address; when the
//     radio's peer table is full the least recently used unicast peer is
//     removed.
//
// Thread safety: hal_radio_send() may be called from one task at a time
// (Braid: only the protocol task). init is called once at boot.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_RADIO_ADDR_LEN   6u
#define HAL_RADIO_MAX_FRAME  250u   // Braid max_frame on mesh carriers

typedef struct {
    uint8_t channel;                // 1..13; every board of a mesh uses the same one
} hal_radio_cfg_t;

// Radio-task context: copy what you need, enqueue with timeout 0, return.
typedef void (*hal_radio_rx_cb)(void *user, const uint8_t src[HAL_RADIO_ADDR_LEN], int8_t rssi,
                                const uint8_t *data, size_t len);
typedef void (*hal_radio_tx_cb)(void *user, const uint8_t dst[HAL_RADIO_ADDR_LEN], bool delivered);

typedef struct {
    uint32_t peer_adds;             // unicast peers added
    uint32_t peer_evictions;        // LRU unicast peers removed because the table was full
    uint32_t send_busy;             // sends refused for lack of radio buffers
    uint32_t send_err;              // sends refused for any other reason
    uint32_t rx_oversize;           // received frames longer than HAL_RADIO_MAX_FRAME (dropped)
} hal_radio_stats_t;

// Bring the radio up: station mode without association on cfg->channel,
// power save off, long range off, broadcast peer registered, callbacks
// installed. HAL_ERR_INVALID_ARG on a bad channel or NULL callbacks.
// Requires hal_kv_init() first (the Wi-Fi driver keeps calibration in NVS).
hal_result_t hal_radio_init(const hal_radio_cfg_t *cfg, hal_radio_rx_cb rx_cb, hal_radio_tx_cb tx_cb,
                            void *user);

// Queue one frame; returns at once. dst NULL = broadcast.
// HAL_OK queued; HAL_ERR_BUSY no radio buffer (try later / count the loss);
// HAL_ERR_NO_MEM peer could not be added; HAL_ERR_INVALID_ARG len 0 or
// > HAL_RADIO_MAX_FRAME; other codes for driver errors.
hal_result_t hal_radio_send(const uint8_t *dst, const uint8_t *data, size_t len);

// The station address other boards see as our source address.
hal_result_t hal_radio_get_addr(uint8_t addr_out[HAL_RADIO_ADDR_LEN]);

// Snapshot of the port counters.
hal_result_t hal_radio_get_stats(hal_radio_stats_t *out);

// 12.4 bridge arbitration hook (firmware/RADIO-ARB.txt): frames accepted by
// hal_radio_send() whose transmission has not completed yet, unicast AND
// broadcast (ESP-NOW: between esp_now_send() returning OK and its send
// callback, which the driver runs for every accepted frame; the tx-done
// callback above still reports unicast verdicts only). 0 before init.
// Callable from any task; the value can change as soon as it is read.
// Reception is not observable: ESP-NOW gives no "receiving now" signal.
uint32_t hal_radio_tx_inflight(void);

#ifdef __cplusplus
}
#endif
