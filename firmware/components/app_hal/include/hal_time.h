// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_time.h - wall-clock (UTC) time from SNTP over the WiFi station.
//
// Device implementation: components/port_esp_idf/port_sntp.cpp (ESP-IDF
// esp_netif_sntp, lwIP SNTP client; no external dependency). There is no
// host implementation: nothing on the host calls these.
//
// Purpose: the single-chip nRF24 gateway (firmware/GATEWAY-NRF24.txt) and
// any LAN-side station board get UTC from the internet. Spec 6.5 makes the
// manager the network time source of the mesh (MGMT_REQ/RESP, 11.10); the
// protocol core has no network-time hook yet (MGMT is not served), so for
// now the app only logs the synced time (BRNTP line). When the core gains a
// hook, hal_time_utc_us() is what feeds it.
//
// Model:
//   - hal_sntp_start() once, after hal_udp_wifi_sta_start() returned HAL_OK
//     or HAL_ERR_TIMEOUT (the netif must exist; SNTP waits for the IP by
//     itself). The client polls the server every
//     CONFIG_LWIP_SNTP_UPDATE_DELAY (ESP-IDF default 1 h) and steps the
//     system clock (settimeofday) on each answer;
//   - every successful sync increments a counter. The callback runs on the
//     lwIP tcpip thread and only touches atomics: the application polls
//     hal_sntp_sync_count() from its own task and logs there;
//   - hal_time_utc_us() reads the system clock once at least one sync has
//     happened (before that the clock counts from boot, not from 1970).

#pragma once

#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_SNTP_SERVER_MAX 63u   // host name or dotted IPv4, bytes without the NUL

// Start the SNTP client on server (copied into static storage: lwIP keeps
// the pointer). HAL_OK started; HAL_ERR_INVALID_ARG NULL / empty / longer
// than HAL_SNTP_SERVER_MAX; HAL_ERR_BUSY already started; other codes from
// esp_netif_sntp_init().
hal_result_t hal_sntp_start(const char *server);

// Number of successful syncs since hal_sntp_start() (0 = never synced).
// Lock-free, any task.
uint32_t hal_sntp_sync_count(void);

// UTC now, microseconds since 1970-01-01T00:00:00Z. HAL_OK; HAL_ERR_NOT_FOUND
// never synced (output 0); HAL_ERR_INVALID_ARG NULL.
hal_result_t hal_time_utc_us(int64_t *utc_us_out);

#ifdef __cplusplus
}
#endif
