// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_sntp.cpp - ESP-IDF implementation of hal_time.h: the lwIP SNTP client
// through esp_netif_sntp (ESP-IDF 5.x), on the WiFi station of port_udp.cpp.
//
// Two traps handled here:
//   - lwIP's sntp_setservername() stores the POINTER, not a copy
//     (lwip/src/apps/sntp/sntp.c): the server name lives in g_server for
//     the life of the image;
//   - the sync callback runs on the lwIP tcpip thread: it only bumps an
//     atomic counter; the application task polls hal_sntp_sync_count() and
//     does the logging (BRNTP line in node_app.cpp).
// The system clock is stepped by the client (settimeofday, no smoothing);
// time zone stays UTC (TZ is never set).

#include <atomic>
#include <cstring>

#include <sys/time.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"

#include "hal_time.h"
#include "port_err.h"

namespace {

constexpr char TAG[] = "port_sntp";

char g_server[HAL_SNTP_SERVER_MAX + 1] = {};
std::atomic<bool> g_started{false};
std::atomic<uint32_t> g_syncs{0};

// lwIP tcpip thread: count only.
void sntp_synced(struct timeval *)
{
    g_syncs.fetch_add(1, std::memory_order_relaxed);
}

}  // namespace

extern "C" hal_result_t hal_sntp_start(const char *server)
{
    if (server == nullptr) {
        return HAL_ERR_INVALID_ARG;
    }
    const size_t n = strnlen(server, HAL_SNTP_SERVER_MAX + 1);
    if (n == 0 || n > HAL_SNTP_SERVER_MAX) {
        return HAL_ERR_INVALID_ARG;
    }
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true)) {
        return HAL_ERR_BUSY;
    }
    std::memcpy(g_server, server, n);
    g_server[n] = '\0';
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(g_server);
    cfg.wait_for_sync = false;  // nobody blocks on it: the app polls the counter
    cfg.start = true;
    cfg.sync_cb = sntp_synced;
    const esp_err_t e = esp_netif_sntp_init(&cfg);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_sntp_init failed: %s", esp_err_to_name(e));
        g_started.store(false);
        return port::map_err(e);
    }
    return HAL_OK;
}

extern "C" uint32_t hal_sntp_sync_count(void)
{
    return g_syncs.load(std::memory_order_relaxed);
}

extern "C" hal_result_t hal_time_utc_us(int64_t *utc_us_out)
{
    if (utc_us_out == nullptr) {
        return HAL_ERR_INVALID_ARG;
    }
    *utc_us_out = 0;
    if (g_syncs.load(std::memory_order_relaxed) == 0) {
        return HAL_ERR_NOT_FOUND;
    }
    struct timeval tv = {};
    if (gettimeofday(&tv, nullptr) != 0) {
        return HAL_ERR_INTERNAL;
    }
    *utc_us_out = static_cast<int64_t>(tv.tv_sec) * 1000000 + static_cast<int64_t>(tv.tv_usec);
    return HAL_OK;
}
