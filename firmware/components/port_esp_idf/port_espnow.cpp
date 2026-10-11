// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_espnow.cpp - ESP-NOW implementation of hal_radio.h.
//
// The only translation unit that includes the Wi-Fi / ESP-NOW headers.
//
// Radio setup (hal_radio_init): Wi-Fi station mode without association,
// fixed channel (esp_wifi_set_channel after esp_wifi_start), power save off
// (WIFI_PS_NONE), protocol 11b/g/n only (long range off), calibration data
// in RAM storage. ESP-NOW v1 frames (<= 250 bytes, = Braid max_frame).
//
// Callbacks run in the Wi-Fi task (core 0, CONFIG_ESP_WIFI_TASK_PINNED_TO_CORE_0):
// they forward to the hal_radio callbacks, which only copy and enqueue.
//
// Peers: the broadcast peer is added at init. A unicast peer is added
// lazily before the first send to its address; the port keeps a mirror of
// the unicast peers it added with a last-use time, and when the driver's
// table is full (20 incl. broadcast) the least recently used unicast peer is
// deleted first. Real ESP-NOW unicast is acknowledged and retried by the MAC
// before the send callback reports ESP_NOW_SEND_FAIL (SPEC-NOTES "Simulator vs
// hardware correspondence": mac_attempts 3 in the simulator).
//
// 12.4 bridge arbitration: hal_radio_tx_inflight() counts frames between
// esp_now_send() and their send callback (broadcasts included); the portable
// radio_arb / espnow_link modules in app_node read it from the protocol task
// (firmware/RADIO-ARB.txt).

#include <atomic>
#include <cstring>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "hal_radio.h"
#include "port_err.h"

namespace {

constexpr char TAG[] = "port_espnow";
constexpr uint8_t kBroadcast[HAL_RADIO_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr size_t kUnicastPeers = ESP_NOW_MAX_TOTAL_PEER_NUM - 1;  // one slot is the broadcast peer
constexpr TickType_t kLockWait = pdMS_TO_TICKS(20);

struct Peer {
    uint8_t  addr[HAL_RADIO_ADDR_LEN];
    uint64_t last_us;
    bool     used;
};

Peer g_peers[kUnicastPeers] = {};
StaticSemaphore_t g_lock_buf;
SemaphoreHandle_t g_lock = nullptr;

hal_radio_rx_cb g_rx = nullptr;
hal_radio_tx_cb g_tx = nullptr;
void *g_user = nullptr;
std::atomic<bool> g_up{false};

std::atomic<uint32_t> g_peer_adds{0};
std::atomic<uint32_t> g_peer_evictions{0};
std::atomic<uint32_t> g_send_busy{0};
std::atomic<uint32_t> g_send_err{0};
std::atomic<uint32_t> g_rx_oversize{0};
// Frames accepted by esp_now_send() whose send callback has not run yet
// (hal_radio_tx_inflight, 12.4 bridge arbitration). Incremented BEFORE
// esp_now_send (the Wi-Fi task on core 0 may run the callback before the
// call returns on core 1), undone if the send is refused, decremented in
// send_cb for every frame including broadcasts. Never wraps below 0.
std::atomic<uint32_t> g_tx_inflight{0};

void tx_inflight_done() {
    uint32_t v = g_tx_inflight.load(std::memory_order_relaxed);
    while (v > 0 && !g_tx_inflight.compare_exchange_weak(v, v - 1, std::memory_order_relaxed)) {
    }
}

bool is_broadcast(const uint8_t *a) { return std::memcmp(a, kBroadcast, HAL_RADIO_ADDR_LEN) == 0; }

// ---- Wi-Fi task context ----------------------------------------------------

void recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (info == nullptr || info->src_addr == nullptr || data == nullptr || len <= 0 || g_rx == nullptr) {
        return;
    }
    if (static_cast<size_t>(len) > HAL_RADIO_MAX_FRAME) {
        g_rx_oversize.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const int8_t rssi = info->rx_ctrl != nullptr ? static_cast<int8_t>(info->rx_ctrl->rssi) : INT8_MIN;
    g_rx(g_user, info->src_addr, rssi, data, static_cast<size_t>(len));
}

void send_cb(const esp_now_send_info_t *tx_info, esp_now_send_status_t status) {
    tx_inflight_done();  // every accepted frame, broadcast included, before any early return
    if (tx_info == nullptr || tx_info->des_addr == nullptr || g_tx == nullptr) {
        return;
    }
    if (is_broadcast(tx_info->des_addr)) {
        return;  // broadcasts are not acknowledged: no verdict
    }
    g_tx(g_user, tx_info->des_addr, status == ESP_NOW_SEND_SUCCESS);
}

// ---- peer table (protocol task, under g_lock) ---------------------------------

hal_result_t evict_lru() {
    Peer *lru = nullptr;
    for (auto &p : g_peers) {
        if (p.used && (lru == nullptr || p.last_us < lru->last_us)) lru = &p;
    }
    if (lru == nullptr) return HAL_ERR_NO_MEM;  // table full of peers we did not add
    const esp_err_t e = esp_now_del_peer(lru->addr);
    if (e != ESP_OK && e != ESP_ERR_ESPNOW_NOT_FOUND) {
        ESP_LOGW(TAG, "del_peer failed: %s", esp_err_to_name(e));
        return port::map_err(e);
    }
    lru->used = false;
    g_peer_evictions.fetch_add(1, std::memory_order_relaxed);
    return HAL_OK;
}

hal_result_t add_peer(const uint8_t *addr) {
    esp_now_peer_info_t info = {};
    std::memcpy(info.peer_addr, addr, HAL_RADIO_ADDR_LEN);
    info.channel = 0;  // current channel
    info.ifidx = WIFI_IF_STA;
    info.encrypt = false;  // Braid authenticates and encrypts end to end (section 8)
    esp_err_t e = esp_now_add_peer(&info);
    if (e == ESP_ERR_ESPNOW_FULL) {
        const hal_result_t r = evict_lru();
        if (r != HAL_OK) return r;
        e = esp_now_add_peer(&info);
    }
    if (e == ESP_ERR_ESPNOW_EXIST) return HAL_OK;
    if (e == ESP_ERR_ESPNOW_FULL) return HAL_ERR_NO_MEM;
    return port::map_err(e);
}

hal_result_t ensure_peer(const uint8_t *addr) {
    const uint64_t now = static_cast<uint64_t>(esp_timer_get_time());
    Peer *free_slot = nullptr;
    for (auto &p : g_peers) {
        if (p.used && std::memcmp(p.addr, addr, HAL_RADIO_ADDR_LEN) == 0) {
            p.last_us = now;
            return HAL_OK;
        }
        if (!p.used && free_slot == nullptr) free_slot = &p;
    }
    if (free_slot == nullptr) {
        const hal_result_t r = evict_lru();
        if (r != HAL_OK) return r;
        for (auto &p : g_peers) {
            if (!p.used) {
                free_slot = &p;
                break;
            }
        }
        if (free_slot == nullptr) return HAL_ERR_INTERNAL;
    }
    const hal_result_t r = add_peer(addr);
    if (r != HAL_OK) return r;
    std::memcpy(free_slot->addr, addr, HAL_RADIO_ADDR_LEN);
    free_slot->last_us = now;
    free_slot->used = true;
    g_peer_adds.fetch_add(1, std::memory_order_relaxed);
    return HAL_OK;
}

hal_result_t step(esp_err_t e, const char *what) {
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "%s failed: %s", what, esp_err_to_name(e));
    }
    return port::map_err(e);
}

}  // namespace

extern "C" hal_result_t hal_radio_init(const hal_radio_cfg_t *cfg, hal_radio_rx_cb rx_cb, hal_radio_tx_cb tx_cb,
                                       void *user) {
    if (cfg == nullptr || rx_cb == nullptr || tx_cb == nullptr || cfg->channel < 1 || cfg->channel > 13) {
        return HAL_ERR_INVALID_ARG;
    }
    if (g_up.load()) return HAL_ERR_BUSY;
    g_lock = xSemaphoreCreateMutexStatic(&g_lock_buf);
    if (g_lock == nullptr) return HAL_ERR_NO_MEM;
    g_rx = rx_cb;
    g_tx = tx_cb;
    g_user = user;

    hal_result_t r = step(esp_netif_init(), "esp_netif_init");
    if (r != HAL_OK) return r;
    esp_err_t e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return step(e, "esp_event_loop_create_default");

    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    if ((r = step(esp_wifi_init(&wc), "esp_wifi_init")) != HAL_OK) return r;
    if ((r = step(esp_wifi_set_storage(WIFI_STORAGE_RAM), "esp_wifi_set_storage")) != HAL_OK) return r;
    if ((r = step(esp_wifi_set_mode(WIFI_MODE_STA), "esp_wifi_set_mode")) != HAL_OK) return r;
    if ((r = step(esp_wifi_start(), "esp_wifi_start")) != HAL_OK) return r;
    if ((r = step(esp_wifi_set_ps(WIFI_PS_NONE), "esp_wifi_set_ps")) != HAL_OK) return r;
    if ((r = step(esp_wifi_set_channel(cfg->channel, WIFI_SECOND_CHAN_NONE), "esp_wifi_set_channel")) != HAL_OK) {
        return r;
    }
    // Long range off: 11b/g/n only (WIFI_PROTOCOL_LR not set). This is the
    // driver default already, so a failure is logged and not fatal.
    (void)step(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N),
               "esp_wifi_set_protocol");

    if ((r = step(esp_now_init(), "esp_now_init")) != HAL_OK) return r;
    if ((r = step(esp_now_register_recv_cb(recv_cb), "esp_now_register_recv_cb")) != HAL_OK) return r;
    if ((r = step(esp_now_register_send_cb(send_cb), "esp_now_register_send_cb")) != HAL_OK) return r;
    if ((r = add_peer(kBroadcast)) != HAL_OK) {
        ESP_LOGE(TAG, "broadcast peer: %s", hal_result_name(r));
        return r;
    }
    g_up.store(true);
    return HAL_OK;
}

extern "C" hal_result_t hal_radio_send(const uint8_t *dst, const uint8_t *data, size_t len) {
    if (data == nullptr || len == 0 || len > HAL_RADIO_MAX_FRAME) return HAL_ERR_INVALID_ARG;
    if (!g_up.load()) return HAL_ERR_BUSY;
    const uint8_t *to = kBroadcast;
    if (dst != nullptr && !is_broadcast(dst)) {
        if (xSemaphoreTake(g_lock, kLockWait) != pdTRUE) {
            g_send_busy.fetch_add(1, std::memory_order_relaxed);
            return HAL_ERR_BUSY;
        }
        const hal_result_t r = ensure_peer(dst);
        xSemaphoreGive(g_lock);
        if (r != HAL_OK) {
            g_send_err.fetch_add(1, std::memory_order_relaxed);
            return r;
        }
        to = dst;
    }
    g_tx_inflight.fetch_add(1, std::memory_order_relaxed);
    const esp_err_t e = esp_now_send(to, data, len);
    if (e == ESP_OK) return HAL_OK;
    tx_inflight_done();  // refused: no callback will come for it
    if (e == ESP_ERR_ESPNOW_NO_MEM) {
        g_send_busy.fetch_add(1, std::memory_order_relaxed);
        return HAL_ERR_BUSY;
    }
    g_send_err.fetch_add(1, std::memory_order_relaxed);
    return port::map_err(e);
}

extern "C" hal_result_t hal_radio_get_addr(uint8_t addr_out[HAL_RADIO_ADDR_LEN]) {
    if (addr_out == nullptr) return HAL_ERR_INVALID_ARG;
    return port::map_err(esp_wifi_get_mac(WIFI_IF_STA, addr_out));
}

extern "C" uint32_t hal_radio_tx_inflight(void) { return g_tx_inflight.load(std::memory_order_relaxed); }

extern "C" hal_result_t hal_radio_get_stats(hal_radio_stats_t *out) {
    if (out == nullptr) return HAL_ERR_INVALID_ARG;
    out->peer_adds = g_peer_adds.load(std::memory_order_relaxed);
    out->peer_evictions = g_peer_evictions.load(std::memory_order_relaxed);
    out->send_busy = g_send_busy.load(std::memory_order_relaxed);
    out->send_err = g_send_err.load(std::memory_order_relaxed);
    out->rx_oversize = g_rx_oversize.load(std::memory_order_relaxed);
    return HAL_OK;
}
