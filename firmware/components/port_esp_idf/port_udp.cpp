// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_udp.cpp - ESP-IDF implementation of hal_udp.h (lwIP BSD sockets) plus
// the WiFi station bring-up helper for the LAN side (spec 12.4, C.4).
//
// The socket part is kept textually near-identical to firmware/host/udp_posix.c
// (same BSD calls: ESP-IDF exposes lwIP through <sys/socket.h>,
// <netinet/in.h>, <arpa/inet.h>, <sys/select.h> and the VFS close()). When
// you change one, change both. Differences: C++ with extern "C", ESP_LOG
// for failures, and hal_udp_wifi_sta_start() at the end.
//
// In the build since the integration pass (port_esp_idf/CMakeLists.txt
// SRCS + lwip in PRIV_REQUIRES); node_app's "udprx" task receives on the
// socket, the protocol task sends on it (firmware/UDP-LINK.txt section 3).
//
// WiFi: a UDP node is a LAN station (esp_wifi STA, associated, DHCP). It
// never shares a chip with ESP-NOW (hal_radio_init): association moves the
// channel under the mesh (12.4). Both helpers own esp_wifi; whichever runs
// second fails with HAL_ERR_BUSY. Power save is off (WIFI_PS_NONE) so the
// 50 ms HELLO window and the ARQ RTO are not stretched by DTIM sleep.
// Credentials are passed in by the caller (NVS keys ssid= / pass=), never
// compiled in; the driver keeps them in RAM only (WIFI_STORAGE_RAM) and the
// local wifi_config_t copy is wiped after esp_wifi_set_config(). The station
// reconnects forever with capped exponential backoff + jitter on an
// esp_timer (hal_udp.h, SPEC-NOTES N69); it no longer gives up after 10
// failures.
// The same station serves the single-chip nRF24 gateway (console wifi=on
// without udp=on, firmware/GATEWAY-NRF24.txt): hal_udp_wifi_sta_info()
// reports the AP channel so the app can check its distance from the nRF24
// channel; SNTP runs on this netif (port_sntp.cpp).

#include <atomic>
#include <cstring>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "hal_udp.h"
#include "port_err.h"

namespace {

constexpr char TAG[] = "port_udp";

/* ---- common socket code (same in udp_posix.c) ----------------------------- */

void udp_fill_addr(struct sockaddr_in *sa, uint32_t addr4, uint16_t port)
{
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(addr4);
}

hal_result_t udp_errno_result(int e)
{
    switch (e) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case ENOBUFS:
    case ENOMEM:
        return HAL_ERR_BUSY;
    case EADDRINUSE:
        return HAL_ERR_BUSY;
    case EADDRNOTAVAIL:
    case ENODEV:
    case ENOPROTOOPT:
    case EOPNOTSUPP:
        return HAL_ERR_UNSUPPORTED;
    case EINVAL:
    case EBADF:
        return HAL_ERR_INVALID_ARG;
    default:
        return HAL_ERR_HW_FAULT;
    }
}

hal_result_t udp_mcast_membership(int fd, uint32_t group, uint32_t mcast_if, bool join)
{
    struct ip_mreq mr;
    memset(&mr, 0, sizeof mr);
    mr.imr_multiaddr.s_addr = htonl(group);
    mr.imr_interface.s_addr = htonl(mcast_if == 0u ? INADDR_ANY : mcast_if);
    const int opt = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
    if (setsockopt(fd, IPPROTO_IP, opt, &mr, sizeof mr) != 0) {
        const hal_result_t r = udp_errno_result(errno);
        ESP_LOGW(TAG, "%s multicast group failed: errno %d", join ? "join" : "leave", errno);
        return r == HAL_ERR_HW_FAULT ? HAL_ERR_UNSUPPORTED : r;
    }
    return HAL_OK;
}

}  // namespace

extern "C" hal_result_t hal_udp_open(hal_udp_t *s, const hal_udp_cfg_t *cfg)
{
    if (s == nullptr || cfg == nullptr) {
        return HAL_ERR_INVALID_ARG;
    }
    s->fd = -1;
    s->local_port = 0;
    s->mcast_group = 0;
    const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        ESP_LOGE(TAG, "socket failed: errno %d", errno);
        return udp_errno_result(errno);
    }
    if (cfg->reuse_addr) {
        const int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    struct sockaddr_in sa;
    udp_fill_addr(&sa, INADDR_ANY, cfg->local_port);
    if (bind(fd, reinterpret_cast<const struct sockaddr *>(&sa), sizeof sa) != 0) {
        const int e = errno;
        ESP_LOGE(TAG, "bind port %u failed: errno %d", cfg->local_port, e);
        (void)close(fd);
        return udp_errno_result(e);
    }
    socklen_t sl = sizeof sa;
    if (getsockname(fd, reinterpret_cast<struct sockaddr *>(&sa), &sl) != 0) {
        const int e = errno;
        (void)close(fd);
        return udp_errno_result(e);
    }
    s->fd = fd;
    s->local_port = ntohs(sa.sin_port);
    if (cfg->mcast_group == 0u) {
        return HAL_OK;
    }
    const unsigned char ttl = cfg->mcast_ttl == 0u ? 1u : cfg->mcast_ttl;
    const unsigned char loop = cfg->mcast_loop ? 1u : 0u;
    (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
    (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);
    if (cfg->mcast_if != 0u) {
        struct in_addr ia;
        ia.s_addr = htonl(cfg->mcast_if);
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ia, sizeof ia);
    }
    const hal_result_t r = udp_mcast_membership(fd, cfg->mcast_group, cfg->mcast_if, true);
    if (r != HAL_OK) {
        return r; /* socket stays open without the membership */
    }
    s->mcast_group = cfg->mcast_group;
    return HAL_OK;
}

extern "C" hal_result_t hal_udp_sendto(hal_udp_t *s, uint32_t addr4, uint16_t port, const uint8_t *buf, size_t len)
{
    if (s == nullptr || s->fd < 0 || buf == nullptr || len == 0u || port == 0u) {
        return HAL_ERR_INVALID_ARG;
    }
    struct sockaddr_in sa;
    udp_fill_addr(&sa, addr4, port);
    const ssize_t n = sendto(s->fd, buf, len, 0, reinterpret_cast<const struct sockaddr *>(&sa), sizeof sa);
    if (n < 0) {
        return udp_errno_result(errno);
    }
    return static_cast<size_t>(n) == len ? HAL_OK : HAL_ERR_HW_FAULT;
}

extern "C" hal_result_t hal_udp_recvfrom(hal_udp_t *s, uint8_t *buf, size_t cap, size_t *len_out,
                                         uint32_t *addr4_out, uint16_t *port_out, uint32_t timeout_ms)
{
    if (s == nullptr || s->fd < 0 || buf == nullptr || cap == 0u || len_out == nullptr) {
        return HAL_ERR_INVALID_ARG;
    }
    *len_out = 0;
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(s->fd, &rs);
    struct timeval tv;
    tv.tv_sec = static_cast<time_t>(timeout_ms / 1000u);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000u) * 1000u);
    const int sel = select(s->fd + 1, &rs, nullptr, nullptr, &tv);
    if (sel < 0) {
        return errno == EINTR ? HAL_ERR_TIMEOUT : udp_errno_result(errno);
    }
    if (sel == 0) {
        return HAL_ERR_TIMEOUT;
    }
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    memset(&sa, 0, sizeof sa);
    const ssize_t n = recvfrom(s->fd, buf, cap, 0, reinterpret_cast<struct sockaddr *>(&sa), &sl);
    if (n < 0) {
        const int e = errno;
        if (e == EAGAIN || e == EINTR
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
            || e == EWOULDBLOCK
#endif
        ) {
            return HAL_ERR_TIMEOUT;
        }
        return udp_errno_result(e);
    }
    *len_out = static_cast<size_t>(n);
    if (addr4_out != nullptr) {
        *addr4_out = ntohl(sa.sin_addr.s_addr);
    }
    if (port_out != nullptr) {
        *port_out = ntohs(sa.sin_port);
    }
    return HAL_OK;
}

extern "C" hal_result_t hal_udp_mcast(hal_udp_t *s, uint32_t group, uint32_t mcast_if, bool join)
{
    if (s == nullptr || s->fd < 0 || group == 0u) {
        return HAL_ERR_INVALID_ARG;
    }
    const hal_result_t r = udp_mcast_membership(s->fd, group, mcast_if, join);
    if (r == HAL_OK) {
        s->mcast_group = join ? group : 0u;
    }
    return r;
}

extern "C" hal_result_t hal_udp_close(hal_udp_t *s)
{
    if (s == nullptr) {
        return HAL_OK;
    }
    if (s->fd >= 0) {
        (void)close(s->fd);
    }
    s->fd = -1;
    s->local_port = 0;
    s->mcast_group = 0;
    return HAL_OK;
}

/* ---- WiFi station (device only) --------------------------------------------- */

namespace {

constexpr EventBits_t kGotIp = BIT0;

StaticEventGroup_t g_wifi_eg_buf;
EventGroupHandle_t g_wifi_eg = nullptr;
std::atomic<bool> g_wifi_started{false};
std::atomic<uint32_t> g_wifi_ip{0};

// Reconnect (hal_udp.h, SPEC-NOTES N69): retry forever on the schedule of
// hal_udp_wifi_backoff_next(). g_backoff is touched by the default event
// loop task (DISCONNECTED, GOT_IP) and by the esp_timer task (a failed
// esp_wifi_connect() in the retry callback), hence the spinlock; the
// critical sections hold arithmetic only (no logging, no driver calls).
esp_timer_handle_t g_retry_timer = nullptr;
portMUX_TYPE g_backoff_mux = portMUX_INITIALIZER_UNLOCKED;
hal_udp_wifi_backoff_t g_backoff = {0};
std::atomic<uint32_t> g_wifi_attempts{0};     // mirror of g_backoff.attempts for hal_udp_wifi_sta_retry_info
std::atomic<uint16_t> g_wifi_last_reason{0};

// Byte-wise volatile store: not removable by the optimiser (credentials).
void wipe(void *p, size_t n)
{
    volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
    for (size_t i = 0; i < n; i++) {
        v[i] = 0;
    }
}

// Count one failed attempt and arm the one-shot retry timer. At most one
// retry is pending: a second DISCONNECTED while the timer runs belongs to
// the same attempt and is neither counted nor logged again. Never blocks.
void schedule_retry(uint16_t reason)
{
    g_wifi_last_reason.store(reason, std::memory_order_relaxed);
    if (g_retry_timer == nullptr || esp_timer_is_active(g_retry_timer)) {
        return;
    }
    const uint32_t rnd = esp_random();
    portENTER_CRITICAL(&g_backoff_mux);
    const uint32_t delay_ms = hal_udp_wifi_backoff_next(&g_backoff, rnd);
    const uint32_t attempts = g_backoff.attempts;
    portEXIT_CRITICAL(&g_backoff_mux);
    g_wifi_attempts.store(attempts, std::memory_order_relaxed);
    const esp_err_t e = esp_timer_start_once(g_retry_timer, static_cast<uint64_t>(delay_ms) * 1000u);
    if (e == ESP_ERR_INVALID_STATE) {
        return;  // armed by the other context in between: that retry stands
    }
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "BRWIFI retry timer failed (%s): reconnect stalls until reboot", esp_err_to_name(e));
        return;
    }
    ESP_LOGW(TAG, "BRWIFI sta down (reason=%u) retry in %u.%us", static_cast<unsigned>(reason),
             static_cast<unsigned>(delay_ms / 1000u), static_cast<unsigned>((delay_ms % 1000u) / 100u));
}

// esp_timer task: one association attempt. Its outcome arrives as an event
// (GOT_IP, or DISCONNECTED -> schedule_retry); a call refused outright counts
// as a failed attempt here.
void retry_timer_cb(void *)
{
    const esp_err_t e = esp_wifi_connect();
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_connect failed: %s", esp_err_to_name(e));
        schedule_retry(g_wifi_last_reason.load(std::memory_order_relaxed));
    }
}

// Default event loop task: record state, arm the timer; never blocks and
// never calls esp_wifi_connect() except for the first attempt at STA_START.
void wifi_event_handler(void *, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        if (esp_wifi_connect() != ESP_OK) {
            schedule_retry(0);
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        g_wifi_ip.store(0, std::memory_order_relaxed);
        const auto *ev = static_cast<const wifi_event_sta_disconnected_t *>(data);
        schedule_retry(ev != nullptr ? static_cast<uint16_t>(ev->reason) : 0u);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const auto *ev = static_cast<const ip_event_got_ip_t *>(data);
        if (g_retry_timer != nullptr && esp_timer_is_active(g_retry_timer)) {
            (void)esp_timer_stop(g_retry_timer);
        }
        portENTER_CRITICAL(&g_backoff_mux);
        hal_udp_wifi_backoff_reset(&g_backoff);
        portEXIT_CRITICAL(&g_backoff_mux);
        g_wifi_attempts.store(0, std::memory_order_relaxed);
        g_wifi_ip.store(ntohl(ev->ip_info.ip.addr), std::memory_order_relaxed);
        xEventGroupSetBits(g_wifi_eg, kGotIp);
    }
}

hal_result_t step(esp_err_t e, const char *what)
{
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "%s failed: %s", what, esp_err_to_name(e));
    }
    return port::map_err(e);
}

}  // namespace

extern "C" hal_result_t hal_udp_wifi_sta_start(const char *ssid, const char *pass, uint32_t timeout_ms,
                                               uint32_t *ip4_out)
{
    if (ip4_out != nullptr) {
        *ip4_out = 0;
    }
    if (ssid == nullptr) {
        return HAL_ERR_INVALID_ARG;
    }
    const size_t ssid_len = strnlen(ssid, 33);
    const size_t pass_len = pass != nullptr ? strnlen(pass, 65) : 0;
    if (ssid_len == 0 || ssid_len > 32 || pass_len > 63) {
        return HAL_ERR_INVALID_ARG;
    }
    if (g_wifi_started.load()) {
        return HAL_ERR_BUSY;
    }
    g_wifi_eg = xEventGroupCreateStatic(&g_wifi_eg_buf);
    if (g_wifi_eg == nullptr) {
        return HAL_ERR_NO_MEM;
    }
    if (g_retry_timer == nullptr) {
        esp_timer_create_args_t ta = {};
        ta.callback = &retry_timer_cb;
        ta.arg = nullptr;
        ta.dispatch_method = ESP_TIMER_TASK;
        ta.name = "plwifi";
        ta.skip_unhandled_events = true;
        const hal_result_t tr = step(esp_timer_create(&ta, &g_retry_timer), "esp_timer_create");
        if (tr != HAL_OK) return tr;
    }
    hal_result_t r = step(esp_netif_init(), "esp_netif_init");
    if (r != HAL_OK) return r;
    esp_err_t e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return step(e, "esp_event_loop_create_default");
    if (esp_netif_create_default_wifi_sta() == nullptr) {
        ESP_LOGE(TAG, "esp_netif_create_default_wifi_sta failed");
        return HAL_ERR_NO_MEM;
    }
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    e = esp_wifi_init(&wc);
    if (e == ESP_ERR_INVALID_STATE) return HAL_ERR_BUSY;  // hal_radio_init() (ESP-NOW) owns the driver: 12.4
    if ((r = step(e, "esp_wifi_init")) != HAL_OK) return r;
    if ((r = step(esp_wifi_set_storage(WIFI_STORAGE_RAM), "esp_wifi_set_storage")) != HAL_OK) return r;
    if ((r = step(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, nullptr),
                  "register WIFI_EVENT")) != HAL_OK) {
        return r;
    }
    if ((r = step(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, nullptr),
                  "register IP_EVENT")) != HAL_OK) {
        return r;
    }
    {
        // Local copy of the credentials: wiped on every path out of this block
        // (the driver keeps its own copy in RAM, WIFI_STORAGE_RAM).
        wifi_config_t sc = {};
        struct Wipe {
            wifi_config_t *p;
            ~Wipe() { wipe(p, sizeof *p); }
        } sc_wipe{&sc};
        memcpy(sc.sta.ssid, ssid, ssid_len);
        if (pass_len > 0) memcpy(sc.sta.password, pass, pass_len);
        sc.sta.threshold.authmode = pass_len > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        // PMF (802.11w): capable, so a router with PMF "required" protects the
        // link against spoofed deauthentication; not required, so routers
        // without PMF still work (GATEWAY-NRF24.txt section 4).
        sc.sta.pmf_cfg.capable = true;
        sc.sta.pmf_cfg.required = false;
        if ((r = step(esp_wifi_set_mode(WIFI_MODE_STA), "esp_wifi_set_mode")) != HAL_OK) return r;
        if ((r = step(esp_wifi_set_config(WIFI_IF_STA, &sc), "esp_wifi_set_config")) != HAL_OK) return r;
    }
    portENTER_CRITICAL(&g_backoff_mux);
    hal_udp_wifi_backoff_reset(&g_backoff);
    portEXIT_CRITICAL(&g_backoff_mux);
    g_wifi_attempts.store(0, std::memory_order_relaxed);
    g_wifi_last_reason.store(0, std::memory_order_relaxed);
    xEventGroupClearBits(g_wifi_eg, kGotIp);
    if ((r = step(esp_wifi_start(), "esp_wifi_start")) != HAL_OK) return r;
    (void)step(esp_wifi_set_ps(WIFI_PS_NONE), "esp_wifi_set_ps");
    g_wifi_started.store(true);

    TickType_t wait = pdMS_TO_TICKS(timeout_ms);
    if (timeout_ms > 0 && wait == 0) wait = 1;
    const EventBits_t bits = xEventGroupWaitBits(g_wifi_eg, kGotIp, pdFALSE, pdFALSE, wait);
    if ((bits & kGotIp) != 0) {
        const uint32_t ip = g_wifi_ip.load(std::memory_order_relaxed);
        if (ip4_out != nullptr) *ip4_out = ip;
        ESP_LOGI(TAG, "BRWIFI sta up ip=%u.%u.%u.%u", static_cast<unsigned>(ip >> 24),
                 static_cast<unsigned>((ip >> 16) & 0xFFu), static_cast<unsigned>((ip >> 8) & 0xFFu),
                 static_cast<unsigned>(ip & 0xFFu));
        return HAL_OK;
    }
    ESP_LOGW(TAG, "BRWIFI sta no IP within %u ms (attempts=%u last reason=%u): reconnecting with backoff",
             static_cast<unsigned>(timeout_ms), static_cast<unsigned>(g_wifi_attempts.load()),
             static_cast<unsigned>(g_wifi_last_reason.load()));
    return HAL_ERR_TIMEOUT;
}

extern "C" hal_result_t hal_udp_wifi_sta_retry_info(uint32_t *attempts_out, uint16_t *last_reason_out)
{
    if (attempts_out != nullptr) *attempts_out = 0;
    if (last_reason_out != nullptr) *last_reason_out = 0;
    if (!g_wifi_started.load()) {
        return HAL_ERR_NOT_FOUND;
    }
    if (attempts_out != nullptr) *attempts_out = g_wifi_attempts.load(std::memory_order_relaxed);
    if (last_reason_out != nullptr) *last_reason_out = g_wifi_last_reason.load(std::memory_order_relaxed);
    return HAL_OK;
}

extern "C" hal_result_t hal_udp_wifi_sta_info(uint32_t *ip4_out, uint8_t *ap_ch_out)
{
    if (ip4_out != nullptr) *ip4_out = 0;
    if (ap_ch_out != nullptr) *ap_ch_out = 0;
    if (!g_wifi_started.load()) {
        return HAL_ERR_NOT_FOUND;
    }
    const uint32_t ip = g_wifi_ip.load(std::memory_order_relaxed);
    if (ip == 0) {
        return HAL_ERR_TIMEOUT;  // not associated (or DHCP not done): the channel is the scan's, not the AP's
    }
    uint8_t primary = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    const esp_err_t e = esp_wifi_get_channel(&primary, &second);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_get_channel failed: %s", esp_err_to_name(e));
        return port::map_err(e);
    }
    if (primary < 1 || primary > 14) {
        return HAL_ERR_TIMEOUT;
    }
    if (ip4_out != nullptr) *ip4_out = ip;
    if (ap_ch_out != nullptr) *ap_ch_out = primary;
    return HAL_OK;
}
