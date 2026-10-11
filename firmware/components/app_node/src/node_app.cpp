// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// node_app.cpp - phase 1c Braid 3-board demo (see node_app.h).
//
// Task layout (ESP32 / ESP32-S3, dual core; Wi-Fi task is on core 0):
//   "br"     core 1, prio 5, 8192 B  the only task that touches br_node_t:
//                                    drains the event queue (radio RX, radio
//                                    TX status, UART chunks, UDP datagrams,
//                                    nRF24 IRQs, button presses, stats
//                                    requests), runs the nRF24 pump and
//                                    br_node_tick(), the role logic and the
//                                    BRSTAT line. Waits with the timeout of
//                                    the earliest deadline (core, nRF24 pump,
//                                    capped at 1 s for the watchdog), never
//                                    polls. Subscribed to the task watchdog.
//   "led"    core 1, prio 3, 3072 B  probe only: 5 x (200 ms on, 200 ms off)
//                                    per notification from "br".
//   "btn"    core 1, prio 4, 3072 B  sender only: 10 ms polled button,
//                                    30 ms debounce (3 equal reads).
//   "con"    core 0, prio 2, 6144 B  serial console (UART0, line based).
//   "ulrx<n>" core 0, prio 6, 3072 B UART link receive task (port_uart_link,
//                                    only with uart=on): copies byte chunks
//                                    into the event queue with timeout 0.
//   "udprx"  core 0, prio 6, 3072 B  UDP link receive task (only with udp=on,
//                                    UDP-LINK.txt option 2): blocks in
//                                    hal_udp_recvfrom() next to the lwIP
//                                    tasks and copies each datagram plus its
//                                    ip:port into the event queue, timeout 0.
//   Wi-Fi task (core 0, ESP-IDF):    radio callbacks copy into the event
//                                    queue with timeout 0 and return.
//   lwIP tcpip thread (ESP-IDF):     SNTP sync callback (port_sntp.cpp) only
//                                    bumps an atomic counter; "br" polls it
//                                    and logs BRNTP.
//   nRF24 IRQ (ISR, only with nirq set): posts one kEvtNrfIrq event with
//                                    xQueueSendFromISR; "br" runs the pump.
//
// Transports (br_node_config_t.transports, registered in this order; each
// present link takes the next index, see g_link_*):
//   "espnow"  PACKET, present unless `br set espnow=off` (a LAN-side UDP
//             board, spec 12.4).
//   "uart"    RAW (uart_link.h), present with `br set uart=on`:
//             UART2 on ESP32 (GPIO17 TX / GPIO16 RX by default),
//             UART1 on ESP32-S3 (GPIO17 TX / GPIO18 RX by default):
//             the IO_MUX pins of spec C.6. COBS reassembly runs in
//             "br" (uart_link_feed), RS in the core (N42).
//   "udp"     PACKET (udp_link.h, spec C.4), present with `br set udp=on`:
//             WiFi station (ssid= / pass=), lwIP UDP socket on port=,
//             floods by multicast 239.255.40.88 or the peers= list. Never
//             together with ESP-NOW on one chip (the console refuses it).
//   "nrf24"   PACKET (nrf24_link.h, spec C.5), present with `br set nrf=on`
//             and a module answering on the SPI pins: 32-byte ESB payloads
//             with link-local segmentation, driven by the pump from "br".
//   The bench allowlist (`nbr`) is applied to every transport by unit ID.
//
// WiFi station (`br set wifi=on`, or udp=on which rides on it): STA to the
// AP of ssid= / pass=, WIFI_PS_NONE, SNTP from ntp=. Never with ESP-NOW on
// one chip (association moves the channel ESP-NOW is pinned to, 12.4); fine
// with the nRF24 link: wifi=on + nrf=on + espnow=off is the single-chip
// nRF24 gateway (firmware/GATEWAY-NRF24.txt). "br" polls the station state:
// BRWIFI when it comes up or the AP channel changes, then the BRNRF
// coexistence check of the AP channel against nch (log only, never a
// retune: every other mesh node would have to follow).
//
// Event queue: one static FreeRTOS queue of kQueueDepth items. Radio RX
// frames, UART byte chunks and UDP datagrams together may occupy at most
// BR_RX_QUEUE_FRAMES (16) slots (section 7); a radio frame arriving when 16
// are queued is dropped and counted, and "br" folds the count into
// br_node_count_rx_queue_drop() (the core is single-task); a dropped UART
// chunk is counted (u_qdrop) and makes the adapter resynchronise on the next
// 0x00 (the frame in flight is lost, ARQ recovers it); a dropped datagram is
// counted (ud_qdrop). The remaining slots keep room for TX-status, nRF24 IRQ
// and app events.

#include <atomic>
#include <cinttypes>
#include <cstring>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "hal_gpio.h"
#include "hal_kv.h"
#include "hal_nrf24.h"
#include "hal_radio.h"
#include "hal_result.h"
#include "hal_sys.h"
#include "hal_time.h"
#include "hal_uart.h"
#include "hal_uart_link.h"
#include "hal_udp.h"

#include "braid/br_node.h"
#include "braid/br_sample.h"
#include "braid/br_session.h"
#include "braid/br_tables.h"

#include "node_app.h"
#include "node_console.h"
#include "nrf24_link.h"
#include "nrf24_link_hal.h"
#include "espnow_link.h"
#include "radio_arb.h"
#include "radio_arb_hal.h"
#include "uart_link.h"
#include "udp_link.h"

namespace {

constexpr char TAG[] = "node";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#if CONFIG_IDF_TARGET_ESP32S3
constexpr node_chip_t kChip = NODE_CHIP_ESP32S3;
#else
constexpr node_chip_t kChip = NODE_CHIP_ESP32;
#endif

constexpr BaseType_t kCoreNet = 0;  // PRO_CPU: Wi-Fi, lwIP, console, link receive tasks
constexpr BaseType_t kCoreApp = 1;  // APP_CPU: br_task and the role helpers

constexpr UBaseType_t kPrioUdpRx = tskIDLE_PRIORITY + 6;
constexpr UBaseType_t kPrioBr  = tskIDLE_PRIORITY + 5;
constexpr UBaseType_t kPrioBtn = tskIDLE_PRIORITY + 4;
constexpr UBaseType_t kPrioLed = tskIDLE_PRIORITY + 3;
constexpr UBaseType_t kPrioCon = tskIDLE_PRIORITY + 2;

constexpr uint32_t kStackBr    = 8192;
constexpr uint32_t kStackLed   = 3072;
constexpr uint32_t kStackBtn   = 3072;
constexpr uint32_t kStackCon   = 6144;   // node_cfg_t copies (peers, ssid, pass) + NODE_SHOW_MAX line + ESP_LOG
constexpr uint32_t kStackUdpRx = 3072;

constexpr uint32_t kRxFrames   = BR_RX_QUEUE_FRAMES;  // 16
constexpr uint32_t kUdpRxSlots = kRxFrames / 2;        // UDP's share: any LAN host can send, pre-authentication
constexpr uint32_t kQueueDepth = kRxFrames + 8;

constexpr uint64_t kStatsPeriodUs = 5000000;    // BRSTAT every 5 s
constexpr uint64_t kMaxWaitUs     = 1000000;    // watchdog feed cadence
constexpr uint64_t kBootWindowUs  = 3000000;    // console window before start
constexpr uint64_t kReseekMinUs   = 1000000;    // sender re-SEEK backoff 1 s .. 30 s
constexpr uint64_t kReseekMaxUs   = 30000000;

constexpr uint32_t kLedFlashes = 5;
constexpr uint32_t kLedHalfMs  = 200;
constexpr uint32_t kBtnPollMs  = 10;
constexpr uint8_t  kBtnStable  = 3;              // 3 x 10 ms = 30 ms debounce

constexpr uint32_t kWifiTimeoutMs = 15000;       // hal_udp_wifi_sta_start() wait for an IP
constexpr uint64_t kWifiPollDownUs = 1000000;    // station state poll while not associated
constexpr uint64_t kWifiPollUpUs   = 5000000;    // ... and while associated (AP channel change, loss)
constexpr uint32_t kUdpRxWaitMs   = 1000;        // udprx task recvfrom timeout (lets the task notice shutdown)

constexpr char kNs[] = "br";                     // NVS namespace

// Transport indices are assigned at registration (node_init_from), in the
// order espnow, uart, udp, nrf24, skipping absent links. kNoLink = absent.
constexpr uint8_t kNoLink = 0xFF;

// UART link controller: the one whose IO_MUX pins are the spec C.6 defaults
// (ESP32: UART2 = GPIO17 TX / GPIO16 RX; ESP32-S3: UART1 = GPIO17 TX /
// GPIO18 RX). UART0 is the console. Other pins work through the GPIO matrix.
// STRAPPING: no UART link pin may be a strapping pin (the peer holds our RX
// high through reset; GPIO12 high on ESP32 selects 1.8 V flash). The console
// refuses them (node_uart_pin_ok): ESP32 GPIO0/2/5/12/15, S3 GPIO0/3/45/46.
#if CONFIG_IDF_TARGET_ESP32S3
constexpr uint8_t kUartLinkPort = 1;
#else
constexpr uint8_t kUartLinkPort = 2;
#endif

constexpr uint16_t kCapsBase = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY;

// The console (node_console.h) mirrors a few adapter constants so that it
// stays free of adapter headers (host tests link it alone); keep them equal.
static_assert(NODE_PEERS_MAX == UDP_LINK_MAX_PEERS, "console peer list vs udp_link peer list");
static_assert(NODE_DEFAULT_PORT == UDP_LINK_PORT, "console default port vs udp_link port");
static_assert(NODE_NCH_MIN == NRF24_LINK_CH_MIN && NODE_NCH_MAX == NRF24_LINK_CH_MAX &&
                  NODE_NCH_MAX_2M == NRF24_LINK_CH_MAX_2M,
              "console nRF24 channel range vs nrf24_link");
static_assert(NODE_NRATE_250K == static_cast<int>(HAL_NRF24_RATE_250K) &&
                  NODE_NRATE_1M == static_cast<int>(HAL_NRF24_RATE_1M) &&
                  NODE_NRATE_2M == static_cast<int>(HAL_NRF24_RATE_2M),
              "console nrate values vs hal_nrf24_rate_t");
static_assert(NODE_NPA_MIN == static_cast<int>(HAL_NRF24_PA_MIN) && NODE_NPA_LOW == static_cast<int>(HAL_NRF24_PA_LOW) &&
                  NODE_NPA_HIGH == static_cast<int>(HAL_NRF24_PA_HIGH) &&
                  NODE_NPA_MAX == static_cast<int>(HAL_NRF24_PA_MAX),
              "console npa values vs hal_nrf24_pa_t");
static_assert(UDP_LINK_ADDR_LEN <= BR_ADDR_MAX && NRF24_LINK_ADDR_LEN <= BR_ADDR_MAX, "carrier address fits br_rx_meta_t");
static_assert(NODE_NTP_MAX == HAL_SNTP_SERVER_MAX, "console ntp= length vs hal_sntp_start()");

#ifndef BR_FIELD_BUILD
// Appendix A.6 K_site, TEST ONLY (bytes 0x00..0x1F): the bench profile key
// (spec 12.1). Field builds refuse it (test-key blacklist), so it is compiled
// in only when BR_FIELD_BUILD is not defined.
constexpr uint8_t kBenchKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
#else
#error "BR_FIELD_BUILD: phase 1c has no field keystore; the demo is bench profile only"
#endif

// ---------------------------------------------------------------------------
// Counter persistence policy (spec 3.5, br_node_config_t.persist)
// ---------------------------------------------------------------------------
//
// The core asks to persist a counter BEFORE it uses the first value of a new
// block (txseq blocks of 4096, preseq blocks of 64) and stops transmitting if
// the write fails, so a reboot can never reuse a hop_seq or pre_ctr. That
// already limits flash writes to one per block plus one per boot. On top:
//   - a request that an earlier write already covers is answered without a
//     write;
//   - when the previous write of the same counter is less than 60 s old, the
//     stored value is reserve_to + 3 blocks, so sustained traffic costs one
//     write per 4 blocks (txseq: >= 16384 frames per write);
//   - worst-case jump after a reboot is 4 blocks: 16384 hop_seq values, far
//     below BR_HOP_MAX_JUMP (65536) that neighbours accept, and 256 pre_ctr.
// Values are written synchronously from br_task (a few ms) and committed.
// `br erase` never touches br/txseq or br/preseq.

constexpr uint64_t kPersistBurstUs = 60000000;
constexpr uint32_t kPersistLookaheadBlocks = 3;
constexpr uint32_t kCounterDefault = 1;          // first value on a board with empty NVS

struct PersistState {
    const char *key;
    uint32_t    block;
    uint32_t    stored;
    uint64_t    last_write_us;
    uint32_t    writes;
};

PersistState g_persist[2] = {
    {"txseq", BR_TXSEQ_BLOCK, 0, 0, 0},
    {"preseq", BR_PRESEQ_BLOCK, 0, 0, 0},
};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

enum EvtKind : uint8_t { kEvtRx = 1, kEvtTxStatus, kEvtPress, kEvtStatsReq, kEvtUartRx, kEvtUdpRx, kEvtNrfIrq };

struct Evt {
    uint8_t  kind;
    int8_t   rssi;
    uint8_t  ok;                          // TX status: delivered; UART RX: bytes were lost before this chunk
    uint8_t  addr[HAL_RADIO_ADDR_LEN];    // ESP-NOW: MAC; UDP RX: ip:port (udp_link_addr_pack, 6 bytes)
    uint16_t len;
    uint8_t  data[HAL_RADIO_MAX_FRAME];
};

static_assert(HAL_UART_LINK_RX_CHUNK <= sizeof(Evt::data), "UART chunk must fit one event");
static_assert(UDP_LINK_ADDR_LEN == sizeof(Evt::addr), "UDP ip:port must fit the event address");
static_assert(UDP_LINK_MAX_FRAME <= sizeof(Evt::data), "UDP frame must fit one event");

StaticQueue_t g_q_buf;
uint8_t g_q_storage[kQueueDepth * sizeof(Evt)];
QueueHandle_t g_q = nullptr;

std::atomic<uint32_t> g_rx_qdrop{0};     // radio frames dropped (queue full): folded into the core
std::atomic<uint32_t> g_txst_qdrop{0};   // TX verdicts dropped (queue full)
std::atomic<uint32_t> g_evt_qdrop{0};    // app events dropped (queue full)
std::atomic<uint32_t> g_uart_qdrop{0};   // UART link chunks dropped (queue full)
std::atomic<bool>     g_uart_lost{false}; // bytes lost since the last queued UART chunk
std::atomic<uint32_t> g_udp_qdrop{0};    // UDP datagrams dropped (queue full)
std::atomic<uint32_t> g_udp_oversize{0}; // UDP datagrams > max_frame (dropped in udprx)
std::atomic<uint32_t> g_udp_rxerr{0};    // UDP socket receive errors / empty datagrams
std::atomic<uint32_t> g_nrf_irq_qdrop{0}; // nRF24 IRQ events not queued (queue full; the poll deadline covers it)

// ---------------------------------------------------------------------------
// Configuration (console + boot gate)
// ---------------------------------------------------------------------------

StaticSemaphore_t g_cfg_lock_buf;
SemaphoreHandle_t g_cfg_lock = nullptr;
StaticSemaphore_t g_cfg_changed_buf;
SemaphoreHandle_t g_cfg_changed = nullptr;
node_cfg_t g_cfg;                         // stored configuration (under g_cfg_lock)
node_cfg_t g_run;                         // configuration the role started with (read-only after start)
std::atomic<bool> g_started{false};

void cfg_defaults(node_cfg_t *c) {
    node_cfg_defaults(c);
    node_uart_default_pins(kChip, &c->utx, &c->urx);
    node_nrf_default_pins(kChip, c);
}

// NVS keys (namespace "br", all <= 15 characters):
//   u32:  role uid grp led btn chan uart utx urx ubaud espnow udp port mcast
//         nrf nch nrate npa nsck nmiso nmosi ncsn nce nirq (nirq 0xFF = none)
//         wifi (absent on boards configured before wifi= existed: udp=1 then
//         means wifi=1, node_cfg_legacy_wifi)
//   blob: nbr (2 bytes per unit ID, LE), udp_peers (6 bytes per peer: IPv4
//         then port, big endian), ssid (bytes, no NUL), pass (bytes, no NUL;
//         plaintext until the production overlay enables NVS encryption),
//         ntp (bytes, no NUL; absent = pool.ntp.org). Each blob is validated on
//         load by node_cfg_load_blobs(): a bad optional one falls back to its
//         default, a bad required one (ssid / pass with the station on,
//         udp_peers with udp=on mcast=off) is flagged in nvs_bad (N70)
//   An empty list / string erases its key. txseq / preseq are the counters
//   (persist_cb), never touched by `br erase`.
// Scope guard: node_wipe() on every path out (passphrase copies, N71).
struct WipeGuard {
    void *p;
    size_t n;
    ~WipeGuard() { node_wipe(p, n); }
};

// One blob key into *out (node_console decodes and validates it). A blob
// longer than cap is NODE_KV_UNREADABLE (falls back / refuses per key, N70);
// other store errors fail the whole load as before.
hal_result_t cfg_load_blob(const char *key, uint8_t *buf, size_t cap, node_kv_blob_t *out) {
    size_t len = 0;
    out->state = NODE_KV_ABSENT;
    out->data = buf;
    out->len = 0;
    const hal_result_t r = hal_kv_get_blob(kNs, key, buf, cap, &len);
    if (r == HAL_ERR_NOT_FOUND) return HAL_OK;
    if (r == HAL_ERR_NO_MEM) {
        out->state = NODE_KV_UNREADABLE;
        return HAL_OK;
    }
    if (r != HAL_OK) return r;
    out->state = NODE_KV_PRESENT;
    out->len = len;
    return HAL_OK;
}

hal_result_t cfg_load(node_cfg_t *c) {
    cfg_defaults(c);
    uint32_t v = 0;
    struct U8Key { const char *key; uint8_t *dst; };
    const U8Key u8keys[] = {{"role", &c->role},   {"led", &c->led},     {"btn", &c->btn},     {"chan", &c->chan},
                            {"uart", &c->uart},   {"utx", &c->utx},     {"urx", &c->urx},     {"espnow", &c->espnow},
                            {"udp", &c->udp},     {"mcast", &c->mcast}, {"nrf", &c->nrf},     {"nch", &c->nch},
                            {"nrate", &c->nrate}, {"npa", &c->npa},     {"nsck", &c->nsck},   {"nmiso", &c->nmiso},
                            {"nmosi", &c->nmosi}, {"ncsn", &c->ncsn},   {"nce", &c->nce},     {"nirq", &c->nirq}};
    for (const auto &k : u8keys) {
        const hal_result_t r = hal_kv_get_u32(kNs, k.key, &v);
        if (r == HAL_OK) {
            *k.dst = v <= 0xFFu ? static_cast<uint8_t>(v) : 0xFFu;  // out of range -> rejected by ready()
        } else if (r != HAL_ERR_NOT_FOUND) {
            return r;
        }
    }
    struct U16Key { const char *key; uint16_t *dst; };
    const U16Key u16keys[] = {{"uid", &c->uid}, {"grp", &c->grp}, {"port", &c->port}};
    for (const auto &k : u16keys) {
        const hal_result_t r = hal_kv_get_u32(kNs, k.key, &v);
        if (r == HAL_OK) {
            *k.dst = v <= 0xFFFFu ? static_cast<uint16_t>(v) : 0u;
        } else if (r != HAL_ERR_NOT_FOUND) {
            return r;
        }
    }
    {
        const hal_result_t r = hal_kv_get_u32(kNs, "ubaud", &v);
        if (r == HAL_OK) {
            c->ubaud = v;  // unsupported rate -> rejected by ready()
        } else if (r != HAL_ERR_NOT_FOUND) {
            return r;
        }
    }
    bool wifi_key = false;
    {
        const hal_result_t r = hal_kv_get_u32(kNs, "wifi", &v);
        if (r == HAL_OK) {
            c->wifi = v <= 0xFFu ? static_cast<uint8_t>(v) : 0xFFu;  // out of range -> rejected by ready()
            wifi_key = true;
        } else if (r != HAL_ERR_NOT_FOUND) {
            return r;
        }
    }
    node_cfg_legacy_wifi(c, wifi_key);  // udp=1 stored before wifi= existed -> wifi=1 (before the blobs: ssid
                                        // and pass are required only with the station on)
    // Blob keys: each one decoded and validated on its own by
    // node_cfg_load_blobs(); an invalid optional key falls back to its default
    // and the rest still loads (SPEC-NOTES N70).
    uint8_t b_nbr[NODE_NBR_MAX * 2];
    uint8_t b_peers[NODE_PEERS_MAX * 6];
    uint8_t b_ssid[NODE_SSID_MAX];
    uint8_t b_pass[NODE_PASS_MAX];
    uint8_t b_ntp[NODE_NTP_MAX];
    WipeGuard pass_wipe{b_pass, sizeof b_pass};
    node_cfg_blobs_t bl;
    hal_result_t r = cfg_load_blob("nbr", b_nbr, sizeof b_nbr, &bl.nbr);
    if (r == HAL_OK) r = cfg_load_blob("udp_peers", b_peers, sizeof b_peers, &bl.peers);
    if (r == HAL_OK) r = cfg_load_blob("ssid", b_ssid, sizeof b_ssid, &bl.ssid);
    if (r == HAL_OK) r = cfg_load_blob("pass", b_pass, sizeof b_pass, &bl.pass);
    if (r == HAL_OK) r = cfg_load_blob("ntp", b_ntp, sizeof b_ntp, &bl.ntp);
    if (r != HAL_OK) return r;
    const uint32_t fallback = node_cfg_load_blobs(c, &bl);
    for (uint32_t bit = NODE_F_NBR; bit != 0u && bit <= NODE_F_NTP; bit <<= 1) {
        if ((fallback & bit) != 0u) {
            ESP_LOGW(TAG, "BRCFG %s invalid in NVS, using default", node_cfg_nvs_key(bit));
        }
        if ((c->nvs_bad & bit) != 0u) {
            ESP_LOGE(TAG, "BRCFG %s invalid in NVS and required by this configuration: set it again with br set",
                     node_cfg_nvs_key(bit));
        }
    }
    return HAL_OK;
}

hal_result_t cfg_save_blob(const char *key, const uint8_t *data, size_t len) {
    if (len == 0) return hal_kv_erase_key(kNs, key);
    return hal_kv_set_blob(kNs, key, data, len);
}

hal_result_t cfg_save(const node_cfg_t *c) {
    struct Kv { const char *key; uint32_t val; };
    const Kv kv[] = {{"role", c->role},     {"uid", c->uid},     {"grp", c->grp},     {"led", c->led},
                     {"btn", c->btn},       {"chan", c->chan},   {"uart", c->uart},   {"utx", c->utx},
                     {"urx", c->urx},       {"ubaud", c->ubaud}, {"espnow", c->espnow}, {"udp", c->udp},
                     {"port", c->port},     {"mcast", c->mcast}, {"nrf", c->nrf},     {"nch", c->nch},
                     {"nrate", c->nrate},   {"npa", c->npa},     {"nsck", c->nsck},   {"nmiso", c->nmiso},
                     {"nmosi", c->nmosi},   {"ncsn", c->ncsn},   {"nce", c->nce},     {"nirq", c->nirq},
                     {"wifi", c->wifi}};
    for (const auto &k : kv) {
        const hal_result_t r = hal_kv_set_u32(kNs, k.key, k.val);
        if (r != HAL_OK) return r;
    }
    uint8_t blob[NODE_PEERS_MAX * 6];
    for (uint8_t i = 0; i < c->n_nbr && i < NODE_NBR_MAX; i++) {
        blob[2 * i] = static_cast<uint8_t>(c->nbr[i] & 0xFFu);
        blob[2 * i + 1] = static_cast<uint8_t>(c->nbr[i] >> 8);
    }
    const size_t n_nbr = c->n_nbr < NODE_NBR_MAX ? c->n_nbr : NODE_NBR_MAX;
    hal_result_t r = cfg_save_blob("nbr", blob, n_nbr * 2u);
    if (r != HAL_OK) return r;
    for (uint8_t i = 0; i < c->n_peers && i < NODE_PEERS_MAX; i++) {
        udp_link_addr_pack(c->peers[i].ip, c->peers[i].port, blob + 6 * i);
    }
    // A key flagged in nvs_bad (invalid in NVS, required, not set again yet)
    // keeps its stored value: writing the empty field would erase it, and an
    // erased pass would make the next boot associate with an open AP.
    const size_t n_peers = c->n_peers < NODE_PEERS_MAX ? c->n_peers : NODE_PEERS_MAX;
    if ((c->nvs_bad & NODE_F_PEERS) == 0u) {
        r = cfg_save_blob("udp_peers", blob, n_peers * 6u);
        if (r != HAL_OK) return r;
    }
    if ((c->nvs_bad & NODE_F_SSID) == 0u) {
        r = cfg_save_blob("ssid", reinterpret_cast<const uint8_t *>(c->ssid), strnlen(c->ssid, NODE_SSID_MAX));
        if (r != HAL_OK) return r;
    }
    r = cfg_save_blob("ntp", reinterpret_cast<const uint8_t *>(c->ntp), strnlen(c->ntp, NODE_NTP_MAX));
    if (r != HAL_OK) return r;
    if ((c->nvs_bad & NODE_F_PASS) != 0u) return HAL_OK;
    return cfg_save_blob("pass", reinterpret_cast<const uint8_t *>(c->pass), strnlen(c->pass, NODE_PASS_MAX));
}

hal_result_t cfg_erase() {
    const char *keys[] = {"role", "uid",   "grp",   "nbr",   "led",   "btn",   "chan", "uart",      "utx",
                          "urx",  "ubaud", "espnow", "udp",  "port",  "mcast", "nrf",  "nch",       "nrate",
                          "npa",  "nsck",  "nmiso", "nmosi", "ncsn",  "nce",   "nirq", "udp_peers", "ssid",
                          "pass", "wifi",  "ntp"};
    for (const char *k : keys) {
        const hal_result_t r = hal_kv_erase_key(kNs, k);
        if (r != HAL_OK) return r;
    }
    return HAL_OK;
}

void log_cfg(const char *what, const node_cfg_t *c) {
    char buf[NODE_SHOW_MAX];  // callers: console task (kStackCon sized for it) and the boot path
    node_cfg_format(c, buf, sizeof buf);
    const char *why = nullptr;
    const bool ready = node_cfg_ready(c, kChip, &why);
    ESP_LOGI(TAG, "BRCFG %s %s (%s%s)", what, buf, ready ? "ready" : "incomplete: ", ready ? "" : why);
}

void fmt_mac(node_fmt_t *f, const uint8_t *mac) {
    for (uint32_t i = 0; i < HAL_RADIO_ADDR_LEN; i++) {
        if (i > 0) node_fmt_str(f, ":");
        node_fmt_hex8(f, mac[i]);
    }
}

void fmt_addr5(node_fmt_t *f, const uint8_t *a) {
    for (uint32_t i = 0; i < NRF24_LINK_ADDR_LEN; i++) {
        if (i > 0) node_fmt_str(f, ":");
        node_fmt_hex8(f, a[i]);
    }
}

void fmt_ip(node_fmt_t *f, uint32_t ip, uint16_t port) {
    char buf[24];
    (void)udp_link_format_peer(ip, port, buf, sizeof buf);
    node_fmt_str(f, buf);
}

// ---------------------------------------------------------------------------
// Protocol task state (owned by "br")
// ---------------------------------------------------------------------------

br_node_t g_node;
br_session_t g_sess = BR_SESSION_NONE;    // sender handle
TaskHandle_t g_br_task = nullptr;
TaskHandle_t g_led_task = nullptr;
TaskHandle_t g_btn_task = nullptr;
TaskHandle_t g_con_task = nullptr;
TaskHandle_t g_udprx_task = nullptr;

uint32_t g_delivered = 0;                 // sender: DATA acked; probe: DATA delivered
uint32_t g_presses = 0;
uint32_t g_bench_drop = 0;                // ESP-NOW frames refused by the bench allowlist (N22)
uint32_t g_send_refused = 0;              // transport send() not queued by the radio
uint32_t g_mac_ok = 0;
uint32_t g_mac_fail = 0;
bool     g_reseek_pending = false;
uint64_t g_reseek_at_us = 0;
uint64_t g_reseek_backoff_us = kReseekMinUs;

struct LastVal { uint16_t src; uint8_t val; };
LastVal g_last[4] = {};                   // probe: last digital value per sender (edge detect)

constexpr size_t kLinksLogged = 16;
struct LoggedLink { uint16_t unit; uint8_t transport; };
LoggedLink g_links_logged[kLinksLogged] = {};

// Transport indices (kNoLink when absent). Set in node_init_from() before any
// frame is handled; the g_*_on flags are set in start_role() before "br" runs
// and never change.
uint8_t g_link_espnow = kNoLink;
uint8_t g_link_uart = kNoLink;
uint8_t g_link_udp = kNoLink;
uint8_t g_link_nrf = kNoLink;
bool g_espnow_on = false;

// UART link.
uart_link_t g_ulink;
bool g_uart_on = false;
uint8_t g_uart_tx = 0;
uint8_t g_uart_rx = 0;
uint32_t g_uart_baud = 0;
Evt g_uart_evt;                           // receive-task staging buffer (one link, one producer)

// WiFi station (wifi=on or udp=on). Written by start_role() before "br"
// runs, then only by "br" (wifi_poll); show_running() on "con" reads them,
// hence the atomics for the values that change after start.
bool g_wifi_on = false;                   // station started (HAL_OK or HAL_ERR_TIMEOUT); fixed after start
std::atomic<bool> g_wifi_up{false};       // associated with an IPv4 address at the last poll
std::atomic<uint32_t> g_wifi_ip{0};       // station IPv4 (0 while not associated)
std::atomic<uint8_t> g_wifi_ap_ch{0};     // AP primary channel (0 = unknown)
uint64_t g_wifi_next_poll_us = 0;
bool g_ntp_on = false;                    // SNTP client started
uint32_t g_ntp_logged = 0;                // sync count already logged (BRNTP)

// WiFi UDP link.
udp_link_t g_udp;
bool g_udp_on = false;
std::atomic<bool> g_udp_mcast{false};    // floods by multicast (else by the peer list), as finally opened
uint16_t g_udp_port = 0;
uint8_t g_udp_rxbuf[UDP_LINK_RX_BUF];     // udprx staging: > max_frame so oversize datagrams are seen
Evt g_udp_evt;                            // udprx staging event (one producer)

// nRF24 link.
nrf24_link_t g_nlink;
bool g_nrf_on = false;
hal_nrf24_cfg_t g_nrf_cfg;
uint64_t g_nrf_deadline = BR_NEVER_US;    // when the pump wants to run again
radio_arb_t g_arb;                        // 12.4 bridge arbitration (RADIO-ARB.txt)
espnow_link_t g_elink;                    // ESP-NOW TX deferral around tr_send
uint64_t g_esp_deadline = BR_NEVER_US;    // when the ESP-NOW deferral pump wants to run again
Evt g_nrf_irq_evt;                        // pre-filled kEvtNrfIrq, copied by the ISR

Evt g_evt;                                // receive buffer of "br" (keeps 262 B off its stack)

const char *snd_state_name(uint8_t s) {
    static const char *const names[] = {"IDLE", "SEEKING", "BINDING", "CONFIGURING", "STREAMING", "PARKED", "CLOSED"};
    return s < sizeof names / sizeof names[0] ? names[s] : "?";
}

const char *prb_state_name(uint8_t s) {
    static const char *const names[] = {"LISTENING", "OFFERED", "BOUND", "STREAMING", "PARKED"};
    return s < sizeof names / sizeof names[0] ? names[s] : "?";
}

bool is_sender_handle(br_session_t s) { return (s & BR_SESSION_PROBE) == 0; }

// ---- transport adapter -----------------------------------------------------

br_err_t tr_send(void *, const uint8_t *addr, const uint8_t *frame, uint16_t len) {
    const hal_result_t r = hal_radio_send(addr, frame, len);
    if (r == HAL_OK) return BR_OK;
    g_send_refused++;
    return r == HAL_ERR_BUSY ? BR_ERR_QUEUE_FULL : BR_ERR_BUSY;
}

// Wi-Fi task context: copy and enqueue, timeout 0.
void radio_rx(void *, const uint8_t src[HAL_RADIO_ADDR_LEN], int8_t rssi, const uint8_t *data, size_t len) {
    if (g_q == nullptr || len > HAL_RADIO_MAX_FRAME) return;
    if (uxQueueMessagesWaiting(g_q) >= kRxFrames) {
        g_rx_qdrop.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    Evt e;
    e.kind = kEvtRx;
    e.rssi = rssi;
    e.ok = 0;
    std::memcpy(e.addr, src, HAL_RADIO_ADDR_LEN);
    e.len = static_cast<uint16_t>(len);
    std::memcpy(e.data, data, len);
    if (xQueueSend(g_q, &e, 0) != pdTRUE) g_rx_qdrop.fetch_add(1, std::memory_order_relaxed);
}

// Wi-Fi task context.
void radio_tx(void *, const uint8_t dst[HAL_RADIO_ADDR_LEN], bool delivered) {
    if (g_q == nullptr) return;
    Evt e;
    e.kind = kEvtTxStatus;
    e.rssi = 0;
    e.ok = delivered ? 1 : 0;
    std::memcpy(e.addr, dst, HAL_RADIO_ADDR_LEN);
    e.len = 0;
    if (xQueueSend(g_q, &e, 0) != pdTRUE) g_txst_qdrop.fetch_add(1, std::memory_order_relaxed);
}

// ---- UART link glue ----------------------------------------------------------

// Port receive task context: copy one chunk into the queue, timeout 0.
void uart_rx(void *, const uint8_t *data, size_t len, uint32_t flags) {
    if (g_q == nullptr) return;
    if ((flags & HAL_UART_LINK_RX_LOST) != 0) g_uart_lost.store(true, std::memory_order_relaxed);
    if (data == nullptr || len == 0 || len > sizeof g_uart_evt.data) return;
    if (uxQueueMessagesWaiting(g_q) >= kRxFrames) {
        g_uart_qdrop.fetch_add(1, std::memory_order_relaxed);
        g_uart_lost.store(true, std::memory_order_relaxed);
        return;
    }
    Evt &e = g_uart_evt;
    e.kind = kEvtUartRx;
    e.rssi = 0;
    e.ok = g_uart_lost.exchange(false, std::memory_order_relaxed) ? 1 : 0;
    e.len = static_cast<uint16_t>(len);
    std::memcpy(e.data, data, len);
    if (xQueueSend(g_q, &e, 0) != pdTRUE) {
        g_uart_qdrop.fetch_add(1, std::memory_order_relaxed);
        g_uart_lost.store(true, std::memory_order_relaxed);
    }
}

// uart_link byte pipe ("br" task, and once from start_role before "br" runs).
bool uart_write(void *, const uint8_t *data, size_t len) {
    return hal_uart_link_write(kUartLinkPort, data, len) == HAL_OK;
}

// uart_link frame sink ("br" task, inside uart_link_feed()).
void uart_frame(void *, const uint8_t *frame, size_t len) {
    if (g_link_uart == kNoLink) return;
    (void)uart_link_deliver(&g_ulink, &g_node, g_link_uart, &g_node.cfg.transports[g_link_uart], frame, len, nullptr);
}

// ---- UDP link glue -----------------------------------------------------------

// The adapter's opaque socket storage holds the hal_udp_t (udp_link_hal.c
// documents it; udp_link_t.sock is uint64_t-aligned, hal_udp_t fits).
static_assert(sizeof(hal_udp_t) <= sizeof(udp_link_t::sock), "hal_udp_t fits udp_link_t.sock");
hal_udp_t *udp_sock() { return reinterpret_cast<hal_udp_t *>(g_udp.sock); }

// "udprx" task (core 0): only receives on the socket; "br" sends on it and
// runs udp_link_deliver(). One datagram per event, ip:port in Evt.addr.
void udprx_task(void *) {
    for (;;) {
        size_t len = 0;
        uint32_t ip = 0;
        uint16_t port = 0;
        const hal_result_t r = hal_udp_recvfrom(udp_sock(), g_udp_rxbuf, sizeof g_udp_rxbuf, &len, &ip, &port,
                                                kUdpRxWaitMs);
        if (r == HAL_ERR_TIMEOUT) continue;
        if (r != HAL_OK) {
            g_udp_rxerr.fetch_add(1, std::memory_order_relaxed);
            vTaskDelay(pdMS_TO_TICKS(10));  // a dead socket must not spin at prio 6 on the lwIP core
            continue;
        }
        if (len == 0) {
            g_udp_rxerr.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (len > UDP_LINK_MAX_FRAME) {
            g_udp_oversize.fetch_add(1, std::memory_order_relaxed);  // would be truncated to a valid length otherwise
            continue;
        }
        // Own quota (half of the RX slots): a LAN flood must not starve the
        // other carriers' RX events before the core has authenticated anything.
        if (g_q == nullptr || uxQueueMessagesWaiting(g_q) >= kUdpRxSlots) {
            g_udp_qdrop.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        Evt &e = g_udp_evt;
        e.kind = kEvtUdpRx;
        e.rssi = 0;
        e.ok = 0;
        udp_link_addr_pack(ip, port, e.addr);
        e.len = static_cast<uint16_t>(len);
        std::memcpy(e.data, g_udp_rxbuf, len);
        if (xQueueSend(g_q, &e, 0) != pdTRUE) g_udp_qdrop.fetch_add(1, std::memory_order_relaxed);
    }
}

// ---- nRF24 link glue ---------------------------------------------------------

// ISR context (hal_gpio shared ISR; the port installs the GPIO ISR service
// without ESP_INTR_FLAG_IRAM, so this runs with the flash cache enabled).
// Only a queue post: "br" wakes and runs the pump. A full queue is not an
// error: the pump's own poll deadline covers the missed edge.
void nrf_irq(void *) {
    if (g_q == nullptr) return;
    if (uxQueueMessagesWaitingFromISR(g_q) >= kQueueDepth - 2) {
        g_nrf_irq_qdrop.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(g_q, &g_nrf_irq_evt, &woken) != pdTRUE) {
        g_nrf_irq_qdrop.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    portYIELD_FROM_ISR(woken);
}

// App events from "btn" and "con". The 262-byte item lives in a static
// buffer (not on the small helper stacks), serialised by g_post_lock.
StaticSemaphore_t g_post_lock_buf;
SemaphoreHandle_t g_post_lock = nullptr;
Evt g_post_evt;

void post_app_event(uint8_t kind) {
    if (g_q == nullptr || g_post_lock == nullptr) return;
    if (xSemaphoreTake(g_post_lock, pdMS_TO_TICKS(20)) != pdTRUE) {
        g_evt_qdrop.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    std::memset(&g_post_evt, 0, sizeof g_post_evt);
    g_post_evt.kind = kind;
    if (xQueueSend(g_q, &g_post_evt, 0) != pdTRUE) g_evt_qdrop.fetch_add(1, std::memory_order_relaxed);
    xSemaphoreGive(g_post_lock);
}

// ---- persistence callback (br_task) -----------------------------------------

br_err_t persist_cb(void *, uint8_t which, uint32_t reserve_to) {
    if (which > BR_PERSIST_PRESEQ) return BR_ERR_ARG;
    PersistState &p = g_persist[which];
    if (reserve_to <= p.stored) return BR_OK;  // covered by an earlier look-ahead write
    const uint64_t now = hal_sys_time_us();
    uint32_t extra = 0;
    if (p.last_write_us != 0 && now - p.last_write_us < kPersistBurstUs) {
        extra = kPersistLookaheadBlocks * p.block;
    }
    if (reserve_to > UINT32_MAX - extra) extra = 0;
    const uint32_t value = reserve_to + extra;
    const hal_result_t r = hal_kv_set_u32(kNs, p.key, value);
    if (r != HAL_OK) {
        ESP_LOGE(TAG, "BRNVS write %s=%" PRIu32 " FAILED (%s): transmission stops (no counter reuse)", p.key,
                 value, hal_result_name(r));
        return BR_ERR_STATE;
    }
    p.stored = value;
    p.last_write_us = now;
    p.writes++;
    ESP_LOGI(TAG, "BRNVS %s reserved to %" PRIu32 " (write %" PRIu32 ")", p.key, value, p.writes);
    return BR_OK;
}

// ---- app callbacks (br_task, inside br_node_* calls) ---------------------

void schedule_reseek(const char *why) {
    if (g_run.role != NODE_ROLE_SENDER) return;
    g_reseek_pending = true;
    g_reseek_at_us = hal_sys_time_us() + g_reseek_backoff_us;
    ESP_LOGW(TAG, "BRRESEEK in %" PRIu32 " ms (%s)", static_cast<uint32_t>(g_reseek_backoff_us / 1000), why);
    g_reseek_backoff_us = g_reseek_backoff_us * 2 > kReseekMaxUs ? kReseekMaxUs : g_reseek_backoff_us * 2;
}

void cb_seek_result(void *, br_session_t s, br_err_t result, uint16_t probe_id, uint8_t hops) {
    ESP_LOGI(TAG, "BRSEEK s=%u result=%d probe=0x%04X hops=%u", s, static_cast<int>(result), probe_id, hops);
}

void cb_bound(void *, br_session_t s, uint16_t peer_id) {
    ESP_LOGI(TAG, "BRBOUND s=0x%02X peer=0x%04X", s, peer_id);
}

void cb_mode(void *, br_session_t s, const br_mode_t *mode) {
    ESP_LOGI(TAG, "BRMODE s=0x%02X config_id=%u mode=%s ch=%u arq=%u fec_m=%u keepalive=%u", s, mode->config_id,
             mode->mode == BR_MODE_HIGH ? "HIGH" : (mode->mode == BR_MODE_LOW ? "LOW" : "BULK"), mode->ch_count,
             mode->arq, mode->fec_m, mode->keepalive_ms);
}

LastVal *last_for(uint16_t src) {
    LastVal *freeslot = nullptr;
    for (auto &l : g_last) {
        if (l.src == src) return &l;
        if (l.src == 0 && freeslot == nullptr) freeslot = &l;
    }
    if (freeslot == nullptr) freeslot = &g_last[0];
    freeslot->src = src;
    freeslot->val = 0;
    return freeslot;
}

void cb_samples(void *, const br_samples_meta_t *meta, const br_mode_t *mode, const uint8_t *samples,
                size_t samples_len) {
    g_delivered++;
    size_t sz = 0;
    if (br_sample_size(mode, &sz) != BR_OK || sz == 0) return;
    LastVal *lv = last_for(meta->src_id);
    for (uint8_t i = 0; i < meta->hdr.n_samples; i++) {
        const size_t off = static_cast<size_t>(i) * sz;
        if (off + sz > samples_len) break;
        br_value_t vals[BR_MAX_CHANNELS];
        if (br_sample_decode(mode, samples + off, sz, vals) != BR_OK) {
            ESP_LOGW(TAG, "BRRX src=0x%04X seq=%u undecodable sample", meta->src_id, meta->seq);
            continue;
        }
        const uint8_t v = static_cast<uint8_t>(vals[0].lines & 1u);
        ESP_LOGI(TAG, "BRRX src=0x%04X hops=%u seq=%u value=%u", meta->src_id, meta->hops, meta->seq, v);
        if (lv->val == 0 && v == 1) {
            ESP_LOGI(TAG, "BREDGE src=0x%04X hops=%u 0->1: LED x%" PRIu32, meta->src_id, meta->hops, kLedFlashes);
            if (g_led_task != nullptr) xTaskNotifyGive(g_led_task);
        }
        lv->val = v;
    }
}

void cb_gap(void *, br_session_t s, uint16_t first_seq, uint16_t count) {
    ESP_LOGW(TAG, "BRGAP s=0x%02X first_seq=%u count=%u", s, first_seq, count);
    if (!is_sender_handle(s)) {
        // Values were lost: forget the last value so the next 1 counts as an edge.
        for (auto &l : g_last) l.val = 0;
    }
}

void cb_acked(void *, br_session_t s, uint16_t seq) {
    g_delivered++;
    ESP_LOGI(TAG, "BRACK s=%u seq=%u acked=%" PRIu32, s, seq, g_delivered);
}

void cb_closed(void *, br_session_t s, uint8_t reason) {
    ESP_LOGW(TAG, "BRCLOSED s=0x%02X reason=%u", s, reason);
    if (is_sender_handle(s)) schedule_reseek("session closed");
}

void cb_state(void *, br_session_t s, uint8_t old_state, uint8_t new_state) {
    if (is_sender_handle(s)) {
        ESP_LOGI(TAG, "BRSTATE sender %s -> %s", snd_state_name(old_state), snd_state_name(new_state));
        if (new_state == BR_SND_STREAMING) {
            g_reseek_backoff_us = kReseekMinUs;
            g_reseek_pending = false;
            ESP_LOGI(TAG, "BRREADY streaming to group 0x%04X: press BOOT (GPIO%u)", g_run.grp, g_run.btn);
        }
    } else {
        ESP_LOGI(TAG, "BRSTATE probe rec=%u %s -> %s", s & 0x7Fu, prb_state_name(old_state),
                 prb_state_name(new_state));
    }
}

void cb_event(void *, uint16_t event, uint32_t arg) {
    switch (event) {
        case BR_EVT_NO_PROBE:
            ESP_LOGW(TAG, "BREVT no probe answered for 0x%04" PRIX32 " yet (still seeking)", arg);
            break;
        case BR_EVT_ID_COLLISION:
            ESP_LOGE(TAG, "BREVT ID collision: unit 0x%04" PRIX32 " (two boards with the same id?)", arg);
            break;
        case BR_EVT_LINK_FAIL:
            ESP_LOGW(TAG, "BREVT link to 0x%04" PRIX32 " deleted after repeated MAC failures", arg & 0xFFFFu);
            break;
        default:
            ESP_LOGW(TAG, "BREVT %u arg=0x%" PRIX32, event, arg);
            break;
    }
}

// ---- role actions (br_task, outside callbacks) ---------------------------

void sender_start() {
    br_session_t s = BR_SESSION_NONE;
    br_err_t rc = br_node_seek(&g_node, g_run.grp, &s);
    if (rc != BR_OK) {
        ESP_LOGE(TAG, "BRSEEK start failed rc=%d", static_cast<int>(rc));
        schedule_reseek("seek refused");
        return;
    }
    g_sess = s;
    // Demo MODE (same as the simulator's sc_mode): HIGH resolution, one
    // digital channel of 1 line, ARQ on, no group FEC, keepalive 5 s.
    br_mode_t m;
    std::memset(&m, 0, sizeof m);
    m.config_id = 1;
    m.mode = BR_MODE_HIGH;
    m.ch_count = 1;
    m.period = 1;
    m.flags = BR_MODE_FLAG_PERIOD_MS;
    m.fec_k = 8;
    m.fec_m = 0;
    m.arq = 1;
    m.keepalive_ms = BR_KEEPALIVE_DEFAULT_MS;
    m.ch[0].kind = BR_CH_KIND_DIGITAL;
    m.ch[0].fmt = 1;
    rc = br_node_set_mode(&g_node, g_sess, &m);
    if (rc != BR_OK) ESP_LOGE(TAG, "BRMODE set failed rc=%d", static_cast<int>(rc));
    ESP_LOGI(TAG, "BRSEEKING group 0x%04X (s=%u)", g_run.grp, g_sess);
}

void sender_press() {
    g_presses++;
    uint8_t st = BR_SND_IDLE;
    if (g_sess == BR_SESSION_NONE || br_node_session_state(&g_node, g_sess, &st) != BR_OK ||
        st != BR_SND_STREAMING) {
        ESP_LOGW(TAG, "BRPRESS n=%" PRIu32 " ignored: session %s", g_presses,
                 g_sess == BR_SESSION_NONE ? "none" : snd_state_name(st));
        return;
    }
    // Each press sends value 1 then value 0 (two DATA frames, both ACK_REQ),
    // so the probe sees a 0->1 edge per press even if a release is missed.
    const uint32_t t_us = static_cast<uint32_t>(hal_sys_time_us());
    br_err_t rc[2];
    for (uint32_t v = 1, i = 0; i < 2; i++, v = 0) {
        br_value_t val;
        val.lines = v;
        rc[i] = br_node_send_sample(&g_node, g_sess, &val, 1, t_us, 0, true);
    }
    ESP_LOGI(TAG, "BRPRESS n=%" PRIu32 " sent value 1 rc=%d, value 0 rc=%d", g_presses, static_cast<int>(rc[0]),
             static_cast<int>(rc[1]));
}

void sender_after_tick(uint64_t now) {
    if (!g_reseek_pending || now < g_reseek_at_us) return;
    g_reseek_pending = false;
    uint8_t st = BR_SND_IDLE;
    if (g_sess != BR_SESSION_NONE && br_node_session_state(&g_node, g_sess, &st) == BR_OK &&
        st != BR_SND_IDLE && st != BR_SND_CLOSED) {
        return;  // the core is already seeking / bound (4.1.8, 4.2 re-SEEK)
    }
    sender_start();
}

void log_new_links() {
    const br_tables_t *t = nullptr;
    if (br_node_get_tables(&g_node, &t) != BR_OK || t == nullptr) return;
    for (const auto &e : t->link.e) {
        if (e.transport == BR_NO_TRANSPORT || e.unit_id == 0) continue;
        bool known = false;
        size_t free_i = kLinksLogged;
        for (size_t i = 0; i < kLinksLogged; i++) {
            if (g_links_logged[i].unit == e.unit_id && g_links_logged[i].transport == e.transport) known = true;
            if (g_links_logged[i].unit == 0 && free_i == kLinksLogged) free_i = i;
        }
        if (known) continue;
        if (free_i < kLinksLogged) g_links_logged[free_i] = {e.unit_id, e.transport};
        char buf[24];
        node_fmt_t f;
        node_fmt_init(&f, buf, sizeof buf);
        if (e.transport == g_link_uart) {
            ESP_LOGI(TAG, "BRLINK neighbour 0x%04X via=uart%u (wire, no mac, cost %u)", e.unit_id, kUartLinkPort,
                     static_cast<unsigned>(UART_LINK_COST));
        } else if (e.transport == g_link_udp) {
            uint32_t ip = 0;
            uint16_t port = 0;
            udp_link_addr_unpack(e.addr, &ip, &port);
            fmt_ip(&f, ip, port);
            ESP_LOGI(TAG, "BRLINK neighbour 0x%04X via=udp %s (lan, cost %u)", e.unit_id, buf,
                     static_cast<unsigned>(UDP_LINK_COST));
        } else if (e.transport == g_link_nrf) {
            fmt_addr5(&f, e.addr);
            ESP_LOGI(TAG, "BRLINK neighbour 0x%04X via=nrf24 %s (esb, cost %u)", e.unit_id, buf,
                     static_cast<unsigned>(NRF24_LINK_COST));
        } else {
            fmt_mac(&f, e.addr);
            ESP_LOGI(TAG, "BRLINK neighbour 0x%04X mac=%s rssi=%d", e.unit_id, buf, e.rssi_ewma);
        }
    }
}

void handle_event(const Evt &e) {
    switch (e.kind) {
        case kEvtRx: {
            if (g_link_espnow == kNoLink) break;
            const br_transport_t *tr = &g_node.cfg.transports[g_link_espnow];
            if (!br_transport_admit(tr, e.data, e.len)) {  // bench allowlist (N22), before the core
                g_bench_drop++;
                return;
            }
            br_rx_meta_t m;
            std::memcpy(m.addr, e.addr, HAL_RADIO_ADDR_LEN);
            m.addr_len = HAL_RADIO_ADDR_LEN;
            m.rssi = e.rssi;
            (void)br_node_rx(&g_node, e.data, e.len, g_link_espnow, &m, nullptr);
            break;
        }
        case kEvtUartRx:
            if (!g_uart_on) break;
            if (e.ok != 0) uart_link_rx_lost(&g_ulink);
            uart_link_feed(&g_ulink, e.data, e.len);  // complete frames -> uart_frame() -> br_node_rx()
            break;
        case kEvtUdpRx: {
            if (!g_udp_on || g_link_udp == kNoLink) break;
            uint32_t ip = 0;
            uint16_t port = 0;
            udp_link_addr_unpack(e.addr, &ip, &port);
            // oversize check, bench allowlist (N22), then br_node_rx() with the ip:port hint
            (void)udp_link_deliver(&g_udp, &g_node, g_link_udp, &g_node.cfg.transports[g_link_udp], e.data, e.len,
                                   ip, port, nullptr);
            break;
        }
        case kEvtNrfIrq:
            break;  // the pump runs after the queue is drained
        case kEvtTxStatus:
            if (g_link_espnow == kNoLink) break;
            if (e.ok != 0) {
                g_mac_ok++;
            } else {
                g_mac_fail++;
            }
            (void)br_node_tx_status(&g_node, g_link_espnow, e.addr, HAL_RADIO_ADDR_LEN, e.ok != 0);
            break;
        case kEvtPress:
            if (g_run.role == NODE_ROLE_SENDER) sender_press();
            break;
        default:
            break;  // kEvtStatsReq: handled by the caller
    }
}

// ---- BRSTAT ------------------------------------------------------------------

const char *session_summary() {
    uint8_t st = 0;
    switch (g_run.role) {
        case NODE_ROLE_SENDER:
            if (g_sess == BR_SESSION_NONE || br_node_session_state(&g_node, g_sess, &st) != BR_OK) return "none";
            return snd_state_name(st);
        case NODE_ROLE_PROBE: {
            uint8_t best = BR_PRB_LISTENING;
            for (uint8_t i = 0; i < BR_RX_RECORDS; i++) {
                if (br_node_session_state(&g_node, static_cast<br_session_t>(BR_SESSION_PROBE | i), &st) == BR_OK &&
                    st > best && st != BR_PRB_PARKED) {
                    best = st;
                }
            }
            return prb_state_name(best);
        }
        default:
            return "-";
    }
}

void print_stats() {
    br_stats_t s;
    if (br_node_get_stats(&g_node, &s) != BR_OK) return;
    const br_tables_t *t = nullptr;
    uint32_t routes = 0;
    if (br_node_get_tables(&g_node, &t) == BR_OK && t != nullptr) {
        const uint32_t now_ms = br_ms_from_us(hal_sys_time_us());
        for (const auto &r : t->route.e) {
            if (r.dst_id != 0 && br_ms_before(now_ms, r.expiry_ms)) routes++;
        }
    }
    const uint32_t hwm = static_cast<uint32_t>(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t));
    hal_radio_stats_t rs = {};
    if (g_espnow_on) (void)hal_radio_get_stats(&rs);
    uart_link_stats_t us = {};
    hal_uart_link_stats_t uh = {};
    if (g_uart_on) {
        uart_link_get_stats(&g_ulink, &us);
        (void)hal_uart_link_get_stats(kUartLinkPort, &uh);
    }
    udp_link_stats_t ds = {};
    if (g_udp_on) udp_link_get_stats(&g_udp, &ds);
    nrf24_link_stats_t ns = {};
    nrf24_seg_stats_t ss = {};
    hal_nrf24_stats_t nh = {};
    if (g_nrf_on) {
        nrf24_link_get_stats(&g_nlink, &ns);
        nrf24_link_get_seg_stats(&g_nlink, &ss);
        (void)hal_nrf24_get_stats(&nh);
    }

    static char buf[1100];  // every carrier on with every drop name non-zero stays under this
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    node_fmt_str(&f, "BRSTAT role=");
    node_fmt_str(&f, node_role_name(g_run.role));
    node_fmt_str(&f, " uid=");
    node_fmt_hex16(&f, g_run.uid);
    node_fmt_str(&f, " sess=");
    node_fmt_str(&f, session_summary());
    node_fmt_str(&f, " relay_fwd=");
    node_fmt_u32(&f, s.f.relay_fwd);
    node_fmt_str(&f, " delivered=");
    node_fmt_u32(&f, g_delivered);
    node_fmt_str(&f, " retx=");
    node_fmt_u32(&f, s.f.arq_retx);
    node_fmt_str(&f, " auth_fail=");
    node_fmt_u32(&f, s.f.auth_fail);
    node_fmt_str(&f, " tx=");
    node_fmt_u32(&f, s.f.tx_frames);
    node_fmt_str(&f, " rx=");
    node_fmt_u32(&f, s.f.rx_frames);
    node_fmt_str(&f, " routes=");
    node_fmt_u32(&f, routes);
    if (g_uart_on) {
        node_fmt_str(&f, " uart_tx=");
        node_fmt_u32(&f, us.tx_frames);
        node_fmt_str(&f, " uart_rx=");
        node_fmt_u32(&f, us.rx_frames);
        node_fmt_str(&f, " rs_fixed=");
        node_fmt_u32(&f, s.f.rs_corrected);
    }
    if (g_udp_on) {
        node_fmt_str(&f, " udp_tx=");
        node_fmt_u32(&f, ds.tx_datagrams);
        node_fmt_str(&f, " udp_rx=");
        node_fmt_u32(&f, ds.rx_datagrams);
    }
    if (g_nrf_on) {
        node_fmt_str(&f, " nrf_tx=");
        node_fmt_u32(&f, ns.tx_frames);
        node_fmt_str(&f, " nrf_rx=");
        node_fmt_u32(&f, ns.rx_frames);
        node_fmt_str(&f, " nrf_seg=");
        node_fmt_u32(&f, ss.seg_tx);
        node_fmt_str(&f, "/");
        node_fmt_u32(&f, ss.seg_rx);
        node_fmt_str(&f, " nrf_maxrt=");
        node_fmt_u32(&f, ns.tx_max_rt);
    }
    if (g_nrf_on && g_espnow_on) {
        radio_arb_stats_t as = {};
        espnow_link_stats_t es = {};
        radio_arb_get_stats(&g_arb, &as);
        espnow_link_get_stats(&g_elink, &es);
        node_fmt_str(&f, " arb_hold_e=");  node_fmt_u32(&f, as.hold_espnow);
        node_fmt_str(&f, " arb_hold_n=");  node_fmt_u32(&f, as.hold_nrf);
        node_fmt_str(&f, " arb_to=");      node_fmt_u32(&f, as.timeout);
        node_fmt_str(&f, " arb_defer=");   node_fmt_u32(&f, es.deferred);
        node_fmt_str(&f, " arb_qfull=");   node_fmt_u32(&f, es.qfull);
        node_fmt_str(&f, " arb_derr=");    node_fmt_u32(&f, es.drain_err);
    }
    if (g_wifi_on) {
        node_fmt_str(&f, " ap_ch=");
        node_fmt_u32(&f, g_wifi_ap_ch.load());  // 0 = not associated
        node_fmt_str(&f, " ntp=");
        node_fmt_u32(&f, g_ntp_on ? hal_sntp_sync_count() : 0u);  // syncs so far
        uint32_t retries = 0;
        uint16_t reason = 0;
        (void)hal_udp_wifi_sta_retry_info(&retries, &reason);
        node_fmt_str(&f, " wifi_retry=");
        node_fmt_u32(&f, retries);  // consecutive failed attempts (0 while up), N69
        if (retries > 0u) {
            node_fmt_str(&f, " wifi_reason=");
            node_fmt_u32(&f, reason);
        }
    }
    node_fmt_str(&f, " hwm=");
    node_fmt_u32(&f, hwm);
    node_fmt_str(&f, " heap=");
    node_fmt_u32(&f, hal_sys_free_heap());
    node_fmt_str(&f, " drops=");
    struct Named { const char *name; uint32_t v; };
    const Named drops[] = {
        {"crc", s.f.crc_fail},
        {"rs_fail", s.f.rs_fail},
        {"seg_fail", s.f.seg_fail},
        {"bad_frame", s.f.bad_frame},
        {"bad_version", s.f.bad_version},
        {"hop_tag", s.f.hop_tag_fail},
        {"hop_replay", s.f.hop_replay},
        {"replay", s.f.replay_dropped},
        {"gaps", s.f.gaps},
        {"rx_queue", s.f.rx_queue_drop},
        {"ttl", s.f.relay_drop_ttl},
        {"dedup", s.f.relay_drop_dedup},
        {"stale", s.f.relay_drop_stale},
        {"noroute", s.f.relay_drop_noroute},
        {"mtu", s.f.relay_drop_mtu},
        {"rate", s.f.relay_drop_rate},
        {"q_data", s.f.relay_drop_queue_data},
        {"q_ctrl", s.f.relay_drop_queue_ctrl},
        {"loop", s.f.relay_drop_loop},
        {"link_fail", s.f.link_fail_drops},
        {"unknown_session", s.f.unknown_session},
        {"flood_pending", s.f.flood_pending_full},
        {"id_collision", s.f.id_collisions},
        {"allowlist", g_bench_drop + us.allowlist_drop + ds.allowlist_drop + ns.rx_admit_drop},
        {"send_refused", g_send_refused},
        {"mac_fail", g_mac_fail},
        {"txstatus_q", g_txst_qdrop.load(std::memory_order_relaxed)},
        {"evt_q", g_evt_qdrop.load(std::memory_order_relaxed)},
        {"rx_oversize", rs.rx_oversize},
        {"peer_evict", rs.peer_evictions},
        // UART link (u_*)
        {"u_cobs", us.cobs_err},
        {"u_oversize", us.oversize},
        {"u_resync", us.resyncs},
        {"u_lost", us.rx_lost},
        {"u_qdrop", g_uart_qdrop.load(std::memory_order_relaxed)},
        {"u_txfull", us.tx_refused},
        {"u_framing", uh.frame_err},
        {"u_break", uh.breaks},
        // WiFi UDP link (ud_*; u_* belongs to the UART link)
        {"ud_oversize", ds.oversize + g_udp_oversize.load(std::memory_order_relaxed)},
        {"ud_refused", ds.tx_refused},
        {"ud_partial", ds.tx_partial},
        {"ud_badlen", ds.tx_bad_len},
        {"ud_unknown", ds.unknown_next_hop},
        {"ud_rxerr", ds.rx_err + g_udp_rxerr.load(std::memory_order_relaxed)},
        {"ud_qdrop", g_udp_qdrop.load(std::memory_order_relaxed)},
        // nRF24 link (n_*): adapter, reassembly, HAL
        {"n_maxrt", ns.tx_max_rt},
        {"n_stuck", ns.tx_stuck},
        {"n_txfull", ns.tx_refused},
        {"n_badlen", ns.tx_bad_len},
        {"n_radio", ns.tx_radio_err + ns.rx_radio_err},
        {"n_badpipe", ns.rx_bad_pipe},
        {"n_srcmis", ns.rx_src_mismatch},
        {"n_drop", ss.frames_dropped},
        {"n_timeout", ss.timeouts},
        {"n_gap", ss.gaps},
        {"n_orphan", ss.orphans},
        {"n_foreign", ss.foreign_tag},
        {"n_dup", ss.dups},
        {"n_malformed", ss.malformed},
        {"n_oversize", ss.oversize},
        {"n_full", ss.buffer_full},
        {"n_spi", nh.spi_err},
        {"n_badwidth", nh.rx_bad_width},
        {"n_irqq", g_nrf_irq_qdrop.load(std::memory_order_relaxed)},
    };
    bool any = false;
    for (const auto &d : drops) {
        if (d.v == 0) continue;
        if (any) node_fmt_str(&f, ",");
        node_fmt_str(&f, d.name);
        node_fmt_str(&f, ":");
        node_fmt_u32(&f, d.v);
        any = true;
    }
    if (!any) node_fmt_str(&f, "none");
    ESP_LOGI(TAG, "%s", buf);
}

// ---- WiFi station and SNTP ("br", and once from start_role before "br") ----

void fmt_ip4(node_fmt_t *f, uint32_t ip) {
    for (int sh = 24; sh >= 0; sh -= 8) {
        node_fmt_u32(f, (ip >> static_cast<unsigned>(sh)) & 0xFFu);
        if (sh > 0) node_fmt_str(f, ".");
    }
}

// AP channel vs nRF24 channel (GATEWAY-NRF24.txt). Log only: retuning the
// nRF24 here would cut this board off from every other mesh node.
void log_coexist() {
    if (!g_nrf_on || g_wifi_ap_ch == 0) return;
    char buf[160];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    if (node_fmt_coexist(&f, g_wifi_ap_ch.load(), g_run.nch, g_run.nrate)) {
        ESP_LOGW(TAG, "%s", buf);
    } else {
        ESP_LOGI(TAG, "%s", buf);
    }
}

// Station state poll: BRWIFI when the station comes up, when the AP channel
// changes (router auto-channel, roaming to another AP of the same ssid) and
// when it goes down; the coexistence check follows every new channel.
void wifi_poll(uint64_t now) {
    if (!g_wifi_on || now < g_wifi_next_poll_us) return;
    uint32_t ip = 0;
    uint8_t ch = 0;
    const hal_result_t r = hal_udp_wifi_sta_info(&ip, &ch);
    const bool up = r == HAL_OK;
    g_wifi_next_poll_us = now + (up ? kWifiPollUpUs : kWifiPollDownUs);
    if (up && (!g_wifi_up.load() || ch != g_wifi_ap_ch.load() || ip != g_wifi_ip.load())) {
        const uint8_t old_ch = g_wifi_ap_ch.load();
        g_wifi_up.store(true);
        g_wifi_ip.store(ip);
        g_wifi_ap_ch.store(ch);
        char buf[20];
        node_fmt_t f;
        node_fmt_init(&f, buf, sizeof buf);
        fmt_ip4(&f, ip);
        char ssid[NODE_SSID_MAX + 1];
        node_fmt_init(&f, ssid, sizeof ssid);
        node_fmt_ssid(&f, g_run.ssid);
        ESP_LOGI(TAG, "BRWIFI sta up ip=%s ssid=%s ap_ch=%u", buf, ssid, ch);
        if (ch != old_ch) log_coexist();
    } else if (!up && g_wifi_up.load()) {
        g_wifi_up.store(false);
        g_wifi_ip.store(0);
        // The port logs "BRWIFI sta down (reason=N) retry in Xs" once per
        // attempt and reconnects on its own timer (N69); this line only
        // marks the loss of the address as seen by the app.
        ESP_LOGW(TAG, "BRWIFI sta lost its address (%s, last ap_ch=%u): port reconnects with backoff",
                 hal_result_name(r), g_wifi_ap_ch.load());
    }
}

// BRNTP once per successful sync (first sync and every resync, ESP-IDF
// default every hour). TODO(core): spec 6.5 network time - the protocol
// core has no hook for it (br_node.h / br_platform.h: MGMT time sync not
// served yet); when it gains one, feed hal_time_utc_us() into it here.
// SECURITY (SPEC-NOTES N73): SNTP is unauthenticated (any host on the LAN
// path can answer). Before SNTP time feeds the core, a max-step guard is
// REQUIRED: refuse (and log) a correction larger than a bound once the
// clock is set (e.g. > 10 s per resync) instead of jumping, so a spoofed
// reply cannot move key epochs, replay windows or session expiry (6.5).
void ntp_poll() {
    if (!g_ntp_on) return;
    const uint32_t n = hal_sntp_sync_count();
    if (n == g_ntp_logged) return;
    g_ntp_logged = n;
    int64_t us = 0;
    if (hal_time_utc_us(&us) != HAL_OK) return;
    char buf[32];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    node_fmt_iso8601(&f, us / 1000000);
    ESP_LOGI(TAG, "BRNTP synced %s sync=%" PRIu32 " server=%s", buf, n, g_run.ntp);
}

// ---- the protocol task -----------------------------------------------------

bool node_init_from(const node_cfg_t &c) {
    uint32_t v = 0;
    for (auto &p : g_persist) {
        const hal_result_t r = hal_kv_get_u32(kNs, p.key, &v);
        if (r == HAL_OK) {
            p.stored = v;
        } else if (r == HAL_ERR_NOT_FOUND) {
            p.stored = kCounterDefault;
        } else {
            ESP_LOGE(TAG, "BRNVS read %s failed (%s)", p.key, hal_result_name(r));
            return false;
        }
    }
    br_node_config_t nc;
    std::memset(&nc, 0, sizeof nc);
    nc.unit_id = c.uid;
    nc.role = BR_ROLE_NODE;  // sender, relay and probe are all mesh nodes (br_node.h)
    nc.node_count = 3;
    nc.seek_ttl = BR_SEEK_TTL_DEFAULT;
    nc.caps = c.role == NODE_ROLE_PROBE ? static_cast<uint16_t>(kCapsBase | BR_CAP_MULTI) : kCapsBase;
    nc.auth = true;
    nc.cold_boot = true;  // first SEEK waits rand(0..BOOT_SPREAD_MS = 1800 ms)
    nc.n_groups = 0;      // probe subscribes with br_node_listen() after init
    nc.key_epoch = 1;
    nc.net_key = kBenchKey;
    nc.net_key_len = sizeof kBenchKey;
    // The bench allowlist (unit IDs, N22) is the same for every transport: a
    // wire or LAN peer is identified by the prev_hop in its frames.
    br_bench_allowlist_t al;
    std::memset(&al, 0, sizeof al);
    al.enabled = c.n_nbr > 0;
    al.n = c.n_nbr;
    for (uint8_t i = 0; i < c.n_nbr && i < BR_BENCH_ALLOWLIST_MAX; i++) al.ids[i] = c.nbr[i];
    nc.n_transports = 0;
    char tnames[40];
    node_fmt_t tf;
    node_fmt_init(&tf, tnames, sizeof tnames);
    if (g_espnow_on) {
        g_link_espnow = nc.n_transports++;
        br_transport_t &tr = nc.transports[g_link_espnow];
        tr.name = "espnow";
        tr.link_class = BR_LINK_PACKET;
        tr.max_frame = BR_MAX_FRAME_MESH;
        tr.rs_nsym = BR_RS_NSYM_PACKET;
        tr.can_broadcast = true;
        tr.mac_retry = true;
        tr.edge_only = false;
        tr.link_cost = 1;
        tr.addr_len = HAL_RADIO_ADDR_LEN;
        (void)espnow_link_init(&g_elink, tr_send, nullptr, &g_arb);  // g_arb is set up below
        tr.send = espnow_link_send;
        tr.user = &g_elink;
        tr.allowlist = al;
        node_fmt_str(&tf, "espnow");
    }
    if (g_uart_on) {
        g_link_uart = nc.n_transports++;
        br_transport_t &ut = nc.transports[g_link_uart];
        uart_link_fill_transport(&g_ulink, &ut);
        ut.allowlist = al;
        node_fmt_str(&tf, tf.len > 0 ? "+uart" : "uart");
    }
    if (g_udp_on) {
        g_link_udp = nc.n_transports++;
        br_transport_t &dt = nc.transports[g_link_udp];
        udp_link_fill_transport(&g_udp, &dt);  // the socket is already open (start_role)
        dt.allowlist = al;
        node_fmt_str(&tf, tf.len > 0 ? "+udp" : "udp");
    }
    if (g_nrf_on) {
        nrf24_link_cfg_t lc;
        std::memset(&lc, 0, sizeof lc);
        lc.unit_id = c.uid;
        const br_err_t rc = nrf24_link_register(&g_nlink, &nc, &lc, nrf24_link_hal_ops());
        if (rc != BR_OK) {
            ESP_LOGE(TAG, "BRNRF register failed rc=%d: running without the nRF24 link", static_cast<int>(rc));
            g_nrf_on = false;
        } else {
            g_link_nrf = g_nlink.link;
            nc.transports[g_link_nrf].allowlist = al;
            node_fmt_str(&tf, tf.len > 0 ? "+nrf24" : "nrf24");
        }
    }
    // 12.4: hold one radio's TX start while the other is busy (no-op unless both are on).
    (void)radio_arb_setup_board(&g_arb, g_espnow_on, g_nrf_on ? &g_nlink : nullptr);
    static_assert(BR_NODE_MAX_TRANSPORTS >= 4, "espnow + uart + udp + nrf24 need four transport slots");
    nc.app.user = nullptr;
    nc.app.on_seek_result = cb_seek_result;
    nc.app.on_bound = cb_bound;
    nc.app.on_mode = cb_mode;
    nc.app.on_samples = cb_samples;
    nc.app.on_gap = cb_gap;
    nc.app.on_acked = cb_acked;
    nc.app.on_closed = cb_closed;
    nc.app.on_state = cb_state;
    nc.app.on_event = cb_event;
    nc.txseq_start = g_persist[BR_PERSIST_TXSEQ].stored;
    nc.preseq_start = g_persist[BR_PERSIST_PRESEQ].stored;
    nc.persist = persist_cb;
    nc.persist_user = nullptr;
    const br_err_t rc = br_node_init(&g_node, sizeof g_node, &nc);
    if (rc != BR_OK) {
        ESP_LOGE(TAG, "BRSTART br_node_init failed rc=%d (transports=%u)", static_cast<int>(rc), nc.n_transports);
        return false;
    }
    ESP_LOGI(TAG, "BRSTART node 0x%04X txseq=%" PRIu32 " preseq=%" PRIu32 " allowlist=%s transports=%s", c.uid,
             nc.txseq_start, nc.preseq_start, c.n_nbr > 0 ? "on" : "off (all neighbours)",
             tf.len > 0 ? tnames : "none");
    return true;
}

TickType_t wait_ticks(uint64_t now, uint64_t wake) {
    if (wake <= now) return 0;
    uint64_t us = wake - now;
    if (us > kMaxWaitUs) us = kMaxWaitUs;
    const TickType_t t = pdMS_TO_TICKS((us + 999) / 1000);
    return t == 0 ? 1 : t;
}

void br_task(void *) {
    if (!node_init_from(g_run)) {
        ESP_LOGE(TAG, "BRSTART failed: protocol task stops (console still up)");
        vTaskDelete(nullptr);
        return;
    }
    if (hal_sys_wdt_subscribe_self() != HAL_OK) ESP_LOGW(TAG, "br_task: watchdog subscribe failed");
    if (g_nrf_on) {
        // Pipe 0 = own address, pipe 1 = broadcast, PRX. send() refuses frames before this.
        if (!nrf24_link_start(&g_nlink)) {
            ESP_LOGE(TAG, "BRNRF start failed (radio op refused): running without the nRF24 link");
            g_nrf_on = false;
        } else {
            g_nrf_deadline = nrf24_link_pump(&g_nlink, &g_node, hal_sys_time_us());
        }
    }
    if (g_run.role == NODE_ROLE_SENDER) {
        sender_start();
    } else if (g_run.role == NODE_ROLE_PROBE) {
        const br_err_t rc = br_node_listen(&g_node, &g_run.grp, 1);
        ESP_LOGI(TAG, "BRLISTEN group 0x%04X rc=%d", g_run.grp, static_cast<int>(rc));
    } else {
        ESP_LOGI(TAG, "BRRELAY forwarding only");
    }

    uint64_t next_deadline = 0;
    uint64_t next_stats = hal_sys_time_us() + kStatsPeriodUs;
    for (;;) {
        uint64_t now = hal_sys_time_us();
        uint64_t wake = next_deadline < next_stats ? next_deadline : next_stats;
        if (g_reseek_pending && g_reseek_at_us < wake) wake = g_reseek_at_us;
        if (g_nrf_on && g_nrf_deadline < wake) wake = g_nrf_deadline;  // pump cadence (poll / guard / reassembly)
        if (g_espnow_on && g_esp_deadline < wake) wake = g_esp_deadline;  // held ESP-NOW frames (12.4)
        bool stats_now = false;
        if (xQueueReceive(g_q, &g_evt, wait_ticks(now, wake)) == pdTRUE) {
            bool got_rx = false;
            uint32_t n = 0;
            do {
                if (g_evt.kind == kEvtStatsReq) {
                    stats_now = true;
                } else {
                    got_rx = got_rx || g_evt.kind == kEvtRx || g_evt.kind == kEvtUartRx || g_evt.kind == kEvtUdpRx;
                    handle_event(g_evt);
                }
            } while (++n < kQueueDepth && xQueueReceive(g_q, &g_evt, 0) == pdTRUE);
            if (got_rx) log_new_links();
        }
        const uint32_t dropped = g_rx_qdrop.exchange(0, std::memory_order_relaxed);
        for (uint32_t i = 0; i < dropped; i++) (void)br_node_count_rx_queue_drop(&g_node);

        // nRF24: drain the RX FIFO into reassembly (frames -> br_node_rx), advance
        // the transmit state machine, report delivery. Outside any br_node_* call.
        if (g_nrf_on) {
            g_nrf_deadline = nrf24_link_pump(&g_nlink, &g_node, hal_sys_time_us());
            log_new_links();
        }
        if (g_espnow_on) g_esp_deadline = espnow_link_pump(&g_elink, hal_sys_time_us());

        now = hal_sys_time_us();
        uint64_t nd = BR_NEVER_US;
        (void)br_node_tick(&g_node, now, &nd);
        next_deadline = nd;
        if (g_run.role == NODE_ROLE_SENDER) sender_after_tick(now);
        // A wire or a datagram has no MAC ACK: frames the driver accepted count
        // as delivered (no-op in the core for mac_retry false / addr_len 0).
        if (g_uart_on) (void)uart_link_report_tx_status(&g_ulink, &g_node, g_link_uart);
        if (g_udp_on) (void)udp_link_report_tx_status(&g_udp, &g_node, g_link_udp);
        // Frames the tick just queued leave at once instead of at the next wake-up.
        if (g_nrf_on) g_nrf_deadline = nrf24_link_pump(&g_nlink, &g_node, hal_sys_time_us());
        if (g_espnow_on) g_esp_deadline = espnow_link_pump(&g_elink, hal_sys_time_us());

        wifi_poll(now);
        ntp_poll();

        if (stats_now || now >= next_stats) {
            print_stats();
            if (now >= next_stats) next_stats = now + kStatsPeriodUs;
        }
        (void)hal_sys_wdt_feed();
    }
}

// ---- role helper tasks ---------------------------------------------------

// STRAPPING: GPIO2 (default LED) must be low or floating at boot (download
// mode needs it low together with GPIO0). An LED to GND through a resistor
// pulls it low: fine. GPIO2 is also ADC2_CH2; used here as a digital output
// only, which works with Wi-Fi on.
void led_task(void *) {
    const hal_gpio_cfg_t io = {g_run.led, HAL_GPIO_DIR_OUT, HAL_GPIO_PULL_NONE, HAL_GPIO_INT_NONE};
    hal_result_t r = hal_gpio_init(&io);
    if (r == HAL_OK) r = hal_gpio_set(g_run.led, false);
    if (r != HAL_OK) {
        ESP_LOGE(TAG, "BRLED GPIO%u init failed (%s)", g_run.led, hal_result_name(r));
        g_led_task = nullptr;
        vTaskDelete(nullptr);
        return;
    }
    for (;;) {
        // One notification per 0->1 edge; each one is one 5-flash sequence.
        if (ulTaskNotifyTake(pdFALSE, pdMS_TO_TICKS(1000)) == 0) continue;
        for (uint32_t i = 0; i < kLedFlashes; i++) {
            (void)hal_gpio_set(g_run.led, true);
            vTaskDelay(pdMS_TO_TICKS(kLedHalfMs));
            (void)hal_gpio_set(g_run.led, false);
            vTaskDelay(pdMS_TO_TICKS(kLedHalfMs));
        }
    }
}

// STRAPPING: GPIO0 (default button, the devkit BOOT button) must be high at
// reset for a normal boot; the button pulls it low only while pressed, so do
// not hold it during reset (that enters the ROM download mode). Input with
// the internal pull-up (the devkit also has an external 10k pull-up). GPIO0
// is ADC2_CH1; used here as a digital input only, which works with Wi-Fi on.
void button_task(void *) {
    const hal_gpio_cfg_t io = {g_run.btn, HAL_GPIO_DIR_IN, HAL_GPIO_PULL_UP, HAL_GPIO_INT_NONE};
    if (hal_gpio_init(&io) != HAL_OK) {
        ESP_LOGE(TAG, "BRBTN GPIO%u init failed", g_run.btn);
        vTaskDelete(nullptr);
        return;
    }
    bool stable = true;  // released (pull-up)
    (void)hal_gpio_get(g_run.btn, &stable);
    uint8_t differing = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(kBtnPollMs));
        bool raw = stable;
        if (hal_gpio_get(g_run.btn, &raw) != HAL_OK) continue;
        if (raw == stable) {
            differing = 0;
            continue;
        }
        if (++differing < kBtnStable) continue;
        differing = 0;
        stable = raw;
        if (!stable) post_app_event(kEvtPress);  // pressed = low
    }
}

// ---- console -----------------------------------------------------------------

void show_running() {
    char buf[24];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    uint8_t mac[HAL_RADIO_ADDR_LEN];
    if (g_espnow_on && hal_radio_get_addr(mac) == HAL_OK) {
        fmt_mac(&f, mac);
    } else {
        node_fmt_str(&f, "none (espnow=off)");
    }
    ESP_LOGI(TAG, "BRCFG running role=%s id=0x%04X mac=%s", node_role_name(g_run.role), g_run.uid, buf);
    if (g_uart_on) {
        ESP_LOGI(TAG, "BRCFG running uart%u tx=GPIO%u rx=GPIO%u baud=%" PRIu32, kUartLinkPort, g_uart_tx, g_uart_rx,
                 g_uart_baud);
    }
    if (g_wifi_on) {
        node_fmt_init(&f, buf, sizeof buf);
        fmt_ip4(&f, g_wifi_ip.load());
        ESP_LOGI(TAG, "BRCFG running wifi %s ip=%s ap_ch=%u ntp=%s syncs=%" PRIu32, g_wifi_up.load() ? "up" : "down",
                 buf, g_wifi_ap_ch.load(), g_run.ntp, g_ntp_on ? hal_sntp_sync_count() : 0u);
    }
    if (g_udp_on) {
        node_fmt_init(&f, buf, sizeof buf);
        fmt_ip(&f, g_wifi_ip.load(), g_udp_port);
        ESP_LOGI(TAG, "BRCFG running udp %s mcast=%s peers=%u", buf, g_udp_mcast.load() ? "on" : "off",
                 g_run.n_peers);
    }
    if (g_nrf_on) {
        uint8_t a[NRF24_LINK_ADDR_LEN];
        nrf24_link_unit_addr(g_run.uid, a);
        node_fmt_init(&f, buf, sizeof buf);
        fmt_addr5(&f, a);
        ESP_LOGI(TAG, "BRCFG running nrf24 ch=%u rate=%s pa=%s addr=%s irq=%s", g_nrf_cfg.channel,
                 node_nrate_name(static_cast<uint8_t>(g_nrf_cfg.rate)), node_npa_name(static_cast<uint8_t>(g_nrf_cfg.pa)),
                 buf, g_nrf_cfg.irq_pin == HAL_NRF24_PIN_NONE ? "poll" : "pin");
    }
}

void console_exec(const char *line) {
    node_cmd_t cmd;
    WipeGuard cmd_wipe{&cmd, sizeof cmd};  // cmd.val.pass on every return (N71)
    if (!node_cmd_parse(line, kChip, &cmd)) {
        ESP_LOGW(TAG, "BRCFG error: %s", cmd.err);
        return;
    }
    switch (cmd.kind) {
        case NODE_CMD_NONE:
            return;
        case NODE_CMD_SET: {
            char err[NODE_ERR_MAX];
            if (xSemaphoreTake(g_cfg_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
                ESP_LOGW(TAG, "BRCFG busy, try again");
                return;
            }
            node_cfg_t n = g_cfg;
            WipeGuard n_wipe{&n, sizeof n};
            bool ok = node_cfg_apply(&n, &cmd, err, sizeof err);
            hal_result_t r = HAL_OK;
            if (ok) {
                r = cfg_save(&n);
                if (r == HAL_OK) g_cfg = n;
            }
            xSemaphoreGive(g_cfg_lock);
            if (!ok) {
                ESP_LOGW(TAG, "BRCFG error: %s", err);
                return;
            }
            if (r != HAL_OK) {
                ESP_LOGE(TAG, "BRCFG error: NVS write failed (%s); nothing changed", hal_result_name(r));
                return;
            }
            log_cfg("saved", &n);
            if (g_started.load()) {
                ESP_LOGI(TAG, "BRCFG running role unchanged; br reboot to apply");
            } else {
                xSemaphoreGive(g_cfg_changed);
            }
            return;
        }
        case NODE_CMD_SHOW: {
            node_cfg_t c;
            WipeGuard c_wipe{&c, sizeof c};
            if (xSemaphoreTake(g_cfg_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return;
            c = g_cfg;
            xSemaphoreGive(g_cfg_lock);
            log_cfg("stored", &c);  // never prints the passphrase (pass=set|unset)
            if (g_started.load()) {
                show_running();
            } else {
                ESP_LOGI(TAG, "BRCFG not started");
            }
            return;
        }
        case NODE_CMD_ERASE: {
            if (xSemaphoreTake(g_cfg_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return;
            const hal_result_t r = cfg_erase();
            if (r == HAL_OK) cfg_defaults(&g_cfg);
            xSemaphoreGive(g_cfg_lock);
            if (r != HAL_OK) {
                ESP_LOGE(TAG, "BRCFG erase failed (%s)", hal_result_name(r));
                return;
            }
            ESP_LOGI(TAG, "BRCFG erased (txseq/preseq counters kept)%s",
                     g_started.load() ? "; br reboot to apply" : "");
            if (!g_started.load()) xSemaphoreGive(g_cfg_changed);
            return;
        }
        case NODE_CMD_REBOOT:
            ESP_LOGI(TAG, "BRCFG rebooting");
            vTaskDelay(pdMS_TO_TICKS(100));  // let the log line leave the UART
            hal_sys_restart();
            return;
        case NODE_CMD_STATS:
            if (g_started.load()) {
                post_app_event(kEvtStatsReq);
            } else {
                ESP_LOGI(TAG, "BRSTAT not started");
            }
            return;
        case NODE_CMD_ERROR:
        default:
            ESP_LOGW(TAG, "BRCFG error: %s", cmd.err);
            return;
    }
}

void console_task(void *) {
    constexpr uint8_t kUart = 0;  // UART0: the USB-serial console of the devkit
    const hal_uart_cfg_t uc = {kUart, 115200, -1, -1, 256};
    const hal_result_t r = hal_uart_init(&uc);
    if (r != HAL_OK) {
        ESP_LOGE(TAG, "BRCFG console UART0 init failed (%s); no console", hal_result_name(r));
        g_con_task = nullptr;
        vTaskDelete(nullptr);
        return;
    }
    static char line[NODE_LINE_MAX + 1];
    size_t len = 0;
    bool overflow = false;
    uint8_t chunk[32];
    for (;;) {
        size_t got = 0;
        if (hal_uart_read(kUart, chunk, sizeof chunk, 200, &got) != HAL_OK) continue;
        for (size_t i = 0; i < got; i++) {
            const uint8_t ch = chunk[i];
            if (ch == '\r' || ch == '\n') {
                if (overflow) {
                    ESP_LOGW(TAG, "BRCFG error: line longer than %u characters ignored", NODE_LINE_MAX);
                } else if (len > 0) {
                    line[len] = '\0';
                    console_exec(line);
                    node_wipe(line, sizeof line);  // the line may carry pass= (N71)
                }
                len = 0;
                overflow = false;
            } else if (ch == 0x08 || ch == 0x7F) {
                if (len > 0) len--;
            } else if (ch >= 0x20 && ch < 0x7F) {
                if (len < NODE_LINE_MAX) {
                    line[len++] = static_cast<char>(ch);
                } else {
                    overflow = true;
                }
            }
        }
    }
}

// ---- start -----------------------------------------------------------------

// WiFi station (wifi=on, or udp=on; espnow is off then, 12.4), WIFI_PS_NONE
// (set by the port: a mains-powered station, no DTIM latency), then SNTP.
// The STA helper runs exactly once. On HAL_ERR_TIMEOUT the station stays
// started and the port reconnects forever with capped backoff + jitter on
// its own esp_timer (hal_udp.h, SPEC-NOTES N69; wifi_poll logs BRWIFI when
// it comes up, BRSTAT shows wifi_retry=); a wrong ssid / pass is just
// another failure reason and is retried on the same schedule. On any other
// error (driver init) the board runs without the station (no UDP link, no
// SNTP) and the console stays up.
void start_wifi(const node_cfg_t &c) {
    uint32_t ip = 0;
    const hal_result_t wr = hal_udp_wifi_sta_start(c.ssid, c.pass, kWifiTimeoutMs, &ip);
    char ssid[NODE_SSID_MAX + 1];
    node_fmt_t sf;
    node_fmt_init(&sf, ssid, sizeof ssid);
    node_fmt_ssid(&sf, c.ssid);
    if (wr == HAL_ERR_TIMEOUT) {
        ESP_LOGW(TAG, "BRWIFI no IP within %u ms (ssid=%s): reconnecting with backoff (check ssid= / pass= if it "
                 "persists)%s",
                 static_cast<unsigned>(kWifiTimeoutMs), ssid, c.udp != 0 ? ", UDP link opens anyway" : "");
    } else if (wr != HAL_OK) {
        ESP_LOGE(TAG, "BRWIFI sta start failed (%s): running without the station (no UDP, no SNTP; check ssid= / pass=)",
                 hal_result_name(wr));
        return;
    }
    g_wifi_on = true;
    wifi_poll(hal_sys_time_us());  // HAL_OK: BRWIFI sta up ... ap_ch=N now
    const hal_result_t nr = hal_sntp_start(c.ntp);
    if (nr == HAL_OK) {
        g_ntp_on = true;
        ESP_LOGI(TAG, "BRNTP sntp started server=%s (first sync after the station has an IP)", c.ntp);
    } else {
        ESP_LOGE(TAG, "BRNTP sntp start failed (%s): no network time", hal_result_name(nr));
    }
}

// UDP socket on the station (udp=on and the station started).
void start_udp(const node_cfg_t &c) {
    udp_link_cfg_t ucfg;
    std::memset(&ucfg, 0, sizeof ucfg);
    ucfg.local_port = c.port;
    ucfg.mcast = c.mcast != 0;
    ucfg.mcast_port = c.port;
    ucfg.mcast_loop = false;  // a device never needs its own echo (the core drops it anyway, 11.4 9a)
    ucfg.n_peers = c.n_peers;
    for (uint8_t i = 0; i < c.n_peers && i < UDP_LINK_MAX_PEERS; i++) {
        ucfg.peers[i].ip = c.peers[i].ip;
        ucfg.peers[i].port = c.peers[i].port;
    }
    if (!udp_link_init(&g_udp, &ucfg, nullptr)) {
        ESP_LOGE(TAG, "BRUDP adapter init refused the configuration: running without the UDP link");
        return;
    }
    br_err_t rc = udp_link_open(&g_udp);
    if (rc == BR_ERR_NOT_IMPLEMENTED) {
        // Socket open, multicast join refused (client isolation, no IGMP, no IP yet).
        udp_link_close(&g_udp);
        if (ucfg.n_peers > 0) {
            ESP_LOGW(TAG, "BRUDP multicast join refused: floods go to the %u configured peers instead", ucfg.n_peers);
            ucfg.mcast = false;
            if (udp_link_init(&g_udp, &ucfg, nullptr)) rc = udp_link_open(&g_udp);
        } else {
            ESP_LOGE(TAG, "BRUDP multicast join refused and no peers= list: running without the UDP link");
            return;
        }
    }
    if (rc != BR_OK) {
        ESP_LOGE(TAG, "BRUDP open failed rc=%d (port %u taken?): running without the UDP link", static_cast<int>(rc),
                 c.port);
        udp_link_close(&g_udp);
        return;
    }
    if (xTaskCreatePinnedToCore(udprx_task, "udprx", kStackUdpRx, nullptr, kPrioUdpRx, &g_udprx_task, kCoreNet) !=
        pdPASS) {
        ESP_LOGE(TAG, "BRUDP receive task create failed: running without the UDP link");
        udp_link_close(&g_udp);
        return;
    }
    g_udp_on = true;
    g_udp_mcast.store(ucfg.mcast);
    g_udp_port = udp_link_bound_port(&g_udp);
    ESP_LOGI(TAG, "BRUDP port=%u mcast=%s ttl=%u peers=%u PACKET max_frame=%u cost=%u", g_udp_port,
             g_udp_mcast.load() ? "239.255.40.88" : "off", static_cast<unsigned>(UDP_LINK_TTL), ucfg.n_peers,
             static_cast<unsigned>(UDP_LINK_MAX_FRAME), static_cast<unsigned>(UDP_LINK_COST));
}

// nRF24L01+ radio (nrf=on): HAL init with the console's pins and radio
// settings. No module answering (HAL_ERR_HW_FAULT) is not fatal: the board
// runs without the link (same policy as a refused UART init).
void start_nrf(const node_cfg_t &c) {
    hal_nrf24_cfg_t nc;
    hal_nrf24_default_cfg(&nc);
    nc.sck_pin = c.nsck;
    nc.miso_pin = c.nmiso;
    nc.mosi_pin = c.nmosi;
    nc.csn_pin = c.ncsn;
    nc.ce_pin = c.nce;
    nc.irq_pin = c.nirq == NODE_PIN_NONE ? static_cast<int16_t>(HAL_NRF24_PIN_NONE) : static_cast<int16_t>(c.nirq);
    nc.channel = c.nch;
    nc.rate = static_cast<hal_nrf24_rate_t>(c.nrate);
    nc.pa = static_cast<hal_nrf24_pa_t>(c.npa);
    const hal_result_t r = hal_nrf24_init(&nc);
    if (r == HAL_ERR_HW_FAULT) {
        ESP_LOGE(TAG, "BRNRF no module answering on SCK=GPIO%u MISO=GPIO%u MOSI=GPIO%u CSN=GPIO%u (3.3 V? wiring?): "
                      "running without the nRF24 link", c.nsck, c.nmiso, c.nmosi, c.ncsn);
        return;
    }
    if (r != HAL_OK) {
        ESP_LOGE(TAG, "BRNRF init failed (%s): running without the nRF24 link", hal_result_name(r));
        return;
    }
    g_nrf_cfg = nc;
    std::memset(&g_nrf_irq_evt, 0, sizeof g_nrf_irq_evt);
    g_nrf_irq_evt.kind = kEvtNrfIrq;
    if (nc.irq_pin != HAL_NRF24_PIN_NONE) {
        const hal_result_t ir = hal_nrf24_set_irq_cb(nrf_irq, nullptr);
        if (ir != HAL_OK) ESP_LOGW(TAG, "BRNRF IRQ callback refused (%s): polling only", hal_result_name(ir));
    }
    g_nrf_on = true;
    uint8_t a[NRF24_LINK_ADDR_LEN];
    nrf24_link_unit_addr(c.uid, a);
    char buf[24];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    fmt_addr5(&f, a);
    char irq[12];
    node_fmt_init(&f, irq, sizeof irq);
    if (c.nirq == NODE_PIN_NONE) {
        node_fmt_str(&f, "poll");
    } else {
        node_fmt_str(&f, "GPIO");
        node_fmt_u32(&f, c.nirq);
    }
    ESP_LOGI(TAG, "BRNRF ch=%u rate=%s pa=%s PACKET max_frame=%u cost=%u addr=%s irq=%s", c.nch,
             node_nrate_name(c.nrate), node_npa_name(c.npa), static_cast<unsigned>(NRF24_LINK_MAX_FRAME),
             static_cast<unsigned>(NRF24_LINK_COST), buf, irq);
}

bool start_role(const node_cfg_t &c) {
    g_run = c;
    // Queue before radio: the radio callbacks enqueue from the first frame on.
    g_post_lock = xSemaphoreCreateMutexStatic(&g_post_lock_buf);
    g_q = xQueueCreateStatic(kQueueDepth, sizeof(Evt), g_q_storage, &g_q_buf);
    if (g_q == nullptr || g_post_lock == nullptr) {
        ESP_LOGE(TAG, "BRBOOT event queue create failed");
        return false;
    }
    if (c.espnow != 0) {
        const hal_radio_cfg_t rc = {c.chan};
        const hal_result_t r = hal_radio_init(&rc, radio_rx, radio_tx, nullptr);
        if (r != HAL_OK) {
            ESP_LOGE(TAG, "BRBOOT radio init failed (%s); fix with br set chan=.. then br reboot", hal_result_name(r));
            return false;
        }
        g_espnow_on = true;
        uint8_t mac[HAL_RADIO_ADDR_LEN] = {};
        (void)hal_radio_get_addr(mac);
        char buf[24];
        node_fmt_t f;
        node_fmt_init(&f, buf, sizeof buf);
        fmt_mac(&f, mac);
        ESP_LOGI(TAG, "BRRADIO espnow chan=%u mac=%s", c.chan, buf);
    } else {
        ESP_LOGI(TAG, "BRRADIO espnow off (station board: LAN side or single-chip nRF24 gateway, 12.4)");
    }

    if (c.uart != 0) {
        // Adapter first (the HAL receive task may deliver bytes at once; they
        // wait in the queue until "br" has initialised the node).
        (void)uart_link_init(&g_ulink, uart_write, nullptr, uart_frame, nullptr);
        hal_uart_link_cfg_t uc = {};
        uc.port = kUartLinkPort;
        uc.tx_pin = c.utx;
        uc.rx_pin = c.urx;
        uc.baud = c.ubaud;
        uc.rx_buf_len = HAL_UART_LINK_RX_BUF_DEFAULT;
        uc.tx_buf_len = HAL_UART_LINK_TX_BUF_DEFAULT;
        const hal_result_t r = hal_uart_link_init(&uc, uart_rx, nullptr);
        if (r != HAL_OK) {
            ESP_LOGE(TAG, "BRUART uart%u init failed (%s): running without the UART link", kUartLinkPort,
                     hal_result_name(r));
        } else {
            g_uart_on = true;
            g_uart_tx = c.utx;
            g_uart_rx = c.urx;
            g_uart_baud = c.ubaud;
            if (!uart_link_start(&g_ulink)) ESP_LOGW(TAG, "BRUART start delimiter not queued");
            ESP_LOGI(TAG,
                     "BRUART uart%u tx=GPIO%u rx=GPIO%u baud=%" PRIu32 " RAW max_frame=%u rs_nsym=%u "
                     "path_mtu=%u",
                     kUartLinkPort, c.utx, c.urx, c.ubaud, static_cast<unsigned>(UART_LINK_MAX_FRAME),
                     static_cast<unsigned>(UART_LINK_RS_NSYM),
                     static_cast<unsigned>(UART_LINK_MAX_FRAME - UART_LINK_RS_NSYM));
        }
    }

    if (node_cfg_wifi_on(&c)) start_wifi(c);   // console guarantees espnow == 0 here (12.4)
    std::memset(g_run.pass, 0, sizeof g_run.pass);  // the driver holds the credentials from here on
    if (c.udp != 0) {
        if (g_wifi_on) {
            start_udp(c);
        } else {
            ESP_LOGE(TAG, "BRUDP no station: running without the UDP link");
        }
    }
    if (c.nrf != 0) start_nrf(c);
    log_coexist();  // station already up with a known AP channel: check it against nch now

    if (c.role == NODE_ROLE_PROBE) {
        if (xTaskCreatePinnedToCore(led_task, "led", kStackLed, nullptr, kPrioLed, &g_led_task, kCoreApp) != pdPASS) {
            ESP_LOGE(TAG, "BRBOOT led task create failed");
            g_led_task = nullptr;
        }
    }
    if (xTaskCreatePinnedToCore(br_task, "br", kStackBr, nullptr, kPrioBr, &g_br_task, kCoreApp) != pdPASS) {
        ESP_LOGE(TAG, "BRBOOT br task create failed");
        return false;
    }
    if (c.role == NODE_ROLE_SENDER) {
        if (xTaskCreatePinnedToCore(button_task, "btn", kStackBtn, nullptr, kPrioBtn, &g_btn_task, kCoreApp) !=
            pdPASS) {
            ESP_LOGE(TAG, "BRBOOT button task create failed");
        }
    }
    g_started.store(true);
    ESP_LOGI(TAG,
             "BRBOOT started role=%s id=0x%04X grp=0x%04X tasks: br@core%d led=%s btn=%s con@core%d uart=%s udp=%s "
             "nrf=%s wifi=%s",
             node_role_name(c.role), c.uid, c.grp, static_cast<int>(kCoreApp), g_led_task ? "yes" : "no",
             g_btn_task ? "yes" : "no", static_cast<int>(kCoreNet), g_uart_on ? "yes" : "no",
             g_udp_on ? "yes" : "no", g_nrf_on ? "yes" : "no", g_wifi_on ? "yes" : "no");
    return true;
}

}  // namespace

extern "C" void node_app_run(void) {
    g_cfg_lock = xSemaphoreCreateMutexStatic(&g_cfg_lock_buf);
    g_cfg_changed = xSemaphoreCreateBinaryStatic(&g_cfg_changed_buf);
    if (g_cfg_lock == nullptr || g_cfg_changed == nullptr) {
        ESP_LOGE(TAG, "BRBOOT semaphore create failed");
        return;
    }
    node_cfg_t c;
    WipeGuard c_wipe{&c, sizeof c};  // after start_role(): g_cfg / the driver hold the credentials (N71)
    const hal_result_t lr = cfg_load(&c);
    if (lr != HAL_OK) {
        ESP_LOGE(TAG, "BRBOOT NVS read failed (%s); using defaults", hal_result_name(lr));
        cfg_defaults(&c);
    }
    g_cfg = c;
    if (xTaskCreatePinnedToCore(console_task, "con", kStackCon, nullptr, kPrioCon, &g_con_task, kCoreNet) != pdPASS) {
        ESP_LOGE(TAG, "BRBOOT console task create failed");
    }

    const char *why = nullptr;
    bool ready = node_cfg_ready(&c, kChip, &why);
    uint64_t start_at = 0;
    if (ready) {
        log_cfg("boot", &c);
        ESP_LOGI(TAG, "BRBOOT starting in 3 s; send br commands now to change the configuration");
        start_at = hal_sys_time_us() + kBootWindowUs;
    } else {
        log_cfg("boot", &c);
        ESP_LOGW(TAG, "BRBOOT waiting for configuration, e.g.: br set role=probe id=0x0103 grp=0xFF10 nbr=0x0102");
    }
    for (;;) {
        const uint64_t now = hal_sys_time_us();
        if (ready && now >= start_at) break;
        const TickType_t wait = ready ? wait_ticks(now, start_at) : pdMS_TO_TICKS(30000);
        const bool changed = xSemaphoreTake(g_cfg_changed, wait) == pdTRUE;
        if (xSemaphoreTake(g_cfg_lock, pdMS_TO_TICKS(1000)) == pdTRUE) {
            c = g_cfg;
            xSemaphoreGive(g_cfg_lock);
        }
        const bool was_ready = ready;
        ready = node_cfg_ready(&c, kChip, &why);
        if (ready && !was_ready) start_at = hal_sys_time_us();  // first valid config: start now
        if (!ready && !changed) {
            ESP_LOGW(TAG, "BRBOOT still waiting for configuration (%s)", why);
        }
    }
    (void)start_role(c);
}
