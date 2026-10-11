// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_udp.h - vendor-neutral IPv4 UDP socket (Braid WiFi UDP carrier,
// spec 1.2 "WiFi UDP" row, 11.11, 12.4, C.4). Two implementations of the
// same five calls:
//   components/port_esp_idf/port_udp.cpp   ESP-IDF, lwIP BSD sockets
//   firmware/host/udp_posix.c              POSIX (host tests, future laptop node)
// Keep them textually near-identical; the socket code is the same, only the
// WiFi station helper at the end exists on the device.
//
// Model:
//   - one socket per link, bound to a local port (0 = any free port; the
//     port actually bound is written back to hal_udp_t.local_port);
//   - datagram in, datagram out: no framing, no interpretation (the
//     transport adapter in components/app_udp_link does Braid);
//   - IPv4 addresses are plain uint32_t in HOST order, a.b.c.d =
//     (a << 24) | (b << 16) | (c << 8) | d (HAL_UDP_IP4()); ports are host
//     order uint16_t. No lwIP or POSIX type crosses this header;
//   - multicast: hal_udp_open() joins cfg->mcast_group (0 = none) on the
//     interface cfg->mcast_if (0 = the stack's default), sets the IP TTL of
//     outgoing multicast to cfg->mcast_ttl and the loopback flag to
//     cfg->mcast_loop (host tests run several nodes in one process and need
//     to hear their own floods; a device leaves it off: the core drops its
//     own echo anyway, 11.4 step 9a). hal_udp_mcast() joins or leaves more
//     groups later;
//   - receive: hal_udp_recvfrom() waits at most timeout_ms (0 = poll) and
//     returns HAL_ERR_TIMEOUT when nothing arrived. A datagram longer than
//     cap is truncated to cap bytes (the caller passes cap > max_frame to
//     detect oversize);
//   - send: hal_udp_sendto() hands the datagram to the stack and returns
//     at once. There is no delivery report (UDP): HAL_OK means "queued".
//
// Thread safety: one owner task per socket (Braid: the protocol task,
// or the small RX task described in firmware/UDP-LINK.txt which only
// receives). hal_udp_open() / hal_udp_close() once per link.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_UDP_IP4(a, b, c, d) \
    ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) | (((uint32_t)(c)) << 8) | ((uint32_t)(d)))

#define HAL_UDP_PORT_DEFAULT   40888u                          // spec C.4
#define HAL_UDP_MCAST_DEFAULT  HAL_UDP_IP4(239, 255, 40, 88)   // spec C.4
#define HAL_UDP_TTL_DEFAULT    1u                              // spec C.4: link local
#define HAL_UDP_LOOPBACK       HAL_UDP_IP4(127, 0, 0, 1)

typedef struct {
    uint16_t local_port;    // 0 = any free port (read back from hal_udp_t.local_port)
    uint32_t mcast_group;   // 0 = no multicast; else joined at open
    uint32_t mcast_if;      // local interface address for join / outgoing multicast; 0 = default
    uint8_t  mcast_ttl;     // IP TTL of outgoing multicast (1 = link local)
    bool     mcast_loop;    // receive our own multicast (host tests); false on a device
    bool     reuse_addr;    // SO_REUSEADDR (several sockets on one host sharing a multicast port)
} hal_udp_cfg_t;

// Socket object, caller-owned (static). Treat fd as private.
typedef struct {
    int      fd;            // -1 when closed
    uint16_t local_port;    // port actually bound (filled by hal_udp_open)
    uint32_t mcast_group;   // group joined at open (0 = none)
} hal_udp_t;

// 1. Open: socket, bind local_port, multicast options and join (if any).
//    HAL_ERR_INVALID_ARG NULL / bad cfg; HAL_ERR_BUSY the port is taken;
//    HAL_ERR_UNSUPPORTED the join was refused (socket left open, no
//    membership: the caller decides whether to fall back to a peer list);
//    HAL_ERR_HW_FAULT other stack errors (nothing left open).
hal_result_t hal_udp_open(hal_udp_t *s, const hal_udp_cfg_t *cfg);

// 2. Send one datagram to addr4:port. HAL_OK queued; HAL_ERR_INVALID_ARG
//    NULL / len 0 / closed socket; HAL_ERR_BUSY the stack had no buffer
//    (EAGAIN / ENOBUFS / ENOMEM); HAL_ERR_HW_FAULT other errors (no route,
//    interface down).
hal_result_t hal_udp_sendto(hal_udp_t *s, uint32_t addr4, uint16_t port, const uint8_t *buf, size_t len);

// 3. Receive one datagram, waiting at most timeout_ms (0 = poll). On
//    HAL_OK *len_out is the byte count (0 for an empty datagram, cap when
//    truncated) and *addr4_out / *port_out the sender. HAL_ERR_TIMEOUT
//    nothing arrived; HAL_ERR_INVALID_ARG; HAL_ERR_HW_FAULT socket error.
hal_result_t hal_udp_recvfrom(hal_udp_t *s, uint8_t *buf, size_t cap, size_t *len_out, uint32_t *addr4_out,
                              uint16_t *port_out, uint32_t timeout_ms);

// 4. Join (join = true) or leave a multicast group on interface mcast_if
//    (0 = default). HAL_OK; HAL_ERR_INVALID_ARG; HAL_ERR_UNSUPPORTED the
//    stack / interface refused it (no multicast on that interface).
hal_result_t hal_udp_mcast(hal_udp_t *s, uint32_t group, uint32_t mcast_if, bool join);

// 5. Close. Safe on an already closed socket and on NULL.
hal_result_t hal_udp_close(hal_udp_t *s);

// WiFi station bring-up for the LAN side (spec 12.4: a UDP node lives on the
// LAN only and NEVER shares a chip with ESP-NOW: STA association moves the
// channel) and for the single-chip nRF24 gateway (nRF24 mesh + station on
// one ESP32, GATEWAY-NRF24.txt; the nRF24 is a separate transceiver and does
// not follow the AP channel). Device only (port_udp.cpp); udp_posix.c returns
// HAL_ERR_UNSUPPORTED. Initialises netif, the default event loop and the
// WiFi driver in STA mode (calibration data in RAM, power save off:
// WIFI_PS_NONE, a mains-powered station; modem sleep would add DTIM latency),
// associates with ssid / pass (WPA2-PSK, PMF capable but not required; an
// empty pass means an open AP), runs the DHCP client and waits at most
// timeout_ms for an IPv4 address, written to *ip4_out. HAL_ERR_INVALID_ARG
// bad ssid (1..32 bytes) or pass (> 63 bytes); HAL_ERR_BUSY already started
// (or hal_radio_init() owns the WiFi driver); HAL_ERR_TIMEOUT no IP in time
// (the station stays started and keeps reconnecting, see below);
// HAL_ERR_HW_FAULT / HAL_ERR_NO_MEM driver errors. Credentials come from the
// caller (NVS keys ssid= / pass=, see firmware/UDP-LINK.txt); they are never
// compiled in; the port wipes its own copy (wifi_config_t) once the driver
// has it.
//
// Reconnect (SPEC-NOTES N69): the station NEVER gives up. Every failed
// association or loss of the AP (WIFI_EVENT_STA_DISCONNECTED, whatever the
// reason: AP gone, wrong passphrase, AP not found) schedules ONE retry on an
// esp_timer after hal_udp_wifi_backoff_next() (1 s doubling to 60 s, +/- 20 %
// jitter); an IPv4 address resets the schedule. The event handler never
// blocks and never calls esp_wifi_connect() itself (only the STA_START
// first attempt). One log line per attempt:
//   port_udp: BRWIFI sta down (reason=201) retry in 4.3s
hal_result_t hal_udp_wifi_sta_start(const char *ssid, const char *pass, uint32_t timeout_ms, uint32_t *ip4_out);

// Station state after hal_udp_wifi_sta_start() (device only; udp_posix.c
// does not provide it and no host code calls it). Also used without the UDP
// link: the single-chip nRF24 gateway runs the station for SNTP only
// (firmware/GATEWAY-NRF24.txt, console key wifi=). Never blocks; safe from
// any task. HAL_OK: associated with an IPv4 address; *ip4_out is the
// address (host order) and *ap_ch_out the AP's primary channel (1..14,
// esp_wifi_get_channel()), which is where the 2.4 GHz WiFi energy of this
// board sits. HAL_ERR_TIMEOUT: started but not (or no longer) associated
// with an address (outputs 0). HAL_ERR_NOT_FOUND: the station was never
// started. Either output pointer may be NULL.
hal_result_t hal_udp_wifi_sta_info(uint32_t *ip4_out, uint8_t *ap_ch_out);

// Reconnect state of the station (device only, like hal_udp_wifi_sta_info;
// never blocks, safe from any task). *attempts_out: consecutive failed
// association attempts since the last IPv4 address (0 while up, saturates);
// *last_reason_out: wifi disconnect reason of the last failure (802.11
// reason code, or ESP-IDF 2xx such as 201 NO_AP_FOUND; 15 or 204 for a
// handshake timeout, typically a wrong passphrase), 0 = none yet. HAL_ERR_NOT_FOUND: the
// station was never started (outputs 0). Either pointer may be NULL.
hal_result_t hal_udp_wifi_sta_retry_info(uint32_t *attempts_out, uint16_t *last_reason_out);

// ---- station reconnect schedule (portable, header-only) --------------------
// The pure schedule the port follows, kept here so it is host-testable
// (firmware/test/host/test_console_robust.c) without ESP-IDF. attempt n
// (1-based count of consecutive failures) waits
//   base(n) = min(1000 ms x 2^(n-1), 60000 ms)    1, 2, 4, 8, 16, 32, 60, 60 ... s
//   delay   = base(n) - base/5 + (rnd mod (2 x base/5 + 1))
// i.e. uniform within base +/- 20 % (the jitter is applied to the capped
// base: 48..72 s at the cap), so gateways behind one router that comes back
// do not all reassociate in the same second. A success resets n to 0.
#define HAL_UDP_WIFI_BACKOFF_MIN_MS     1000u
#define HAL_UDP_WIFI_BACKOFF_MAX_MS     60000u
#define HAL_UDP_WIFI_BACKOFF_JITTER_PCT 20u

typedef struct {
    uint32_t attempts;      // consecutive failures (0 = none since the last success)
} hal_udp_wifi_backoff_t;

static inline void hal_udp_wifi_backoff_reset(hal_udp_wifi_backoff_t *b)
{
    b->attempts = 0u;
}

// base(attempt) in ms; attempt 0 is treated as 1. No shift: doubling stops at the cap.
static inline uint32_t hal_udp_wifi_backoff_base_ms(uint32_t attempt)
{
    uint32_t base = HAL_UDP_WIFI_BACKOFF_MIN_MS;
    for (uint32_t i = 1u; i < attempt && base < HAL_UDP_WIFI_BACKOFF_MAX_MS; i++) {
        base *= 2u;
    }
    return base < HAL_UDP_WIFI_BACKOFF_MAX_MS ? base : HAL_UDP_WIFI_BACKOFF_MAX_MS;
}

// Count one failure and return the delay in ms before the next attempt.
// rnd: any 32-bit random value (esp_random() on the device).
static inline uint32_t hal_udp_wifi_backoff_next(hal_udp_wifi_backoff_t *b, uint32_t rnd)
{
    if (b->attempts < 0xFFFFFFFFu) {
        b->attempts++;
    }
    const uint32_t base = hal_udp_wifi_backoff_base_ms(b->attempts);
    const uint32_t span = base * HAL_UDP_WIFI_BACKOFF_JITTER_PCT / 100u;
    return base - span + rnd % (2u * span + 1u);
}

#ifdef __cplusplus
}
#endif
