// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * udp_link.h - Braid WiFi UDP transport adapter (PACKET link class, spec
 * 1.2 "WiFi UDP" row, 11.11, 12.4, Appendix C.4). Portable C11: no ESP-IDF,
 * FreeRTOS, lwIP or HAL header; the socket below it is injected as a table
 * of five function pointers (udp_link_ops_t, the hal_udp.h calls), so the
 * same file is host-tested with a fake socket and with real loopback
 * sockets (firmware/test/host/test_udp_link.c includes udp_link.c and
 * udp_link_hal.c directly) and on the device sits on hal_udp.h through
 * udp_link_ops_hal() (src/udp_link_hal.c).
 *
 * Where it lives (12.4, USER-DECIDED): the LAN side of the gateway only. A
 * UDP node never shares a chip with ESP-NOW: station association moves the
 * WiFi channel under the mesh. The console must refuse udp=on together
 * with espnow=on on one board (firmware/UDP-LINK.txt, Integration TODO).
 *
 * Transport facts (udp_link_fill_transport(), spec 1.2 table):
 *   link_class PACKET, max_frame 250, rs_nsym 0, can_broadcast true (floods
 *   go to one multicast datagram, or to every entry of the configured
 *   unicast peer list when multicast is off: C.4 "a configured unicast peer
 *   list replaces multicast on isolated LANs"), mac_retry false (see
 *   below), edge_only false, link_cost 1 (no RSSI on a LAN, 11.2),
 *   addr_len 6.
 *
 * Carrier address (deviation from the spec's addr_len 4, candidate for a
 * v0.9 note): 6 bytes, IPv4 in network order followed by the UDP port in
 * network order (a.b.c.d:port). The port is part of the address because
 * several nodes may share one IP (host tests: every node on 127.0.0.1 with
 * its own port; a laptop running two nodes), and a relay must tell them
 * apart when it unicasts. On a real LAN with every node on 40888 the
 * trailing two bytes are constant. The adapter keeps NO address table of
 * its own: it hands the sender's ip:port to br_node_rx() as the prev_hop
 * hint and the core learns (prev_hop, link) -> ip:port at pipeline step 6,
 * after the hop_tag check (so a spoofed prev_hop cannot redirect unicast,
 * unlike a table filled before authentication). send() gets that address
 * back for unicast frames. When the core has no link entry for next_hop it
 * calls send() with addr NULL even for a unicast frame (br_node.c
 * node_unicast: addr_len 0 -> broadcast); the adapter then floods the frame
 * (multicast / peer list) and counts unknown_next_hop.
 *
 * Delivery status: UDP has no acknowledgement. Like the UART adapter
 * (SPEC-NOTES N44) the transport is mac_retry false and every datagram the
 * socket accepted is later reported as delivered through
 * udp_link_report_tx_status() (br_node_tx_status(delivered = true, addr_len
 * 0)), never from inside send(). The core ignores the report for mac_retry
 * false, so 11.6 link deletion never fires on UDP; a dead peer is found by
 * ARQ / N37, keepalive, session timeout and table expiry (11.9).
 *
 * Receive: udp_link_pump() is called by the OWNER task (no thread of its
 * own): it waits at most timeout_ms for the first datagram, then drains
 * what else is queued without waiting (up to max_frames), and for each
 * datagram: drops oversize (> 250 bytes, counted), applies the bench
 * allowlist br_transport_admit() BEFORE br_node_rx() (SPEC-NOTES N22,
 * counted), and calls br_node_rx() with the ip:port hint. Two ways to run
 * it (firmware/UDP-LINK.txt): inside the existing "br" protocol task loop
 * with a short timeout (the task then wakes on UDP traffic as well as on
 * its queue), or from a small receive task on core 0 that copies each
 * datagram plus ip:port into the br queue (like the ESP-NOW callback) and
 * lets "br" call udp_link_deliver().
 *
 * Threading: one owner task for the whole object; not reentrant across tasks.
 */
#ifndef UDP_LINK_H
#define UDP_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "braid/br_node.h"
#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_LINK_MAX_FRAME    BR_MAX_FRAME_MESH                 /**< 250 */
#define UDP_LINK_COST         1u                                /**< 11.2 fixed cost (no RSSI) */
#define UDP_LINK_ADDR_LEN     6u                                /**< IPv4 (4) || port (2), network order */
#define UDP_LINK_PORT         40888u                            /**< C.4 */
#define UDP_LINK_MCAST_GROUP  0xEFFF2858u                       /**< 239.255.40.88 (C.4) */
#define UDP_LINK_TTL          1u                                /**< C.4: IP TTL 1 for floods */
#define UDP_LINK_RX_BUF       (UDP_LINK_MAX_FRAME + 6u)         /**< > max_frame so oversize is seen */
#ifndef UDP_LINK_MAX_PEERS
#define UDP_LINK_MAX_PEERS    8u                                /**< unicast peer list (br/udp_peers) */
#endif

/** IPv4 a.b.c.d as a host-order uint32_t (same convention as hal_udp.h). */
#define UDP_LINK_IP4(a, b, c, d) \
    ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) | (((uint32_t)(c)) << 8) | ((uint32_t)(d)))

/** One unicast peer. */
typedef struct {
    uint32_t ip;      /**< host order */
    uint16_t port;
} udp_link_peer_t;

/**
 * The socket below the adapter: the five hal_udp.h calls with the HAL
 * types erased (sock is the adapter's opaque socket storage, see
 * udp_link_ops_hal()). Return codes: 0 ok; 1 timeout (recvfrom only);
 * 2 busy / no buffer; 3 unsupported (multicast refused); other = error.
 */
#define UDP_LINK_IO_OK           0
#define UDP_LINK_IO_TIMEOUT      1
#define UDP_LINK_IO_BUSY         2
#define UDP_LINK_IO_UNSUPPORTED  3
#define UDP_LINK_IO_ERROR        4

typedef struct {
    int (*open)(void *sock, uint16_t local_port, uint32_t mcast_group, uint8_t ttl, bool mcast_loop,
                uint16_t *bound_port_out);
    int (*sendto)(void *sock, uint32_t ip, uint16_t port, const uint8_t *buf, size_t len);
    int (*recvfrom)(void *sock, uint8_t *buf, size_t cap, size_t *len_out, uint32_t *ip_out, uint16_t *port_out,
                    uint32_t timeout_ms);
    int (*mcast)(void *sock, uint32_t group, bool join);
    int (*close)(void *sock);
} udp_link_ops_t;

/** Storage for the socket object of the ops in use (hal_udp_t fits). */
#define UDP_LINK_SOCK_WORDS 8u

typedef struct {
    uint16_t        local_port;      /**< 0 = UDP_LINK_PORT; host tests pass 0xFFFF for "any free port" */
    bool            mcast;           /**< floods by multicast (else by the peer list) */
    uint32_t        mcast_group;     /**< 0 = UDP_LINK_MCAST_GROUP */
    uint16_t        mcast_port;      /**< 0 = UDP_LINK_PORT */
    uint8_t         ttl;             /**< 0 = UDP_LINK_TTL */
    bool            mcast_loop;      /**< receive own multicast (host tests only) */
    udp_link_peer_t peers[UDP_LINK_MAX_PEERS];
    uint8_t         n_peers;
} udp_link_cfg_t;

#define UDP_LINK_PORT_ANY 0xFFFFu

typedef struct {
    uint32_t tx_frames;        /**< frames accepted from the node (send() returned BR_OK) */
    uint32_t tx_datagrams;     /**< datagrams the socket accepted (peer-list floods count each) */
    uint32_t tx_unicast;       /**< frames sent to one learnt address */
    uint32_t tx_flood;         /**< frames flooded (multicast or peer list) */
    uint32_t tx_refused;       /**< frames lost: every sendto failed (BR_ERR_QUEUE_FULL / BR_ERR_BUSY) */
    uint32_t tx_partial;       /**< peer-list floods where some, not all, sendto failed */
    uint32_t tx_bad_len;       /**< send() with len 0 or > max_frame, or a bad address */
    uint32_t unknown_next_hop; /**< unicast frame with no learnt address: flooded instead */
    uint32_t rx_datagrams;     /**< datagrams received */
    uint32_t rx_frames;        /**< frames handed to br_node_rx() */
    uint32_t rx_err;           /**< socket receive errors, and empty datagrams */
    uint32_t oversize;         /**< datagrams > UDP_LINK_MAX_FRAME (dropped) */
    uint32_t allowlist_drop;   /**< frames refused by the bench allowlist (N22) */
    uint32_t tx_status;        /**< delivered = true reports passed to the node */
} udp_link_stats_t;

/** Adapter state. Treat every field as private. Statically allocatable. */
typedef struct {
    const udp_link_ops_t *ops;
    udp_link_cfg_t        cfg;
    bool                  open;
    bool                  mcast_joined;
    uint16_t              bound_port;
    uint32_t              tx_ok_pending;
    uint64_t              sock[UDP_LINK_SOCK_WORDS];
    uint8_t               rx[UDP_LINK_RX_BUF];
    udp_link_stats_t      st;
} udp_link_t;

/* ---- address helpers ------------------------------------------------------ */

/** Write ip:port as the 6-byte carrier address. */
void udp_link_addr_pack(uint32_t ip, uint16_t port, uint8_t out[UDP_LINK_ADDR_LEN]);

/** Read a 6-byte carrier address. */
void udp_link_addr_unpack(const uint8_t in[UDP_LINK_ADDR_LEN], uint32_t *ip_out, uint16_t *port_out);

/**
 * Parse "a.b.c.d" or "a.b.c.d:port" (console peers= value). Port defaults
 * to UDP_LINK_PORT. @return false on a malformed string (outputs untouched).
 */
bool udp_link_parse_peer(const char *s, uint32_t *ip_out, uint16_t *port_out);

/** Format ip:port into out (at most 22 chars incl. NUL). @return chars written (0 if cap too small). */
size_t udp_link_format_peer(uint32_t ip, uint16_t port, char *out, size_t cap);

/* ---- lifecycle ------------------------------------------------------------ */

/**
 * Reset the adapter, copy cfg (defaults filled for zero fields) and
 * install the socket ops (NULL = udp_link_ops_hal()). Does not open the
 * socket. @return false on NULL l, a cfg with mcast off and no peers, or
 * more than UDP_LINK_MAX_PEERS peers.
 */
bool udp_link_init(udp_link_t *l, const udp_link_cfg_t *cfg, const udp_link_ops_t *ops);

/**
 * Open the socket (bind cfg.local_port, join the group when cfg.mcast).
 * @return BR_OK; BR_ERR_ARG NULL / not initialised; BR_ERR_BUSY the port
 *         is taken or the socket could not be created; BR_ERR_NOT_IMPLEMENTED
 *         the multicast join was refused (socket open, floods would be
 *         lost: the caller switches to a peer list or gives up).
 */
br_err_t udp_link_open(udp_link_t *l);

/** Close the socket (idempotent). */
void udp_link_close(udp_link_t *l);

/** The local port actually bound (after udp_link_open()). */
uint16_t udp_link_bound_port(const udp_link_t *l);

/**
 * Fill the 1.2 transport fields for this link (name "udp", see the file
 * header) with send = udp_link_send and user = l. The allowlist is left
 * untouched (the caller sets it).
 */
void udp_link_fill_transport(udp_link_t *l, br_transport_t *tr);

/**
 * Convenience for node_app: udp_link_init(l, ucfg, NULL) and fill the next
 * free slot of cfg->transports (n_transports++). The caller sets the
 * slot's allowlist afterwards (cfg->transports[*link_out].allowlist) and
 * calls udp_link_open() before br_node_init().
 * @return BR_OK; BR_ERR_ARG (NULL, bad ucfg); BR_ERR_NO_MEM every slot used
 *         (BR_NODE_MAX_TRANSPORTS, see firmware/UDP-LINK.txt).
 */
br_err_t udp_link_register(br_node_config_t *cfg, udp_link_t *l, const udp_link_cfg_t *ucfg, uint8_t *link_out);

/* ---- data path -------------------------------------------------------------- */

/**
 * br_transport_t.send. addr NULL: flood (one multicast datagram, or one
 * unicast datagram per configured peer); else a 6-byte ip:port address
 * from the link table: one unicast datagram. A unicast frame (header
 * next_hop != 0xFFFF) arriving with addr NULL is flooded and counted
 * unknown_next_hop.
 * @return BR_OK at least one datagram was accepted; BR_ERR_ARG NULL user /
 *         frame, len 0; BR_ERR_TOO_BIG len > UDP_LINK_MAX_FRAME; BR_ERR_STATE
 *         socket not open; BR_ERR_QUEUE_FULL the socket had no buffer;
 *         BR_ERR_BUSY every datagram failed for another reason (frame lost,
 *         counted).
 */
br_err_t udp_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);

/**
 * Receive and deliver: wait at most timeout_ms for the first datagram,
 * then drain without waiting, at most max_frames datagrams in all (0 = 16).
 * Each datagram goes through udp_link_deliver().
 * @param tr  The node's copy of this transport (its allowlist); may be NULL (admit all).
 * @return datagrams handed to br_node_rx() (oversize / allowlist drops not counted).
 */
uint32_t udp_link_pump(udp_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr, uint32_t timeout_ms,
                       uint32_t max_frames);

/**
 * One received datagram (from udp_link_pump(), or from a receive task's
 * queue): oversize check, bench allowlist (N22) BEFORE br_node_rx(), then
 * br_node_rx() with the ip:port hint (addr_len 6, rssi unknown).
 * @param verdict_out  Optional, written only when the frame reached the node.
 * @return true if the frame reached br_node_rx(); false if dropped (counted) or bad arguments.
 */
bool udp_link_deliver(udp_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr, const uint8_t *frame,
                      size_t len, uint32_t ip, uint16_t port, br_rx_verdict_t *verdict_out);

/**
 * Report every frame the socket accepted since the last call as delivered
 * (br_node_tx_status(delivered = true, addr_len 0): a no-op in the core for
 * mac_retry false, kept for symmetry with the other adapters). Call from
 * the owner task outside any br_node_* call. @return reports made.
 */
uint32_t udp_link_report_tx_status(udp_link_t *l, br_node_t *node, uint8_t link);

/** Copy the counters. */
void udp_link_get_stats(const udp_link_t *l, udp_link_stats_t *out);

/**
 * The ops table over hal_udp.h (src/udp_link_hal.c, the only file of this
 * component that includes a HAL header). udp_link_t.sock holds the hal_udp_t.
 */
const udp_link_ops_t *udp_link_ops_hal(void);

#ifdef __cplusplus
}
#endif

#endif /* UDP_LINK_H */
