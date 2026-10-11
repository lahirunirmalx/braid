// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * udp_link.c - Braid WiFi UDP transport adapter (see udp_link.h).
 * Portable C11; host-tested by firmware/test/host/test_udp_link.c.
 */
#include "../include/udp_link.h" /* relative: host tests include this file without -I */

#include <string.h>

#include "braid/br_frame.h"

/* ---- address helpers ------------------------------------------------------ */

void udp_link_addr_pack(uint32_t ip, uint16_t port, uint8_t out[UDP_LINK_ADDR_LEN])
{
    out[0] = (uint8_t)(ip >> 24);
    out[1] = (uint8_t)(ip >> 16);
    out[2] = (uint8_t)(ip >> 8);
    out[3] = (uint8_t)ip;
    out[4] = (uint8_t)(port >> 8);
    out[5] = (uint8_t)port;
}

void udp_link_addr_unpack(const uint8_t in[UDP_LINK_ADDR_LEN], uint32_t *ip_out, uint16_t *port_out)
{
    if (ip_out != NULL) {
        *ip_out = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    }
    if (port_out != NULL) {
        *port_out = (uint16_t)(((uint16_t)in[4] << 8) | (uint16_t)in[5]);
    }
}

/* Decimal number of at most max_digits digits with value <= max; advances *s. */
static bool parse_dec(const char **s, uint32_t max, unsigned max_digits, uint32_t *out)
{
    const char *p = *s;
    uint32_t v = 0;
    unsigned n = 0;
    while (*p >= '0' && *p <= '9') {
        if (n == max_digits) {
            return false;
        }
        v = v * 10u + (uint32_t)(*p - '0');
        if (v > max) {
            return false;
        }
        p++;
        n++;
    }
    if (n == 0u) {
        return false;
    }
    *s = p;
    *out = v;
    return true;
}

bool udp_link_parse_peer(const char *s, uint32_t *ip_out, uint16_t *port_out)
{
    if (s == NULL) {
        return false;
    }
    uint32_t ip = 0;
    for (unsigned i = 0; i < 4u; i++) {
        uint32_t oct = 0;
        if (!parse_dec(&s, 255u, 3u, &oct)) {
            return false;
        }
        ip = (ip << 8) | oct;
        if (i < 3u) {
            if (*s != '.') {
                return false;
            }
            s++;
        }
    }
    uint32_t port = UDP_LINK_PORT;
    if (*s == ':') {
        s++;
        if (!parse_dec(&s, 65535u, 5u, &port) || port == 0u) {
            return false;
        }
    }
    if (*s != '\0') {
        return false;
    }
    if (ip_out != NULL) {
        *ip_out = ip;
    }
    if (port_out != NULL) {
        *port_out = (uint16_t)port;
    }
    return true;
}

static size_t put_dec(char *out, size_t cap, uint32_t v)
{
    char tmp[10];
    size_t n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v != 0u);
    if (n > cap) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1u - i];
    }
    return n;
}

size_t udp_link_format_peer(uint32_t ip, uint16_t port, char *out, size_t cap)
{
    char buf[22];
    size_t n = 0;
    for (unsigned i = 0; i < 4u; i++) {
        n += put_dec(buf + n, sizeof buf - n, (ip >> (24u - 8u * i)) & 0xFFu);
        buf[n++] = (i < 3u) ? '.' : ':';
    }
    n += put_dec(buf + n, sizeof buf - n, port);
    if (out == NULL || cap <= n) {
        return 0;
    }
    memcpy(out, buf, n);
    out[n] = '\0';
    return n;
}

/* ---- lifecycle ------------------------------------------------------------ */

bool udp_link_init(udp_link_t *l, const udp_link_cfg_t *cfg, const udp_link_ops_t *ops)
{
    if (l == NULL || cfg == NULL || cfg->n_peers > UDP_LINK_MAX_PEERS || (!cfg->mcast && cfg->n_peers == 0u)) {
        return false;
    }
    for (uint8_t i = 0; i < cfg->n_peers; i++) {
        if (cfg->peers[i].port == 0u) {
            return false;
        }
    }
    memset(l, 0, sizeof *l);
    l->ops = ops != NULL ? ops : udp_link_ops_hal();
    l->cfg = *cfg;
    if (l->cfg.local_port == 0u) {
        l->cfg.local_port = UDP_LINK_PORT;
    }
    if (l->cfg.mcast_group == 0u) {
        l->cfg.mcast_group = UDP_LINK_MCAST_GROUP;
    }
    if (l->cfg.mcast_port == 0u) {
        l->cfg.mcast_port = UDP_LINK_PORT;
    }
    if (l->cfg.ttl == 0u) {
        l->cfg.ttl = UDP_LINK_TTL;
    }
    return true;
}

br_err_t udp_link_open(udp_link_t *l)
{
    if (l == NULL || l->ops == NULL || l->ops->open == NULL) {
        return BR_ERR_ARG;
    }
    if (l->open) {
        return BR_OK;
    }
    const uint16_t want = l->cfg.local_port == UDP_LINK_PORT_ANY ? 0u : l->cfg.local_port;
    uint16_t bound = 0;
    const int r = l->ops->open(l->sock, want, l->cfg.mcast ? l->cfg.mcast_group : 0u, l->cfg.ttl, l->cfg.mcast_loop,
                               &bound);
    if (r == UDP_LINK_IO_OK) {
        l->open = true;
        l->bound_port = bound;
        l->mcast_joined = l->cfg.mcast;
        return BR_OK;
    }
    if (r == UDP_LINK_IO_UNSUPPORTED) {
        l->open = true; /* socket is up, the group is not */
        l->bound_port = bound;
        l->mcast_joined = false;
        return BR_ERR_NOT_IMPLEMENTED;
    }
    return BR_ERR_BUSY;
}

void udp_link_close(udp_link_t *l)
{
    if (l == NULL || !l->open) {
        return;
    }
    if (l->ops != NULL && l->ops->close != NULL) {
        (void)l->ops->close(l->sock);
    }
    l->open = false;
    l->mcast_joined = false;
}

uint16_t udp_link_bound_port(const udp_link_t *l)
{
    return (l != NULL && l->open) ? l->bound_port : 0u;
}

void udp_link_fill_transport(udp_link_t *l, br_transport_t *tr)
{
    if (tr == NULL) {
        return;
    }
    tr->name = "udp";
    tr->link_class = BR_LINK_PACKET;
    tr->max_frame = UDP_LINK_MAX_FRAME;
    tr->rs_nsym = BR_RS_NSYM_PACKET;
    tr->can_broadcast = true;
    tr->mac_retry = false;
    tr->edge_only = false;
    tr->link_cost = UDP_LINK_COST;
    tr->addr_len = UDP_LINK_ADDR_LEN;
    tr->send = udp_link_send;
    tr->user = l;
}

br_err_t udp_link_register(br_node_config_t *cfg, udp_link_t *l, const udp_link_cfg_t *ucfg, uint8_t *link_out)
{
    if (cfg == NULL || l == NULL || ucfg == NULL) {
        return BR_ERR_ARG;
    }
    if (cfg->n_transports >= BR_NODE_MAX_TRANSPORTS) {
        return BR_ERR_NO_MEM;
    }
    if (!udp_link_init(l, ucfg, NULL)) {
        return BR_ERR_ARG;
    }
    const uint8_t idx = cfg->n_transports;
    udp_link_fill_transport(l, &cfg->transports[idx]);
    cfg->n_transports = (uint8_t)(idx + 1u);
    if (link_out != NULL) {
        *link_out = idx;
    }
    return BR_OK;
}

/* ---- transmit ------------------------------------------------------------- */

/* One datagram; maps the io code and counts. */
static int send_one(udp_link_t *l, uint32_t ip, uint16_t port, const uint8_t *frame, uint16_t len)
{
    const int r = l->ops->sendto(l->sock, ip, port, frame, len);
    if (r == UDP_LINK_IO_OK) {
        l->st.tx_datagrams++;
    }
    return r;
}

static br_err_t io_to_err(int r)
{
    return r == UDP_LINK_IO_BUSY ? BR_ERR_QUEUE_FULL : BR_ERR_BUSY;
}

static br_err_t flood(udp_link_t *l, const uint8_t *frame, uint16_t len)
{
    l->st.tx_flood++;
    if (l->cfg.mcast) {
        const int r = send_one(l, l->cfg.mcast_group, l->cfg.mcast_port, frame, len);
        if (r != UDP_LINK_IO_OK) {
            l->st.tx_refused++;
            return io_to_err(r);
        }
        return BR_OK;
    }
    unsigned ok = 0;
    int last = UDP_LINK_IO_ERROR;
    for (uint8_t i = 0; i < l->cfg.n_peers; i++) {
        const int r = send_one(l, l->cfg.peers[i].ip, l->cfg.peers[i].port, frame, len);
        if (r == UDP_LINK_IO_OK) {
            ok++;
        } else {
            last = r;
        }
    }
    if (ok == 0u) {
        l->st.tx_refused++;
        return io_to_err(last);
    }
    if (ok < l->cfg.n_peers) {
        l->st.tx_partial++;
    }
    return BR_OK;
}

br_err_t udp_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    udp_link_t *l = (udp_link_t *)user;
    if (l == NULL || frame == NULL || len == 0u) {
        if (l != NULL) {
            l->st.tx_bad_len++;
        }
        return BR_ERR_ARG;
    }
    if (len > UDP_LINK_MAX_FRAME) {
        l->st.tx_bad_len++;
        return BR_ERR_TOO_BIG;
    }
    if (!l->open || l->ops == NULL || l->ops->sendto == NULL) {
        return BR_ERR_STATE;
    }
    br_err_t rc;
    if (addr == NULL) {
        if (len >= BR_OFF_NEXT_HOP + 2u && br_rd_le16(frame + BR_OFF_NEXT_HOP) != BR_ID_FLOOD) {
            l->st.unknown_next_hop++; /* unicast frame, no learnt address: the core asked for a broadcast */
        }
        rc = flood(l, frame, len);
    } else {
        uint32_t ip = 0;
        uint16_t port = 0;
        udp_link_addr_unpack(addr, &ip, &port);
        if (port == 0u) {
            l->st.tx_bad_len++;
            return BR_ERR_ARG;
        }
        l->st.tx_unicast++;
        const int r = send_one(l, ip, port, frame, len);
        if (r != UDP_LINK_IO_OK) {
            l->st.tx_refused++;
            return io_to_err(r);
        }
        rc = BR_OK;
    }
    if (rc == BR_OK) {
        l->st.tx_frames++;
        l->tx_ok_pending++;
    }
    return rc;
}

/* ---- receive --------------------------------------------------------------- */

bool udp_link_deliver(udp_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr, const uint8_t *frame,
                      size_t len, uint32_t ip, uint16_t port, br_rx_verdict_t *verdict_out)
{
    if (l == NULL || node == NULL || frame == NULL) {
        return false;
    }
    l->st.rx_datagrams++;
    if (len == 0u) {
        l->st.rx_err++;
        return false;
    }
    if (len > UDP_LINK_MAX_FRAME) {
        l->st.oversize++;
        return false;
    }
    if (!br_transport_admit(tr, frame, len)) {
        l->st.allowlist_drop++;
        return false;
    }
    br_rx_meta_t m;
    memset(&m, 0, sizeof m);
    udp_link_addr_pack(ip, port, m.addr);
    m.addr_len = UDP_LINK_ADDR_LEN;
    m.rssi = (int8_t)BR_RSSI_UNKNOWN;
    l->st.rx_frames++;
    (void)br_node_rx(node, frame, len, link, &m, verdict_out);
    return true;
}

uint32_t udp_link_pump(udp_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr, uint32_t timeout_ms,
                       uint32_t max_frames)
{
    if (l == NULL || node == NULL || !l->open || l->ops == NULL || l->ops->recvfrom == NULL) {
        return 0u;
    }
    if (max_frames == 0u) {
        max_frames = 16u;
    }
    uint32_t delivered = 0;
    uint32_t wait = timeout_ms;
    for (uint32_t i = 0; i < max_frames; i++) {
        size_t n = 0;
        uint32_t ip = 0;
        uint16_t port = 0;
        const int r = l->ops->recvfrom(l->sock, l->rx, sizeof l->rx, &n, &ip, &port, wait);
        wait = 0u; /* only the first datagram is waited for */
        if (r == UDP_LINK_IO_TIMEOUT) {
            break;
        }
        if (r != UDP_LINK_IO_OK) {
            l->st.rx_err++;
            break;
        }
        if (udp_link_deliver(l, node, link, tr, l->rx, n, ip, port, NULL)) {
            delivered++;
        }
    }
    return delivered;
}

uint32_t udp_link_report_tx_status(udp_link_t *l, br_node_t *node, uint8_t link)
{
    if (l == NULL || node == NULL) {
        return 0u;
    }
    const uint32_t n = l->tx_ok_pending;
    l->tx_ok_pending = 0u;
    for (uint32_t i = 0; i < n; i++) {
        (void)br_node_tx_status(node, link, NULL, 0u, true);
    }
    l->st.tx_status += n;
    return n;
}

void udp_link_get_stats(const udp_link_t *l, udp_link_stats_t *out)
{
    if (l == NULL || out == NULL) {
        return;
    }
    *out = l->st;
}
