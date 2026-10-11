// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * udp_link_hal.c - the udp_link_ops_t table over hal_udp.h. The only file
 * of app_udp_link that includes a HAL header; udp_link.c stays HAL-free so
 * the host test can drive it with a fake table.
 *
 * Host tests include this file after udp_link.c and host/udp_posix.c.
 */
#include <stddef.h>
#include <string.h>

#include "../../app_hal/include/hal_udp.h" /* relative: host tests include this file without -I */
#include "../include/udp_link.h" /* relative: host tests include this file without -I */

/* hal_udp_t must fit the adapter's opaque socket storage. */
typedef char udp_link_sock_fits[(sizeof(hal_udp_t) <= sizeof(uint64_t) * UDP_LINK_SOCK_WORDS) ? 1 : -1];

static int map(hal_result_t r)
{
    switch (r) {
    case HAL_OK:
        return UDP_LINK_IO_OK;
    case HAL_ERR_TIMEOUT:
        return UDP_LINK_IO_TIMEOUT;
    case HAL_ERR_BUSY:
    case HAL_ERR_NO_MEM:
        return UDP_LINK_IO_BUSY;
    case HAL_ERR_UNSUPPORTED:
        return UDP_LINK_IO_UNSUPPORTED;
    default:
        return UDP_LINK_IO_ERROR;
    }
}

static int ops_open(void *sock, uint16_t local_port, uint32_t mcast_group, uint8_t ttl, bool mcast_loop,
                    uint16_t *bound_port_out)
{
    hal_udp_t *s = (hal_udp_t *)sock;
    hal_udp_cfg_t c;
    memset(&c, 0, sizeof c);
    c.local_port = local_port;
    c.mcast_group = mcast_group;
    c.mcast_if = 0u;
    c.mcast_ttl = ttl;
    c.mcast_loop = mcast_loop;
    c.reuse_addr = mcast_group != 0u; /* several receivers of one multicast port on one host */
    const hal_result_t r = hal_udp_open(s, &c);
    if (bound_port_out != NULL) {
        *bound_port_out = s->local_port;
    }
    return map(r);
}

static int ops_sendto(void *sock, uint32_t ip, uint16_t port, const uint8_t *buf, size_t len)
{
    return map(hal_udp_sendto((hal_udp_t *)sock, ip, port, buf, len));
}

static int ops_recvfrom(void *sock, uint8_t *buf, size_t cap, size_t *len_out, uint32_t *ip_out, uint16_t *port_out,
                        uint32_t timeout_ms)
{
    return map(hal_udp_recvfrom((hal_udp_t *)sock, buf, cap, len_out, ip_out, port_out, timeout_ms));
}

static int ops_mcast(void *sock, uint32_t group, bool join)
{
    return map(hal_udp_mcast((hal_udp_t *)sock, group, 0u, join));
}

static int ops_close(void *sock)
{
    return map(hal_udp_close((hal_udp_t *)sock));
}

const udp_link_ops_t *udp_link_ops_hal(void)
{
    static const udp_link_ops_t ops = {ops_open, ops_sendto, ops_recvfrom, ops_mcast, ops_close};
    return &ops;
}
