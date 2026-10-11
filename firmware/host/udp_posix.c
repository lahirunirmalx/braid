// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * udp_posix.c - POSIX implementation of hal_udp.h (host tests, and the
 * future "laptop node", see firmware/UDP-LINK.txt).
 *
 * Kept textually near-identical to components/port_esp_idf/port_udp.cpp:
 * the socket code is the same BSD API on both (ESP-IDF exposes lwIP through
 * <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>, <sys/select.h>); only the
 * language wrapper (C here, C++ with extern "C" there), the error logging
 * and the WiFi station helper differ. When you change one, change both.
 *
 * Host tests include this file directly (firmware/test/host/test_udp_link.c
 * line "#include \"../../host/udp_posix.c\""). The feature-test macro below
 * must be visible before the first system header, so a test that includes
 * this file defines _DEFAULT_SOURCE on its own first line.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../components/app_hal/include/hal_udp.h"

/* ---- common socket code (same in port_udp.cpp) --------------------------- */

static void udp_fill_addr(struct sockaddr_in *sa, uint32_t addr4, uint16_t port)
{
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(addr4);
}

static hal_result_t udp_errno_result(int e)
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

static hal_result_t udp_mcast_membership(int fd, uint32_t group, uint32_t mcast_if, bool join)
{
    struct ip_mreq mr;
    memset(&mr, 0, sizeof mr);
    mr.imr_multiaddr.s_addr = htonl(group);
    mr.imr_interface.s_addr = htonl(mcast_if == 0u ? INADDR_ANY : mcast_if);
    const int opt = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
    if (setsockopt(fd, IPPROTO_IP, opt, &mr, sizeof mr) != 0) {
        const hal_result_t r = udp_errno_result(errno);
        return r == HAL_ERR_HW_FAULT ? HAL_ERR_UNSUPPORTED : r;
    }
    return HAL_OK;
}

hal_result_t hal_udp_open(hal_udp_t *s, const hal_udp_cfg_t *cfg)
{
    if (s == NULL || cfg == NULL) {
        return HAL_ERR_INVALID_ARG;
    }
    s->fd = -1;
    s->local_port = 0;
    s->mcast_group = 0;
    const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return udp_errno_result(errno);
    }
    if (cfg->reuse_addr) {
        const int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    struct sockaddr_in sa;
    udp_fill_addr(&sa, INADDR_ANY, cfg->local_port);
    if (bind(fd, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        const int e = errno;
        (void)close(fd);
        return udp_errno_result(e);
    }
    socklen_t sl = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
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

hal_result_t hal_udp_sendto(hal_udp_t *s, uint32_t addr4, uint16_t port, const uint8_t *buf, size_t len)
{
    if (s == NULL || s->fd < 0 || buf == NULL || len == 0u || port == 0u) {
        return HAL_ERR_INVALID_ARG;
    }
    struct sockaddr_in sa;
    udp_fill_addr(&sa, addr4, port);
    const ssize_t n = sendto(s->fd, buf, len, 0, (const struct sockaddr *)&sa, sizeof sa);
    if (n < 0) {
        return udp_errno_result(errno);
    }
    return (size_t)n == len ? HAL_OK : HAL_ERR_HW_FAULT;
}

hal_result_t hal_udp_recvfrom(hal_udp_t *s, uint8_t *buf, size_t cap, size_t *len_out, uint32_t *addr4_out,
                              uint16_t *port_out, uint32_t timeout_ms)
{
    if (s == NULL || s->fd < 0 || buf == NULL || cap == 0u || len_out == NULL) {
        return HAL_ERR_INVALID_ARG;
    }
    *len_out = 0;
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(s->fd, &rs);
    struct timeval tv;
    tv.tv_sec = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    const int sel = select(s->fd + 1, &rs, NULL, NULL, &tv);
    if (sel < 0) {
        return errno == EINTR ? HAL_ERR_TIMEOUT : udp_errno_result(errno);
    }
    if (sel == 0) {
        return HAL_ERR_TIMEOUT;
    }
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    memset(&sa, 0, sizeof sa);
    const ssize_t n = recvfrom(s->fd, buf, cap, 0, (struct sockaddr *)&sa, &sl);
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
    *len_out = (size_t)n;
    if (addr4_out != NULL) {
        *addr4_out = ntohl(sa.sin_addr.s_addr);
    }
    if (port_out != NULL) {
        *port_out = ntohs(sa.sin_port);
    }
    return HAL_OK;
}

hal_result_t hal_udp_mcast(hal_udp_t *s, uint32_t group, uint32_t mcast_if, bool join)
{
    if (s == NULL || s->fd < 0 || group == 0u) {
        return HAL_ERR_INVALID_ARG;
    }
    const hal_result_t r = udp_mcast_membership(s->fd, group, mcast_if, join);
    if (r == HAL_OK) {
        s->mcast_group = join ? group : 0u;
    }
    return r;
}

hal_result_t hal_udp_close(hal_udp_t *s)
{
    if (s == NULL) {
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

/* ---- device-only helper: no WiFi driver on a host --------------------------- */

hal_result_t hal_udp_wifi_sta_start(const char *ssid, const char *pass, uint32_t timeout_ms, uint32_t *ip4_out)
{
    (void)ssid;
    (void)pass;
    (void)timeout_ms;
    if (ip4_out != NULL) {
        *ip4_out = 0;
    }
    return HAL_ERR_UNSUPPORTED;
}
