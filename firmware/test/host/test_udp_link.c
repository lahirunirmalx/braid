// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_udp_link.c - host test of the WiFi UDP transport adapter
 * (components/app_udp_link; spec 1.2 "WiFi UDP" row, 11.11, 12.4, C.4;
 * SPEC-NOTES N22). ASCII only.
 *
 * The adapter is portable C; this test compiles the real sources into the
 * executable (as test_uart_link.c does): udp_link.c, the POSIX hal_udp port
 * host/udp_posix.c and the ops glue udp_link_hal.c.
 *
 * Part A  Adapter unit tests against a FAKE socket table: transport
 *         fields, peer parsing, address packing, init / open errors,
 *         floods by multicast vs peer list, unicast to a learnt address,
 *         unknown next_hop fallback, send errors, oversize drop, bench
 *         allowlist, receive errors, tx-status reporting.
 * Part B  REAL sockets on 127.0.0.1: sender 0x0101 and probe 0x0103 (group
 *         0xFF10), each br_node with its own udp_link on its own port,
 *         unicast peer lists (multicast on loopback is unreliable in CI),
 *         Appendix A bench key, AUTH on, fec_m 0, ARQ on: seek, bind, the
 *         sender's link table holds the probe's ip:port (addr_len 6),
 *         presses delivered with hops == 1 and acknowledged.
 * Part C  Three nodes with relay 0x0102; peer lists A = {B}, B = {A, C},
 *         C = {B} and matching allowlists: presses delivered with hops == 2.
 * Part D  Multicast on loopback: join / leave and a flood through two
 *         adapters sharing one port; skipped (not failed) when the host
 *         offers no multicast on the loopback interface.
 *
 * Time is real: br_platform now_us is CLOCK_MONOTONIC and every wait is
 * bounded in wall time. Total run is a few seconds.
 */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include <time.h>

#include "braid/br_frame.h"
#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_sample.h"
#include "braid/br_session.h"
#include "braid/br_tables.h"
#include "test_util.h"
#include "vectors_generated.h"

#include "../../components/app_udp_link/include/udp_link.h"
#include "../../components/app_udp_link/src/udp_link.c"
#include "../../host/udp_posix.c"
#include "../../components/app_udp_link/src/udp_link_hal.c"

/* ========================================================================= */
/* Platform: real monotonic clock, OS randomness                             */
/* ========================================================================= */

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t t_now(void *user)
{
    (void)user;
    return now_us();
}

static FILE *g_urandom;
static tu_rng_t g_fallback_rng;

static br_err_t t_random(void *user, uint8_t *buf, size_t len)
{
    (void)user;
    if (g_urandom != NULL && fread(buf, 1, len, g_urandom) == len) {
        return BR_OK;
    }
    tu_rng_fill(&g_fallback_rng, buf, len);
    return BR_OK;
}

static void t_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    (void)user;
    (void)level;
    (void)tag;
    (void)msg;
}

static br_stats_t node_stats(const br_node_t *n)
{
    br_stats_t s;
    memset(&s, 0, sizeof s);
    CHECK_ERR(br_node_get_stats(n, &s), BR_OK);
    return s;
}

/* Demo node config shared by every part (node_app kCapsBase; test_uart_link.c). */
static void base_cfg(br_node_config_t *c, uint16_t unit, bool probe)
{
    memset(c, 0, sizeof *c);
    c->unit_id = unit;
    c->role = BR_ROLE_NODE;
    c->node_count = 3;
    c->seek_ttl = BR_SEEK_TTL_DEFAULT;
    c->caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY;
    if (probe) {
        c->caps = (uint16_t)(c->caps | BR_CAP_MULTI);
        c->groups[0] = 0xFF10;
        c->n_groups = 1;
    }
    c->auth = true;
    c->cold_boot = false;
    c->key_epoch = 1;
    c->net_key = BRV_A6_K_SITE; /* Appendix A bench key (node_app kBenchKey) */
    c->net_key_len = BRV_A6_K_SITE_LEN;
    c->txseq_start = 1;
    c->preseq_start = 1;
}

/* ========================================================================= */
/* Part A: fake socket                                                        */
/* ========================================================================= */

#define FAKE_MAX_TX 32u
#define FAKE_MAX_RX 8u

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint16_t len;
    uint8_t  data[300];
} fake_dgram_t;

typedef struct {
    /* open */
    int      open_rc;
    uint16_t open_local_port;
    uint32_t open_group;
    uint8_t  open_ttl;
    bool     open_loop;
    uint16_t bound_port;
    unsigned opens;
    unsigned closes;
    /* sendto */
    int      send_rc;          /* applied to every sendto */
    int      send_rc_nth;      /* if >= 0: only the nth sendto (0-based) gets send_rc, others OK */
    unsigned sends;
    fake_dgram_t tx[FAKE_MAX_TX];
    unsigned n_tx;
    /* recvfrom */
    fake_dgram_t rx[FAKE_MAX_RX];
    unsigned n_rx;
    unsigned rx_rd;
    int      rx_err_after;     /* if >= 0: recvfrom returns UDP_LINK_IO_ERROR once the queue is drained */
    unsigned recvs;
    uint32_t first_timeout;
    uint32_t last_timeout;
    /* mcast */
    unsigned joins;
    unsigned leaves;
} fake_t;

static fake_t F;

static void fake_reset(void)
{
    memset(&F, 0, sizeof F);
    F.open_rc = UDP_LINK_IO_OK;
    F.bound_port = 40888;
    F.send_rc = UDP_LINK_IO_OK;
    F.send_rc_nth = -1;
    F.rx_err_after = -1;
    F.first_timeout = 0xFFFFFFFFu;
}

static int fk_open(void *sock, uint16_t local_port, uint32_t group, uint8_t ttl, bool loop, uint16_t *bound)
{
    (void)sock;
    F.opens++;
    F.open_local_port = local_port;
    F.open_group = group;
    F.open_ttl = ttl;
    F.open_loop = loop;
    if (bound != NULL) {
        *bound = local_port == 0u ? F.bound_port : local_port;
    }
    return F.open_rc;
}

static int fk_sendto(void *sock, uint32_t ip, uint16_t port, const uint8_t *buf, size_t len)
{
    (void)sock;
    const unsigned i = F.sends++;
    int rc = UDP_LINK_IO_OK;
    if (F.send_rc_nth < 0) {
        rc = F.send_rc;
    } else if ((int)i == F.send_rc_nth) {
        rc = F.send_rc;
    }
    if (rc == UDP_LINK_IO_OK && F.n_tx < FAKE_MAX_TX && len <= sizeof F.tx[0].data) {
        fake_dgram_t *d = &F.tx[F.n_tx++];
        d->ip = ip;
        d->port = port;
        d->len = (uint16_t)len;
        memcpy(d->data, buf, len);
    }
    return rc;
}

static int fk_recvfrom(void *sock, uint8_t *buf, size_t cap, size_t *len_out, uint32_t *ip, uint16_t *port,
                       uint32_t timeout_ms)
{
    (void)sock;
    if (F.recvs == 0u) {
        F.first_timeout = timeout_ms;
    }
    F.last_timeout = timeout_ms;
    F.recvs++;
    if (F.rx_rd >= F.n_rx) {
        return F.rx_err_after >= 0 ? UDP_LINK_IO_ERROR : UDP_LINK_IO_TIMEOUT;
    }
    const fake_dgram_t *d = &F.rx[F.rx_rd++];
    size_t n = d->len;
    if (n > cap) {
        n = cap; /* truncation, as a real socket does */
    }
    memcpy(buf, d->data, n);
    *len_out = n;
    *ip = d->ip;
    *port = d->port;
    return UDP_LINK_IO_OK;
}

static int fk_mcast(void *sock, uint32_t group, bool join)
{
    (void)sock;
    (void)group;
    if (join) {
        F.joins++;
    } else {
        F.leaves++;
    }
    return UDP_LINK_IO_OK;
}

static int fk_close(void *sock)
{
    (void)sock;
    F.closes++;
    return UDP_LINK_IO_OK;
}

static const udp_link_ops_t FAKE_OPS = {fk_open, fk_sendto, fk_recvfrom, fk_mcast, fk_close};

static void fake_push_rx(uint32_t ip, uint16_t port, const uint8_t *d, size_t n)
{
    CHECK(F.n_rx < FAKE_MAX_RX && n <= sizeof F.rx[0].data);
    fake_dgram_t *g = &F.rx[F.n_rx++];
    g->ip = ip;
    g->port = port;
    g->len = (uint16_t)n;
    if (n > 0u) {
        memcpy(g->data, d, n);
    }
}

static udp_link_t L;

static udp_link_cfg_t cfg_mcast(void)
{
    udp_link_cfg_t c;
    memset(&c, 0, sizeof c);
    c.mcast = true;
    return c;
}

static udp_link_cfg_t cfg_peers(unsigned n)
{
    udp_link_cfg_t c;
    memset(&c, 0, sizeof c);
    for (unsigned i = 0; i < n && i < UDP_LINK_MAX_PEERS; i++) {
        c.peers[i].ip = UDP_LINK_IP4(192, 168, 1, 10 + i);
        c.peers[i].port = (uint16_t)(40000u + i);
    }
    c.n_peers = (uint8_t)n;
    return c;
}

static void test_transport_fields(void)
{
    tu_ctx("transport fields (1.2 WiFi UDP row)");
    fake_reset();
    udp_link_cfg_t c = cfg_mcast();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    br_transport_t tr;
    memset(&tr, 0xAA, sizeof tr);
    udp_link_fill_transport(&L, &tr);
    CHECK(strcmp(tr.name, "udp") == 0);
    CHECK_EQ_U32(tr.link_class, BR_LINK_PACKET);
    CHECK_EQ_U32(tr.max_frame, 250u);
    CHECK_EQ_U32(tr.rs_nsym, 0u);
    CHECK(tr.can_broadcast);
    CHECK(!tr.mac_retry);
    CHECK(!tr.edge_only);
    CHECK_EQ_U32(tr.link_cost, 1u);
    CHECK_EQ_U32(tr.addr_len, 6u);
    CHECK(tr.addr_len <= BR_ADDR_MAX);
    CHECK(tr.send == udp_link_send);
    CHECK(tr.user == &L);
    /* defaults filled */
    CHECK_EQ_U32(L.cfg.local_port, 40888u);
    CHECK_EQ_U32(L.cfg.mcast_group, UDP_LINK_IP4(239, 255, 40, 88));
    CHECK_EQ_U32(L.cfg.mcast_port, 40888u);
    CHECK_EQ_U32(L.cfg.ttl, 1u);
    CHECK_EQ_U32(UDP_LINK_MCAST_GROUP, 0xEFFF2858u);
    CHECK(udp_link_ops_hal() != NULL);
    CHECK(sizeof(hal_udp_t) <= sizeof L.sock);
}

static void test_peer_parse_format(void)
{
    uint32_t ip = 0;
    uint16_t port = 0;
    char buf[24];

    tu_ctx("parse a.b.c.d:port");
    CHECK(udp_link_parse_peer("192.168.1.20:40888", &ip, &port));
    CHECK_EQ_U32(ip, UDP_LINK_IP4(192, 168, 1, 20));
    CHECK_EQ_U32(port, 40888u);
    CHECK(udp_link_parse_peer("10.0.0.1", &ip, &port));
    CHECK_EQ_U32(ip, UDP_LINK_IP4(10, 0, 0, 1));
    CHECK_EQ_U32(port, UDP_LINK_PORT);
    CHECK(udp_link_parse_peer("255.255.255.255:65535", &ip, &port));
    CHECK_EQ_U32(ip, 0xFFFFFFFFu);
    CHECK_EQ_U32(port, 65535u);
    CHECK(udp_link_parse_peer("0.0.0.0:1", &ip, &port));
    CHECK_EQ_U32(ip, 0u);
    CHECK_EQ_U32(port, 1u);

    tu_ctx("parse rejects");
    ip = 7;
    port = 7;
    CHECK(!udp_link_parse_peer("", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4.5", &ip, &port));
    CHECK(!udp_link_parse_peer("256.1.1.1", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4:0", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4:65536", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4:", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4:12a", &ip, &port));
    CHECK(!udp_link_parse_peer("1.2.3.4 ", &ip, &port));
    CHECK(!udp_link_parse_peer("a.b.c.d", &ip, &port));
    CHECK(!udp_link_parse_peer("1..2.3", &ip, &port));
    CHECK(!udp_link_parse_peer("0001.2.3.4", &ip, &port));
    CHECK(!udp_link_parse_peer(NULL, &ip, &port));
    CHECK_EQ_U32(ip, 7u); /* outputs untouched on failure */
    CHECK_EQ_U32(port, 7u);

    tu_ctx("format");
    CHECK_EQ_U32(udp_link_format_peer(UDP_LINK_IP4(192, 168, 1, 20), 40888, buf, sizeof buf), 18u);
    CHECK(strcmp(buf, "192.168.1.20:40888") == 0);
    CHECK_EQ_U32(udp_link_format_peer(0xFFFFFFFFu, 65535, buf, sizeof buf), 21u);
    CHECK(strcmp(buf, "255.255.255.255:65535") == 0);
    CHECK_EQ_U32(udp_link_format_peer(0, 1, buf, sizeof buf), 9u);
    CHECK(strcmp(buf, "0.0.0.0:1") == 0);
    CHECK_EQ_U32(udp_link_format_peer(0xFFFFFFFFu, 65535, buf, 21), 0u); /* needs 22 */
    CHECK_EQ_U32(udp_link_format_peer(0, 1, NULL, 99), 0u);
    /* round trip */
    CHECK(udp_link_parse_peer("172.16.254.3:4100", &ip, &port));
    CHECK(udp_link_format_peer(ip, port, buf, sizeof buf) > 0u);
    CHECK(strcmp(buf, "172.16.254.3:4100") == 0);

    tu_ctx("address pack / unpack (6 bytes: IPv4 || port, network order)");
    uint8_t a[UDP_LINK_ADDR_LEN];
    udp_link_addr_pack(UDP_LINK_IP4(192, 168, 1, 20), 40888, a);
    const uint8_t exp[6] = {192, 168, 1, 20, 0x9F, 0xB8};
    CHECK_MEM(exp, a, 6);
    ip = 0;
    port = 0;
    udp_link_addr_unpack(a, &ip, &port);
    CHECK_EQ_U32(ip, UDP_LINK_IP4(192, 168, 1, 20));
    CHECK_EQ_U32(port, 40888u);
    udp_link_addr_unpack(a, NULL, NULL); /* tolerated */
}

static void test_init_and_open(void)
{
    udp_link_cfg_t c;

    tu_ctx("init rejects");
    fake_reset();
    memset(&c, 0, sizeof c); /* mcast off, no peers: floods would go nowhere */
    CHECK(!udp_link_init(&L, &c, &FAKE_OPS));
    c = cfg_peers(1);
    c.n_peers = UDP_LINK_MAX_PEERS + 1u;
    CHECK(!udp_link_init(&L, &c, &FAKE_OPS));
    c = cfg_peers(2);
    c.peers[1].port = 0;
    CHECK(!udp_link_init(&L, &c, &FAKE_OPS));
    CHECK(!udp_link_init(NULL, &c, &FAKE_OPS));
    CHECK(!udp_link_init(&L, NULL, &FAKE_OPS));
    c = cfg_peers(UDP_LINK_MAX_PEERS);
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK(udp_link_init(&L, &c, NULL)); /* NULL ops = HAL table */
    CHECK(L.ops == udp_link_ops_hal());

    tu_ctx("open multicast: group, ttl, loop reach the socket");
    fake_reset();
    c = cfg_mcast();
    c.ttl = 3;
    c.mcast_loop = true;
    c.local_port = 41000;
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK(!L.open);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_STATE); /* not open */
    CHECK_ERR(udp_link_open(&L), BR_OK);
    CHECK(L.open);
    CHECK(L.mcast_joined);
    CHECK_EQ_U32(F.opens, 1u);
    CHECK_EQ_U32(F.open_local_port, 41000u);
    CHECK_EQ_U32(F.open_group, UDP_LINK_MCAST_GROUP);
    CHECK_EQ_U32(F.open_ttl, 3u);
    CHECK(F.open_loop);
    CHECK_EQ_U32(udp_link_bound_port(&L), 41000u);
    CHECK_ERR(udp_link_open(&L), BR_OK); /* idempotent */
    CHECK_EQ_U32(F.opens, 1u);
    udp_link_close(&L);
    CHECK(!L.open);
    CHECK_EQ_U32(F.closes, 1u);
    udp_link_close(&L);
    CHECK_EQ_U32(F.closes, 1u);
    CHECK_EQ_U32(udp_link_bound_port(&L), 0u);

    tu_ctx("open peer list: no group; port any");
    fake_reset();
    c = cfg_peers(2);
    c.local_port = UDP_LINK_PORT_ANY;
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    CHECK_EQ_U32(F.open_local_port, 0u);
    CHECK_EQ_U32(F.open_group, 0u);
    CHECK(!L.mcast_joined);
    CHECK_EQ_U32(udp_link_bound_port(&L), 40888u); /* what the fake bound */
    udp_link_close(&L);

    tu_ctx("open: join refused -> socket up, BR_ERR_NOT_IMPLEMENTED");
    fake_reset();
    F.open_rc = UDP_LINK_IO_UNSUPPORTED;
    c = cfg_mcast();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_ERR_NOT_IMPLEMENTED);
    CHECK(L.open);
    CHECK(!L.mcast_joined);
    udp_link_close(&L);

    tu_ctx("open: bind failed -> BR_ERR_BUSY");
    fake_reset();
    F.open_rc = UDP_LINK_IO_BUSY;
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_ERR_BUSY);
    CHECK(!L.open);
    CHECK_ERR(udp_link_open(NULL), BR_ERR_ARG);

    tu_ctx("register fills a transport slot");
    br_node_config_t nc;
    memset(&nc, 0, sizeof nc);
    nc.n_transports = 1; /* pretend espnow is slot 0 */
    uint8_t idx = 0xFF;
    c = cfg_peers(1);
    CHECK_ERR(udp_link_register(&nc, &L, &c, &idx), BR_OK);
    CHECK_EQ_U32(idx, 1u);
    CHECK_EQ_U32(nc.n_transports, 2u);
    CHECK(nc.transports[1].send == udp_link_send);
    CHECK(nc.transports[1].user == &L);
    CHECK_EQ_U32(nc.transports[1].addr_len, 6u);
    CHECK(L.ops == udp_link_ops_hal());
    nc.n_transports = BR_NODE_MAX_TRANSPORTS;
    CHECK_ERR(udp_link_register(&nc, &L, &c, &idx), BR_ERR_NO_MEM);
    nc.n_transports = 0;
    memset(&c, 0, sizeof c);
    CHECK_ERR(udp_link_register(&nc, &L, &c, &idx), BR_ERR_ARG); /* bad ucfg */
    CHECK_ERR(udp_link_register(NULL, &L, &c, &idx), BR_ERR_ARG);
}

static void test_send(void)
{
    udp_link_cfg_t c;
    uint8_t addr[UDP_LINK_ADDR_LEN];

    tu_ctx("send: argument errors");
    fake_reset();
    c = cfg_mcast();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    CHECK_ERR(udp_link_send(NULL, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_ARG);
    CHECK_ERR(udp_link_send(&L, NULL, NULL, 10), BR_ERR_ARG);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, 0), BR_ERR_ARG);
    uint8_t big[UDP_LINK_MAX_FRAME + 1u];
    memset(big, 0x5A, sizeof big);
    CHECK_ERR(udp_link_send(&L, NULL, big, (uint16_t)sizeof big), BR_ERR_TOO_BIG);
    CHECK_EQ_U32(L.st.tx_bad_len, 3u);
    CHECK_EQ_U32(F.sends, 0u);
    udp_link_addr_pack(UDP_LINK_IP4(10, 0, 0, 9), 0, addr); /* port 0 is not an address */
    CHECK_ERR(udp_link_send(&L, addr, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_ARG);
    CHECK_EQ_U32(L.st.tx_bad_len, 4u);

    tu_ctx("flood by multicast: one datagram to 239.255.40.88:40888");
    /* BRV_A2_FRAME is a SEEK: next_hop 0xFFFF, so this is a real flood */
    CHECK_EQ_U32(br_rd_le16(BRV_A2_FRAME + BR_OFF_NEXT_HOP), 0xFFFFu);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    CHECK_EQ_U32(F.sends, 1u);
    CHECK_EQ_U32(F.n_tx, 1u);
    CHECK_EQ_U32(F.tx[0].ip, UDP_LINK_IP4(239, 255, 40, 88));
    CHECK_EQ_U32(F.tx[0].port, 40888u);
    CHECK_EQ_U32(F.tx[0].len, BRV_A2_FRAME_LEN);
    CHECK_MEM(BRV_A2_FRAME, F.tx[0].data, BRV_A2_FRAME_LEN);
    CHECK_EQ_U32(L.st.tx_frames, 1u);
    CHECK_EQ_U32(L.st.tx_flood, 1u);
    CHECK_EQ_U32(L.st.tx_datagrams, 1u);
    CHECK_EQ_U32(L.st.unknown_next_hop, 0u);
    CHECK_EQ_U32(L.tx_ok_pending, 1u);
    /* a 250-byte frame is accepted */
    uint8_t full[UDP_LINK_MAX_FRAME];
    memset(full, 0x3C, sizeof full);
    CHECK_ERR(udp_link_send(&L, NULL, full, (uint16_t)sizeof full), BR_OK);
    CHECK_EQ_U32(F.tx[1].len, 250u);

    tu_ctx("unicast to a learnt address");
    udp_link_addr_pack(UDP_LINK_IP4(192, 168, 7, 33), 40889, addr);
    CHECK_ERR(udp_link_send(&L, addr, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    CHECK_EQ_U32(F.n_tx, 3u);
    CHECK_EQ_U32(F.tx[2].ip, UDP_LINK_IP4(192, 168, 7, 33));
    CHECK_EQ_U32(F.tx[2].port, 40889u);
    CHECK_EQ_U32(L.st.tx_unicast, 1u);
    CHECK_EQ_U32(L.st.tx_frames, 3u);

    tu_ctx("multicast send refused: BR_ERR_QUEUE_FULL, counted, frame lost");
    F.send_rc = UDP_LINK_IO_BUSY;
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_QUEUE_FULL);
    CHECK_EQ_U32(L.st.tx_refused, 1u);
    CHECK_EQ_U32(L.st.tx_frames, 3u);
    F.send_rc = UDP_LINK_IO_ERROR;
    CHECK_ERR(udp_link_send(&L, addr, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_BUSY);
    CHECK_EQ_U32(L.st.tx_refused, 2u);
    CHECK_EQ_U32(L.tx_ok_pending, 3u);
    udp_link_close(&L);

    tu_ctx("flood by peer list: one datagram per peer");
    fake_reset();
    c = cfg_peers(3);
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    CHECK_EQ_U32(F.n_tx, 3u);
    for (unsigned i = 0; i < 3u; i++) {
        CHECK_EQ_U32(F.tx[i].ip, UDP_LINK_IP4(192, 168, 1, 10 + i));
        CHECK_EQ_U32(F.tx[i].port, 40000u + i);
        CHECK_EQ_U32(F.tx[i].len, BRV_A2_FRAME_LEN);
    }
    CHECK_EQ_U32(L.st.tx_frames, 1u);
    CHECK_EQ_U32(L.st.tx_flood, 1u);
    CHECK_EQ_U32(L.st.tx_datagrams, 3u);
    CHECK_EQ_U32(L.st.tx_partial, 0u);
    CHECK_EQ_U32(L.tx_ok_pending, 1u);

    tu_ctx("peer list: one peer fails -> still BR_OK, tx_partial");
    F.send_rc = UDP_LINK_IO_ERROR;
    F.send_rc_nth = (int)F.sends + 1; /* the 2nd peer of the next flood */
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    CHECK_EQ_U32(L.st.tx_partial, 1u);
    CHECK_EQ_U32(L.st.tx_datagrams, 5u);
    CHECK_EQ_U32(L.st.tx_frames, 2u);

    tu_ctx("peer list: every peer fails -> frame lost");
    F.send_rc_nth = -1;
    F.send_rc = UDP_LINK_IO_BUSY;
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_QUEUE_FULL);
    CHECK_EQ_U32(L.st.tx_refused, 1u);
    CHECK_EQ_U32(L.st.tx_frames, 2u);
    F.send_rc = UDP_LINK_IO_OK;

    tu_ctx("unicast frame with addr NULL: unknown next_hop, flooded to the list");
    uint8_t uni[BRV_A2_FRAME_LEN];
    memcpy(uni, BRV_A2_FRAME, sizeof uni);
    br_wr_le16(uni + BR_OFF_NEXT_HOP, 0x0102);
    const unsigned before = F.n_tx;
    CHECK_ERR(udp_link_send(&L, NULL, uni, (uint16_t)sizeof uni), BR_OK);
    CHECK_EQ_U32(L.st.unknown_next_hop, 1u);
    CHECK_EQ_U32(F.n_tx - before, 3u);
    CHECK_EQ_U32(L.st.tx_flood, 4u);
    /* with a learnt address it is a plain unicast */
    udp_link_addr_pack(UDP_LINK_IP4(10, 1, 2, 3), 40888, addr);
    CHECK_ERR(udp_link_send(&L, addr, uni, (uint16_t)sizeof uni), BR_OK);
    CHECK_EQ_U32(L.st.unknown_next_hop, 1u);
    CHECK_EQ_U32(L.st.tx_unicast, 1u);
    CHECK_EQ_U32(F.tx[F.n_tx - 1u].ip, UDP_LINK_IP4(10, 1, 2, 3));
    /* a short datagram (no next_hop field) with addr NULL is a flood, not counted */
    CHECK_ERR(udp_link_send(&L, NULL, uni, 8), BR_OK);
    CHECK_EQ_U32(L.st.unknown_next_hop, 1u);
    udp_link_close(&L);
}

/* A node to receive into (frames from the vectors are rejected by hop_tag
 * but counted as rx_frames: the point is what the adapter did before). */
static br_node_t g_lone;
static br_transport_t g_lone_tr;

static void lone_init(uint16_t allow_id)
{
    br_node_config_t c;
    base_cfg(&c, 0x0103, false);
    udp_link_fill_transport(&L, &c.transports[0]);
    c.transports[0].allowlist.enabled = allow_id != 0u;
    c.transports[0].allowlist.n = allow_id != 0u ? 1u : 0u;
    c.transports[0].allowlist.ids[0] = allow_id;
    c.n_transports = 1;
    g_lone_tr = c.transports[0];
    memset(&g_lone, 0, sizeof g_lone);
    CHECK_ERR(br_node_init(&g_lone, sizeof g_lone, &c), BR_OK);
}

static void test_receive(void)
{
    const uint32_t ip = UDP_LINK_IP4(192, 168, 1, 77);
    const uint16_t port = 40888;
    const uint16_t prev = br_rd_le16(BRV_A2_FRAME + BR_OFF_PREV_HOP);
    CHECK(prev != 0u && prev != 0x0102u);

    tu_ctx("deliver: a frame reaches br_node_rx with the ip:port hint");
    fake_reset();
    udp_link_cfg_t c = cfg_mcast();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    lone_init(0);
    br_rx_verdict_t v;
    memset(&v, 0, sizeof v);
    CHECK(udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, &v));
    CHECK_EQ_U32(L.st.rx_datagrams, 1u);
    CHECK_EQ_U32(L.st.rx_frames, 1u);
    CHECK_EQ_U32(node_stats(&g_lone).f.rx_frames, 1u); /* the core saw it */
    CHECK_EQ_U32(v.type, BR_TYPE_SEEK);

    tu_ctx("deliver: oversize dropped before the core");
    uint8_t big[UDP_LINK_MAX_FRAME + 1u];
    memset(big, 0x11, sizeof big);
    CHECK(!udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, big, sizeof big, ip, port, NULL));
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.rx_frames, 1u);
    CHECK_EQ_U32(node_stats(&g_lone).f.rx_frames, 1u);
    /* exactly 250 passes the adapter (the core then judges it) */
    CHECK(udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, big, UDP_LINK_MAX_FRAME, ip, port, NULL));
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.rx_frames, 2u);

    tu_ctx("deliver: empty datagram counted as rx_err");
    CHECK(!udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, big, 0, ip, port, NULL));
    CHECK_EQ_U32(L.st.rx_err, 1u);
    CHECK(!udp_link_deliver(&L, NULL, 0, &g_lone_tr, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, NULL));
    CHECK(!udp_link_deliver(NULL, &g_lone, 0, &g_lone_tr, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, NULL));
    CHECK(!udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, NULL, 9, ip, port, NULL));
    br_node_deinit(&g_lone);

    tu_ctx("deliver: bench allowlist (N22) excludes prev_hop -> dropped, core sees nothing");
    lone_init(0x0102);
    L.st.rx_frames = 0;
    CHECK(!udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, NULL));
    CHECK_EQ_U32(L.st.allowlist_drop, 1u);
    CHECK_EQ_U32(L.st.rx_frames, 0u);
    CHECK_EQ_U32(node_stats(&g_lone).f.rx_frames, 0u);
    /* shorter than 8 bytes: an enabled list drops it (nothing to attribute) */
    CHECK(!udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, BRV_A2_FRAME, 7, ip, port, NULL));
    CHECK_EQ_U32(L.st.allowlist_drop, 2u);
    /* NULL tr = admit everything */
    CHECK(udp_link_deliver(&L, &g_lone, 0, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, NULL));
    CHECK_EQ_U32(L.st.rx_frames, 1u);
    br_node_deinit(&g_lone);

    tu_ctx("deliver: allowlist includes prev_hop -> delivered");
    lone_init(prev);
    L.st.rx_frames = 0;
    CHECK(udp_link_deliver(&L, &g_lone, 0, &g_lone_tr, BRV_A2_FRAME, BRV_A2_FRAME_LEN, ip, port, NULL));
    CHECK_EQ_U32(L.st.allowlist_drop, 2u);
    CHECK_EQ_U32(L.st.rx_frames, 1u);
    CHECK_EQ_U32(node_stats(&g_lone).f.rx_frames, 1u);
    br_node_deinit(&g_lone);
    udp_link_close(&L);

    tu_ctx("pump: first wait = timeout, then poll; stops at the timeout");
    fake_reset();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    lone_init(0);
    fake_push_rx(ip, port, BRV_A2_FRAME, BRV_A2_FRAME_LEN);
    fake_push_rx(ip, port, BRV_A3_FRAME, BRV_A3_FRAME_LEN);
    fake_push_rx(ip, port, big, sizeof big); /* oversize: truncated by the socket, seen as 251+ */
    fake_push_rx(ip, port, NULL, 0);          /* empty */
    CHECK_EQ_U32(udp_link_pump(&L, &g_lone, 0, &g_lone_tr, 25, 0), 2u);
    CHECK_EQ_U32(F.recvs, 5u); /* 4 datagrams + the timeout */
    CHECK_EQ_U32(F.first_timeout, 25u);
    CHECK_EQ_U32(F.last_timeout, 0u);
    CHECK_EQ_U32(L.st.rx_datagrams, 4u);
    CHECK_EQ_U32(L.st.rx_frames, 2u);
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.rx_err, 1u);
    CHECK_EQ_U32(node_stats(&g_lone).f.rx_frames, 2u);

    tu_ctx("pump: max_frames bounds the drain");
    F.rx_rd = 0;
    F.recvs = 0;
    L.st.rx_frames = 0;
    CHECK_EQ_U32(udp_link_pump(&L, &g_lone, 0, &g_lone_tr, 0, 1), 1u);
    CHECK_EQ_U32(F.recvs, 1u);
    CHECK_EQ_U32(udp_link_pump(&L, &g_lone, 0, &g_lone_tr, 0, 1), 1u);
    CHECK_EQ_U32(L.st.rx_frames, 2u);

    tu_ctx("pump: socket error counted, loop ends");
    F.rx_rd = F.n_rx;
    F.rx_err_after = 0;
    L.st.rx_err = 0;
    CHECK_EQ_U32(udp_link_pump(&L, &g_lone, 0, &g_lone_tr, 0, 0), 0u);
    CHECK_EQ_U32(L.st.rx_err, 1u);
    CHECK_EQ_U32(udp_link_pump(&L, NULL, 0, &g_lone_tr, 0, 0), 0u);
    CHECK_EQ_U32(udp_link_pump(NULL, &g_lone, 0, &g_lone_tr, 0, 0), 0u);
    udp_link_close(&L);
    CHECK_EQ_U32(udp_link_pump(&L, &g_lone, 0, &g_lone_tr, 0, 0), 0u); /* closed: nothing */

    tu_ctx("tx status: every accepted frame reported once, delivered = true");
    fake_reset();
    CHECK(udp_link_init(&L, &c, &FAKE_OPS));
    CHECK_ERR(udp_link_open(&L), BR_OK);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_OK);
    F.send_rc = UDP_LINK_IO_BUSY;
    CHECK_ERR(udp_link_send(&L, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN), BR_ERR_QUEUE_FULL);
    CHECK_EQ_U32(udp_link_report_tx_status(&L, &g_lone, 0), 2u);
    CHECK_EQ_U32(udp_link_report_tx_status(&L, &g_lone, 0), 0u);
    CHECK_EQ_U32(L.st.tx_status, 2u);
    CHECK_EQ_U32(L.st.tx_frames, 2u);
    CHECK_EQ_U32(udp_link_report_tx_status(NULL, &g_lone, 0), 0u);
    udp_link_stats_t st;
    memset(&st, 0xFF, sizeof st);
    udp_link_get_stats(&L, &st);
    CHECK_EQ_U32(st.tx_status, 2u);
    CHECK_EQ_U32(st.tx_refused, 1u);
    /* 11.6 never fires on UDP: mac_retry false makes the report a no-op in the core */
    CHECK_EQ_U32(node_stats(&g_lone).f.link_fail_drops, 0u);
    br_node_deinit(&g_lone);
    udp_link_close(&L);
}

/* ========================================================================= */
/* Parts B and C: real sockets on 127.0.0.1                                   */
/* ========================================================================= */

#define MAX_EP 3u

typedef struct {
    const char    *name;
    uint16_t       unit;
    bool           probe;
    bool           sender;
    br_node_t      node;
    udp_link_t     link;
    br_transport_t tr;          /* the node's copy of the transport (allowlist for deliver) */
    uint8_t        want_hops;   /* probe: expected meta->hops */
    br_session_t   sess;
    bool           streaming;
    bool           bound;
    unsigned       acked;
    unsigned       gap_seqs;
    unsigned       samples;
    unsigned       ones;
    unsigned       zeros;
    unsigned       bad_hops;
    unsigned       closed;
} ep_t;

static ep_t EP[MAX_EP];
static unsigned g_n_ep;

static void cb_acked(void *user, br_session_t s, uint16_t seq)
{
    (void)s;
    (void)seq;
    ((ep_t *)user)->acked++;
}

static void cb_state(void *user, br_session_t s, uint8_t old_state, uint8_t new_state)
{
    ep_t *e = (ep_t *)user;
    (void)old_state;
    if ((s & BR_SESSION_PROBE) == 0u && new_state == BR_SND_STREAMING) {
        e->streaming = true;
    }
}

static void cb_bound(void *user, br_session_t s, uint16_t peer)
{
    (void)s;
    (void)peer;
    ((ep_t *)user)->bound = true;
}

static void cb_samples(void *user, const br_samples_meta_t *meta, const br_mode_t *mode, const uint8_t *samples,
                       size_t samples_len)
{
    ep_t *e = (ep_t *)user;
    size_t sz = 0;
    CHECK_ERR(br_sample_size(mode, &sz), BR_OK);
    CHECK_EQ_U32(meta->src_id, 0x0101u);
    if (meta->hops != e->want_hops) {
        e->bad_hops++;
    }
    for (uint8_t i = 0; i < meta->hdr.n_samples && sz > 0u; i++) {
        size_t off = (size_t)i * sz;
        if (off + sz > samples_len) {
            break;
        }
        br_value_t vals[BR_MAX_CHANNELS];
        if (br_sample_decode(mode, samples + off, sz, vals) == BR_OK) {
            e->samples++;
            if ((vals[0].lines & 1u) != 0u) {
                e->ones++;
            } else {
                e->zeros++;
            }
        }
    }
}

static void cb_gap(void *user, br_session_t s, uint16_t first, uint16_t count)
{
    ep_t *e = (ep_t *)user;
    (void)first;
    if ((s & BR_SESSION_PROBE) == 0u) {
        e->gap_seqs += count;
    }
}

static void cb_closed(void *user, br_session_t s, uint8_t reason)
{
    (void)s;
    (void)reason;
    ((ep_t *)user)->closed++;
}

/*
 * Open every socket first (port 0 = any free port, read back), then build
 * the peer lists from the real ports, then init the nodes. ids[] lists the
 * units; peers[i] is the index bitmask of i's peers (and its allowlist).
 */
static void topo_start(const uint16_t *ids, const uint8_t *peer_mask, unsigned n, uint8_t probe_hops)
{
    memset(EP, 0, sizeof EP);
    g_n_ep = n;
    hal_udp_t probe_socks[MAX_EP];
    uint16_t ports[MAX_EP];
    /* reserve n distinct free ports, then release them for the adapters */
    for (unsigned i = 0; i < n; i++) {
        hal_udp_cfg_t hc;
        memset(&hc, 0, sizeof hc);
        CHECK_ERR(hal_udp_open(&probe_socks[i], &hc), HAL_OK);
        ports[i] = probe_socks[i].local_port;
        CHECK(ports[i] != 0u);
    }
    for (unsigned i = 0; i < n; i++) {
        (void)hal_udp_close(&probe_socks[i]);
    }
    for (unsigned i = 0; i < n; i++) {
        ep_t *e = &EP[i];
        e->unit = ids[i];
        e->sender = ids[i] == 0x0101u;
        e->probe = ids[i] == 0x0103u;
        e->name = e->sender ? "A" : (e->probe ? "C" : "B");
        e->want_hops = probe_hops;
        e->sess = BR_SESSION_NONE;

        udp_link_cfg_t uc;
        memset(&uc, 0, sizeof uc);
        uc.local_port = ports[i];
        uc.mcast = false;
        for (unsigned j = 0; j < n; j++) {
            if ((peer_mask[i] & (1u << j)) != 0u) {
                uc.peers[uc.n_peers].ip = HAL_UDP_LOOPBACK;
                uc.peers[uc.n_peers].port = ports[j];
                uc.n_peers++;
            }
        }
        CHECK(udp_link_init(&e->link, &uc, NULL)); /* NULL ops: hal_udp over udp_posix.c */
        br_err_t rc = udp_link_open(&e->link);
        if (rc == BR_ERR_BUSY) {
            /* the reserved port was grabbed in between: take any */
            e->link.cfg.local_port = UDP_LINK_PORT_ANY;
            rc = udp_link_open(&e->link);
        }
        CHECK_ERR(rc, BR_OK);
        CHECK_EQ_U32(udp_link_bound_port(&e->link), ports[i]);

        br_node_config_t c;
        base_cfg(&c, e->unit, e->probe);
        udp_link_fill_transport(&e->link, &c.transports[0]);
        c.transports[0].allowlist.enabled = true;
        c.transports[0].allowlist.n = 0;
        for (unsigned j = 0; j < n; j++) {
            if ((peer_mask[i] & (1u << j)) != 0u) {
                c.transports[0].allowlist.ids[c.transports[0].allowlist.n++] = ids[j];
            }
        }
        c.n_transports = 1;
        e->tr = c.transports[0];
        c.app.user = e;
        c.app.on_bound = cb_bound;
        c.app.on_samples = cb_samples;
        c.app.on_gap = cb_gap;
        c.app.on_acked = cb_acked;
        c.app.on_closed = cb_closed;
        c.app.on_state = cb_state;
        CHECK_ERR(br_node_init(&e->node, sizeof e->node, &c), BR_OK);
    }
}

static void topo_stop(void)
{
    for (unsigned i = 0; i < g_n_ep; i++) {
        br_node_deinit(&EP[i].node);
        udp_link_close(&EP[i].link);
    }
}

static ep_t *ep_sender(void)
{
    for (unsigned i = 0; i < g_n_ep; i++) {
        if (EP[i].sender) {
            return &EP[i];
        }
    }
    return NULL;
}

static ep_t *ep_probe(void)
{
    for (unsigned i = 0; i < g_n_ep; i++) {
        if (EP[i].probe) {
            return &EP[i];
        }
    }
    return NULL;
}

/* One scheduling round: receive (1 ms wait each), tick, report. */
static void step(void)
{
    for (unsigned i = 0; i < g_n_ep; i++) {
        (void)udp_link_pump(&EP[i].link, &EP[i].node, 0, &EP[i].tr, 1, 16);
    }
    const uint64_t now = now_us();
    for (unsigned i = 0; i < g_n_ep; i++) {
        uint64_t nd = 0;
        CHECK_ERR(br_node_tick(&EP[i].node, now, &nd), BR_OK);
        (void)udp_link_report_tx_status(&EP[i].link, &EP[i].node, 0);
    }
}

static bool run_until(bool (*cond)(void), uint32_t max_ms)
{
    const uint64_t end = now_us() + (uint64_t)max_ms * 1000u;
    while (now_us() < end) {
        if (cond()) {
            return true;
        }
        step();
    }
    return cond();
}

static void run_for(uint32_t ms)
{
    const uint64_t end = now_us() + (uint64_t)ms * 1000u;
    while (now_us() < end) {
        step();
    }
}

static unsigned g_want_acked;
static bool cond_streaming(void) { return ep_sender()->streaming; }
static bool cond_acked(void) { return ep_sender()->acked + ep_sender()->gap_seqs >= g_want_acked; }

static void start_session(void)
{
    ep_t *a = ep_sender();
    CHECK_ERR(br_node_seek(&a->node, 0xFF10, &a->sess), BR_OK);
    br_mode_t m; /* node_app demo MODE: HIGH, one digital line, ARQ on, fec_m 0 */
    memset(&m, 0, sizeof m);
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
    CHECK_ERR(br_node_set_mode(&a->node, a->sess, &m), BR_OK);
}

/* One press = value 1 then value 0, both ACK_REQ (node_app sender_press). */
static bool press(unsigned i)
{
    ep_t *a = ep_sender();
    br_value_t v;
    v.lines = 1;
    CHECK_ERR(br_node_send_sample(&a->node, a->sess, &v, 1, (uint32_t)now_us(), 0, true), BR_OK);
    v.lines = 0;
    CHECK_ERR(br_node_send_sample(&a->node, a->sess, &v, 1, (uint32_t)now_us(), 0, true), BR_OK);
    g_want_acked = 2u * (i + 1u);
    return run_until(cond_acked, 3000);
}

/* The learnt link entry for `unit` on transport 0 of `node`, or NULL. */
static const br_link_entry_t *link_entry(const br_node_t *node, uint16_t unit)
{
    const br_tables_t *t = NULL;
    CHECK_ERR(br_node_get_tables(node, &t), BR_OK);
    if (t == NULL) {
        return NULL;
    }
    for (unsigned i = 0; i < BR_LINK_ENTRIES; i++) {
        const br_link_entry_t *le = &t->link.e[i];
        if (le->transport == 0u && le->unit_id == unit) {
            return le;
        }
    }
    return NULL;
}

static void check_link_addr(const ep_t *from, const ep_t *to)
{
    const br_link_entry_t *le = link_entry(&from->node, to->unit);
    CHECK_MSG(le != NULL, "link entry missing");
    if (le == NULL) {
        return;
    }
    CHECK_EQ_U32(le->addr_len, UDP_LINK_ADDR_LEN);
    uint32_t ip = 0;
    uint16_t port = 0;
    udp_link_addr_unpack(le->addr, &ip, &port);
    CHECK_EQ_U32(ip, HAL_UDP_LOOPBACK);
    CHECK_EQ_U32(port, udp_link_bound_port(&to->link));
    CHECK_EQ_U32(le->rssi_ewma, (uint32_t)(int8_t)BR_RSSI_UNKNOWN);
}

#define PRESSES 5u

static void run_presses(const char *what, uint8_t hops)
{
    const uint64_t t0 = now_us();
    start_session();
    const bool up = run_until(cond_streaming, 4000);
    CHECK_MSG(up, "session did not reach STREAMING in 4 s");
    ep_t *a = ep_sender();
    ep_t *p = ep_probe();
    CHECK(p->bound);
    unsigned ok = 0;
    for (unsigned i = 0; up && i < PRESSES; i++) {
        if (press(i)) {
            ok++;
        }
        run_for(20);
    }
    CHECK_EQ_U32(ok, PRESSES);
    CHECK_EQ_U32(a->acked, 2u * PRESSES);
    CHECK_EQ_U32(a->gap_seqs, 0u);
    run_for(50); /* let the last ACK / rebroadcast settle */
    CHECK_EQ_U32(p->ones, PRESSES);
    CHECK_EQ_U32(p->zeros, PRESSES);
    CHECK_EQ_U32(p->samples, 2u * PRESSES);
    CHECK_EQ_U32(p->bad_hops, 0u);
    uint8_t st = 0;
    CHECK_ERR(br_node_session_state(&a->node, a->sess, &st), BR_OK);
    CHECK_EQ_U32(st, BR_SND_STREAMING);
    CHECK_EQ_U32(a->closed, 0u);
    CHECK_EQ_U32(p->closed, 0u);
    br_stats_t sa = node_stats(&a->node);
    br_stats_t sp = node_stats(&p->node);
    /* no multicast: every flood went out as unicast datagrams to the peer list */
    for (unsigned i = 0; i < g_n_ep; i++) {
        CHECK_EQ_U32(EP[i].link.st.tx_refused, 0u);
        CHECK_EQ_U32(EP[i].link.st.oversize, 0u);
        CHECK_EQ_U32(EP[i].link.st.rx_err, 0u);
        CHECK_EQ_U32(EP[i].link.st.tx_status, EP[i].link.st.tx_frames);
        CHECK_EQ_U32(EP[i].link.st.unknown_next_hop, 0u);
        CHECK(EP[i].link.st.tx_frames > 0u);
    }
    CHECK_EQ_U32(sa.f.link_fail_drops, 0u); /* 11.6 off on UDP */
    CHECK_EQ_U32(sa.f.auth_fail + sp.f.auth_fail, 0u);
    printf("  %-34s t=%5.2fs hops=%u presses %u/%u acked %u retx %u | dgrams", what,
           (double)(now_us() - t0) / 1e6, hops, ok, (unsigned)PRESSES, a->acked, (unsigned)sa.f.arq_retx);
    for (unsigned i = 0; i < g_n_ep; i++) {
        printf(" %s tx=%u rx=%u al=%u", EP[i].name, (unsigned)EP[i].link.st.tx_datagrams,
               (unsigned)EP[i].link.st.rx_datagrams, (unsigned)EP[i].link.st.allowlist_drop);
    }
    printf("\n");
}

static void test_two_nodes(void)
{
    tu_ctx("two nodes on 127.0.0.1, peer lists, direct");
    const uint16_t ids[2] = {0x0101, 0x0103};
    const uint8_t peers[2] = {0x02, 0x01}; /* A <-> C */
    topo_start(ids, peers, 2, 1);
    run_presses("B: sender <-> probe direct", 1);
    /* the sender learnt the probe's ip:port (step 6), and the other way round */
    check_link_addr(ep_sender(), ep_probe());
    check_link_addr(ep_probe(), ep_sender());
    /* hops 1: a direct route */
    br_route_entry_t r;
    bool found = false;
    CHECK_ERR(br_node_route(&ep_sender()->node, 0x0103, &r, &found), BR_OK);
    CHECK(found);
    if (found) {
        CHECK_EQ_U32(r.hops, 1u);
        CHECK_EQ_U32(r.next_hop, 0x0103u);
    }
    CHECK_EQ_U32(EP[0].link.st.allowlist_drop + EP[1].link.st.allowlist_drop, 0u);
    topo_stop();
}

static void test_three_nodes(void)
{
    tu_ctx("three nodes on 127.0.0.1, A <-> B <-> C by peer list and allowlist");
    const uint16_t ids[3] = {0x0101, 0x0102, 0x0103};
    const uint8_t peers[3] = {0x02, 0x05, 0x02}; /* A = {B}, B = {A, C}, C = {B} */
    topo_start(ids, peers, 3, 2);
    run_presses("C: sender -> relay -> probe", 2);
    ep_t *a = ep_sender();
    ep_t *b = &EP[1];
    ep_t *c = ep_probe();
    /* addresses: A knows B only, C knows B only, B knows both */
    check_link_addr(a, b);
    check_link_addr(c, b);
    check_link_addr(b, a);
    check_link_addr(b, c);
    CHECK(link_entry(&a->node, 0x0103) == NULL);
    CHECK(link_entry(&c->node, 0x0101) == NULL);
    /* the route is two hops through B */
    br_route_entry_t r;
    bool found = false;
    CHECK_ERR(br_node_route(&a->node, 0x0103, &r, &found), BR_OK);
    CHECK(found);
    if (found) {
        CHECK_EQ_U32(r.hops, 2u);
        CHECK_EQ_U32(r.next_hop, 0x0102u);
    }
    CHECK(node_stats(&b->node).f.relay_fwd > 0u);
    /* nothing was ever sent A -> C directly (peer lists), so no allowlist drops anywhere */
    CHECK_EQ_U32(a->link.st.allowlist_drop + b->link.st.allowlist_drop + c->link.st.allowlist_drop, 0u);
    topo_stop();
}

static void test_allowlist_excludes_sender(void)
{
    tu_ctx("two nodes, probe allowlist excludes the sender: nothing binds");
    const uint16_t ids[2] = {0x0101, 0x0103};
    const uint8_t peers[2] = {0x02, 0x01};
    topo_start(ids, peers, 2, 1);
    /* overwrite the probe's allowlist: only 0x0102 may talk to it */
    ep_t *p = ep_probe();
    p->tr.allowlist.n = 1;
    p->tr.allowlist.ids[0] = 0x0102;
    start_session();
    const bool up = run_until(cond_streaming, 1500);
    CHECK(!up);
    CHECK(!p->bound);
    CHECK_EQ_U32(node_stats(&p->node).f.rx_frames, 0u); /* the core saw nothing (N22) */
    CHECK(p->link.st.allowlist_drop > 0u);
    CHECK_EQ_U32(p->link.st.allowlist_drop, p->link.st.rx_datagrams);
    topo_stop();
}

/* ========================================================================= */
/* Part D: multicast on the loopback interface (skipped when unavailable)     */
/* ========================================================================= */

static void test_multicast_loopback(void)
{
    tu_ctx("multicast join / leave on 127.0.0.1");
    hal_udp_t s1;
    hal_udp_t s2;
    hal_udp_cfg_t hc;
    memset(&hc, 0, sizeof hc);
    hc.local_port = 0;
    hc.mcast_group = HAL_UDP_MCAST_DEFAULT;
    hc.mcast_if = HAL_UDP_LOOPBACK;
    hc.mcast_ttl = 1;
    hc.mcast_loop = true;
    hc.reuse_addr = true;
    hal_result_t r = hal_udp_open(&s1, &hc);
    if (r == HAL_ERR_UNSUPPORTED) {
        TU_SKIP("multicast on loopback", "IP_ADD_MEMBERSHIP on 127.0.0.1 refused by this host");
        (void)hal_udp_close(&s1);
        return;
    }
    CHECK_ERR(r, HAL_OK);
    CHECK_EQ_U32(s1.mcast_group, HAL_UDP_MCAST_DEFAULT);
    CHECK(s1.local_port != 0u);
    /* second member on the same port */
    hc.local_port = s1.local_port;
    r = hal_udp_open(&s2, &hc);
    CHECK_ERR(r, HAL_OK);
    if (r != HAL_OK) {
        (void)hal_udp_close(&s1);
        return;
    }
    /* leave and re-join through call 4 */
    CHECK_ERR(hal_udp_mcast(&s2, HAL_UDP_MCAST_DEFAULT, HAL_UDP_LOOPBACK, false), HAL_OK);
    CHECK_EQ_U32(s2.mcast_group, 0u);
    CHECK_ERR(hal_udp_mcast(&s2, HAL_UDP_MCAST_DEFAULT, HAL_UDP_LOOPBACK, true), HAL_OK);
    CHECK_EQ_U32(s2.mcast_group, HAL_UDP_MCAST_DEFAULT);

    tu_ctx("multicast datagram from s1 reaches s2 (and s1, loop on)");
    r = hal_udp_sendto(&s1, HAL_UDP_MCAST_DEFAULT, s1.local_port, BRV_A2_FRAME, BRV_A2_FRAME_LEN);
    if (r != HAL_OK) {
        TU_SKIP("multicast send on loopback", "sendto to 239.255.40.88 via 127.0.0.1 refused (no route)");
        (void)hal_udp_close(&s1);
        (void)hal_udp_close(&s2);
        return;
    }
    uint8_t buf[300];
    size_t n = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    r = hal_udp_recvfrom(&s2, buf, sizeof buf, &n, &ip, &port, 500);
    if (r == HAL_ERR_TIMEOUT) {
        TU_SKIP("multicast delivery on loopback", "joined and sent, but nothing arrived in 500 ms");
        (void)hal_udp_close(&s1);
        (void)hal_udp_close(&s2);
        return;
    }
    CHECK_ERR(r, HAL_OK);
    CHECK_EQ_U32(n, BRV_A2_FRAME_LEN);
    CHECK_MEM(BRV_A2_FRAME, buf, BRV_A2_FRAME_LEN);
    CHECK_EQ_U32(ip, HAL_UDP_LOOPBACK);
    CHECK_EQ_U32(port, s1.local_port);
    /* the sender hears itself (mcast_loop true) */
    CHECK_ERR(hal_udp_recvfrom(&s1, buf, sizeof buf, &n, &ip, &port, 500), HAL_OK);
    CHECK_EQ_U32(n, BRV_A2_FRAME_LEN);
    /* and a poll on an idle socket times out */
    CHECK_ERR(hal_udp_recvfrom(&s2, buf, sizeof buf, &n, &ip, &port, 0), HAL_ERR_TIMEOUT);
    (void)hal_udp_close(&s1);
    (void)hal_udp_close(&s2);

    tu_ctx("adapter flood by multicast between two adapters on one port");
    /* two adapters, same local port (reuse), group joined, loop on, default interface */
    udp_link_t la;
    udp_link_t lb;
    udp_link_cfg_t uc;
    memset(&uc, 0, sizeof uc);
    uc.mcast = true;
    uc.mcast_loop = true;
    uc.local_port = UDP_LINK_PORT_ANY;
    CHECK(udp_link_init(&la, &uc, NULL));
    br_err_t rc = udp_link_open(&la);
    if (rc != BR_OK) {
        TU_SKIP("adapter multicast", "join on the default interface refused");
        udp_link_close(&la);
        return;
    }
    uc.local_port = udp_link_bound_port(&la);
    uc.mcast_port = uc.local_port;
    la.cfg.mcast_port = uc.local_port;
    CHECK(udp_link_init(&lb, &uc, NULL));
    rc = udp_link_open(&lb);
    CHECK_ERR(rc, BR_OK);
    if (rc != BR_OK) {
        udp_link_close(&la);
        return;
    }
    rc = udp_link_send(&la, NULL, BRV_A2_FRAME, BRV_A2_FRAME_LEN);
    if (rc != BR_OK) {
        TU_SKIP("adapter multicast send", "sendto 239.255.40.88 on the default interface refused (no route)");
        udp_link_close(&la);
        udp_link_close(&lb);
        return;
    }
    n = 0;
    const int io = lb.ops->recvfrom(lb.sock, buf, sizeof buf, &n, &ip, &port, 500);
    if (io == UDP_LINK_IO_TIMEOUT) {
        TU_SKIP("adapter multicast delivery", "sent on the default interface, nothing arrived in 500 ms");
    } else {
        CHECK_EQ_U32(io, UDP_LINK_IO_OK);
        CHECK_EQ_U32(n, BRV_A2_FRAME_LEN);
        CHECK_MEM(BRV_A2_FRAME, buf, BRV_A2_FRAME_LEN);
        CHECK_EQ_U32(port, udp_link_bound_port(&la));
        printf("  multicast on loopback: works (group %s)\n", "239.255.40.88");
    }
    udp_link_close(&la);
    udp_link_close(&lb);
}

/* ========================================================================= */

int main(void)
{
    const uint64_t t0 = now_us();
    g_urandom = fopen("/dev/urandom", "rb");
    tu_rng_seed(&g_fallback_rng, 0x5EEDu);
    const br_platform_t plat = {t_now, t_random, t_log, NULL};
    CHECK_ERR(br_platform_set(&plat), BR_OK);

    test_transport_fields();
    test_peer_parse_format();
    test_init_and_open();
    test_send();
    test_receive();

    test_two_nodes();
    test_three_nodes();
    test_allowlist_excludes_sender();

    test_multicast_loopback();

    if (g_urandom != NULL) {
        fclose(g_urandom);
    }
    printf("  wall time %.2f s\n", (double)(now_us() - t0) / 1e6);
    return tu_summary("test_udp_link");
}
