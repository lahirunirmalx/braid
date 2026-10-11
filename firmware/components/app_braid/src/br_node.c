// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_node.c - node object, 11.4 receive pipeline, flood control, per-hop
 * sealing, timers and the app API.
 *
 * One function seals every transmitted frame (node_seal_hop): it writes the
 * per-hop header fields, recomputes the hop_tag over [0, end of auth_tag)
 * and the CRC; the end-to-end bytes are never touched. Origin frames (from
 * the session layer, zero per-hop fields), jittered flood copies (11.4 9f)
 * and unicast forwards (10e) all go through it.
 *
 * Table rule R4: nothing reaches a table before step 5 (hop_tag + hop_seq).
 * Reentrancy: the session layer may send from inside pipeline step 7 / 9e;
 * every table update of the current frame is done before that call, no
 * table pointer is held across it, and node->scratch is used only inside a
 * send path that runs to completion without calling the session layer.
 */
#include <string.h>

#include "mbedtls/sha256.h"

#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_rs.h"

#include "br_internal.h"

#define BR_NODE_MAGIC 0x504C4E31u /* "PLN1" */
#define BR_FAR_MS     0x40000000u /* br_session.c "nothing due" horizon */

/* ========================================================================= */
/* Bench allowlist (SPEC-NOTES N22)                                           */
/* ========================================================================= */

#ifndef BR_FIELD_BUILD
bool br_bench_allowlist_admit(const br_bench_allowlist_t *al, const uint8_t *frame, size_t len)
{
    if (al == NULL || !al->enabled) {
        return true;
    }
    if (frame == NULL || len < (size_t)BR_OFF_PREV_HOP + 2u) {
        return false;
    }
    uint16_t prev_hop = br_rd_le16(frame + BR_OFF_PREV_HOP);
    uint8_t n = al->n <= BR_BENCH_ALLOWLIST_MAX ? al->n : (uint8_t)BR_BENCH_ALLOWLIST_MAX;
    for (uint8_t i = 0; i < n; i++) {
        if (al->ids[i] == prev_hop) {
            return true;
        }
    }
    return false;
}
#endif

/* ========================================================================= */
/* Helpers                                                                    */
/* ========================================================================= */

static bool node_ok(const br_node_t *n)
{
    return n != NULL && n->magic == BR_NODE_MAGIC;
}

static uint64_t platform_now_us(void)
{
    br_platform_t pf;
    if (br_platform_get(&pf) != BR_OK) {
        return 0u;
    }
    return pf.now_us(pf.user);
}

static uint16_t tr_mtu(const br_transport_t *t)
{
    return (uint16_t)(t->max_frame > t->rs_nsym ? (unsigned)t->max_frame - t->rs_nsym : 0u);
}

static uint8_t min_u8(uint32_t a, uint32_t b)
{
    uint32_t m = a < b ? a : b;
    return (uint8_t)(m > 0xFFu ? 0xFFu : m);
}

/* Reserve-ahead counters (3.5): persist the next block boundary before using it. */
static br_err_t take_ctr(br_node_t *n, uint32_t *ctr, uint32_t *reserved, uint32_t block, uint8_t which,
                         uint32_t *out)
{
    if (*ctr == *reserved) {
        uint32_t to = *reserved + block;
        if (n->cfg.persist != NULL && n->cfg.persist(n->cfg.persist_user, which, to) != BR_OK) {
            return BR_ERR_STATE; /* never transmit on an unreserved counter (no nonce reuse) */
        }
        *reserved = to;
    }
    *out = (*ctr)++;
    return BR_OK;
}

static br_err_t take_txseq(br_node_t *n, uint32_t *out)
{
    return take_ctr(n, &n->txseq, &n->txseq_reserved, BR_TXSEQ_BLOCK, BR_PERSIST_TXSEQ, out);
}

static br_err_t sess_next_pre_ctr(void *user, uint32_t *pre_ctr_out)
{
    br_node_t *n = (br_node_t *)user;
    return take_ctr(n, &n->preseq, &n->preseq_reserved, BR_PRESEQ_BLOCK, BR_PERSIST_PRESEQ, pre_ctr_out);
}

/* 4.1.14: every random value is SHA-256(rng || preseq || txseq || unit_id || now_us). */
static br_err_t sess_random(void *user, uint8_t *buf, size_t len)
{
    br_node_t *n = (br_node_t *)user;
    br_platform_t pf;
    if (buf == NULL || br_platform_get(&pf) != BR_OK) {
        return BR_ERR_STATE;
    }
    size_t o = 0;
    while (o < len) {
        uint8_t in[4 + 4 + 4 + 2 + 8];
        uint8_t h[BR_SHA256_LEN];
        if (pf.random_bytes(pf.user, in, 4u) != BR_OK) {
            return BR_ERR_CRYPTO;
        }
        br_wr_le32(in + 4, n->preseq);
        br_wr_le32(in + 8, n->txseq);
        br_wr_le16(in + 12, n->cfg.unit_id);
        uint64_t t = pf.now_us(pf.user);
        memcpy(in + 14, &t, sizeof t);
        if (mbedtls_sha256(in, sizeof in, h, 0) != 0) {
            return BR_ERR_CRYPTO;
        }
        size_t k = (len - o) < sizeof h ? (len - o) : sizeof h;
        memcpy(buf + o, h, k);
        o += k;
    }
    return BR_OK;
}

static uint32_t node_rand_upto(br_node_t *n, uint32_t max)
{
    uint8_t b[4] = { 0, 0, 0, 0 };
    (void)sess_random(n, b, sizeof b);
    uint32_t r = br_rd_le32(b);
    return (max == UINT32_MAX) ? r : r % (max + 1u);
}

static bool is_member(const br_node_t *n, uint16_t dst)
{
    if (dst == n->cfg.unit_id) {
        return true;
    }
    bool m = false;
    (void)br_probe_is_member(&n->probe, dst, &m);
    return m;
}

/* ========================================================================= */
/* Per-hop sealing and transmission                                           */
/* ========================================================================= */

/*
 * Rewrite the per-hop fields of buf (a frame without RS parity), recompute
 * the hop_tag (FLAG_AUTH) and the CRC. *len_io is the frame length on input
 * (only the header, len field and tags decide the layout) and the sealed
 * length (body + CRC) on output.
 */
static br_err_t node_seal_hop(br_node_t *n, uint8_t *buf, size_t cap, size_t *len_io,
                              const br_hop_fields_t *hf)
{
    if (*len_io < 2u) {
        return BR_ERR_DECODE;
    }
    size_t hl = br_hdr_len_for_type(buf[BR_OFF_TYPE]);
    if (*len_io < hl) {
        return BR_ERR_DECODE;
    }
    bool auth = (buf[BR_OFF_VER_FLAGS] & BR_FLAG_AUTH) != 0u;
    size_t body = hl + buf[hl - 1u] + (auth ? (size_t)BR_TAGS_LEN : 0u);
    if (body + BR_CRC_LEN > cap || body + BR_CRC_LEN > *len_io) {
        return BR_ERR_DECODE;
    }
    br_err_t rc = br_frame_set_hop_fields(buf, *len_io, hf);
    if (rc == BR_OK && auth) {
        rc = br_hop_tag(&n->crypto, n->keys.k_hop, buf, body - BR_HOP_TAG_LEN, buf + body - BR_HOP_TAG_LEN);
    }
    if (rc == BR_OK) {
        rc = br_frame_seal_crc(buf, body, cap, len_io);
    }
    return rc;
}

/* Per-hop encode (RS on RAW links) and hand to the carrier. */
static br_err_t node_tx(br_node_t *n, uint8_t link, const uint8_t *addr, uint8_t addr_len, uint8_t *buf,
                        size_t len)
{
    const br_transport_t *t = &n->cfg.transports[link];
    size_t total = len;
    if (t->rs_nsym > 0u) {
        if (len + t->rs_nsym > BR_MAX_FRAME_MESH ||
            br_rs_encode(buf, len, t->rs_nsym, buf + len) != BR_OK) {
            return BR_ERR_TOO_BIG;
        }
        total += t->rs_nsym;
    }
    if (total > t->max_frame) {
        return BR_ERR_TOO_BIG;
    }
    br_err_t rc = t->send(t->user, addr_len > 0u ? addr : NULL, buf, (uint16_t)total);
    if (rc == BR_OK) {
        br_stats_inc(&n->stats, BR_STAT_TX_FRAMES);
    }
    return rc;
}

/* Broadcast scratch[0..len) as a flood copy on every eligible transport. */
static void node_flood_out(br_node_t *n, size_t len, uint8_t ttl, uint8_t hops, uint16_t path_mtu,
                           uint8_t path_cost, uint8_t arrival)
{
    for (uint8_t li = 0; li < n->cfg.n_transports; li++) {
        const br_transport_t *t = &n->cfg.transports[li];
        if (t->edge_only || (li == arrival && !t->can_broadcast)) {
            continue; /* 9f: not on edge links, not back over the point-to-point arrival link */
        }
        uint16_t mtu = tr_mtu(t);
        for (uint8_t k = 0; k < BR_FLOOD_REPEAT; k++) {
            br_hop_fields_t hf;
            memset(&hf, 0, sizeof hf);
            hf.prev_hop = n->cfg.unit_id;
            hf.next_hop = BR_ID_FLOOD;
            hf.ttl = ttl;
            hf.hops = hops;
            hf.path_mtu = path_mtu < mtu ? path_mtu : mtu;
            hf.path_cost = path_cost;
            size_t l = len;
            if (take_txseq(n, &hf.hop_seq) != BR_OK ||
                node_seal_hop(n, n->scratch, sizeof n->scratch, &l, &hf) != BR_OK) {
                return;
            }
            (void)node_tx(n, li, NULL, 0u, n->scratch, l);
        }
    }
}

/* env->send: originate an e2e frame built by the session layer. */
static br_err_t sess_send(void *user, const uint8_t *frame, size_t len, bool flood)
{
    br_node_t *n = (br_node_t *)user;
    if (frame == NULL || len < BR_HDR_LEN || len > sizeof n->scratch) {
        return BR_ERR_ARG;
    }
    uint32_t now_ms = br_ms_from_us(platform_now_us());
    memcpy(n->scratch, frame, len);
    br_hdr_t h;
    size_t hl = 0;
    if (br_hdr_decode(n->scratch, len, &h, &hl) != BR_OK) {
        return BR_ERR_ARG;
    }
    if (flood) {
        /* 11.5 origin bookkeeping: our own (src_id, pre_ctr) first, so echoes hit 9a */
        if (h.len >= BR_LEN_PRE_CTR && len >= hl + BR_LEN_PRE_CTR) {
            (void)br_dedup_insert(&n->tables.dedup, n->cfg.unit_id, br_rd_le32(n->scratch + hl), 0u, now_ms, NULL);
        }
        node_flood_out(n, len, n->cfg.seek_ttl, 0u, BR_MAX_FRAME_MESH, 0u, BR_NO_TRANSPORT);
        return BR_OK;
    }
    br_route_entry_t *r = NULL;
    (void)br_route_find(&n->tables.route, h.dst_id, now_ms, &r);
    if (r == NULL || r->transport >= n->cfg.n_transports) {
        br_stats_inc(&n->stats, BR_STAT_RELAY_DROP_NOROUTE);
        return BR_ERR_STATE;
    }
    br_link_entry_t *le = NULL;
    (void)br_link_find(&n->tables.link, r->next_hop, r->transport, &le);
    br_hop_fields_t hf;
    memset(&hf, 0, sizeof hf);
    hf.prev_hop = n->cfg.unit_id;
    hf.next_hop = r->next_hop;
    hf.ttl = min_u8(BR_MAX_HOPS, (uint32_t)r->hops + 2u); /* 11.4: min(MAX_HOPS, route.hops + 2) */
    hf.hops = 0u;
    uint8_t link = r->transport;
    uint8_t addr[BR_ADDR_MAX];
    uint8_t addr_len = 0;
    if (le != NULL && le->addr_len > 0u) {
        memcpy(addr, le->addr, le->addr_len);
        addr_len = le->addr_len;
    }
    size_t l = len;
    br_err_t rc = take_txseq(n, &hf.hop_seq);
    if (rc == BR_OK) {
        rc = node_seal_hop(n, n->scratch, sizeof n->scratch, &l, &hf);
    }
    if (rc == BR_OK) {
        rc = node_tx(n, link, addr, addr_len, n->scratch, l);
    }
    return rc;
}

static void node_env(br_node_t *n, br_sess_env_t *env, uint32_t now_ms)
{
    memset(env, 0, sizeof *env);
    env->user = n;
    env->self_id = n->cfg.unit_id;
    env->caps = n->cfg.caps;
    env->own_mtu = tr_mtu(&n->cfg.transports[0]);
    env->seek_ttl = n->cfg.seek_ttl;
    env->node_count = n->cfg.node_count;
    env->auth = n->cfg.auth;
    env->now_ms = now_ms;
    env->crypto = &n->crypto;
    env->keys = &n->keys;
    env->app = &n->cfg.app;
    env->stats = &n->stats;
    env->send = sess_send;
    env->next_pre_ctr = sess_next_pre_ctr;
    env->random = sess_random;
}

/* Send every queued unicast forward (11.4 step 10e). */
static void node_drain_fwdq(br_node_t *n)
{
    for (;;) {
        const br_fwd_slot_t *s = NULL;
        if (br_fwdq_pop(&n->tables.fwdq, &s) != BR_OK || s == NULL) {
            return;
        }
        if (s->len > sizeof n->scratch || s->transport >= n->cfg.n_transports) {
            continue;
        }
        uint8_t link = s->transport;
        uint8_t addr[BR_ADDR_MAX];
        uint8_t addr_len = s->addr_len <= BR_ADDR_MAX ? s->addr_len : 0u;
        memcpy(addr, s->addr, sizeof addr);
        uint16_t next_hop = s->next_hop;
        size_t l = s->len;
        memcpy(n->scratch, s->frame, l);
        uint8_t th = n->scratch[BR_OFF_TTL_HOPS];
        br_hop_fields_t hf;
        memset(&hf, 0, sizeof hf);
        hf.prev_hop = n->cfg.unit_id;
        hf.next_hop = next_hop;
        hf.ttl = (uint8_t)(((th >> 4) & 0x0Fu) - 1u);
        hf.hops = (uint8_t)((th & 0x0Fu) + 1u);
        if (n->scratch[BR_OFF_TYPE] == (uint8_t)BR_TYPE_SEEK) {
            hf.path_mtu = br_rd_le16(n->scratch + BR_OFF_PATH_MTU);
            hf.path_cost = n->scratch[BR_OFF_PATH_COST];
        }
        if (take_txseq(n, &hf.hop_seq) != BR_OK ||
            node_seal_hop(n, n->scratch, sizeof n->scratch, &l, &hf) != BR_OK) {
            continue;
        }
        if (node_tx(n, link, addr, addr_len, n->scratch, l) == BR_OK) {
            br_stats_inc(&n->stats, BR_STAT_RELAY_FWD);
        }
    }
}

/* Send the jittered flood copies that are due (11.4 step 9f). */
static void node_run_pending(br_node_t *n, uint32_t now_ms, uint32_t *next_ms)
{
    for (uint8_t i = 0; i < BR_FLOOD_PENDING; i++) {
        br_flood_copy_t *c = &n->tables.pending.c[i];
        if (c->in_use == 0u) {
            continue;
        }
        if (br_ms_before(now_ms, c->due_ms)) {
            if (br_ms_before(c->due_ms, *next_ms)) {
                *next_ms = c->due_ms;
            }
            continue;
        }
        size_t l = c->len <= sizeof n->scratch ? c->len : sizeof n->scratch;
        memcpy(n->scratch, c->frame, l);
        uint8_t th = n->scratch[BR_OFF_TTL_HOPS];
        uint8_t ttl = (uint8_t)(((th >> 4) & 0x0Fu) - 1u);
        uint8_t hops = (uint8_t)((th & 0x0Fu) + 1u);
        uint16_t mtu = BR_MAX_FRAME_MESH;
        uint8_t cost = 0u;
        if (n->scratch[BR_OFF_TYPE] == (uint8_t)BR_TYPE_SEEK) {
            mtu = br_rd_le16(n->scratch + BR_OFF_PATH_MTU);
            cost = min_u8(c->cost, BR_MAX_PATH_COST); /* path_cost += the kept copy's link cost */
        }
        uint8_t arrival = c->transport;
        c->in_use = 0u;
        for (size_t k = 0; k < BR_DEDUP_ENTRIES; k++) {
            if (n->tables.dedup.e[k].pending == i) {
                n->tables.dedup.e[k].pending = BR_NO_INDEX;
            }
        }
        node_flood_out(n, l, ttl, hops, mtu, cost, arrival);
        br_stats_inc(&n->stats, BR_STAT_RELAY_FWD);
    }
}

/* ========================================================================= */
/* Lifecycle                                                                  */
/* ========================================================================= */

br_err_t br_node_init(br_node_t *node, size_t node_size, const br_node_config_t *cfg)
{
    if (node == NULL || cfg == NULL || node_size != sizeof(br_node_t)) {
        return BR_ERR_ARG;
    }
    if (!br_id_is_unit(cfg->unit_id) || cfg->n_transports == 0u ||
        cfg->n_transports > BR_NODE_MAX_TRANSPORTS || cfg->n_groups > BR_MAX_GROUPS ||
        cfg->net_key == NULL || cfg->net_key_len != BR_KEY_LEN || cfg->seek_ttl > BR_MAX_HOPS) {
        return BR_ERR_ARG;
    }
    for (uint8_t i = 0; i < cfg->n_transports; i++) {
        const br_transport_t *t = &cfg->transports[i];
        if (t->send == NULL || t->max_frame < BR_MIN_PATH_MTU || t->max_frame > BR_MAX_FRAME_MESH ||
            t->rs_nsym >= t->max_frame || t->addr_len > BR_ADDR_MAX) {
            return BR_ERR_ARG;
        }
    }
    for (uint8_t i = 0; i < cfg->n_groups; i++) {
        if (!br_id_is_group(cfg->groups[i])) {
            return BR_ERR_ARG;
        }
    }
    br_platform_t pf;
    if (br_platform_get(&pf) != BR_OK) {
        return BR_ERR_STATE;
    }
    uint64_t now_us = pf.now_us(pf.user);
    uint32_t now_ms = br_ms_from_us(now_us);

    br_secure_zero(node, sizeof *node);
    node->cfg = *cfg;
    if (node->cfg.seek_ttl == 0u) {
        node->cfg.seek_ttl = BR_SEEK_TTL_DEFAULT;
    }
    if (node->cfg.node_count == 0u) {
        node->cfg.node_count = 1u;
    }
    if (node->cfg.caps == 0u) {
        /* not configured: the demo set (br_node_config_t doc) */
        node->cfg.caps = (uint16_t)(BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ |
                                    (cfg->auth ? BR_CAP_AUTH : 0u) |
                                    (cfg->role == BR_ROLE_LEAF ? 0u : BR_CAP_RELAY));
    }
    br_err_t rc = br_crypto_init(&node->crypto);
    if (rc != BR_OK) {
        br_secure_zero(node, sizeof *node);
        return rc;
    }
    rc = br_keyring_init_bench(&node->crypto, &node->keys, cfg->net_key, cfg->net_key_len, cfg->key_epoch);
    if (rc != BR_OK) {
        br_crypto_free(&node->crypto);
        br_secure_zero(node, sizeof *node);
        return rc;
    }
    node->cfg.net_key = node->keys.k_site;
    (void)br_tables_init(&node->tables, now_ms);
    for (uint8_t i = 0; i < BR_TX_SESSIONS; i++) {
        (void)br_sender_init(&node->senders[i]);
        node->senders[i].reserved = i; /* handle, BR_SND_HANDLE() */
    }
    (void)br_probe_init(&node->probe);
    (void)br_probe_listen(&node->probe, node->cfg.groups, node->cfg.n_groups);
    node->txseq = cfg->txseq_start;
    node->txseq_reserved = cfg->txseq_start;
    node->preseq = cfg->preseq_start;
    node->preseq_reserved = cfg->preseq_start;
    node->boot_us = now_us;
    node->magic = BR_NODE_MAGIC;
    node->first_seek_not_before_us = now_us;
    if (cfg->cold_boot) {
        uint32_t spread_ms = 600u * (uint32_t)node->cfg.node_count; /* BOOT_SPREAD_MS (4.1.1) */
        node->first_seek_not_before_us = now_us + (uint64_t)node_rand_upto(node, spread_ms) * 1000u;
    }
    return BR_OK;
}

void br_node_deinit(br_node_t *node)
{
    if (node == NULL) {
        return;
    }
    br_crypto_free(&node->crypto);
    br_keyring_wipe(&node->keys);
    for (uint8_t i = 0; i < BR_TX_SESSIONS; i++) {
        br_secure_zero(node->senders[i].ke_hs, sizeof node->senders[i].ke_hs);
        br_secure_zero(node->senders[i].ke_s2p, sizeof node->senders[i].ke_s2p);
        br_secure_zero(node->senders[i].ke_p2s, sizeof node->senders[i].ke_p2s);
    }
    br_secure_zero(&node->probe, sizeof node->probe);
    node->magic = 0;
}

/* ========================================================================= */
/* Receive pipeline (11.4)                                                    */
/* ========================================================================= */

static void verdict_drop(br_rx_verdict_t *v, br_node_t *n, br_stat_id_t stat, uint8_t step)
{
    br_stats_inc(&n->stats, stat);
    v->action = BR_RXV_DROP;
    v->stat = stat;
    v->step = step;
}

static bool version_ok(const br_hdr_t *h)
{
    return h->version >= BR_PROTO_VERSION_MIN && h->version <= BR_PROTO_VERSION;
}

static bool type_to_sender(uint8_t type)
{
    return type == (uint8_t)BR_TYPE_HELLO || type == (uint8_t)BR_TYPE_BIND_ACK ||
           type == (uint8_t)BR_TYPE_BIND_NAK || type == (uint8_t)BR_TYPE_MODE_ACK ||
           type == (uint8_t)BR_TYPE_ACK || type == (uint8_t)BR_TYPE_PONG;
}

static bool type_to_probe(uint8_t type)
{
    return type == (uint8_t)BR_TYPE_SEEK || type == (uint8_t)BR_TYPE_BIND || type == (uint8_t)BR_TYPE_MODE ||
           type == (uint8_t)BR_TYPE_DATA || type == (uint8_t)BR_TYPE_PARITY || type == (uint8_t)BR_TYPE_PING;
}

/* Step 7 / 9e: hand an admitted frame to the endpoint logic. Returns the drop counter. */
static br_stat_id_t node_deliver(br_node_t *n, const br_rx_frame_t *f, uint32_t now_ms)
{
    br_sess_env_t env;
    node_env(n, &env, now_ms);
    uint8_t type = f->view->hdr.type;
    br_stat_id_t drop = BR_STAT_NONE;
    if (type_to_sender(type) || type == (uint8_t)BR_TYPE_CLOSE) {
        br_stat_id_t last = BR_STAT_NONE;
        for (uint8_t i = 0; i < BR_TX_SESSIONS; i++) {
            br_stat_id_t d = BR_STAT_NONE;
            br_err_t rc = br_sender_rx(&n->senders[i], &env, f, &d);
            if (rc == BR_OK) {
                return d;
            }
            if (d != BR_STAT_NONE) {
                last = d;
            }
        }
        if (type != (uint8_t)BR_TYPE_CLOSE) {
            if (last != BR_STAT_NONE) {
                return last;
            }
            /* no sender session for it: a stale pre-session reply is ignored; a
             * session frame of an unknown (src_id, session_id) is counted (N27) */
            bool session_type = type == (uint8_t)BR_TYPE_MODE_ACK || type == (uint8_t)BR_TYPE_ACK ||
                                type == (uint8_t)BR_TYPE_PONG;
            return session_type ? BR_STAT_UNKNOWN_SESSION : BR_STAT_NONE;
        }
    } else if (!type_to_probe(type)) {
        return BR_STAT_BAD_FRAME; /* RESUME / MGMT / unknown types: not served in phase 1b */
    }
    (void)br_probe_rx(&n->probe, &env, f, &drop);
    return drop;
}

static uint8_t route_cost(uint8_t hops_after, uint8_t link_cost)
{
    return min_u8((uint32_t)hops_after * link_cost, BR_MAX_PATH_COST);
}

br_err_t br_node_rx(br_node_t *node, const uint8_t *frame, size_t len, uint8_t link,
                    const br_rx_meta_t *prev_hop_hint, br_rx_verdict_t *verdict_out)
{
    br_rx_verdict_t vloc;
    br_rx_verdict_t *v = verdict_out != NULL ? verdict_out : &vloc;
    memset(v, 0, sizeof *v);
    v->action = BR_RXV_DROP;
    v->stat = BR_STAT_NONE;
    v->reject = BR_REJ_NONE;
    if (node == NULL || frame == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    if (link >= node->cfg.n_transports) {
        return BR_ERR_ARG;
    }
    br_node_t *n = node;
    uint32_t now_ms = br_ms_from_us(platform_now_us());
    const br_transport_t *tr = &n->cfg.transports[link];
    br_stats_inc(&n->stats, BR_STAT_RX_FRAMES);
    v->type = len >= 2u ? frame[BR_OFF_TYPE] : 0u;

    /* ---- step 1: per-hop decode (RS on RAW links; COBS is the adapter's) ---- */
    const uint8_t *buf = frame;
    uint8_t rsbuf[BR_MAX_FRAME_MESH];
    if (tr->rs_nsym > 0u) {
        if (len > sizeof rsbuf || len <= tr->rs_nsym) {
            verdict_drop(v, n, len > sizeof rsbuf ? BR_STAT_BAD_FRAME : BR_STAT_RS_FAIL, 1u);
            return BR_OK;
        }
        memcpy(rsbuf, frame, len);
        uint8_t fixed = 0;
        if (br_rs_decode(rsbuf, len, tr->rs_nsym, NULL, 0u, &fixed) != BR_OK) {
            verdict_drop(v, n, BR_STAT_RS_FAIL, 1u);
            return BR_OK;
        }
        if (fixed > 0u) {
            br_stats_inc(&n->stats, BR_STAT_RS_CORRECTED);
        }
        buf = rsbuf;
    }

    /* ---- steps 1-3: CRC, Length, Header, SEEK hop fields (forwarder rows) ---- */
    br_link_params_t lp = { tr->max_frame, tr->rs_nsym };
    br_frame_view_t view;
    br_reject_t why = BR_REJ_NONE;
    if (br_frame_validate(buf, len, &lp, false, &view, &why) != BR_OK) {
        br_counter_t c = BR_CNT_BAD_FRAME;
        (void)br_reject_counter(why, &c);
        v->reject = why;
        verdict_drop(v, n, br_stat_from_counter(c), why == BR_REJ_CRC ? 1u : 2u);
        return BR_OK;
    }
    const br_hdr_t *h = &view.hdr;
    v->type = h->type;

    /* ---- step 4: AUTH policy ---- */
    if (n->cfg.auth && !view.has_auth) {
        verdict_drop(v, n, BR_STAT_AUTH_FAIL, 4u);
        return BR_OK;
    }

    /* ---- step 5: hop_tag under the held epoch, then hop_seq freshness ---- */
    if (view.has_auth &&
        br_hop_tag_verify(&n->crypto, n->keys.k_hop, buf, view.hop_tag_off, buf + view.hop_tag_off) != BR_OK) {
        v->reject = BR_REJ_HOP_TAG;
        verdict_drop(v, n, BR_STAT_HOP_TAG_FAIL, 5u);
        return BR_OK;
    }
    {
        br_link_entry_t *le = NULL;
        (void)br_link_find(&n->tables.link, h->prev_hop, link, &le);
        br_reject_t hr = BR_REJ_NONE;
        if (br_hop_seq_check(le != NULL, le != NULL ? le->hop_seq : 0u, h->hop_seq, &hr) != BR_OK) {
            v->reject = hr;
            verdict_drop(v, n, BR_STAT_HOP_REPLAY, 5u);
            return BR_OK;
        }
    }
    if (h->prev_hop == n->cfg.unit_id) {
        /* 11.5: a verified frame claiming our ID as transmitter: ID collision */
        br_stats_inc(&n->stats, BR_STAT_ID_COLLISIONS);
        if (n->cfg.app.on_event != NULL) {
            n->cfg.app.on_event(n->cfg.app.user, BR_EVT_ID_COLLISION, h->prev_hop);
        }
        v->action = BR_RXV_DROP;
        v->stat = BR_STAT_ID_COLLISIONS;
        v->step = 5u;
        return BR_OK;
    }

    /* ---- step 6: learn / refresh the link ---- */
    int8_t rssi = prev_hop_hint != NULL ? prev_hop_hint->rssi : (int8_t)BR_RSSI_UNKNOWN;
    (void)br_link_learn(&n->tables.link, &n->tables.route, h->prev_hop, link,
                        prev_hop_hint != NULL ? prev_hop_hint->addr : NULL,
                        prev_hop_hint != NULL ? prev_hop_hint->addr_len : 0u, h->hop_seq, n->keys.epoch,
                        rssi, now_ms, &n->stats);
    uint8_t lcost = 1u;
    (void)br_link_cost(rssi, tr->link_cost, &lcost);
    uint8_t hops_after = (uint8_t)(h->hops + 1u);

    br_rx_frame_t rf;
    rf.buf = buf;
    rf.len = len;
    rf.view = &view;
    rf.transport = link;
    rf.hops = hops_after;
    rf.link_cost = lcost;
    rf.rssi = rssi;
    rf.prev_hop = h->prev_hop;

    /* ================= floods: steps 9a-9f ================= */
    if (h->next_hop == BR_ID_FLOOD) {
        uint32_t pre = 0;
        br_reject_t pr = BR_REJ_NONE;
        if (br_frame_pre_ctr(buf, &view, &pre, &pr) != BR_OK) {
            v->reject = pr;
            verdict_drop(v, n, BR_STAT_BAD_FRAME, 9u);
            return BR_OK;
        }
        if (h->src_id == n->cfg.unit_id) { /* 9a: echo of my own flood */
            br_dedup_entry_t *d = NULL;
            (void)br_dedup_find(&n->tables.dedup, h->src_id, pre, now_ms, &d);
            if (d == NULL) {
                br_stats_inc(&n->stats, BR_STAT_ID_COLLISIONS);
                if (n->cfg.app.on_event != NULL) {
                    n->cfg.app.on_event(n->cfg.app.user, BR_EVT_ID_COLLISION, h->src_id);
                }
            }
            v->step = 9u;
            return BR_OK;
        }
        if (lcost == BR_COST_IGNORE) { /* 11.2: copies below -90 dBm are ignored */
            v->step = 9u;
            return BR_OK;
        }
        bool is_seek = h->type == (uint8_t)BR_TYPE_SEEK;
        uint8_t copy_cost = min_u8((uint32_t)(is_seek ? h->path_cost : h->hops) + lcost, BR_MAX_PATH_COST);
        bool mine = is_member(n, h->dst_id);
        br_dedup_entry_t *d = NULL;
        (void)br_dedup_find(&n->tables.dedup, h->src_id, pre, now_ms, &d);
        if (d != NULL) { /* 9b */
            bool pend = d->pending < BR_FLOOD_PENDING && n->tables.pending.c[d->pending].in_use != 0u;
            bool in_window = pend || !br_ms_before(d->t_ms + BR_RELAY_JITTER_MS, now_ms);
            if (in_window && copy_cost < d->best_cost) {
                d->best_cost = copy_cost;
                (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_FLOOD, h->src_id, h->prev_hop, link,
                                     hops_after, copy_cost, false, true, now_ms, &n->stats);
                if (pend) {
                    br_flood_copy_t *c = &n->tables.pending.c[d->pending];
                    size_t keep = len - tr->rs_nsym;
                    if (keep <= sizeof c->frame) {
                        memcpy(c->frame, buf, keep);
                        c->len = (uint16_t)keep;
                        c->transport = link;
                        c->cost = copy_cost;
                    }
                }
                if (mine && is_seek) {
                    br_probe_offer_copy(&n->probe, h->src_id, pre, h->prev_hop, link, hops_after, h->path_cost,
                                        h->path_mtu); /* HELLO carries path_cost as received (N32) */
                }
            }
            verdict_drop(v, n, BR_STAT_RELAY_DROP_DEDUP, 9u);
            return BR_OK;
        }
        bool fresh = true;
        (void)br_origin_check(&n->tables.origin, h->src_id, pre, now_ms, &fresh);
        if (!fresh) { /* 9c */
            verdict_drop(v, n, BR_STAT_RELAY_DROP_STALE, 9u);
            return BR_OK;
        }
        bool fresher = true;
        for (size_t i = 0; i < BR_ORIGIN_ENTRIES; i++) {
            const br_origin_entry_t *o = &n->tables.origin.e[i];
            if (o->src_id == h->src_id && o->last_ctr == pre) {
                fresher = false;
            }
        }
        bool granted = false;
        (void)br_flood_budget_take(&n->tables.budget, h->src_id, now_ms, &granted);
        if (!granted) { /* 9d */
            verdict_drop(v, n, BR_STAT_RELAY_DROP_RATE, 9u);
            return BR_OK;
        }
        /* 9e: tables first, then local delivery */
        (void)br_dedup_insert(&n->tables.dedup, h->src_id, pre, copy_cost, now_ms, &d);
        (void)br_origin_update(&n->tables.origin, h->src_id, pre, now_ms);
        (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_FLOOD, h->src_id, h->prev_hop, link, hops_after,
                             copy_cost, fresher, true, now_ms, &n->stats);
        bool forward = !(h->dst_id == n->cfg.unit_id || n->cfg.role == BR_ROLE_LEAF || tr->edge_only);
        bool ttl_end = h->ttl <= 1u;
        uint8_t slot = BR_NO_INDEX;
        bool pending_full = false;
        if (forward && !ttl_end) {
            /* 9f: keep the copy for the jittered rebroadcast (before delivery: no
             * table or buffer pointer is held across the session call) */
            for (uint8_t i = 0; i < BR_FLOOD_PENDING && slot == BR_NO_INDEX; i++) {
                if (n->tables.pending.c[i].in_use == 0u) {
                    slot = i;
                }
            }
            size_t keep = len - tr->rs_nsym;
            if (slot != BR_NO_INDEX && keep <= BR_MAX_FRAME_MESH) {
                br_flood_copy_t *c = &n->tables.pending.c[slot];
                memcpy(c->frame, buf, keep);
                c->len = (uint16_t)keep;
                c->in_use = 1u;
                c->transport = link;
                c->cost = copy_cost;
                c->src_id = h->src_id;
                c->pre_ctr = pre;
                c->due_ms = now_ms + node_rand_upto(n, BR_RELAY_JITTER_MS);
                if (d != NULL) {
                    d->pending = slot;
                }
            } else {
                slot = BR_NO_INDEX;
                pending_full = true;
                br_stats_inc(&n->stats, BR_STAT_FLOOD_PENDING_FULL); /* no FLOOD_PENDING buffer (11.5) */
            }
        }
        bool delivered = false;
        br_stat_id_t ds = BR_STAT_NONE;
        if (mine) {
            if (!version_ok(h)) {
                ds = BR_STAT_BAD_VERSION; /* forwarded, never delivered locally (11.4 step 3) */
            } else {
                ds = node_deliver(n, &rf, now_ms);
            }
            br_stats_inc(&n->stats, ds);
            delivered = (ds == BR_STAT_NONE);
        }
        if (forward && ttl_end) {
            br_stats_inc(&n->stats, BR_STAT_RELAY_DROP_TTL);
        }
        v->step = 9u;
        v->stat = ds;
        if (slot != BR_NO_INDEX) {
            v->action = delivered ? BR_RXV_DELIVER_FLOOD : BR_RXV_FLOOD_PENDING;
        } else {
            v->action = delivered ? BR_RXV_DELIVER : BR_RXV_DROP;
            if (!delivered && ds == BR_STAT_NONE) {
                v->stat = pending_full              ? BR_STAT_FLOOD_PENDING_FULL
                          : (forward && ttl_end)    ? BR_STAT_RELAY_DROP_TTL
                                                    : BR_STAT_NONE;
            }
        }
        node_drain_fwdq(n);
        return BR_OK;
    }

    /* ================= unicast ================= */
    if (h->next_hop != n->cfg.unit_id) { /* step 8: overheard */
        v->step = 8u;
        return BR_OK;
    }
    if (is_member(n, h->dst_id)) { /* step 7: for me */
        v->step = 7u;
        if (!version_ok(h)) {
            v->reject = BR_REJ_VERSION;
            verdict_drop(v, n, BR_STAT_BAD_VERSION, 7u);
            return BR_OK;
        }
        if (h->type == (uint8_t)BR_TYPE_HELLO) {
            (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_HELLO, h->src_id, h->prev_hop, link, hops_after,
                                 route_cost(hops_after, lcost), false, false, now_ms, &n->stats);
        } else {
            (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_OTHER, h->src_id, h->prev_hop, link, hops_after,
                                 route_cost(hops_after, lcost), false, false, now_ms, &n->stats);
        }
        (void)br_route_refresh(&n->tables.route, h->src_id, h->prev_hop, link, now_ms);
        br_stat_id_t ds = node_deliver(n, &rf, now_ms);
        if (ds != BR_STAT_NONE) {
            verdict_drop(v, n, ds, 7u);
        } else {
            v->action = BR_RXV_DELIVER;
        }
        node_drain_fwdq(n);
        return BR_OK;
    }

    /* step 10: unicast forwarding */
    v->step = 10u;
    br_route_entry_t *r = NULL;
    (void)br_route_find(&n->tables.route, h->dst_id, now_ms, &r);
    if (r == NULL || n->cfg.role == BR_ROLE_LEAF || tr->edge_only || r->transport >= n->cfg.n_transports) {
        verdict_drop(v, n, BR_STAT_RELAY_DROP_NOROUTE, 10u); /* 10a */
        return BR_OK;
    }
    if (r->next_hop == h->prev_hop && r->transport == link) {
        verdict_drop(v, n, BR_STAT_RELAY_DROP_LOOP, 10u); /* 10b */
        return BR_OK;
    }
    const br_transport_t *out = &n->cfg.transports[r->transport];
    size_t body = view.crc_off + BR_CRC_LEN; /* frame without RS parity */
    if (h->ttl <= 1u) {
        verdict_drop(v, n, BR_STAT_RELAY_DROP_TTL, 10u); /* 10c */
        return BR_OK;
    }
    if (out->edge_only || body > tr_mtu(out)) {
        verdict_drop(v, n, BR_STAT_RELAY_DROP_MTU, 10u);
        return BR_OK;
    }
    uint16_t next_hop = r->next_hop;
    uint8_t out_link = r->transport;
    /* 10e route rows for frames I forward (11.4 table) */
    if (h->type == (uint8_t)BR_TYPE_HELLO) {
        (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_HELLO, h->src_id, h->prev_hop, link, hops_after,
                             route_cost(hops_after, lcost), false, false, now_ms, &n->stats);
    } else {
        (void)br_route_learn(&n->tables.route, BR_ROUTE_EV_OTHER, h->src_id, h->prev_hop, link, hops_after,
                             route_cost(hops_after, lcost), false, false, now_ms, &n->stats);
    }
    (void)br_route_refresh(&n->tables.route, h->src_id, h->prev_hop, link, now_ms);
    br_link_entry_t *le = NULL;
    (void)br_link_find(&n->tables.link, next_hop, out_link, &le);
    uint8_t addr[BR_ADDR_MAX];
    uint8_t addr_len = 0;
    if (le != NULL && le->addr_len > 0u) {
        memcpy(addr, le->addr, le->addr_len);
        addr_len = le->addr_len;
    }
    uint32_t before_data = n->stats.f.relay_drop_queue_data;
    if (br_fwdq_push(&n->tables.fwdq, buf, (uint16_t)body, out_link, addr, addr_len, next_hop, &n->stats) !=
        BR_OK) { /* 10d: counted by the queue */
        v->action = BR_RXV_DROP;
        v->stat = (n->stats.f.relay_drop_queue_data != before_data)
                      ? BR_STAT_RELAY_DROP_QUEUE_DATA
                      : BR_STAT_RELAY_DROP_QUEUE_CTRL;
        return BR_OK;
    }
    v->action = BR_RXV_FORWARD;
    node_drain_fwdq(n);
    return BR_OK;
}

br_err_t br_node_tx_status(br_node_t *node, uint8_t link, const uint8_t *addr, uint8_t addr_len,
                           bool delivered)
{
    if (node == NULL || (addr == NULL && addr_len > 0u) || addr_len > BR_ADDR_MAX) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    if (link >= node->cfg.n_transports) {
        return BR_ERR_ARG;
    }
    if (!node->cfg.transports[link].mac_retry || addr_len == 0u) {
        return BR_OK;
    }
    uint16_t unit = 0;
    for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
        const br_link_entry_t *l = &node->tables.link.e[i];
        if (l->transport == link && l->addr_len == addr_len && memcmp(l->addr, addr, addr_len) == 0) {
            unit = l->unit_id;
        }
    }
    bool deleted = false;
    (void)br_link_tx_result(&node->tables.link, &node->tables.route, link, addr, addr_len, delivered,
                            &node->stats, &deleted);
    if (deleted && node->cfg.app.on_event != NULL) {
        node->cfg.app.on_event(node->cfg.app.user, BR_EVT_LINK_FAIL, ((uint32_t)link << 16) | unit);
    }
    return BR_OK;
}

/* ========================================================================= */
/* Timers                                                                     */
/* ========================================================================= */

br_err_t br_node_tick(br_node_t *node, uint64_t now_us, uint64_t *next_deadline_out)
{
    if (next_deadline_out != NULL) {
        *next_deadline_out = BR_NEVER_US;
    }
    if (node == NULL || next_deadline_out == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    br_node_t *n = node;
    uint32_t now_ms = br_ms_from_us(now_us);
    uint32_t next = now_ms + BR_FAR_MS;
    br_sess_env_t env;
    node_env(n, &env, now_ms);
    for (uint8_t i = 0; i < BR_TX_SESSIONS; i++) {
        uint32_t d = now_ms + BR_FAR_MS;
        (void)br_sender_tick(&n->senders[i], &env, &d);
        if (br_ms_before(d, next)) {
            next = d;
        }
    }
    {
        uint32_t d = now_ms + BR_FAR_MS;
        (void)br_probe_tick(&n->probe, &env, &d);
        if (br_ms_before(d, next)) {
            next = d;
        }
    }
    node_run_pending(n, now_ms, &next);
    node_drain_fwdq(n);
    (void)br_route_expire(&n->tables.route, now_ms);
    (void)br_link_expire(&n->tables.link, &n->tables.route, now_ms);
    uint32_t delta = next - now_ms;
    if (delta >= BR_FAR_MS) {
        *next_deadline_out = BR_NEVER_US;
    } else if (delta == 0u || br_ms_before(next, now_ms)) {
        *next_deadline_out = now_us;
    } else {
        *next_deadline_out = (now_us - now_us % 1000u) + (uint64_t)delta * 1000u;
    }
    return BR_OK;
}

br_err_t br_node_count_rx_queue_drop(br_node_t *node)
{
    if (node == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    br_stats_inc(&node->stats, BR_STAT_RX_QUEUE_DROP);
    return BR_OK;
}

void br_node_count_seg_fail(br_node_t *node)
{
    if (node == NULL || !node_ok(node)) {
        return;
    }
    br_stats_inc(&node->stats, BR_STAT_SEG_FAIL);
}

/* ========================================================================= */
/* Application API                                                            */
/* ========================================================================= */

static br_sender_t *sender_of(br_node_t *n, br_session_t s)
{
    return (s < BR_TX_SESSIONS) ? &n->senders[s] : NULL;
}

br_err_t br_node_seek(br_node_t *node, uint16_t dst_id, br_session_t *s_out)
{
    if (node == NULL || s_out == NULL || dst_id == 0u || dst_id == BR_ID_FLOOD) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    uint64_t now_us = platform_now_us();
    uint32_t now_ms = br_ms_from_us(now_us);
    for (uint8_t i = 0; i < BR_TX_SESSIONS; i++) {
        br_sender_t *s = &node->senders[i];
        if (s->state != BR_SND_IDLE && s->state != BR_SND_CLOSED) {
            continue;
        }
        br_sess_env_t env;
        node_env(node, &env, now_ms);
        br_err_t rc = br_sender_seek(s, &env, dst_id);
        if (rc != BR_OK) {
            return rc;
        }
        if (now_us < node->first_seek_not_before_us) {
            s->t_deadline_ms = br_ms_from_us(node->first_seek_not_before_us); /* BOOT_SPREAD_MS (4.1.1) */
        }
        *s_out = i;
        uint32_t d = 0;
        (void)br_sender_tick(s, &env, &d); /* the first SEEK goes out now unless held off */
        return BR_OK;
    }
    return BR_ERR_BUSY;
}

br_err_t br_node_listen(br_node_t *node, const uint16_t *groups, uint8_t n_groups)
{
    if (node == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    return br_probe_listen(&node->probe, groups, n_groups);
}

br_err_t br_node_set_mode(br_node_t *node, br_session_t s, const br_mode_t *mode)
{
    if (node == NULL || mode == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    br_sender_t *sp = sender_of(node, s);
    if (sp == NULL) {
        return BR_ERR_ARG;
    }
    br_sess_env_t env;
    node_env(node, &env, br_ms_from_us(platform_now_us()));
    return br_sender_set_mode(sp, &env, mode);
}

br_err_t br_node_send_sample(br_node_t *node, br_session_t s, const br_value_t *vals,
                             uint8_t n_samples, uint32_t t_first_us, uint8_t status, bool ack_req)
{
    if (node == NULL || vals == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    br_sender_t *sp = sender_of(node, s);
    if (sp == NULL) {
        return BR_ERR_ARG;
    }
    br_sess_env_t env;
    node_env(node, &env, br_ms_from_us(platform_now_us()));
    return br_sender_send_samples(sp, &env, vals, n_samples, t_first_us, status, ack_req);
}

br_err_t br_node_close(br_node_t *node, br_session_t s, uint8_t reason)
{
    if (node == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    br_sess_env_t env;
    node_env(node, &env, br_ms_from_us(platform_now_us()));
    if ((s & BR_SESSION_PROBE) != 0u && s != BR_SESSION_NONE) {
        return br_probe_close(&node->probe, &env, (uint8_t)(s & 0x7Fu), reason);
    }
    br_sender_t *sp = sender_of(node, s);
    if (sp == NULL) {
        return BR_ERR_ARG;
    }
    return br_sender_close(sp, &env, reason);
}

/* ========================================================================= */
/* Inspection                                                                 */
/* ========================================================================= */

br_err_t br_node_get_stats(const br_node_t *node, br_stats_t *out)
{
    if (node == NULL || out == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    *out = node->stats;
    return BR_OK;
}

br_err_t br_node_get_tables(const br_node_t *node, const br_tables_t **out)
{
    if (node == NULL || out == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    *out = &node->tables;
    return BR_OK;
}

br_err_t br_node_route(const br_node_t *node, uint16_t dst_id, br_route_entry_t *out, bool *found_out)
{
    if (node == NULL || out == NULL || found_out == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    *found_out = false;
    uint32_t now_ms = br_ms_from_us(platform_now_us());
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        const br_route_entry_t *r = &node->tables.route.e[i];
        if (r->dst_id == dst_id && dst_id != 0u && br_ms_before(now_ms, r->expiry_ms)) {
            *out = *r;
            *found_out = true;
            break;
        }
    }
    return BR_OK;
}

br_err_t br_node_session_state(const br_node_t *node, br_session_t s, uint8_t *state_out)
{
    if (node == NULL || state_out == NULL) {
        return BR_ERR_ARG;
    }
    if (!node_ok(node)) {
        return BR_ERR_STATE;
    }
    if ((s & BR_SESSION_PROBE) != 0u && s != BR_SESSION_NONE) {
        uint8_t idx = (uint8_t)(s & 0x7Fu);
        if (idx >= BR_RX_RECORDS) {
            return BR_ERR_ARG;
        }
        *state_out = node->probe.rec[idx].state;
        return BR_OK;
    }
    if (s >= BR_TX_SESSIONS) {
        return BR_ERR_ARG;
    }
    *state_out = node->senders[s].state;
    return BR_OK;
}

#ifdef BR_SIZE_PROBE
/* One-off RAM measurement: `nm -S` on the archive prints sizeof(br_node_t). */
__attribute__((used)) const uint8_t br_node_size_probe[sizeof(br_node_t)] = {0};
#endif
