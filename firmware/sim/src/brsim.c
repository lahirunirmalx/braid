// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * brsim.c - deterministic mesh simulator: event heap, virtual clock, medium,
 * trace, br_node adapter (see brsim.h for the model).
 */
#include "brsim/brsim.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "braid/br_platform.h"

/* ------------------------------------------------------------------------- */
/* PRNG: splitmix64 for seeding, xorshift64* for streams                      */
/* ------------------------------------------------------------------------- */

static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static uint64_t stream_seed(uint64_t seed, uint64_t salt)
{
    uint64_t x = seed ^ salt;
    uint64_t v = splitmix64(&x);
    return v != 0 ? v : 0x2545F4914F6CDD1Dull;
}

static uint64_t rng_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/* Uniform in [0, n) by rejection (no modulo bias); n == 0 -> 0. */
static uint32_t rng_below(uint64_t *s, uint32_t n)
{
    if (n == 0) {
        return 0;
    }
    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    uint32_t v;
    do {
        v = (uint32_t)(rng_next(s) >> 32);
    } while (v >= limit);
    return v % n;
}

/* ------------------------------------------------------------------------- */
/* Platform singleton                                                         */
/* ------------------------------------------------------------------------- */

static brsim_t *s_active;

static uint64_t sim_now_us(void *user)
{
    const brsim_t *sim = (const brsim_t *)user;
    return sim->now_us;
}

static br_err_t sim_random_bytes(void *user, uint8_t *buf, size_t len)
{
    brsim_t *sim = (brsim_t *)user;
    if (buf == NULL && len > 0) {
        return BR_ERR_ARG;
    }
    uint64_t *st = (sim->cur_node < sim->n_nodes) ? &sim->nodes[sim->cur_node].rng : &sim->rng_scenario;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rng_next(st) >> 56);
    }
    return BR_OK;
}

static void sim_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    brsim_t *sim = (brsim_t *)user;
    if (sim->trace == NULL) {
        return;
    }
    char line[BRSIM_TRACE_LINE_MAX];
    unsigned node = sim->cur_node < sim->n_nodes ? sim->nodes[sim->cur_node].unit_id : 0xFFFFu;
    /* Log lines go to the sink but not into the trace hash (verbosity must
     * not change the determinism check). */
    snprintf(line, sizeof line, "# %" PRIu64 " %04X %d %s: %s", sim->now_us, node, (int)level,
             tag != NULL ? tag : "", msg != NULL ? msg : "");
    sim->trace(sim->trace_user, line);
}

/* ------------------------------------------------------------------------- */
/* Event heap (min on (t_us, order))                                          */
/* ------------------------------------------------------------------------- */

static bool ev_less(const brsim_event_t *a, const brsim_event_t *b)
{
    return a->t_us < b->t_us || (a->t_us == b->t_us && a->order < b->order);
}

static void ev_swap(brsim_event_t *a, brsim_event_t *b)
{
    brsim_event_t t = *a;
    *a = *b;
    *b = t;
}

static brsim_event_t *ev_alloc(brsim_t *sim, uint64_t t_us, brsim_ev_kind_t kind)
{
    if (sim->n_events >= BRSIM_MAX_EVENTS) {
        sim->heap_overflows++;
        return NULL;
    }
    brsim_event_t *e = &sim->heap[sim->n_events];
    memset(e, 0, offsetof(brsim_event_t, frame));
    e->t_us = t_us;
    e->order = sim->order++;
    e->kind = (uint8_t)kind;
    return e;
}

/* Sift the event just written at heap[n_events] into place. */
static void ev_commit(brsim_t *sim)
{
    uint32_t i = sim->n_events++;
    while (i > 0) {
        uint32_t p = (i - 1u) / 2u;
        if (!ev_less(&sim->heap[i], &sim->heap[p])) {
            break;
        }
        ev_swap(&sim->heap[i], &sim->heap[p]);
        i = p;
    }
}

static void ev_pop(brsim_t *sim, brsim_event_t *out)
{
    *out = sim->heap[0];
    sim->n_events--;
    if (sim->n_events == 0) {
        return;
    }
    sim->heap[0] = sim->heap[sim->n_events];
    uint32_t i = 0;
    for (;;) {
        uint32_t l = 2u * i + 1u;
        uint32_t r = l + 1u;
        uint32_t m = i;
        if (l < sim->n_events && ev_less(&sim->heap[l], &sim->heap[m])) {
            m = l;
        }
        if (r < sim->n_events && ev_less(&sim->heap[r], &sim->heap[m])) {
            m = r;
        }
        if (m == i) {
            break;
        }
        ev_swap(&sim->heap[i], &sim->heap[m]);
        i = m;
    }
}

/* ------------------------------------------------------------------------- */
/* Trace                                                                      */
/* ------------------------------------------------------------------------- */

static const char *type_name(uint8_t t, char *buf, size_t cap)
{
    switch (t) {
    case BR_TYPE_SEEK: return "SEEK";
    case BR_TYPE_HELLO: return "HELLO";
    case BR_TYPE_BIND: return "BIND";
    case BR_TYPE_BIND_ACK: return "BIND_ACK";
    case BR_TYPE_MODE: return "MODE";
    case BR_TYPE_MODE_ACK: return "MODE_ACK";
    case BR_TYPE_BIND_NAK: return "BIND_NAK";
    case BR_TYPE_DATA: return "DATA";
    case BR_TYPE_PARITY: return "PARITY";
    case BR_TYPE_ACK: return "ACK";
    case BR_TYPE_PING: return "PING";
    case BR_TYPE_PONG: return "PONG";
    case BR_TYPE_CLOSE: return "CLOSE";
    case BR_TYPE_RESUME: return "RESUME";
    case BR_TYPE_RESUME_ACK: return "RESUME_ACK";
    case BR_TYPE_MGMT_REQ: return "MGMT_REQ";
    case BR_TYPE_MGMT_RESP: return "MGMT_RESP";
    default:
        snprintf(buf, cap, "T%02X", (unsigned)t);
        return buf;
    }
}

static void trace_frame(brsim_t *sim, uint16_t from_id, uint16_t to_id, const uint8_t *f, size_t len,
                        const char *verdict)
{
    char line[BRSIM_TRACE_LINE_MAX];
    char tb[8];
    int n;
    if (len >= 2 && len >= br_hdr_len_for_type(f[1])) {
        br_hdr_t h;
        size_t hl = 0;
        if (br_hdr_decode(f, len, &h, &hl) == BR_OK) {
            n = snprintf(line, sizeof line,
                         "%" PRIu64 " %04X>%04X L0 %s seq=%u hops=%u ttl=%u src=%04X dst=%04X len=%u %s",
                         sim->now_us, (unsigned)from_id, (unsigned)to_id, type_name(h.type, tb, sizeof tb),
                         (unsigned)h.seq, (unsigned)h.hops, (unsigned)h.ttl, (unsigned)h.src_id,
                         (unsigned)h.dst_id, (unsigned)len, verdict);
        } else {
            n = snprintf(line, sizeof line, "%" PRIu64 " %04X>%04X L0 ? len=%u %s", sim->now_us,
                         (unsigned)from_id, (unsigned)to_id, (unsigned)len, verdict);
        }
    } else {
        n = snprintf(line, sizeof line, "%" PRIu64 " %04X>%04X L0 %s len=%u %s", sim->now_us,
                     (unsigned)from_id, (unsigned)to_id,
                     len >= 2 ? type_name(f[1], tb, sizeof tb) : "?", (unsigned)len, verdict);
    }
    (void)n;
    for (const char *p = line; *p != '\0'; p++) {
        sim->trace_hash ^= (uint8_t)*p;
        sim->trace_hash *= 0x100000001B3ull;
    }
    sim->trace_hash ^= (uint8_t)'\n';
    sim->trace_hash *= 0x100000001B3ull;
    sim->trace_lines++;
    if (sim->trace != NULL) {
        sim->trace(sim->trace_user, line);
    }
}

static const char *const k_stat_names[BR_STAT_COUNT] = {
    "tx_frames", "rx_frames", "crc_fail", "rs_corrected", "rs_fail", "seg_fail", "bad_frame",
    "bad_version", "auth_fail", "hop_tag_fail", "hop_replay", "replay_dropped", "bundle_fail",
    "fec_recovered", "arq_retx", "gaps", "id_collisions", "rx_queue_drop", "relay_fwd",
    "relay_drop_ttl", "relay_drop_dedup", "relay_drop_stale", "relay_drop_noroute",
    "relay_drop_mtu", "relay_drop_rate", "relay_drop_queue_data", "relay_drop_queue_ctrl",
    "relay_drop_loop", "route_evictions", "link_evictions", "link_fail_drops", "stack_hwm_words",
    "unknown_session", "flood_pending_full"
};

static void verdict_text(br_err_t rc, const br_rx_verdict_t *v, char *out, size_t cap)
{
    if (rc != BR_OK) {
        snprintf(out, cap, "err:%d", (int)rc);
        return;
    }
    switch (v->action) {
    case BR_RXV_DELIVER: snprintf(out, cap, "deliver"); break;
    case BR_RXV_FORWARD: snprintf(out, cap, "forward"); break;
    case BR_RXV_FLOOD_PENDING: snprintf(out, cap, "flood"); break;
    case BR_RXV_DELIVER_FLOOD: snprintf(out, cap, "deliver+flood"); break;
    case BR_RXV_DROP:
    default:
        if ((unsigned)v->stat < (unsigned)BR_STAT_COUNT) {
            snprintf(out, cap, "drop:%s", k_stat_names[v->stat]);
        } else {
            snprintf(out, cap, "drop:silent");
        }
        break;
    }
}

/* ------------------------------------------------------------------------- */
/* Node helpers                                                               */
/* ------------------------------------------------------------------------- */

static bool idx_ok(const brsim_t *sim, uint8_t idx)
{
    return idx < sim->n_nodes && sim->nodes[idx].used;
}

static uint8_t node_index(const brsim_t *sim, const brsim_node_t *n)
{
    return (uint8_t)(n - sim->nodes);
}

static void make_addr(uint16_t unit_id, uint8_t addr[BRSIM_ADDR_LEN])
{
    addr[0] = 0x02;
    addr[1] = 0x50;
    addr[2] = 0x4C;
    addr[3] = 0x00;
    addr[4] = (uint8_t)(unit_id >> 8);
    addr[5] = (uint8_t)(unit_id & 0xFFu);
}

static uint8_t find_by_addr(const brsim_t *sim, const uint8_t *addr)
{
    for (uint8_t i = 0; i < sim->n_nodes; i++) {
        if (sim->nodes[i].used && memcmp(sim->nodes[i].addr, addr, BRSIM_ADDR_LEN) == 0) {
            return i;
        }
    }
    return BRSIM_NO_NODE;
}

static void schedule_tick(brsim_t *sim, uint8_t idx, uint64_t next)
{
    brsim_node_t *n = &sim->nodes[idx];
    if (next == BRSIM_NEVER) {
        n->next_tick_us = BRSIM_NEVER;
        n->tick_gen++;
        return;
    }
    if (next <= sim->now_us) {
        next = sim->now_us + 1u; /* never spin at one instant */
    }
    if (next == n->next_tick_us) {
        return;
    }
    brsim_event_t *e = ev_alloc(sim, next, BRSIM_EV_TICK);
    if (e == NULL) {
        return;
    }
    n->tick_gen++;
    e->to = idx;
    e->gen = n->tick_gen;
    ev_commit(sim);
    n->next_tick_us = next;
}

/* Run the node's timer at now and reschedule. */
static void tick_node(brsim_t *sim, uint8_t idx)
{
    brsim_node_t *n = &sim->nodes[idx];
    uint64_t next = BRSIM_NEVER;
    uint8_t saved = sim->cur_node;
    sim->cur_node = idx;
    if (n->is_br_node) {
        uint64_t d = BR_NEVER_US;
        (void)br_node_tick(n->node, sim->now_us, &d);
        next = d;
    } else if (n->ops != NULL && n->ops->tick != NULL) {
        next = n->ops->tick(sim, idx, n->user, sim->now_us);
    }
    sim->cur_node = saved;
    schedule_tick(sim, idx, next);
}

static void app_push(brsim_t *sim, const brsim_app_rec_t *r)
{
    if (sim->n_app >= BRSIM_MAX_APP_LOG) {
        sim->app_overflows++;
        return;
    }
    sim->app[sim->n_app++] = *r;
}

/* ------------------------------------------------------------------------- */
/* br_node adapter: transport send hook and app callback chain                */
/* ------------------------------------------------------------------------- */

static br_err_t tr_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    brsim_node_t *n = (brsim_node_t *)user;
    return brsim_send(n->sim, node_index(n->sim, n), addr, frame, len);
}

static void rec_init(brsim_node_t *n, brsim_app_kind_t kind, brsim_app_rec_t *r)
{
    memset(r, 0, sizeof *r);
    r->t_us = n->sim->now_us;
    r->node = node_index(n->sim, n);
    r->kind = kind;
}

static void cb_seek_result(void *user, br_session_t s, br_err_t result, uint16_t probe_id, uint8_t hops)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_SEEK_RESULT, &r);
    r.a = s;
    r.b = hops;
    r.c = probe_id;
    r.err = (int32_t)result;
    app_push(n->sim, &r);
    if (n->user_app.on_seek_result != NULL) {
        n->user_app.on_seek_result(n->user_app.user, s, result, probe_id, hops);
    }
}

static void cb_bound(void *user, br_session_t s, uint16_t peer_id)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_BOUND, &r);
    r.a = s;
    r.c = peer_id;
    app_push(n->sim, &r);
    if (n->user_app.on_bound != NULL) {
        n->user_app.on_bound(n->user_app.user, s, peer_id);
    }
}

static void cb_mode(void *user, br_session_t s, const br_mode_t *mode)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_MODE, &r);
    r.a = s;
    r.c = mode != NULL ? mode->config_id : 0u;
    app_push(n->sim, &r);
    if (n->user_app.on_mode != NULL) {
        n->user_app.on_mode(n->user_app.user, s, mode);
    }
}

static void cb_samples(void *user, const br_samples_meta_t *meta, const br_mode_t *mode,
                       const uint8_t *samples, size_t samples_len)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_SAMPLES, &r);
    if (meta != NULL) {
        r.a = meta->src_id;
        r.b = meta->hops;
        r.c = meta->seq;
        r.hdr = meta->hdr;
    }
    size_t k = samples_len < sizeof r.bytes ? samples_len : sizeof r.bytes;
    if (samples != NULL && k > 0) {
        memcpy(r.bytes, samples, k);
    }
    r.n_bytes = (uint8_t)k;
    app_push(n->sim, &r);
    if (n->user_app.on_samples != NULL) {
        n->user_app.on_samples(n->user_app.user, meta, mode, samples, samples_len);
    }
}

static void cb_gap(void *user, br_session_t s, uint16_t first_seq, uint16_t count)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_GAP, &r);
    r.a = s;
    r.b = count;
    r.c = first_seq;
    app_push(n->sim, &r);
    if (n->user_app.on_gap != NULL) {
        n->user_app.on_gap(n->user_app.user, s, first_seq, count);
    }
}

static void cb_acked(void *user, br_session_t s, uint16_t seq)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_ACKED, &r);
    r.a = s;
    r.c = seq;
    app_push(n->sim, &r);
    if (n->user_app.on_acked != NULL) {
        n->user_app.on_acked(n->user_app.user, s, seq);
    }
}

static void cb_closed(void *user, br_session_t s, uint8_t reason)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_CLOSED, &r);
    r.a = s;
    r.b = reason;
    app_push(n->sim, &r);
    if (n->user_app.on_closed != NULL) {
        n->user_app.on_closed(n->user_app.user, s, reason);
    }
}

static void cb_state(void *user, br_session_t s, uint8_t old_state, uint8_t new_state)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_STATE, &r);
    r.a = s;
    r.b = old_state;
    r.c = new_state;
    app_push(n->sim, &r);
    if (n->user_app.on_state != NULL) {
        n->user_app.on_state(n->user_app.user, s, old_state, new_state);
    }
}

static void cb_event(void *user, uint16_t event, uint32_t arg)
{
    brsim_node_t *n = (brsim_node_t *)user;
    brsim_app_rec_t r;
    rec_init(n, BRSIM_APP_EVENT, &r);
    r.c = event;
    r.arg = arg;
    app_push(n->sim, &r);
    if (n->user_app.on_event != NULL) {
        n->user_app.on_event(n->user_app.user, event, arg);
    }
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                 */
/* ------------------------------------------------------------------------- */

br_err_t brsim_init(brsim_t *sim, uint64_t seed)
{
    if (sim == NULL) {
        return BR_ERR_ARG;
    }
    memset(sim, 0, offsetof(brsim_t, heap));
    sim->n_events = 0;
    sim->heap_overflows = 0;
    sim->trace = NULL;
    sim->trace_user = NULL;
    sim->trace_lines = 0;
    sim->trace_hash = 0xCBF29CE484222325ull;
    sim->n_app = 0;
    sim->app_overflows = 0;
    sim->seed = seed;
    sim->rng_medium = stream_seed(seed, 0x4D454449554D0001ull);
    sim->rng_scenario = stream_seed(seed, 0x5343454E41524901ull);
    sim->cur_node = BRSIM_NO_NODE;
    sim->mac_attempts = 1;
    br_platform_t p = { sim_now_us, sim_random_bytes, sim_log, sim };
    br_err_t rc = br_platform_set(&p);
    if (rc != BR_OK) {
        return rc;
    }
    s_active = sim;
    return BR_OK;
}

static br_err_t add_slot(brsim_t *sim, uint16_t unit_id, uint8_t *idx_out)
{
    if (sim == NULL || idx_out == NULL || s_active != sim) {
        return BR_ERR_ARG;
    }
    if (brsim_find(sim, unit_id) != BRSIM_NO_NODE) {
        return BR_ERR_ARG;
    }
    if (sim->n_nodes >= BRSIM_MAX_NODES) {
        return BR_ERR_QUEUE_FULL;
    }
    uint8_t idx = sim->n_nodes;
    brsim_node_t *n = &sim->nodes[idx];
    memset(n, 0, sizeof *n);
    n->sim = sim;
    n->unit_id = unit_id;
    make_addr(unit_id, n->addr);
    n->next_tick_us = BRSIM_NEVER;
    n->rng = stream_seed(sim->seed, 0x4E4F444500000000ull | unit_id);
    *idx_out = idx;
    return BR_OK;
}

br_err_t brsim_add_endpoint(brsim_t *sim, uint16_t unit_id, const brsim_endpoint_ops_t *ops,
                            void *user, uint8_t *idx_out)
{
    if (ops == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t idx = 0;
    br_err_t rc = add_slot(sim, unit_id, &idx);
    if (rc != BR_OK) {
        return rc;
    }
    brsim_node_t *n = &sim->nodes[idx];
    n->used = true;
    n->ops = ops;
    n->user = user;
    sim->n_nodes++;
    *idx_out = idx;
    tick_node(sim, idx);
    return BR_OK;
}

br_err_t brsim_add_br_node(brsim_t *sim, br_node_t *node, const br_node_config_t *cfg,
                           uint8_t *idx_out)
{
    if (node == NULL || cfg == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t idx = 0;
    br_err_t rc = add_slot(sim, cfg->unit_id, &idx);
    if (rc != BR_OK) {
        return rc;
    }
    brsim_node_t *n = &sim->nodes[idx];
    br_node_config_t c = *cfg;
    br_transport_t *t = &c.transports[0];
    t->name = "sim";
    t->link_class = BR_LINK_PACKET;
    t->max_frame = BR_MAX_FRAME_MESH;
    t->rs_nsym = BR_RS_NSYM_PACKET;
    t->can_broadcast = true;
    t->mac_retry = true;
    t->edge_only = false;
    t->link_cost = 1;
    t->addr_len = BRSIM_ADDR_LEN;
    t->send = tr_send;
    t->user = n;
    c.n_transports = 1;
    n->user_app = cfg->app;
    c.app.user = n;
    c.app.on_seek_result = cb_seek_result;
    c.app.on_bound = cb_bound;
    c.app.on_mode = cb_mode;
    c.app.on_samples = cb_samples;
    c.app.on_gap = cb_gap;
    c.app.on_acked = cb_acked;
    c.app.on_closed = cb_closed;
    c.app.on_state = cb_state;
    c.app.on_event = cb_event;
    n->tr = *t;
    n->is_br_node = true;
    n->node = node;

    /* Mark used while br_node_init runs (it may send); roll back on failure. */
    n->used = true;
    sim->n_nodes++;
    uint8_t saved = sim->cur_node;
    sim->cur_node = idx;
    rc = br_node_init(node, sizeof *node, &c);
    sim->cur_node = saved;
    if (rc != BR_OK) {
        sim->n_nodes--;
        memset(n, 0, sizeof *n);
        return rc;
    }
    *idx_out = idx;
    tick_node(sim, idx);
    return BR_OK;
}

br_err_t brsim_set_link(brsim_t *sim, uint8_t from, uint8_t to, const brsim_link_t *l)
{
    if (sim == NULL || l == NULL || from >= BRSIM_MAX_NODES || to >= BRSIM_MAX_NODES || from == to ||
        l->delay_max_us < l->delay_min_us || l->loss_ppm > 1000000u) {
        return BR_ERR_ARG;
    }
    sim->link[from][to] = *l;
    return BR_OK;
}

br_err_t brsim_set_link_sym(brsim_t *sim, uint8_t a, uint8_t b, const brsim_link_t *l)
{
    br_err_t rc = brsim_set_link(sim, a, b, l);
    return rc != BR_OK ? rc : brsim_set_link(sim, b, a, l);
}

br_err_t brsim_set_allowlist(brsim_t *sim, uint8_t idx, bool enable, const uint16_t *ids, uint8_t n)
{
    if (sim == NULL || !idx_ok(sim, idx) || n > BR_BENCH_ALLOWLIST_MAX || (ids == NULL && n > 0)) {
        return BR_ERR_ARG;
    }
#ifndef BR_FIELD_BUILD
    br_bench_allowlist_t *al = &sim->nodes[idx].tr.allowlist;
    memset(al, 0, sizeof *al);
    al->enabled = enable;
    al->n = n;
    for (uint8_t i = 0; i < n; i++) {
        al->ids[i] = ids[i];
    }
    return BR_OK;
#else
    (void)enable;
    return BR_ERR_STATE;
#endif
}

br_err_t brsim_set_mac_attempts(brsim_t *sim, uint8_t attempts)
{
    if (sim == NULL || attempts == 0 || attempts > 16u) {
        return BR_ERR_ARG;
    }
    sim->mac_attempts = attempts;
    return BR_OK;
}

static uint64_t draw_delay(brsim_t *sim, const brsim_link_t *l)
{
    uint32_t span = l->delay_max_us - l->delay_min_us;
    uint32_t d = l->delay_min_us + (span == UINT32_MAX ? (uint32_t)(rng_next(&sim->rng_medium) >> 32)
                                                        : rng_below(&sim->rng_medium, span + 1u));
    return (uint64_t)d;
}

static bool draw_lost(brsim_t *sim, const brsim_link_t *l)
{
    if (l->loss_ppm == 0) {
        return false;
    }
    return rng_below(&sim->rng_medium, 1000000u) < l->loss_ppm;
}

static br_err_t schedule_delivery(brsim_t *sim, uint8_t from, uint8_t to, const uint8_t *frame,
                                  size_t len, const brsim_link_t *l, uint64_t *t_out)
{
    uint64_t t = sim->now_us + draw_delay(sim, l);
    brsim_node_t *rx = &sim->nodes[to];
    if (!l->reorder) {
        if (t < rx->last_deliver_us[from]) {
            t = rx->last_deliver_us[from];
        }
        rx->last_deliver_us[from] = t;
    }
    brsim_event_t *e = ev_alloc(sim, t, BRSIM_EV_DELIVER);
    if (e == NULL) {
        return BR_ERR_QUEUE_FULL;
    }
    e->from = from;
    e->to = to;
    e->len = (uint16_t)len;
    memcpy(e->frame, frame, len);
    ev_commit(sim);
    if (t_out != NULL) {
        *t_out = t;
    }
    return BR_OK;
}

static br_err_t schedule_tx_status(brsim_t *sim, uint8_t from, uint8_t to, uint64_t t, bool delivered,
                                   const uint8_t *addr)
{
    brsim_event_t *e = ev_alloc(sim, t, BRSIM_EV_TX_STATUS);
    if (e == NULL) {
        return BR_ERR_QUEUE_FULL;
    }
    e->from = from;
    e->to = to;
    e->delivered = delivered ? 1u : 0u;
    e->len = BRSIM_ADDR_LEN;
    memcpy(e->frame, addr, BRSIM_ADDR_LEN);
    ev_commit(sim);
    return BR_OK;
}

br_err_t brsim_send(brsim_t *sim, uint8_t from, const uint8_t *addr, const uint8_t *frame, size_t len)
{
    if (sim == NULL || !idx_ok(sim, from) || frame == NULL || len == 0 || len > BR_MAX_FRAME_MESH) {
        return BR_ERR_ARG;
    }
    uint16_t from_id = sim->nodes[from].unit_id;
    br_err_t rc = BR_OK;

    if (addr == NULL) {
        bool any = false;
        for (uint8_t to = 0; to < sim->n_nodes; to++) {
            const brsim_link_t *l = &sim->link[from][to];
            if (to == from || !sim->nodes[to].used || !l->connected) {
                continue;
            }
            any = true;
            brsim_link_stats_t *st = &sim->lstats[from][to];
            st->sent++;
            if (draw_lost(sim, l)) {
                st->lost++;
                trace_frame(sim, from_id, sim->nodes[to].unit_id, frame, len, "lost");
                continue;
            }
            br_err_t r2 = schedule_delivery(sim, from, to, frame, len, l, NULL);
            if (r2 != BR_OK) {
                rc = r2;
            }
        }
        if (!any) {
            trace_frame(sim, from_id, 0xFFFFu, frame, len, "noconn");
        }
        return rc;
    }

    uint8_t to = find_by_addr(sim, addr);
    if (to == BRSIM_NO_NODE || to == from || !sim->link[from][to].connected) {
        trace_frame(sim, from_id, to == BRSIM_NO_NODE ? 0xFFFFu : sim->nodes[to].unit_id, frame, len,
                    "noconn");
        return schedule_tx_status(sim, from, BRSIM_NO_NODE, sim->now_us, false, addr);
    }
    const brsim_link_t *l = &sim->link[from][to];
    brsim_link_stats_t *st = &sim->lstats[from][to];
    st->sent++;
    bool ok = false;
    for (uint8_t a = 0; a < sim->mac_attempts && !ok; a++) {
        ok = !draw_lost(sim, l);
    }
    if (!ok) {
        st->lost++;
        trace_frame(sim, from_id, sim->nodes[to].unit_id, frame, len, "lost");
        return schedule_tx_status(sim, from, to, sim->now_us + l->delay_min_us, false, addr);
    }
    uint64_t t = sim->now_us;
    rc = schedule_delivery(sim, from, to, frame, len, l, &t);
    if (rc != BR_OK) {
        return rc;
    }
    return schedule_tx_status(sim, from, to, t, true, addr);
}

br_err_t brsim_schedule(brsim_t *sim, uint64_t at_us, brsim_call_fn fn, void *arg)
{
    if (sim == NULL || fn == NULL || at_us < sim->now_us) {
        return BR_ERR_ARG;
    }
    brsim_event_t *e = ev_alloc(sim, at_us, BRSIM_EV_CALL);
    if (e == NULL) {
        return BR_ERR_QUEUE_FULL;
    }
    e->fn = fn;
    e->arg = arg;
    ev_commit(sim);
    return BR_OK;
}

static void handle_deliver(brsim_t *sim, const brsim_event_t *e)
{
    brsim_node_t *rx = &sim->nodes[e->to];
    uint16_t from_id = sim->nodes[e->from].unit_id;
    brsim_link_stats_t *st = &sim->lstats[e->from][e->to];
    st->delivered++;
    if (!br_transport_admit(&rx->tr, e->frame, e->len)) {
        st->allowlist_drop++;
        trace_frame(sim, from_id, rx->unit_id, e->frame, e->len, "allowlist");
        return;
    }
    br_rx_meta_t meta;
    memset(&meta, 0, sizeof meta);
    memcpy(meta.addr, sim->nodes[e->from].addr, BRSIM_ADDR_LEN);
    meta.addr_len = BRSIM_ADDR_LEN;
    int8_t rssi = sim->link[e->from][e->to].rssi_dbm;
    meta.rssi = rssi != 0 ? rssi : (int8_t)-60;

    char verdict[48];
    snprintf(verdict, sizeof verdict, "rx");
    sim->cur_node = e->to;
    if (rx->is_br_node) {
        br_rx_verdict_t v;
        memset(&v, 0, sizeof v);
        br_err_t rc = br_node_rx(rx->node, e->frame, e->len, 0, &meta, &v);
        verdict_text(rc, &v, verdict, sizeof verdict);
    } else if (rx->ops != NULL && rx->ops->rx != NULL) {
        rx->ops->rx(sim, e->to, rx->user, e->frame, e->len, &meta, verdict, sizeof verdict);
        verdict[sizeof verdict - 1u] = '\0';
    }
    sim->cur_node = BRSIM_NO_NODE;
    trace_frame(sim, from_id, rx->unit_id, e->frame, e->len, verdict);
    tick_node(sim, e->to);
}

static void handle_tx_status(brsim_t *sim, const brsim_event_t *e)
{
    brsim_node_t *tx = &sim->nodes[e->from];
    sim->cur_node = e->from;
    if (tx->is_br_node) {
        (void)br_node_tx_status(tx->node, 0, e->frame, BRSIM_ADDR_LEN, e->delivered != 0);
    } else if (tx->ops != NULL && tx->ops->tx_status != NULL) {
        tx->ops->tx_status(sim, e->from, tx->user, e->frame, BRSIM_ADDR_LEN, e->delivered != 0);
    }
    sim->cur_node = BRSIM_NO_NODE;
    tick_node(sim, e->from);
}

br_err_t brsim_run_until(brsim_t *sim, uint64_t t_end_us)
{
    if (sim == NULL || t_end_us < sim->now_us) {
        return BR_ERR_ARG;
    }
    brsim_event_t e;
    while (sim->n_events > 0 && sim->heap[0].t_us <= t_end_us) {
        ev_pop(sim, &e);
        sim->now_us = e.t_us;
        switch ((brsim_ev_kind_t)e.kind) {
        case BRSIM_EV_DELIVER:
            if (idx_ok(sim, e.to) && idx_ok(sim, e.from)) {
                handle_deliver(sim, &e);
            }
            break;
        case BRSIM_EV_TX_STATUS:
            if (idx_ok(sim, e.from)) {
                handle_tx_status(sim, &e);
            }
            break;
        case BRSIM_EV_TICK:
            if (idx_ok(sim, e.to) && e.gen == sim->nodes[e.to].tick_gen) {
                sim->nodes[e.to].next_tick_us = BRSIM_NEVER;
                tick_node(sim, e.to);
            }
            break;
        case BRSIM_EV_CALL:
            e.fn(sim, e.arg);
            for (uint8_t i = 0; i < sim->n_nodes; i++) {
                if (sim->nodes[i].used) {
                    tick_node(sim, i);
                }
            }
            break;
        default:
            break;
        }
    }
    sim->now_us = t_end_us;
    return BR_OK;
}

br_err_t brsim_run_for(brsim_t *sim, uint64_t dt_us)
{
    if (sim == NULL || dt_us > UINT64_MAX - sim->now_us) {
        return BR_ERR_ARG;
    }
    return brsim_run_until(sim, sim->now_us + dt_us);
}

uint64_t brsim_now(const brsim_t *sim)
{
    return sim != NULL ? sim->now_us : 0u;
}

uint32_t brsim_rand_below(brsim_t *sim, uint32_t n)
{
    return sim != NULL ? rng_below(&sim->rng_scenario, n) : 0u;
}

void brsim_set_trace(brsim_t *sim, void (*sink)(void *user, const char *line), void *user)
{
    if (sim != NULL) {
        sim->trace = sink;
        sim->trace_user = user;
    }
}

void brsim_trace_file(void *user, const char *line)
{
    FILE *f = (FILE *)user;
    if (f != NULL && line != NULL) {
        fputs(line, f);
        fputc('\n', f);
    }
}

uint64_t brsim_trace_hash(const brsim_t *sim, uint32_t *lines_out)
{
    if (sim == NULL) {
        return 0;
    }
    if (lines_out != NULL) {
        *lines_out = sim->trace_lines;
    }
    return sim->trace_hash;
}

br_err_t brsim_link_stats(const brsim_t *sim, uint8_t from, uint8_t to, brsim_link_stats_t *out)
{
    if (sim == NULL || out == NULL || from >= BRSIM_MAX_NODES || to >= BRSIM_MAX_NODES) {
        return BR_ERR_ARG;
    }
    *out = sim->lstats[from][to];
    return BR_OK;
}

uint8_t brsim_find(const brsim_t *sim, uint16_t unit_id)
{
    if (sim == NULL) {
        return BRSIM_NO_NODE;
    }
    for (uint8_t i = 0; i < sim->n_nodes; i++) {
        if (sim->nodes[i].used && sim->nodes[i].unit_id == unit_id) {
            return i;
        }
    }
    return BRSIM_NO_NODE;
}

br_err_t brsim_addr(const brsim_t *sim, uint8_t idx, uint8_t addr_out[BRSIM_ADDR_LEN])
{
    if (sim == NULL || addr_out == NULL || !idx_ok(sim, idx)) {
        return BR_ERR_ARG;
    }
    memcpy(addr_out, sim->nodes[idx].addr, BRSIM_ADDR_LEN);
    return BR_OK;
}

br_node_t *brsim_br_node(brsim_t *sim, uint8_t idx)
{
    if (sim == NULL || !idx_ok(sim, idx) || !sim->nodes[idx].is_br_node) {
        return NULL;
    }
    return sim->nodes[idx].node;
}

br_err_t brsim_app_log(const brsim_t *sim, const brsim_app_rec_t **recs_out, uint32_t *n_out)
{
    if (sim == NULL || recs_out == NULL || n_out == NULL) {
        return BR_ERR_ARG;
    }
    *recs_out = sim->app;
    *n_out = sim->n_app;
    return BR_OK;
}
