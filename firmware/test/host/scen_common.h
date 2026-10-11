// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * scen_common.h - shared harness for the phase 1b scenario tests
 * (test_scen_accept.c, test_scen_rules.c, test_scen_races.c).
 *
 * Written from PROTOCOL.md v0.8, SPEC-NOTES.md, the public headers, the
 * simulator API (brsim.h) and README-SCENARIOS.txt. It never touches the
 * protocol sources.
 *
 * What the harness gives a scenario:
 *   - one static brsim_t + up to 15 static br_node_t, fixed seeds, a trace
 *     store (parsed trace lines) and queries over it;
 *   - sc_add()/sc_link2() to build topologies, a test-double "tap" endpoint
 *     that records every BROADCAST frame it hears (SEEK floods) and can
 *     re-send recorded bytes (replay);
 *   - sc_rule_*(): "drop the next frame of type T from X at Y" injection.
 *     LIMITATION: the allowlist can only exclude a neighbour, not a frame type, so while a rule is armed EVERY
 *     frame from that neighbour at that receiver is dropped; the type only decides when the rule counts a drop
 *     and ends. Each scenario arranges that nothing else is in flight on that neighbour in the window (own
 *     relay per sender where needed). A per-type drop hook in brsim would remove the limit.
 *     The drop is done at the RECEIVER's adapter with the bench allowlist
 *     (the sender's MAC still reports success), so no 11.6 link-failure
 *     accounting is triggered by the injection itself. A rule may be armed
 *     by a trace-line trigger (e.g. "HELLO delivered at the sender");
 *     frames already in flight when the rule arms are covered because the
 *     allowlist check happens at delivery time;
 *   - sc_reboot(): br_node_deinit + br_node_init with txseq/preseq taken
 *     from the persisted reserve (persist callback);
 *   - sc_run() wrapper: runs a scenario twice with seed A (trace hash must
 *     be identical) and once with seed B, prints "name: PASS|FAIL (cite)".
 *
 * ASCII only. Host only.
 */
#ifndef SCEN_COMMON_H
#define SCEN_COMMON_H

#include <stdlib.h>
#include <string.h>

#include "test_util.h"
#include "vectors_generated.h"
#include "../../sim/include/brsim/brsim.h"
#include "braid/br_node.h"
#include "braid/br_sample.h"

/* ------------------------------------------------------------------------- */
/* Types                                                                      */
/* ------------------------------------------------------------------------- */

#define SC_MAX_NODES   15u
#define SC_TL_MAX   24000u
#define SC_CAP_MAX    128u
#define SC_MAX_RULES    8u
#define SC_TAP_ID  0x0F01u

typedef struct {
    uint64_t t;                 /* us, delivery / verdict time */
    uint16_t from, to, src, dst, seq, len;
    uint8_t  hops, ttl;
    char     type[12];
    char     verdict[20];
} sc_tl_t;

typedef struct {
    uint8_t  b[BR_MAX_FRAME_MESH];
    uint16_t len;
    uint16_t from_id;
    uint64_t t;
} sc_cap_t;

typedef struct {
    uint16_t id;
    uint8_t  idx;               /* simulator index */
    bool     ok;
    br_node_config_t cfg;
    uint32_t pers_tx, pers_pre;
    bool     base_en;           /* base bench allowlist (scenario-level) */
    uint16_t base_ids[BR_BENCH_ALLOWLIST_MAX];
    uint8_t  base_n;
    br_session_t sess;          /* sender handle */
    uint16_t role_kind;
} sc_node_t;

typedef struct {
    bool     used, armed, done, has_trig;
    char     trig_type[12];
    int      trig_from, trig_to;
    char     trig_verdict[16];
    int      drop_to, drop_from, drop_src;
    char     drop_type[12];
    int      remaining;
    uint32_t dropped;
    uint64_t t_first;
    void   (*hook)(void *user);
    void    *hook_user;
} sc_rule_t;

typedef struct {
    brsim_t   sim;
    br_node_t pln[SC_MAX_NODES];
    sc_node_t node[SC_MAX_NODES];
    unsigned  n;
    uint8_t   tap_idx;
    bool      tap_on;
    sc_cap_t  cap[SC_CAP_MAX];
    unsigned  n_cap;
    sc_tl_t   tl[SC_TL_MAX];
    unsigned  n_tl, tl_over;
    bool      store_on;
    bool      allow_overflow;
    bool      reorder_default; /* README-SCENARIOS default is true; see sc_link_default() */
    sc_rule_t rule[SC_MAX_RULES];
    uint64_t  acc_hash;
    uint8_t   node_count_default, seek_ttl_default;
    bool      active;
} sc_t;

static sc_t sc;

/* Debug aids: SC_TRACE=1 prints every trace line to stderr; argv[1] (see sc_args) runs only matching scenarios. */
static const char *sc_filter;
static bool sc_dump;

enum { SC_SENDER = 0, SC_RELAY = 1, SC_PROBE = 2 };

#define SC_US(ms) ((uint64_t)(ms) * 1000u)

/* ------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* ------------------------------------------------------------------------- */

static inline sc_node_t *sc_n(uint16_t id)
{
    for (unsigned i = 0; i < sc.n; i++) {
        if (sc.node[i].id == id) {
            return &sc.node[i];
        }
    }
    return NULL;
}

static inline br_node_t *sc_pl(uint16_t id)
{
    sc_node_t *n = sc_n(id);
    return n != NULL ? brsim_br_node(&sc.sim, n->idx) : NULL;
}

static inline uint8_t sc_ix(uint16_t id)
{
    return brsim_find(&sc.sim, id);
}

static inline bool sc_str_prefix(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static inline void sc_copy(char *dst, size_t cap, const char *src)
{
    size_t n = src != NULL ? strlen(src) : 0;
    if (n >= cap) {
        n = cap - 1u;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Bench allowlist driven by rules                                            */
/* ------------------------------------------------------------------------- */

static inline void sc_apply_allow(uint16_t to_id)
{
    sc_node_t *n = sc_n(to_id);
    if (n == NULL || !n->ok) {
        return;
    }
    bool all_excluded = false;
    uint16_t excl[SC_MAX_RULES];
    unsigned n_excl = 0;
    for (unsigned r = 0; r < SC_MAX_RULES; r++) {
        const sc_rule_t *ru = &sc.rule[r];
        if (ru->used && ru->armed && !ru->done && ru->drop_to == (int)to_id) {
            if (ru->drop_from < 0) {
                all_excluded = true;
            } else {
                excl[n_excl++] = (uint16_t)ru->drop_from;
            }
        }
    }
    uint16_t ids[BR_BENCH_ALLOWLIST_MAX];
    unsigned k = 0;
    bool enable = true;
    if (n_excl == 0 && !all_excluded) {
        enable = n->base_en;
        for (unsigned i = 0; i < n->base_n; i++) {
            ids[k++] = n->base_ids[i];
        }
    } else if (!all_excluded) {
        if (n->base_en) {
            for (unsigned i = 0; i < n->base_n; i++) {
                ids[k++] = n->base_ids[i];
            }
        } else {
            for (unsigned i = 0; i < sc.n; i++) {
                if (sc.node[i].id != to_id && k < BR_BENCH_ALLOWLIST_MAX) {
                    ids[k++] = sc.node[i].id;
                }
            }
            CHECK_MSG(sc.n <= BR_BENCH_ALLOWLIST_MAX + 1u, "too many nodes for an allowlist-based drop rule");
        }
        unsigned m = 0;
        for (unsigned i = 0; i < k; i++) {
            bool ex = false;
            for (unsigned e = 0; e < n_excl; e++) {
                ex = ex || (ids[i] == excl[e]);
            }
            if (!ex) {
                ids[m++] = ids[i];
            }
        }
        k = m;
    }
    (void)brsim_set_allowlist(&sc.sim, n->idx, enable, ids, (uint8_t)k);
}

/* ------------------------------------------------------------------------- */
/* Trace sink: parse, store, run rules                                        */
/* ------------------------------------------------------------------------- */

static inline void sc_rules_on_line(const sc_tl_t *t)
{
    for (unsigned r = 0; r < SC_MAX_RULES; r++) {
        sc_rule_t *ru = &sc.rule[r];
        if (!ru->used || ru->done) {
            continue;
        }
        if (!ru->armed && ru->has_trig) {
            bool m = (ru->trig_type[0] == '\0' || strcmp(ru->trig_type, t->type) == 0) &&
                     (ru->trig_from < 0 || ru->trig_from == (int)t->from) &&
                     (ru->trig_to < 0 || ru->trig_to == (int)t->to) &&
                     (ru->trig_verdict[0] == '\0' || sc_str_prefix(t->verdict, ru->trig_verdict));
            if (m) {
                ru->armed = true;
                sc_apply_allow((uint16_t)ru->drop_to);
            }
            continue;
        }
        if (ru->armed && strcmp(t->verdict, "allowlist") == 0 && (int)t->to == ru->drop_to &&
            (ru->drop_from < 0 || (int)t->from == ru->drop_from)) {
            bool type_ok = ru->drop_type[0] == '\0' || strcmp(ru->drop_type, t->type) == 0;
            bool src_ok = ru->drop_src < 0 || (int)t->src == ru->drop_src;
            if (type_ok && src_ok) {
                if (ru->dropped == 0) {
                    ru->t_first = t->t;
                }
                ru->dropped++;
                ru->remaining--;
                if (ru->remaining <= 0) {
                    ru->done = true;
                    sc_apply_allow((uint16_t)ru->drop_to);
                }
                if (ru->hook != NULL) {
                    ru->hook(ru->hook_user);
                }
            }
        }
    }
}

static inline void sc_sink(void *user, const char *line)
{
    (void)user;
    if (line == NULL || line[0] == '#') {
        return;
    }
    sc_tl_t t;
    memset(&t, 0, sizeof t);
    unsigned long long tus = 0;
    unsigned f = 0, to = 0;
    char type[16];
    memset(type, 0, sizeof type);
    if (sscanf(line, "%llu %4x>%4x L0 %15s", &tus, &f, &to, type) != 4) {
        return;
    }
    if (sc_dump) {
        fprintf(stderr, "  | %s\n", line);
    }
    t.t = (uint64_t)tus;
    t.from = (uint16_t)f;
    t.to = (uint16_t)to;
    sc_copy(t.type, sizeof t.type, type);
    const char *p;
    unsigned v;
    if ((p = strstr(line, " src=")) != NULL && sscanf(p + 5, "%x", &v) == 1) {
        t.src = (uint16_t)v;
    }
    if ((p = strstr(line, " dst=")) != NULL && sscanf(p + 5, "%x", &v) == 1) {
        t.dst = (uint16_t)v;
    }
    if ((p = strstr(line, " seq=")) != NULL && sscanf(p + 5, "%u", &v) == 1) {
        t.seq = (uint16_t)v;
    }
    if ((p = strstr(line, " hops=")) != NULL && sscanf(p + 6, "%u", &v) == 1) {
        t.hops = (uint8_t)v;
    }
    if ((p = strstr(line, " ttl=")) != NULL && sscanf(p + 5, "%u", &v) == 1) {
        t.ttl = (uint8_t)v;
    }
    if ((p = strstr(line, " len=")) != NULL && sscanf(p + 5, "%u", &v) == 1) {
        t.len = (uint16_t)v;
    }
    const char *last = strrchr(line, ' ');
    sc_copy(t.verdict, sizeof t.verdict, last != NULL ? last + 1 : "");
    if (sc.store_on) {
        if (sc.n_tl < SC_TL_MAX) {
            sc.tl[sc.n_tl++] = t;
        } else {
            sc.tl_over++;
        }
    }
    sc_rules_on_line(&t);
}

/* ------------------------------------------------------------------------- */
/* Queries over the stored trace                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *type;      /* NULL: any */
    int from, to, src, dst; /* -1: any */
    const char *verdict;   /* prefix; NULL: any */
    uint64_t t0, t1;
} sc_q_t;

static inline sc_q_t sc_q(const char *type, int from, int to, int src)
{
    sc_q_t q;
    q.type = type;
    q.from = from;
    q.to = to;
    q.src = src;
    q.dst = -1;
    q.verdict = NULL;
    q.t0 = 0;
    q.t1 = UINT64_MAX;
    return q;
}

static inline bool sc_q_match(const sc_q_t *q, const sc_tl_t *t)
{
    return (q->type == NULL || strcmp(q->type, t->type) == 0) &&
           (q->from < 0 || q->from == (int)t->from) && (q->to < 0 || q->to == (int)t->to) &&
           (q->src < 0 || q->src == (int)t->src) && (q->dst < 0 || q->dst == (int)t->dst) &&
           (q->verdict == NULL || sc_str_prefix(t->verdict, q->verdict)) && t->t >= q->t0 && t->t <= q->t1;
}

static inline unsigned sc_q_count(const sc_q_t *q)
{
    unsigned c = 0;
    for (unsigned i = 0; i < sc.n_tl; i++) {
        if (sc_q_match(q, &sc.tl[i])) {
            c++;
        }
    }
    return c;
}

static inline const sc_tl_t *sc_q_nth(const sc_q_t *q, unsigned nth)
{
    unsigned c = 0;
    for (unsigned i = 0; i < sc.n_tl; i++) {
        if (sc_q_match(q, &sc.tl[i])) {
            if (c == nth) {
                return &sc.tl[i];
            }
            c++;
        }
    }
    return NULL;
}

/** Trace lines of type that are real frames sent to/from the pair (a, b) in either direction. */
static inline unsigned sc_pair_lines(uint16_t a, uint16_t b)
{
    unsigned c = 0;
    for (unsigned i = 0; i < sc.n_tl; i++) {
        const sc_tl_t *t = &sc.tl[i];
        if ((t->from == a && t->to == b) || (t->from == b && t->to == a)) {
            c++;
        }
    }
    return c;
}

/* ------------------------------------------------------------------------- */
/* App log queries                                                            */
/* ------------------------------------------------------------------------- */

static inline unsigned sc_app_count(brsim_app_kind_t kind, int node_id, int a, int b, int c)
{
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    unsigned cnt = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return 0;
    }
    int idx = node_id >= 0 ? (int)sc_ix((uint16_t)node_id) : -1;
    for (uint32_t i = 0; i < n; i++) {
        if (r[i].kind != kind || (idx >= 0 && r[i].node != idx) || (a >= 0 && r[i].a != a) ||
            (b >= 0 && r[i].b != b) || (c >= 0 && r[i].c != c)) {
            continue;
        }
        cnt++;
    }
    return cnt;
}

static inline const brsim_app_rec_t *sc_app_nth(brsim_app_kind_t kind, int node_id, int a, int b, int c, unsigned nth)
{
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    unsigned cnt = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return NULL;
    }
    int idx = node_id >= 0 ? (int)sc_ix((uint16_t)node_id) : -1;
    for (uint32_t i = 0; i < n; i++) {
        if (r[i].kind != kind || (idx >= 0 && r[i].node != idx) || (a >= 0 && r[i].a != a) ||
            (b >= 0 && r[i].b != b) || (c >= 0 && r[i].c != c)) {
            continue;
        }
        if (cnt == nth) {
            return &r[i];
        }
        cnt++;
    }
    return NULL;
}

/** New-state sequence of BRSIM_APP_STATE records of one node (all its sessions). */
static inline unsigned sc_state_seq(uint16_t id, uint8_t *out, unsigned max)
{
    unsigned k = 0;
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return 0;
    }
    uint8_t idx = sc_ix(id);
    for (uint32_t i = 0; i < n && k < max; i++) {
        if (r[i].kind == BRSIM_APP_STATE && r[i].node == idx) {
            out[k++] = (uint8_t)r[i].c;
        }
    }
    return k;
}

/** True if want[0..m) appears in order (not necessarily adjacent) in seq[0..n). */
static inline bool sc_subseq(const uint8_t *seq, unsigned n, const uint8_t *want, unsigned m)
{
    unsigned j = 0;
    for (unsigned i = 0; i < n && j < m; i++) {
        if (seq[i] == want[j]) {
            j++;
        }
    }
    return j == m;
}

typedef struct {
    uint16_t src, hops, seq;
    uint8_t  b0, n_bytes, cfg;
    uint64_t t;
} sc_smp_t;

static inline unsigned sc_samples(uint16_t probe_id, sc_smp_t *out, unsigned max)
{
    unsigned k = 0;
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return 0;
    }
    uint8_t idx = sc_ix(probe_id);
    for (uint32_t i = 0; i < n && k < max; i++) {
        if (r[i].kind == BRSIM_APP_SAMPLES && r[i].node == idx) {
            out[k].src = r[i].a;
            out[k].hops = r[i].b;
            out[k].seq = r[i].c;
            out[k].b0 = r[i].bytes[0];
            out[k].n_bytes = r[i].n_bytes;
            out[k].cfg = r[i].hdr.config_id;
            out[k].t = r[i].t_us;
            k++;
        }
    }
    return k;
}

static inline bool sc_acked_has(uint16_t sender_id, uint16_t seq)
{
    return sc_app_count(BRSIM_APP_ACKED, sender_id, -1, -1, seq) > 0;
}

/* ------------------------------------------------------------------------- */
/* Node state, counters, routes                                               */
/* ------------------------------------------------------------------------- */

static inline int sc_snd_state(uint16_t id)
{
    sc_node_t *n = sc_n(id);
    br_node_t *p = sc_pl(id);
    uint8_t st = 0;
    if (n == NULL || p == NULL || br_node_session_state(p, n->sess, &st) != BR_OK) {
        return -1;
    }
    return (int)st;
}

/** Probe records by state; returns the number of BOUND + STREAMING records. */
static inline unsigned sc_prb_live(uint16_t id, unsigned counts[5])
{
    unsigned local[5] = { 0, 0, 0, 0, 0 };
    unsigned *c = counts != NULL ? counts : local;
    for (unsigned i = 0; i < 5; i++) {
        c[i] = 0;
    }
    br_node_t *p = sc_pl(id);
    if (p == NULL) {
        return 0;
    }
    for (unsigned i = 0; i < BR_RX_RECORDS; i++) {
        uint8_t st = 0;
        if (br_node_session_state(p, (br_session_t)(BR_SESSION_PROBE | i), &st) == BR_OK && st < 5u) {
            c[st]++;
        }
    }
    return c[BR_PRB_BOUND] + c[BR_PRB_STREAMING];
}

static inline br_stats_t sc_stats(uint16_t id)
{
    br_stats_t s;
    memset(&s, 0, sizeof s);
    br_node_t *p = sc_pl(id);
    if (p != NULL) {
        (void)br_node_get_stats(p, &s);
    }
    return s;
}

static inline bool sc_route(uint16_t node_id, uint16_t dst, br_route_entry_t *out)
{
    br_node_t *p = sc_pl(node_id);
    bool found = false;
    memset(out, 0, sizeof *out);
    if (p == NULL || br_node_route(p, dst, out, &found) != BR_OK) {
        return false;
    }
    return found;
}

/* ------------------------------------------------------------------------- */
/* Simulator driving                                                          */
/* ------------------------------------------------------------------------- */

static inline void sc_noop(brsim_t *sim, void *arg)
{
    (void)sim;
    (void)arg;
}

/** Make the simulator re-tick every node now (call after direct br_node_* calls). */
static inline void sc_kick(void)
{
    if (brsim_schedule(&sc.sim, sc.sim.now_us, sc_noop, NULL) == BR_OK) {
        (void)brsim_run_until(&sc.sim, sc.sim.now_us);
    }
}

static inline void sc_run_ms(uint32_t ms)
{
    (void)brsim_run_for(&sc.sim, SC_US(ms));
}

static inline uint64_t sc_now_ms(void)
{
    return brsim_now(&sc.sim) / 1000u;
}

static inline bool sc_wait_snd_state(uint16_t id, int state, uint32_t max_ms)
{
    for (uint32_t t = 0; t <= max_ms; t += 5) {
        if (sc_snd_state(id) == state) {
            return true;
        }
        sc_run_ms(5);
    }
    return sc_snd_state(id) == state;
}

/* ------------------------------------------------------------------------- */
/* Node construction                                                          */
/* ------------------------------------------------------------------------- */

static inline br_err_t sc_persist(void *user, uint8_t which, uint32_t reserve_to)
{
    sc_node_t *n = (sc_node_t *)user;
    if (which == BR_PERSIST_TXSEQ) {
        n->pers_tx = reserve_to;
    } else if (which == BR_PERSIST_PRESEQ) {
        n->pers_pre = reserve_to;
    }
    return BR_OK;
}

static inline void sc_cfg(br_node_config_t *c, uint16_t id, int kind)
{
    memset(c, 0, sizeof *c);
    c->unit_id = id;
    c->role = BR_ROLE_NODE;
    c->node_count = sc.node_count_default;
    c->seek_ttl = sc.seek_ttl_default;
    c->caps = (uint16_t)(BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY);
    c->auth = true;
    c->cold_boot = false;
    c->key_epoch = 1;
    c->net_key = BRV_A6_K_SITE;
    c->net_key_len = BRV_A6_K_SITE_LEN;
    c->n_transports = 1;
    c->txseq_start = 1000u + 17u * (uint32_t)(id & 0xFFu);
    c->preseq_start = 100u + 3u * (uint32_t)(id & 0xFFu);
    if (kind == SC_PROBE) {
        c->caps = (uint16_t)(c->caps | BR_CAP_MULTI);
        c->groups[0] = 0xFF10;
        c->n_groups = 1;
    }
}

static inline bool sc_add_cfg(const br_node_config_t *cfg_in)
{
    if (sc.n >= SC_MAX_NODES) {
        CHECK_MSG(false, "too many nodes");
        return false;
    }
    sc_node_t *nd = &sc.node[sc.n];
    memset(nd, 0, sizeof *nd);
    nd->id = cfg_in->unit_id;
    nd->cfg = *cfg_in;
    nd->cfg.persist = sc_persist;
    nd->cfg.persist_user = nd;
    nd->sess = 0;
    br_err_t rc = brsim_add_br_node(&sc.sim, &sc.pln[sc.n], &nd->cfg, &nd->idx);
    CHECK_ERR(rc, BR_OK);
    if (rc != BR_OK) {
        return false;
    }
    nd->ok = true;
    sc.n++;
    return true;
}

static inline bool sc_add(uint16_t id, int kind)
{
    br_node_config_t c;
    sc_cfg(&c, id, kind);
    return sc_add_cfg(&c);
}

/** A sender whose caps lack ARQ: it needs a probe record but never a stream (4.1.12). */
static inline bool sc_add_noarq(uint16_t id)
{
    br_node_config_t c;
    sc_cfg(&c, id, SC_SENDER);
    c.caps = (uint16_t)(c.caps & ~BR_CAP_ARQ);
    return sc_add_cfg(&c);
}

static inline void sc_base_allow(uint16_t id, const uint16_t *ids, uint8_t n)
{
    sc_node_t *nd = sc_n(id);
    if (nd == NULL) {
        CHECK_MSG(false, "sc_base_allow: unknown node");
        return;
    }
    nd->base_en = true;
    nd->base_n = n;
    for (uint8_t i = 0; i < n; i++) {
        nd->base_ids[i] = ids[i];
    }
    (void)brsim_set_allowlist(&sc.sim, nd->idx, true, ids, n);
}

/* ------------------------------------------------------------------------- */
/* Links                                                                      */
/* ------------------------------------------------------------------------- */

static inline brsim_link_t sc_link_default(void)
{
    brsim_link_t l;
    memset(&l, 0, sizeof l);
    l.connected = true;
    /* The plan's default is reorder true. With reordering, back-to-back frames of one sender (the FLOOD_REPEAT
     * copies of a flood) can overtake each other inside the 0.3 .. 1.5 ms delay spread, and an overtaken copy is a
     * legitimate hop_replay drop (8.4: hop_seq must be newer). To keep the end-of-scenario hop_replay == 0 check
     * meaningful every scenario runs with in-order links except those that set sc.reorder_default. */
    l.reorder = sc.reorder_default;
    l.loss_ppm = 0;
    l.delay_min_us = 300;
    l.delay_max_us = 1500;
    l.rssi_dbm = -60;
    return l;
}

static inline void sc_link_set(uint16_t from, uint16_t to, const brsim_link_t *l)
{
    br_err_t rc = brsim_set_link(&sc.sim, sc_ix(from), sc_ix(to), l);
    CHECK_ERR(rc, BR_OK);
}

static inline void sc_link2(uint16_t a, uint16_t b)
{
    brsim_link_t l = sc_link_default();
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

static inline void sc_link2_rssi(uint16_t a, uint16_t b, int8_t rssi)
{
    brsim_link_t l = sc_link_default();
    l.rssi_dbm = rssi;
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

/** Symmetric link with RSSI and a fixed delay window (us). */
static inline void sc_link2_slow(uint16_t a, uint16_t b, int8_t rssi, uint32_t dmin_us, uint32_t dmax_us)
{
    brsim_link_t l = sc_link_default();
    l.rssi_dbm = rssi;
    l.delay_min_us = dmin_us;
    l.delay_max_us = dmax_us;
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

static inline void sc_link2_loss(uint16_t a, uint16_t b, uint32_t ppm)
{
    brsim_link_t l = sc_link_default();
    l.loss_ppm = ppm;
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

static inline void sc_link2_delay(uint16_t a, uint16_t b, uint32_t dmin_us, uint32_t dmax_us)
{
    brsim_link_t l = sc_link_default();
    l.delay_min_us = dmin_us;
    l.delay_max_us = dmax_us;
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

static inline void sc_link_dir_delay(uint16_t from, uint16_t to, uint32_t dmin_us, uint32_t dmax_us)
{
    brsim_link_t l = sc_link_default();
    l.delay_min_us = dmin_us;
    l.delay_max_us = dmax_us;
    sc_link_set(from, to, &l);
}

static inline void sc_unlink(uint16_t a, uint16_t b)
{
    brsim_link_t l;
    memset(&l, 0, sizeof l);
    sc_link_set(a, b, &l);
    sc_link_set(b, a, &l);
}

/* ------------------------------------------------------------------------- */
/* Tap (test-double endpoint)                                                 */
/* ------------------------------------------------------------------------- */

static inline void sc_tap_rx(brsim_t *sim, uint8_t node, void *user, const uint8_t *frame, size_t len,
                      const br_rx_meta_t *meta, char *verdict, size_t verdict_cap)
{
    (void)node;
    (void)user;
    if (sc.n_cap < SC_CAP_MAX && len <= sizeof sc.cap[0].b) {
        sc_cap_t *c = &sc.cap[sc.n_cap++];
        memcpy(c->b, frame, len);
        c->len = (uint16_t)len;
        c->from_id = (uint16_t)(((unsigned)meta->addr[4] << 8) | meta->addr[5]);
        c->t = sim->now_us;
    }
    sc_copy(verdict, verdict_cap, "rx");
}

static const brsim_endpoint_ops_t sc_tap_ops = { sc_tap_rx, NULL, NULL };

static inline bool sc_tap_add(void)
{
    br_err_t rc = brsim_add_endpoint(&sc.sim, SC_TAP_ID, &sc_tap_ops, NULL, &sc.tap_idx);
    CHECK_ERR(rc, BR_OK);
    sc.tap_on = rc == BR_OK;
    return sc.tap_on;
}

/** The tap hears every broadcast of node id (one-way link id -> tap). */
static inline void sc_tap_hear(uint16_t id)
{
    brsim_link_t l = sc_link_default();
    CHECK_ERR(brsim_set_link(&sc.sim, sc_ix(id), sc.tap_idx, &l), BR_OK);
}

/** The tap can transmit to node id (one-way link tap -> id), for replay. */
static inline void sc_tap_speak(uint16_t id)
{
    brsim_link_t l = sc_link_default();
    CHECK_ERR(brsim_set_link(&sc.sim, sc.tap_idx, sc_ix(id), &l), BR_OK);
}

/** Captured frame number nth of type (frame byte 1) sent by from_id (-1 any). */
static inline const sc_cap_t *sc_cap_find(uint8_t type_byte, int from_id, unsigned nth)
{
    unsigned c = 0;
    for (unsigned i = 0; i < sc.n_cap; i++) {
        if (sc.cap[i].len >= 2 && sc.cap[i].b[1] == type_byte && (from_id < 0 || sc.cap[i].from_id == from_id)) {
            if (c == nth) {
                return &sc.cap[i];
            }
            c++;
        }
    }
    return NULL;
}

static inline void sc_tap_replay(const sc_cap_t *c)
{
    if (c == NULL) {
        CHECK_MSG(false, "replay of a frame the tap never captured");
        return;
    }
    CHECK_ERR(brsim_send(&sc.sim, sc.tap_idx, NULL, c->b, c->len), BR_OK);
    sc_kick();
}

/* SEEK payload (18 bytes, clear, after the 22-byte header): pre_ctr u32, nonce_s u32, ... */
static inline uint32_t sc_cap_pre_ctr(const sc_cap_t *c)
{
    return tu_get32(c->b + 22);
}

static inline uint32_t sc_cap_nonce_s(const sc_cap_t *c)
{
    return tu_get32(c->b + 26);
}

/* ------------------------------------------------------------------------- */
/* Drop rules                                                                 */
/* ------------------------------------------------------------------------- */

/**
 * Drop `count` frames of `type` ("" = any) delivered at unit `to`, coming
 * from carrier neighbour `from` (-1: any), with frame src `src` (-1: any).
 * Armed at once.
 */
static inline sc_rule_t *sc_rule_now(int to, int from, int src, const char *type, int count)
{
    for (unsigned r = 0; r < SC_MAX_RULES; r++) {
        if (!sc.rule[r].used) {
            sc_rule_t *ru = &sc.rule[r];
            memset(ru, 0, sizeof *ru);
            ru->used = true;
            ru->armed = true;
            ru->drop_to = to;
            ru->drop_from = from;
            ru->drop_src = src;
            sc_copy(ru->drop_type, sizeof ru->drop_type, type);
            ru->remaining = count;
            sc_apply_allow((uint16_t)to);
            return ru;
        }
    }
    CHECK_MSG(false, "out of drop rules");
    return NULL;
}

/**
 * Same, but armed only when a trace line of `trig_type` from -> to with a
 * verdict starting with `trig_verdict` is seen (e.g. "HELLO", 0x0102,
 * 0x0101, "deliver" = a HELLO just reached the sender).
 */
static inline sc_rule_t *sc_rule_on(const char *trig_type, int trig_from, int trig_to, const char *trig_verdict, int to,
                             int from, int src, const char *type, int count)
{
    for (unsigned r = 0; r < SC_MAX_RULES; r++) {
        if (!sc.rule[r].used) {
            sc_rule_t *ru = &sc.rule[r];
            memset(ru, 0, sizeof *ru);
            ru->used = true;
            ru->has_trig = true;
            sc_copy(ru->trig_type, sizeof ru->trig_type, trig_type);
            ru->trig_from = trig_from;
            ru->trig_to = trig_to;
            sc_copy(ru->trig_verdict, sizeof ru->trig_verdict, trig_verdict);
            ru->drop_to = to;
            ru->drop_from = from;
            ru->drop_src = src;
            sc_copy(ru->drop_type, sizeof ru->drop_type, type);
            ru->remaining = count;
            return ru;
        }
    }
    CHECK_MSG(false, "out of drop rules");
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Reboot                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * br_node_deinit + br_node_init at the current sim time, counters resumed
 * from the persisted reserve (3.5). The adapted config (sim transport hook,
 * callbacks, allowlist, groups) is taken from the node's own copy before
 * deinit wipes it; net_key is re-pointed at the static test key.
 */
static inline bool sc_reboot(uint16_t id)
{
    sc_node_t *nd = sc_n(id);
    br_node_t *p = sc_pl(id);
    if (nd == NULL || p == NULL) {
        CHECK_MSG(false, "sc_reboot: unknown node");
        return false;
    }
    br_node_config_t c = p->cfg;
    br_node_deinit(p);
    c.net_key = BRV_A6_K_SITE;
    c.net_key_len = BRV_A6_K_SITE_LEN;
    uint32_t tx = c.txseq_start + 4096u;
    uint32_t pre = c.preseq_start + 64u;
    c.txseq_start = nd->pers_tx > tx ? nd->pers_tx : tx;
    c.preseq_start = nd->pers_pre > pre ? nd->pers_pre : pre;
    uint8_t saved = sc.sim.cur_node;
    sc.sim.cur_node = nd->idx;
    br_err_t rc = br_node_init(p, sizeof *p, &c);
    sc.sim.cur_node = saved;
    CHECK_ERR(rc, BR_OK);
    nd->cfg = c;
    sc_kick();
    return rc == BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Modes, sessions, presses                                                   */
/* ------------------------------------------------------------------------- */

static inline void sc_mode(br_mode_t *m, uint8_t mode)
{
    memset(m, 0, sizeof *m);
    m->config_id = 1;
    m->mode = mode;
    m->ch_count = 1;
    m->period = 1;
    m->fec_k = 8;
    m->fec_m = 0;
    m->arq = 1;
    m->flags = BR_MODE_FLAG_PERIOD_MS;
    m->keepalive_ms = BR_KEEPALIVE_DEFAULT_MS;
    m->ch[0].kind = BR_CH_KIND_DIGITAL;
    m->ch[0].fmt = 1;
}

/** The default MODE without ARQ (arq 0, fire and forget). */
static inline void sc_mode_noarq(br_mode_t *m)
{
    sc_mode(m, BR_MODE_HIGH);
    m->arq = 0;
}

/** br_node_seek + the default MODE queued right behind it (the header allows set_mode while SEEKING). */
static inline bool sc_start(uint16_t id, uint16_t dst, const br_mode_t *mode)
{
    sc_node_t *nd = sc_n(id);
    br_node_t *p = sc_pl(id);
    if (nd == NULL || p == NULL) {
        CHECK_MSG(false, "sc_start: unknown node");
        return false;
    }
    br_err_t rc = br_node_seek(p, dst, &nd->sess);
    CHECK_ERR(rc, BR_OK);
    if (rc != BR_OK) {
        return false;
    }
    br_mode_t m;
    if (mode == NULL) {
        sc_mode(&m, BR_MODE_HIGH);
        mode = &m;
    }
    rc = br_node_set_mode(p, nd->sess, mode);
    CHECK_ERR(rc, BR_OK);
    sc_kick();
    return rc == BR_OK;
}

static inline br_err_t sc_send(uint16_t id, uint32_t lines, bool ack_req)
{
    sc_node_t *nd = sc_n(id);
    br_node_t *p = sc_pl(id);
    if (nd == NULL || p == NULL) {
        return BR_ERR_ARG;
    }
    br_value_t v;
    memset(&v, 0, sizeof v);
    v.lines = lines;
    br_err_t rc = br_node_send_sample(p, nd->sess, &v, 1, (uint32_t)sc.sim.now_us, 0, ack_req);
    sc_kick();
    return rc;
}

/** One button press: value 1 with ack_req, release (0) `hold_ms` later, then `gap_ms` of quiet. */
static inline bool sc_press(uint16_t id, uint32_t hold_ms, uint32_t gap_ms)
{
    br_err_t r1 = sc_send(id, 1, true);
    CHECK_ERR(r1, BR_OK);
    sc_run_ms(hold_ms);
    br_err_t r0 = sc_send(id, 0, true);
    CHECK_ERR(r0, BR_OK);
    sc_run_ms(gap_ms);
    return r1 == BR_OK && r0 == BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Topologies                                                                 */
/* ------------------------------------------------------------------------- */

static inline uint16_t sc_relay_id(unsigned k)
{
    return k == 0 ? 0x0102u : (uint16_t)(0x0103u + k);
}

static inline void sc_reset(uint64_t seed);

/** S1 0x0101 - R1 0x0102 - P1 0x0103, links S-R and R-P only. */
static inline bool sc_topo3(uint64_t seed)
{
    sc_reset(seed);
    if (!sc_add(0x0101, SC_SENDER) || !sc_add(0x0102, SC_RELAY) || !sc_add(0x0103, SC_PROBE)) {
        return false;
    }
    sc_link2(0x0101, 0x0102);
    sc_link2(0x0102, 0x0103);
    return true;
}

/** Chain S 0x0101 - relays (sc_relay_id(0..n-1)) - P 0x0103. node_count/seek_ttl set by the caller via sc_reset defaults. */
static inline bool sc_topo_chain(uint64_t seed, unsigned n_relays, uint8_t seek_ttl)
{
    sc_reset(seed);
    sc.seek_ttl_default = seek_ttl;
    sc.node_count_default = (uint8_t)(n_relays + 2u);
    if (!sc_add(0x0101, SC_SENDER)) {
        return false;
    }
    for (unsigned k = 0; k < n_relays; k++) {
        if (!sc_add(sc_relay_id(k), SC_RELAY)) {
            return false;
        }
    }
    if (!sc_add(0x0103, SC_PROBE)) {
        return false;
    }
    uint16_t prev = 0x0101;
    for (unsigned k = 0; k < n_relays; k++) {
        sc_link2(prev, sc_relay_id(k));
        prev = sc_relay_id(k);
    }
    sc_link2(prev, 0x0103);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle, summary checks                                                  */
/* ------------------------------------------------------------------------- */

static inline void sc_finish(void)
{
    if (!sc.active) {
        return;
    }
    uint32_t lines = 0;
    uint64_t h = brsim_trace_hash(&sc.sim, &lines);
    sc.acc_hash = (sc.acc_hash ^ h) * 1099511628211ull + lines;
    for (unsigned i = 0; i < sc.n; i++) {
        if (sc.node[i].ok) {
            br_node_t *p = brsim_br_node(&sc.sim, sc.node[i].idx);
            if (p != NULL) {
                br_node_deinit(p);
            }
            sc.node[i].ok = false;
        }
    }
    sc.active = false;
}

static inline void sc_reset(uint64_t seed)
{
    sc_finish();
    memset(sc.node, 0, sizeof sc.node);
    sc.n = 0;
    sc.n_cap = 0;
    sc.n_tl = 0;
    sc.tl_over = 0;
    sc.store_on = true;
    sc.allow_overflow = false;
    sc.reorder_default = false;
    sc.tap_on = false;
    memset(sc.rule, 0, sizeof sc.rule);
    sc.node_count_default = 3;
    sc.seek_ttl_default = BR_SEEK_TTL_DEFAULT;
    br_err_t rc = brsim_init(&sc.sim, seed);
    CHECK_ERR(rc, BR_OK);
    brsim_set_trace(&sc.sim, sc_sink, NULL);
    sc.active = true;
}

/**
 * End-of-scenario invariants (README-SCENARIOS "Every scenario ends by
 * asserting"): the validator / replay counters are 0 on every node unless the
 * scenario injected them (bit i of allow_mask = counter br_stat_id_t i may be non-zero),
 * and the simulator / store did not overflow.
 */
static inline void sc_check_clean(uint32_t allow_mask)
{
    static const br_stat_id_t must_zero[] = { BR_STAT_BAD_FRAME, BR_STAT_CRC_FAIL, BR_STAT_HOP_TAG_FAIL,
                                              BR_STAT_HOP_REPLAY, BR_STAT_AUTH_FAIL };
    for (unsigned i = 0; i < sc.n; i++) {
        br_stats_t s = sc_stats(sc.node[i].id);
        for (unsigned k = 0; k < sizeof must_zero / sizeof must_zero[0]; k++) {
            if ((allow_mask & (1u << must_zero[k])) == 0u && s.v[must_zero[k]] != 0u) {
                CHECK_MSG(false, "validator counter non-zero on a clean scenario");
                fprintf(stderr, "  node 0x%04X counter index %u = %u\n", (unsigned)sc.node[i].id,
                        (unsigned)must_zero[k], (unsigned)s.v[must_zero[k]]);
            }
        }
    }
    CHECK(sc.sim.heap_overflows == 0);
    if (!sc.allow_overflow) {
        CHECK(sc.sim.app_overflows == 0);
        CHECK(sc.tl_over == 0);
    }
}

#define SC_STAT_BIT(id) (1u << (id))

/* ------------------------------------------------------------------------- */
/* Scenario runner and report lines                                           */
/* ------------------------------------------------------------------------- */


/** Failure aid (SC_TRACE=1): per-node sender state, probe record states and non-zero counters. */
static inline void sc_diag(void)
{
    static const char *const names[BR_STAT_COUNT] = {
        "tx_frames", "rx_frames", "crc_fail", "rs_corrected", "rs_fail", "seg_fail", "bad_frame", "bad_version",
        "auth_fail", "hop_tag_fail", "hop_replay", "replay_dropped", "bundle_fail", "fec_recovered", "arq_retx",
        "gaps", "id_collisions", "rx_queue_drop", "relay_fwd", "relay_drop_ttl", "relay_drop_dedup",
        "relay_drop_stale", "relay_drop_noroute", "relay_drop_mtu", "relay_drop_rate", "relay_drop_queue_data",
        "relay_drop_queue_ctrl", "relay_drop_loop", "route_evictions", "link_evictions", "link_fail_drops",
        "stack_hwm_words", "unknown_session", "flood_pending_full"
    };
    fprintf(stderr, "  diag at t=%llu us\n", (unsigned long long)brsim_now(&sc.sim));
    for (unsigned i = 0; i < sc.n; i++) {
        uint16_t id = sc.node[i].id;
        unsigned c[5];
        unsigned live = sc_prb_live(id, c);
        br_stats_t st = sc_stats(id);
        fprintf(stderr, "  node %04X snd_state=%d probe(listening %u offered %u bound %u streaming %u) live=%u\n",
                (unsigned)id, sc_snd_state(id), c[0], c[1], c[2], c[3], live);
        for (unsigned k = 0; k < BR_STAT_COUNT; k++) {
            if (st.v[k] != 0 && k != BR_STAT_TX_FRAMES && k != BR_STAT_RX_FRAMES) {
                fprintf(stderr, "      %s=%u\n", names[k], (unsigned)st.v[k]);
            }
        }
    }
}

typedef void (*sc_fn_t)(uint64_t seed);

#ifndef SC_SEED_A
#define SC_SEED_A 0x00C0FFEE0001ull
#endif
#ifndef SC_SEED_B
#define SC_SEED_B 0x00C0FFEE0002ull
#endif

static inline void sc_args(int argc, char **argv)
{
    const char *e = getenv("SC_TRACE");
    sc_dump = e != NULL && e[0] != '\0' && e[0] != '0';
    sc_filter = argc > 1 ? argv[1] : NULL;
}

static inline bool sc_selected(const char *name)
{
    return sc_filter == NULL || strstr(name, sc_filter) != NULL;
}

static inline void sc_run(const char *name, const char *cite, sc_fn_t fn, bool once)
{
    if (!sc_selected(name)) {
        return;
    }
    unsigned long f0 = tu_failed;
    static const uint64_t seeds[3] = { SC_SEED_A, SC_SEED_A, SC_SEED_B };
    uint64_t hashes[3] = { 0, 0, 0 };
    unsigned runs = once ? 1u : 3u;
    tu_ctx(name);
    for (unsigned r = 0; r < runs; r++) {
        sc.acc_hash = 1469598103934665603ull;
        fn(seeds[r]);
        if (tu_failed != f0 && sc_dump) {
            sc_diag();
        }
        sc_finish();
        hashes[r] = sc.acc_hash;
        if (tu_failed != f0) {
            break;
        }
    }
    if (!once && tu_failed == f0) {
        CHECK_MSG(hashes[0] == hashes[1], "same seed produced different trace hashes (not deterministic)");
    }
    printf("%s: %s (%s)\n", name, tu_failed == f0 ? "PASS" : "FAIL", cite);
    fflush(stdout);
}

/** A scenario (or part of one) that cannot be driven through the public API + simulator. */
static inline void sc_skip(const char *name, const char *cite, const char *missing_hook)
{
    static const char *seen[96];
    static unsigned n_seen;
    if (!sc_selected(name)) {
        return;
    }
    for (unsigned i = 0; i < n_seen; i++) {
        if (strcmp(seen[i], name) == 0) {
            return; /* a scenario runs up to three times: report each SKIP once */
        }
    }
    if (n_seen < sizeof seen / sizeof seen[0]) {
        seen[n_seen++] = name;
    }
    tu_skips++;
    printf("%s: SKIP (%s) - missing hook: %s\n", name, cite, missing_hook);
    fflush(stdout);
}

static inline void sc_skip_oos(const char *name, const char *cite)
{
    if (!sc_selected(name)) {
        return;
    }
    tu_skips++;
    printf("%s: SKIP (out of scope phase 1b) (%s)\n", name, cite);
    fflush(stdout);
}

/* ------------------------------------------------------------------------- */
/* Extras shared by the rule / race files                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t pre_ctr, nonce_s;
    uint64_t t;
} sc_round_t;

/** SEEK floods originated by from_id as heard by the tap, one entry per distinct pre_ctr (copies merged). */
static inline unsigned sc_seek_rounds(uint16_t from_id, sc_round_t *out, unsigned max)
{
    unsigned k = 0;
    for (unsigned i = 0; i < sc.n_cap && k < max; i++) {
        const sc_cap_t *c = &sc.cap[i];
        if (c->len < 30u || c->b[1] != BR_TYPE_SEEK || tu_get16(c->b + 2) != from_id || c->from_id != from_id) {
            continue;
        }
        uint32_t pre = sc_cap_pre_ctr(c);
        bool seen = false;
        for (unsigned j = 0; j < k; j++) {
            seen = seen || out[j].pre_ctr == pre;
        }
        if (!seen) {
            out[k].pre_ctr = pre;
            out[k].nonce_s = sc_cap_nonce_s(c);
            out[k].t = c->t;
            k++;
        }
    }
    return k;
}

#define SC_TAP_HEAR_S   0x1u
#define SC_TAP_SPEAK_R  0x2u
#define SC_TAP_SPEAK_P  0x4u

/** Topology S-R-P (+ optional tap), seek + default MODE, wait for STREAMING. */
static inline bool sc_up3(uint64_t seed, unsigned tap_flags)
{
    if (!sc_topo3(seed)) {
        return false;
    }
    if (tap_flags != 0u) {
        if (!sc_tap_add()) {
            return false;
        }
        if ((tap_flags & SC_TAP_HEAR_S) != 0u) {
            sc_tap_hear(0x0101);
        }
        if ((tap_flags & SC_TAP_SPEAK_R) != 0u) {
            sc_tap_speak(0x0102);
        }
        if ((tap_flags & SC_TAP_SPEAK_P) != 0u) {
            sc_tap_speak(0x0103);
        }
    }
    if (!sc_start(0x0101, 0xFF10, NULL)) {
        return false;
    }
    bool ok = sc_wait_snd_state(0x0101, BR_SND_STREAMING, 5000);
    CHECK_MSG(ok, "sender never reached STREAMING within 5 s");
    return ok;
}

/** Number of BRSIM_APP_* records of any kind logged by node id. */
static inline unsigned sc_app_records_of(uint16_t id)
{
    const brsim_app_rec_t *r = NULL;
    uint32_t n = 0;
    unsigned c = 0;
    if (brsim_app_log(&sc.sim, &r, &n) != BR_OK) {
        return 0;
    }
    uint8_t idx = sc_ix(id);
    for (uint32_t i = 0; i < n; i++) {
        c += r[i].node == idx;
    }
    return c;
}

/** Time (us) of the first state record of node id whose new state is `state`, or UINT64_MAX. */
static inline uint64_t sc_state_time(uint16_t id, uint8_t state)
{
    const brsim_app_rec_t *r = sc_app_nth(BRSIM_APP_STATE, id, -1, -1, state, 0);
    return r != NULL ? r->t_us : UINT64_MAX;
}

#endif /* SCEN_COMMON_H */
