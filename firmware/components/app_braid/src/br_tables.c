// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_tables.c - link, route, dedup, ORIGIN tables, flood budget and the
 * forwarding queue (spec 7, 11.4-11.6, 11.9).
 *
 * Fixed arrays, linear scans (64 entries at most), no heap. Every time
 * comparison goes through br_ms_before() (32-bit ms clock, serial compare).
 * Rule R4 (only step-5-admitted frames change a table) is the caller's job.
 */
#include <string.h>

#include "braid/br_tables.h"

#include "br_internal.h"

/* ---- helpers -------------------------------------------------------------- */

static bool route_live(const br_route_entry_t *r, uint32_t now_ms)
{
    return r->dst_id != 0u && br_ms_before(now_ms, r->expiry_ms);
}

static bool link_referenced(const br_route_table_t *rt, const br_link_entry_t *l)
{
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        const br_route_entry_t *r = &rt->e[i];
        if (r->dst_id != 0u && r->next_hop == l->unit_id && r->transport == l->transport) {
            return true;
        }
    }
    return false;
}

static void link_free(br_link_entry_t *l)
{
    memset(l, 0, sizeof *l);
    l->transport = BR_NO_TRANSPORT;
    l->rssi_ewma = (int8_t)BR_RSSI_UNKNOWN;
}

/* ---- init / cost ---------------------------------------------------------- */

br_err_t br_tables_init(br_tables_t *t, uint32_t now_ms)
{
    if (t == NULL) {
        return BR_ERR_ARG;
    }
    memset(t, 0, sizeof *t);
    for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
        link_free(&t->link.e[i]);
    }
    for (size_t i = 0; i < BR_DEDUP_ENTRIES; i++) {
        t->dedup.e[i].pending = BR_NO_INDEX;
    }
    for (size_t i = 0; i < BR_FLOOD_BUCKETS; i++) {
        t->budget.origin[i].milli_tokens = (uint16_t)(BR_BUCKET_ORIGIN_DEPTH * 1000u);
        t->budget.origin[i].t_ms = now_ms;
    }
    t->budget.total.milli_tokens = (uint16_t)(BR_BUCKET_TOTAL_DEPTH * 1000u);
    t->budget.total.t_ms = now_ms;
    for (size_t i = 0; i < BR_FLOOD_PENDING; i++) {
        t->pending.c[i].transport = BR_NO_TRANSPORT;
    }
    return BR_OK;
}

br_err_t br_link_cost(int8_t rssi, uint8_t fixed_cost, uint8_t *cost_out)
{
    if (cost_out == NULL) {
        return BR_ERR_ARG;
    }
    if (rssi == (int8_t)BR_RSSI_UNKNOWN) {
        *cost_out = fixed_cost != 0u ? fixed_cost : 1u;
    } else if (rssi >= -75) {
        *cost_out = BR_COST_RSSI_GOOD;
    } else if (rssi >= -85) {
        *cost_out = BR_COST_RSSI_FAIR;
    } else if (rssi >= -90) {
        *cost_out = BR_COST_RSSI_POOR;
    } else {
        *cost_out = BR_COST_IGNORE;
    }
    return BR_OK;
}

/* ---- link table ----------------------------------------------------------- */

br_err_t br_link_find(br_link_table_t *lt, uint16_t unit_id, uint8_t transport,
                      br_link_entry_t **entry_out)
{
    if (lt == NULL || entry_out == NULL) {
        return BR_ERR_ARG;
    }
    *entry_out = NULL;
    for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
        br_link_entry_t *l = &lt->e[i];
        if (l->transport != BR_NO_TRANSPORT && l->transport == transport && l->unit_id == unit_id) {
            *entry_out = l;
            break;
        }
    }
    return BR_OK;
}

br_err_t br_link_learn(br_link_table_t *lt, const br_route_table_t *rt, uint16_t unit_id,
                       uint8_t transport, const uint8_t *addr, uint8_t addr_len,
                       uint32_t hop_seq, uint8_t epoch, int8_t rssi, uint32_t now_ms,
                       br_stats_t *stats)
{
    if (lt == NULL || rt == NULL || addr_len > BR_ADDR_MAX || (addr == NULL && addr_len > 0u) ||
        transport == BR_NO_TRANSPORT) {
        return BR_ERR_ARG;
    }
    br_link_entry_t *l = NULL;
    (void)br_link_find(lt, unit_id, transport, &l);
    if (l == NULL) {
        for (size_t i = 0; i < BR_LINK_ENTRIES && l == NULL; i++) {
            if (lt->e[i].transport == BR_NO_TRANSPORT) {
                l = &lt->e[i];
            }
        }
    }
    if (l == NULL) {
        /* Full: an unreferenced entry first (earliest expiry), then the earliest expiry. */
        br_link_entry_t *best_unref = NULL;
        br_link_entry_t *best_any = NULL;
        for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
            br_link_entry_t *c = &lt->e[i];
            if (best_any == NULL || br_ms_before(c->expiry_ms, best_any->expiry_ms)) {
                best_any = c;
            }
            if (!link_referenced(rt, c) &&
                (best_unref == NULL || br_ms_before(c->expiry_ms, best_unref->expiry_ms))) {
                best_unref = c;
            }
        }
        l = best_unref != NULL ? best_unref : best_any;
        link_free(l);
        br_stats_inc(stats, BR_STAT_LINK_EVICTIONS);
    }
    bool fresh_entry = (l->transport == BR_NO_TRANSPORT);
    l->unit_id = unit_id;
    l->transport = transport;
    if (addr_len > 0u) {
        memcpy(l->addr, addr, addr_len);
        l->addr_len = addr_len;
    } else if (fresh_entry) {
        l->addr_len = 0u;
    }
    l->epoch = epoch;
    l->fails = 0u;
    if (rssi != (int8_t)BR_RSSI_UNKNOWN) {
        if (fresh_entry || l->rssi_ewma == (int8_t)BR_RSSI_UNKNOWN) {
            l->rssi_ewma = rssi;
        } else {
            l->rssi_ewma = (int8_t)(((int)l->rssi_ewma * 3 + (int)rssi) / 4);
        }
    } else if (fresh_entry) {
        l->rssi_ewma = (int8_t)BR_RSSI_UNKNOWN;
    }
    l->hop_seq = hop_seq;
    l->expiry_ms = now_ms + BR_LINK_TTL_MS;
    return BR_OK;
}

br_err_t br_link_tx_result(br_link_table_t *lt, br_route_table_t *rt, uint8_t transport,
                           const uint8_t *addr, uint8_t addr_len, bool delivered,
                           br_stats_t *stats, bool *deleted_out)
{
    if (lt == NULL || rt == NULL || deleted_out == NULL || (addr == NULL && addr_len > 0u) ||
        addr_len > BR_ADDR_MAX) {
        return BR_ERR_ARG;
    }
    *deleted_out = false;
    if (addr_len == 0u) {
        return BR_OK;
    }
    for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
        br_link_entry_t *l = &lt->e[i];
        if (l->transport != transport || l->addr_len != addr_len ||
            memcmp(l->addr, addr, addr_len) != 0) {
            continue;
        }
        if (delivered) {
            l->fails = 0u;
            continue;
        }
        if (l->fails < 0xFFu) {
            l->fails++;
        }
        if (l->fails >= BR_LINK_FAIL_MAX) {
            uint8_t n = 0;
            (void)br_route_delete_via(rt, l->unit_id, l->transport, &n);
            for (uint8_t k = 0; k < n; k++) {
                br_stats_inc(stats, BR_STAT_LINK_FAIL_DROPS);
            }
            link_free(l);
            *deleted_out = true;
        }
    }
    return BR_OK;
}

br_err_t br_link_expire(br_link_table_t *lt, const br_route_table_t *rt, uint32_t now_ms)
{
    if (lt == NULL || rt == NULL) {
        return BR_ERR_ARG;
    }
    for (size_t i = 0; i < BR_LINK_ENTRIES; i++) {
        br_link_entry_t *l = &lt->e[i];
        if (l->transport == BR_NO_TRANSPORT || br_ms_before(now_ms, l->expiry_ms)) {
            continue;
        }
        bool live_ref = false;
        for (size_t j = 0; j < BR_ROUTE_ENTRIES && !live_ref; j++) {
            const br_route_entry_t *r = &rt->e[j];
            live_ref = route_live(r, now_ms) && r->next_hop == l->unit_id && r->transport == l->transport;
        }
        if (!live_ref) {
            link_free(l);
        }
    }
    return BR_OK;
}

/* ---- route table ---------------------------------------------------------- */

br_err_t br_route_find(br_route_table_t *rt, uint16_t dst_id, uint32_t now_ms,
                       br_route_entry_t **entry_out)
{
    if (rt == NULL || entry_out == NULL) {
        return BR_ERR_ARG;
    }
    *entry_out = NULL;
    if (dst_id == 0u) {
        return BR_OK;
    }
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        if (rt->e[i].dst_id == dst_id && route_live(&rt->e[i], now_ms)) {
            *entry_out = &rt->e[i];
            break;
        }
    }
    return BR_OK;
}

static br_route_entry_t *route_slot(br_route_table_t *rt, uint16_t dst_id, uint32_t now_ms,
                                    br_stats_t *stats)
{
    br_route_entry_t *victim = NULL;
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        br_route_entry_t *r = &rt->e[i];
        if (r->dst_id == dst_id) {
            return r; /* same destination, live or expired: reuse */
        }
    }
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        br_route_entry_t *r = &rt->e[i];
        if (!route_live(r, now_ms)) {
            return r;
        }
        if (victim == NULL || br_ms_before(r->expiry_ms, victim->expiry_ms)) {
            victim = r;
        }
    }
    br_stats_inc(stats, BR_STAT_ROUTE_EVICTIONS);
    return victim;
}

br_err_t br_route_learn(br_route_table_t *rt, br_route_event_t ev, uint16_t dst_id,
                        uint16_t next_hop, uint8_t transport, uint8_t hops, uint8_t cost,
                        bool fresher, bool in_window, uint32_t now_ms, br_stats_t *stats)
{
    if (rt == NULL || dst_id == 0u || next_hop == 0u || ev > BR_ROUTE_EV_OTHER) {
        return BR_ERR_ARG;
    }
    br_route_entry_t *cur = NULL;
    (void)br_route_find(rt, dst_id, now_ms, &cur);
    bool write = false;
    switch (ev) {
    case BR_ROUTE_EV_FLOOD:
        write = (cur == NULL) || (in_window && cost < cur->cost) || fresher;
        break;
    case BR_ROUTE_EV_HELLO:
        write = true;
        break;
    case BR_ROUTE_EV_OTHER:
    default:
        write = (cur == NULL);
        break;
    }
    if (!write) {
        return BR_OK;
    }
    br_route_entry_t *r = (cur != NULL) ? cur : route_slot(rt, dst_id, now_ms, stats);
    r->dst_id = dst_id;
    r->next_hop = next_hop;
    r->transport = transport;
    r->hops = hops;
    r->cost = cost;
    r->flags = (ev == BR_ROUTE_EV_FLOOD && in_window) ? BR_ROUTE_F_IN_WINDOW : 0u;
    r->expiry_ms = now_ms + BR_ROUTE_TTL_MS;
    return BR_OK;
}

br_err_t br_route_refresh(br_route_table_t *rt, uint16_t src_id, uint16_t prev_hop,
                          uint8_t transport, uint32_t now_ms)
{
    if (rt == NULL) {
        return BR_ERR_ARG;
    }
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        br_route_entry_t *r = &rt->e[i];
        if (r->dst_id == src_id && src_id != 0u && r->next_hop == prev_hop &&
            r->transport == transport && route_live(r, now_ms)) {
            r->expiry_ms = now_ms + BR_ROUTE_TTL_MS;
        }
    }
    return BR_OK;
}

br_err_t br_route_delete_via(br_route_table_t *rt, uint16_t next_hop, uint8_t transport,
                             uint8_t *n_deleted_out)
{
    if (rt == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t n = 0;
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        br_route_entry_t *r = &rt->e[i];
        if (r->dst_id != 0u && r->next_hop == next_hop && r->transport == transport) {
            memset(r, 0, sizeof *r);
            n++;
        }
    }
    if (n_deleted_out != NULL) {
        *n_deleted_out = n;
    }
    return BR_OK;
}

br_err_t br_route_expire(br_route_table_t *rt, uint32_t now_ms)
{
    if (rt == NULL) {
        return BR_ERR_ARG;
    }
    for (size_t i = 0; i < BR_ROUTE_ENTRIES; i++) {
        if (rt->e[i].dst_id != 0u && !route_live(&rt->e[i], now_ms)) {
            memset(&rt->e[i], 0, sizeof rt->e[i]);
        }
    }
    return BR_OK;
}

/* ---- dedup / ORIGIN ------------------------------------------------------- */

br_err_t br_dedup_find(br_dedup_table_t *dt, uint16_t src_id, uint32_t pre_ctr, uint32_t now_ms,
                       br_dedup_entry_t **entry_out)
{
    if (dt == NULL || entry_out == NULL) {
        return BR_ERR_ARG;
    }
    *entry_out = NULL;
    for (size_t i = 0; i < BR_DEDUP_ENTRIES; i++) {
        br_dedup_entry_t *d = &dt->e[i];
        if (d->src_id != 0u && d->src_id == src_id && d->pre_ctr == pre_ctr &&
            br_ms_before(now_ms, d->t_ms + BR_DEDUP_TTL_MS)) {
            *entry_out = d;
            break;
        }
    }
    return BR_OK;
}

br_err_t br_dedup_insert(br_dedup_table_t *dt, uint16_t src_id, uint32_t pre_ctr, uint8_t cost,
                         uint32_t now_ms, br_dedup_entry_t **entry_out)
{
    if (dt == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t idx = (uint8_t)(dt->next % BR_DEDUP_ENTRIES);
    br_dedup_entry_t *d = &dt->e[idx];
    d->src_id = src_id;
    d->pre_ctr = pre_ctr;
    d->best_cost = cost;
    d->pending = BR_NO_INDEX;
    d->t_ms = now_ms;
    dt->next = (uint8_t)((idx + 1u) % BR_DEDUP_ENTRIES);
    if (entry_out != NULL) {
        *entry_out = d;
    }
    return BR_OK;
}

static bool origin_live(const br_origin_entry_t *o, uint32_t now_ms)
{
    return o->src_id != 0u && br_ms_before(now_ms, o->t_ms + BR_ORIGIN_TTL_MS);
}

br_err_t br_origin_check(const br_origin_table_t *ot, uint16_t src_id, uint32_t pre_ctr,
                         uint32_t now_ms, bool *fresh_out)
{
    if (ot == NULL || fresh_out == NULL) {
        return BR_ERR_ARG;
    }
    *fresh_out = true;
    for (size_t i = 0; i < BR_ORIGIN_ENTRIES; i++) {
        const br_origin_entry_t *o = &ot->e[i];
        if (o->src_id == src_id && origin_live(o, now_ms)) {
            *fresh_out = pre_ctr >= o->last_ctr && (pre_ctr - o->last_ctr) <= BR_ORIGIN_MAX_JUMP;
            break;
        }
    }
    return BR_OK;
}

br_err_t br_origin_update(br_origin_table_t *ot, uint16_t src_id, uint32_t pre_ctr, uint32_t now_ms)
{
    if (ot == NULL || src_id == 0u) {
        return BR_ERR_ARG;
    }
    br_origin_entry_t *slot = NULL;
    for (size_t i = 0; i < BR_ORIGIN_ENTRIES && slot == NULL; i++) {
        if (ot->e[i].src_id == src_id) {
            slot = &ot->e[i];
        }
    }
    for (size_t i = 0; i < BR_ORIGIN_ENTRIES && slot == NULL; i++) {
        if (!origin_live(&ot->e[i], now_ms)) {
            slot = &ot->e[i];
        }
    }
    if (slot == NULL) {
        slot = &ot->e[0];
        for (size_t i = 1; i < BR_ORIGIN_ENTRIES; i++) {
            if (br_ms_before(ot->e[i].t_ms, slot->t_ms)) {
                slot = &ot->e[i];
            }
        }
    }
    slot->src_id = src_id;
    slot->reserved = 0u;
    slot->last_ctr = pre_ctr;
    slot->t_ms = now_ms;
    return BR_OK;
}

/* ---- flood budget --------------------------------------------------------- */

static void bucket_refill(br_bucket_t *b, uint32_t depth, uint32_t per_s, uint32_t now_ms)
{
    uint32_t cap = depth * 1000u;
    if (br_ms_before(b->t_ms, now_ms)) {
        uint32_t dt = now_ms - b->t_ms;
        if (dt > cap) {
            dt = cap; /* enough to fill from empty at any rate >= 1/s */
        }
        uint32_t m = (uint32_t)b->milli_tokens + dt * per_s;
        b->milli_tokens = (uint16_t)(m > cap ? cap : m);
        b->t_ms = now_ms;
    }
}

br_err_t br_flood_budget_take(br_flood_budget_t *fb, uint16_t src_id, uint32_t now_ms,
                              bool *granted_out)
{
    if (fb == NULL || granted_out == NULL) {
        return BR_ERR_ARG;
    }
    uint32_t h = ((uint32_t)src_id * 40503u) >> 10;
    br_bucket_t *o = &fb->origin[h % BR_FLOOD_BUCKETS];
    bucket_refill(o, BR_BUCKET_ORIGIN_DEPTH, BR_BUCKET_ORIGIN_PER_S, now_ms);
    bucket_refill(&fb->total, BR_BUCKET_TOTAL_DEPTH, BR_BUCKET_TOTAL_PER_S, now_ms);
    *granted_out = o->milli_tokens >= 1000u && fb->total.milli_tokens >= 1000u;
    if (*granted_out) {
        o->milli_tokens = (uint16_t)(o->milli_tokens - 1000u);
        fb->total.milli_tokens = (uint16_t)(fb->total.milli_tokens - 1000u);
    }
    return BR_OK;
}

/* ---- forwarding queue (section 7) ----------------------------------------- */

static bool type_is_data(uint8_t type)
{
    return type == (uint8_t)BR_TYPE_DATA || type == (uint8_t)BR_TYPE_PARITY;
}

/* Remove the element at ring position pos (0 = head) by shifting the newer ones down. */
static void fwdq_remove_at(br_fwd_queue_t *q, uint8_t pos)
{
    for (uint8_t k = pos; (uint8_t)(k + 1u) < q->count; k++) {
        uint8_t a = (uint8_t)((q->head + k) % BR_RELAY_QUEUE_FRAMES);
        uint8_t b = (uint8_t)((q->head + k + 1u) % BR_RELAY_QUEUE_FRAMES);
        q->s[a] = q->s[b];
    }
    uint8_t last = (uint8_t)((q->head + q->count - 1u) % BR_RELAY_QUEUE_FRAMES);
    memset(&q->s[last], 0, sizeof q->s[last]);
    q->count--;
}

br_err_t br_fwdq_push(br_fwd_queue_t *q, const uint8_t *frame, uint16_t len, uint8_t transport,
                      const uint8_t *addr, uint8_t addr_len, uint16_t next_hop, br_stats_t *stats)
{
    if (q == NULL || frame == NULL || len < 2u || len > BR_MAX_FRAME_MESH ||
        addr_len > BR_ADDR_MAX || (addr == NULL && addr_len > 0u)) {
        return BR_ERR_ARG;
    }
    bool is_data = type_is_data(frame[1]);
    if (q->count >= BR_RELAY_QUEUE_FRAMES) {
        if (is_data) {
            br_stats_inc(stats, BR_STAT_RELAY_DROP_QUEUE_DATA);
            return BR_ERR_QUEUE_FULL;
        }
        uint8_t victim = 0xFFu;
        for (uint8_t k = 0; k < q->count; k++) {
            if (q->s[(q->head + k) % BR_RELAY_QUEUE_FRAMES].is_data != 0u) {
                victim = k;
                break;
            }
        }
        if (victim == 0xFFu) {
            br_stats_inc(stats, BR_STAT_RELAY_DROP_QUEUE_CTRL);
            return BR_ERR_QUEUE_FULL;
        }
        fwdq_remove_at(q, victim);
        br_stats_inc(stats, BR_STAT_RELAY_DROP_QUEUE_DATA);
    }
    br_fwd_slot_t *s = &q->s[(q->head + q->count) % BR_RELAY_QUEUE_FRAMES];
    memcpy(s->frame, frame, len);
    s->len = len;
    s->in_use = 1u;
    s->transport = transport;
    s->is_data = is_data ? 1u : 0u;
    s->addr_len = addr_len;
    memset(s->addr, 0, sizeof s->addr);
    if (addr_len > 0u) {
        memcpy(s->addr, addr, addr_len);
    }
    s->next_hop = next_hop;
    q->count++;
    return BR_OK;
}

br_err_t br_fwdq_pop(br_fwd_queue_t *q, const br_fwd_slot_t **slot_out)
{
    if (q == NULL || slot_out == NULL) {
        return BR_ERR_ARG;
    }
    *slot_out = NULL;
    if (q->count == 0u) {
        return BR_OK;
    }
    br_fwd_slot_t *s = &q->s[q->head % BR_RELAY_QUEUE_FRAMES];
    s->in_use = 0u;
    *slot_out = s;
    q->head = (uint8_t)((q->head + 1u) % BR_RELAY_QUEUE_FRAMES);
    q->count--;
    return BR_OK;
}
