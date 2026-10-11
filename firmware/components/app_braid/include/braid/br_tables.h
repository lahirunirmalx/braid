// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_tables.h - mesh tables, flood control and counters (spec 11.4-11.6, 11.9,
 * Appendix B br_stats_t).
 *
 * Every table is a fixed array inside a caller-owned struct (static
 * allocation, no heap). Sizes default to the 11.9 counts; the demo path uses
 * them unchanged. Each BR_* size below may be overridden at build time, but
 * the same value MUST reach every translation unit that includes this header
 * (set it as a PUBLIC compile definition of app_braid / braid):
 * br_node_init() refuses a br_node_t whose size differs from the library's.
 *
 * Time: tables store uint32_t milliseconds of the node's monotonic clock
 * (br_platform now_us / 1000, truncated). It wraps after 49.7 days, so every
 * comparison goes through br_ms_before() (serial arithmetic); every TTL is
 * far below 2^31 ms.
 *
 * Rule R4 (11.4): only frames admitted at pipeline step 5 (hop_tag verified,
 * hop_seq fresh) may change any table. The functions here do not check that;
 * the caller (br_node.c) must.
 */
#ifndef BRAID_BR_TABLES_H
#define BRAID_BR_TABLES_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Sizes and timers (section 9, 11.5, 11.6, 11.9)                             */
/* ------------------------------------------------------------------------- */

#ifndef BR_LINK_ENTRIES
#define BR_LINK_ENTRIES           32u
#endif
#ifndef BR_ROUTE_ENTRIES
#define BR_ROUTE_ENTRIES          64u
#endif
#ifndef BR_DEDUP_ENTRIES
#define BR_DEDUP_ENTRIES          64u
#endif
#ifndef BR_ORIGIN_ENTRIES
#define BR_ORIGIN_ENTRIES         64u
#endif
#ifndef BR_FLOOD_BUCKETS
#define BR_FLOOD_BUCKETS          64u
#endif
#ifndef BR_FLOOD_PENDING
#define BR_FLOOD_PENDING           4u    /**< 11.5 pending (jittered) flood copies */
#endif
#ifndef BR_RELAY_QUEUE_FRAMES
#define BR_RELAY_QUEUE_FRAMES      8u    /**< 7, forwarding queue */
#endif

#define BR_LINK_TTL_MS         60000u    /**< unreferenced link entries */
#define BR_LINK_FAIL_MAX           3u    /**< consecutive send failures delete a link (11.6) */
#define BR_ROUTE_TTL_MS      1200000u    /**< 20 min */
#define BR_DEDUP_TTL_MS         5000u
#define BR_ORIGIN_TTL_MS     3600000u    /**< ORIGIN_TTL_S 3600 */
#define BR_RELAY_JITTER_MS        50u
#define BR_FLOOD_REPEAT            2u
#define BR_HOP_DELAY_MS           60u
#define BR_SEEK_TTL_DEFAULT        4u    /**< manifest default (site diameter + 1) */

/** Flood budgets (11.5): tokens in thousandths. */
#define BR_BUCKET_ORIGIN_DEPTH     6u
#define BR_BUCKET_ORIGIN_PER_S     2u
#define BR_BUCKET_TOTAL_DEPTH     20u
#define BR_BUCKET_TOTAL_PER_S     10u

/** Link cost from RSSI (11.2); below -90 dBm a SEEK copy is ignored. */
#define BR_RSSI_UNKNOWN         (-128)
#define BR_COST_RSSI_GOOD          1u    /**< >= -75 dBm */
#define BR_COST_RSSI_FAIR          3u    /**< -85 .. -75 */
#define BR_COST_RSSI_POOR         10u    /**< -90 .. -85 */
#define BR_COST_IGNORE          0xFFu    /**< below -90: ignore the copy */

#define BR_ADDR_MAX                6u    /**< largest carrier address (ESP-NOW MAC) */
#define BR_NO_TRANSPORT         0xFFu
#define BR_NO_INDEX             0xFFu

/* ------------------------------------------------------------------------- */
/* Time helpers                                                               */
/* ------------------------------------------------------------------------- */

/** Truncate a now_us value to the 32-bit table clock. */
static inline uint32_t br_ms_from_us(uint64_t now_us)
{
    return (uint32_t)(now_us / 1000u);
}

/** Serial compare on the 32-bit ms clock: true if a is strictly before b. */
static inline bool br_ms_before(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) < 0;
}

/* ------------------------------------------------------------------------- */
/* Counters (Appendix B br_stats_t, MGMT section 1 order)                     */
/* ------------------------------------------------------------------------- */

/** Index of each br_stats_t counter, in Appendix B order. */
typedef enum {
    BR_STAT_TX_FRAMES = 0, BR_STAT_RX_FRAMES, BR_STAT_CRC_FAIL, BR_STAT_RS_CORRECTED,
    BR_STAT_RS_FAIL, BR_STAT_SEG_FAIL, BR_STAT_BAD_FRAME, BR_STAT_BAD_VERSION,
    BR_STAT_AUTH_FAIL, BR_STAT_HOP_TAG_FAIL, BR_STAT_HOP_REPLAY, BR_STAT_REPLAY_DROPPED,
    BR_STAT_BUNDLE_FAIL, BR_STAT_FEC_RECOVERED, BR_STAT_ARQ_RETX, BR_STAT_GAPS,
    BR_STAT_ID_COLLISIONS, BR_STAT_RX_QUEUE_DROP, BR_STAT_RELAY_FWD, BR_STAT_RELAY_DROP_TTL,
    BR_STAT_RELAY_DROP_DEDUP, BR_STAT_RELAY_DROP_STALE, BR_STAT_RELAY_DROP_NOROUTE,
    BR_STAT_RELAY_DROP_MTU, BR_STAT_RELAY_DROP_RATE, BR_STAT_RELAY_DROP_QUEUE_DATA,
    BR_STAT_RELAY_DROP_QUEUE_CTRL, BR_STAT_RELAY_DROP_LOOP, BR_STAT_ROUTE_EVICTIONS,
    BR_STAT_LINK_EVICTIONS, BR_STAT_LINK_FAIL_DROPS, BR_STAT_STACK_HWM_WORDS,
    BR_STAT_UNKNOWN_SESSION,       /**< SPEC-NOTES N27: not in Appendix B / MGMT section 1 yet */
    BR_STAT_FLOOD_PENDING_FULL,    /**< 11.5 / 11.9: no FLOOD_PENDING buffer for a 9f copy; same rule as N27 */
    BR_STAT_COUNT,                 /**< 34 */
    BR_STAT_NONE = 0xFF            /**< no counter (silent drop: overheard, own echo) */
} br_stat_id_t;

/**
 * Appendix B br_stats_t. The union gives named access (.f.crc_fail) and
 * indexed access (.v[BR_STAT_CRC_FAIL]) to the same storage (C11 union
 * type punning).
 */
typedef union {
    struct {
        uint32_t tx_frames, rx_frames, crc_fail, rs_corrected, rs_fail, seg_fail, bad_frame,
                 bad_version, auth_fail, hop_tag_fail, hop_replay, replay_dropped, bundle_fail,
                 fec_recovered, arq_retx, gaps, id_collisions, rx_queue_drop, relay_fwd,
                 relay_drop_ttl, relay_drop_dedup, relay_drop_stale, relay_drop_noroute,
                 relay_drop_mtu, relay_drop_rate, relay_drop_queue_data, relay_drop_queue_ctrl,
                 relay_drop_loop, route_evictions, link_evictions, link_fail_drops,
                 stack_hwm_words,
                 unknown_session,  /**< SPEC-NOTES N27 (4.1.13 line 439): appended, not on the MGMT wire */
                 flood_pending_full; /**< 11.5 FLOOD_PENDING full: flood copy not rebroadcast; not on the MGMT wire */
    } f;
    uint32_t v[BR_STAT_COUNT];
} br_stats_t;

/** Increment one counter (saturating). BR_STAT_NONE and NULL are no-ops. */
static inline void br_stats_inc(br_stats_t *s, br_stat_id_t id)
{
    if (s != NULL && (unsigned)id < (unsigned)BR_STAT_COUNT && s->v[id] != UINT32_MAX) {
        s->v[id]++;
    }
}

/** Map a 3.6 validator counter (br_frame.h br_reject_counter()) to its br_stats_t index. */
static inline br_stat_id_t br_stat_from_counter(br_counter_t c)
{
    switch (c) {
    case BR_CNT_BAD_FRAME:      return BR_STAT_BAD_FRAME;
    case BR_CNT_BAD_VERSION:    return BR_STAT_BAD_VERSION;
    case BR_CNT_CRC_FAIL:       return BR_STAT_CRC_FAIL;
    case BR_CNT_HOP_TAG_FAIL:   return BR_STAT_HOP_TAG_FAIL;
    case BR_CNT_HOP_REPLAY:     return BR_STAT_HOP_REPLAY;
    case BR_CNT_AUTH_FAIL:      return BR_STAT_AUTH_FAIL;
    case BR_CNT_REPLAY_DROPPED: return BR_STAT_REPLAY_DROPPED;
    case BR_CNT_NONE:
    default:                    return BR_STAT_NONE;
    }
}

/* ------------------------------------------------------------------------- */
/* Link table (11.9)                                                          */
/* ------------------------------------------------------------------------- */

/** Link entry, keyed (unit_id, transport) (11.9). */
typedef struct {
    uint16_t unit_id;            /**< neighbour (its prev_hop) */
    uint8_t  transport;          /**< br_node transport index; BR_NO_TRANSPORT = free slot */
    uint8_t  addr_len;           /**< carrier address bytes (6 ESP-NOW) */
    uint8_t  addr[BR_ADDR_MAX];  /**< carrier address learnt from the admitted frame */
    uint8_t  epoch;              /**< K_hop epoch last verified from this neighbour (8.5) */
    uint8_t  fails;              /**< consecutive send failures (11.6) */
    int8_t   rssi_ewma;          /**< BR_RSSI_UNKNOWN when the carrier gives none */
    uint8_t  reserved;
    uint32_t hop_seq;            /**< last admitted hop_seq (3.5, 8.4) */
    uint32_t expiry_ms;          /**< now + BR_LINK_TTL_MS at last frame */
} br_link_entry_t;

typedef struct {
    br_link_entry_t e[BR_LINK_ENTRIES];
} br_link_table_t;

/* ------------------------------------------------------------------------- */
/* Route table (11.4, 11.6)                                                   */
/* ------------------------------------------------------------------------- */

/** Route entry: {dst_id, next_hop, transport, hops, cost, expiry} (11.4), 12 bytes. */
typedef struct {
    uint16_t dst_id;             /**< 0 = free slot */
    uint16_t next_hop;
    uint8_t  transport;
    uint8_t  hops;               /**< hop count to dst_id (1 = direct) */
    uint8_t  cost;               /**< accumulated path cost */
    uint8_t  flags;              /**< BR_ROUTE_F_* */
    uint32_t expiry_ms;
} br_route_entry_t;

/** Route flag: installed by a flood copy still inside its jitter window (11.4 row 1). */
#define BR_ROUTE_F_IN_WINDOW  0x01u

typedef struct {
    br_route_entry_t e[BR_ROUTE_ENTRIES];
} br_route_table_t;

/** Which 11.4 route-table row an admitted frame triggers. */
typedef enum {
    BR_ROUTE_EV_FLOOD = 0,   /**< SEEK / RESUME / flooded MGMT_REQ: reverse route to src_id */
    BR_ROUTE_EV_HELLO,       /**< unicast HELLO: forward route to the probe, replaces any entry */
    BR_ROUTE_EV_OTHER        /**< any other admitted frame for me / forwarded: install if none */
} br_route_event_t;

/* ------------------------------------------------------------------------- */
/* Dedup cache and ORIGIN (11.5)                                              */
/* ------------------------------------------------------------------------- */

/** Dedup entry (src_id, pre_ctr, timestamp, best_cost, pending copy), FIFO. */
typedef struct {
    uint16_t src_id;             /**< 0 = free slot */
    uint8_t  best_cost;          /**< lowest path_cost + link cost seen for this flood */
    uint8_t  pending;            /**< index into br_flood_pending_t, or BR_NO_INDEX */
    uint32_t pre_ctr;
    uint32_t t_ms;               /**< insertion time; expires after BR_DEDUP_TTL_MS */
} br_dedup_entry_t;

typedef struct {
    br_dedup_entry_t e[BR_DEDUP_ENTRIES];
    uint8_t          next;       /**< FIFO insertion cursor */
} br_dedup_table_t;

/** ORIGIN entry (src_id, last_ctr, timestamp), 1 h TTL. */
typedef struct {
    uint16_t src_id;             /**< 0 = free slot */
    uint16_t reserved;
    uint32_t last_ctr;
    uint32_t t_ms;
} br_origin_entry_t;

typedef struct {
    br_origin_entry_t e[BR_ORIGIN_ENTRIES];
} br_origin_table_t;

/* ------------------------------------------------------------------------- */
/* Flood budget (11.5)                                                        */
/* ------------------------------------------------------------------------- */

/** Token bucket, tokens in thousandths (depth 6 -> 6000). */
typedef struct {
    uint16_t milli_tokens;
    uint16_t reserved;
    uint32_t t_ms;               /**< last refill */
} br_bucket_t;

typedef struct {
    br_bucket_t origin[BR_FLOOD_BUCKETS];   /**< hashed by src_id */
    br_bucket_t total;
} br_flood_budget_t;

/* ------------------------------------------------------------------------- */
/* Frame buffers (11.5 pending copies, section 7 forwarding queue)            */
/* ------------------------------------------------------------------------- */

/** One jittered flood copy waiting for its rebroadcast time (11.4 step 9f). */
typedef struct {
    uint8_t  frame[BR_MAX_FRAME_MESH];
    uint16_t len;
    uint8_t  in_use;
    uint8_t  transport;          /**< arrival transport (not re-sent on it if point to point) */
    uint8_t  cost;               /**< path_cost + link cost of the kept copy */
    uint8_t  reserved;
    uint16_t src_id;
    uint32_t pre_ctr;
    uint32_t due_ms;
} br_flood_copy_t;

typedef struct {
    br_flood_copy_t c[BR_FLOOD_PENDING];
} br_flood_pending_t;

/** One unicast frame waiting to be sent (section 7 two-class queue). */
typedef struct {
    uint8_t  frame[BR_MAX_FRAME_MESH];
    uint16_t len;
    uint8_t  in_use;
    uint8_t  transport;
    uint8_t  is_data;            /**< DATA / PARITY (evictable class) */
    uint8_t  addr_len;
    uint8_t  addr[BR_ADDR_MAX];
    uint16_t next_hop;
} br_fwd_slot_t;

typedef struct {
    br_fwd_slot_t s[BR_RELAY_QUEUE_FRAMES];
    uint8_t       head;
    uint8_t       count;
} br_fwd_queue_t;

/** All 11.9 mesh state of one node. */
typedef struct {
    br_link_table_t    link;
    br_route_table_t   route;
    br_dedup_table_t   dedup;
    br_origin_table_t  origin;
    br_flood_budget_t  budget;
    br_flood_pending_t pending;
    br_fwd_queue_t     fwdq;
} br_tables_t;

/* ------------------------------------------------------------------------- */
/* API                                                                        */
/* ------------------------------------------------------------------------- */

/**
 * Clear every table (all slots free, buckets full at now_ms).
 * @return BR_OK; BR_ERR_ARG if t is NULL.
 * @spec 11.9
 */
br_err_t br_tables_init(br_tables_t *t, uint32_t now_ms);

/**
 * Link cost of a received copy (11.2): from RSSI when known (1 / 3 / 10,
 * BR_COST_IGNORE below -90 dBm), else the transport's fixed link_cost.
 *
 * @param rssi            dBm, or BR_RSSI_UNKNOWN.
 * @param fixed_cost      br_transport_t.link_cost.
 * @param cost_out        Receives the cost or BR_COST_IGNORE.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.2
 */
br_err_t br_link_cost(int8_t rssi, uint8_t fixed_cost, uint8_t *cost_out);

/**
 * Find the link entry for (unit_id, transport).
 *
 * @param entry_out  Receives the entry, or NULL if absent.
 * @return BR_OK (found or not); BR_ERR_ARG on NULL.
 * @spec 11.9
 */
br_err_t br_link_find(br_link_table_t *lt, uint16_t unit_id, uint8_t transport,
                      br_link_entry_t **entry_out);

/**
 * Pipeline step 6: learn or refresh (prev_hop, transport) -> address,
 * hop_seq, verified epoch, RSSI EWMA; expiry = now + BR_LINK_TTL_MS; fails
 * reset to 0. A different address replaces the stored one (the frame is
 * already fresh: 11.9, 8.4). When full, evict an entry not referenced by
 * any route first, then the earliest expiry (link_evictions).
 *
 * @param lt, rt     Link and route tables (rt for the reference check).
 * @param stats      Counters (link_evictions); may be NULL.
 * @return BR_OK; BR_ERR_ARG on NULL lt / rt / addr with addr_len > 0, or
 *         addr_len > BR_ADDR_MAX.
 * @spec 11.4 step 6, 11.9
 */
br_err_t br_link_learn(br_link_table_t *lt, const br_route_table_t *rt, uint16_t unit_id,
                       uint8_t transport, const uint8_t *addr, uint8_t addr_len,
                       uint32_t hop_seq, uint8_t epoch, int8_t rssi, uint32_t now_ms,
                       br_stats_t *stats);

/**
 * Feed a carrier delivery report (mac_retry transports, 11.6). A success
 * resets fails; BR_LINK_FAIL_MAX consecutive failures delete the link entry
 * and every route through it (link_fail_drops counts the routes).
 *
 * @param deleted_out  Receives true when the link was deleted.
 * @return BR_OK (also for an unknown address); BR_ERR_ARG on NULL.
 * @spec 11.6
 */
br_err_t br_link_tx_result(br_link_table_t *lt, br_route_table_t *rt, uint8_t transport,
                           const uint8_t *addr, uint8_t addr_len, bool delivered,
                           br_stats_t *stats, bool *deleted_out);

/**
 * Expire link entries not referenced by any route whose expiry passed
 * (11.6: a referenced entry lives as long as the route).
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.6, 11.9
 */
br_err_t br_link_expire(br_link_table_t *lt, const br_route_table_t *rt, uint32_t now_ms);

/**
 * Find the route to dst_id.
 * @param entry_out  Receives the entry, or NULL if absent / expired.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.4
 */
br_err_t br_route_find(br_route_table_t *rt, uint16_t dst_id, uint32_t now_ms,
                       br_route_entry_t **entry_out);

/**
 * Apply one 11.4 route-table row for an admitted frame:
 * - BR_ROUTE_EV_FLOOD: reverse route to dst_id (= the flood's src_id) via
 *   next_hop (= prev_hop), hops, cost; while in_window a lower-cost copy
 *   replaces the entry; outside it only a fresher flood does (fresher =
 *   newer pre_ctr, decided by the caller from ORIGIN).
 * - BR_ROUTE_EV_HELLO: forward route to the probe; replaces any entry.
 * - BR_ROUTE_EV_OTHER: install only if no route exists; never changes an
 *   existing next_hop.
 * Expiry = now + BR_ROUTE_TTL_MS on install. Full table: evict the earliest
 * expiry (route_evictions).
 *
 * @param fresher    Flood only: the copy carries a newer pre_ctr than the
 *                   one that installed the entry.
 * @param in_window  Flood only: inside this node's relay jitter window for it.
 * @return BR_OK; BR_ERR_ARG on NULL or dst_id / next_hop 0.
 * @spec 11.4, 11.6
 */
br_err_t br_route_learn(br_route_table_t *rt, br_route_event_t ev, uint16_t dst_id,
                        uint16_t next_hop, uint8_t transport, uint8_t hops, uint8_t cost,
                        bool fresher, bool in_window, uint32_t now_ms, br_stats_t *stats);

/**
 * 11.4 row 4: a frame received from prev_hop whose src_id is the dst of a
 * route with next_hop == prev_hop refreshes that route's expiry. Forwarding
 * toward dst refreshes nothing (review H4).
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.4, 11.6
 */
br_err_t br_route_refresh(br_route_table_t *rt, uint16_t src_id, uint16_t prev_hop,
                          uint8_t transport, uint32_t now_ms);

/**
 * Delete every route whose next hop is (next_hop, transport) (11.6 fast
 * failover).
 * @param n_deleted_out  Optional (may be NULL).
 * @return BR_OK; BR_ERR_ARG if rt is NULL.
 * @spec 11.6
 */
br_err_t br_route_delete_via(br_route_table_t *rt, uint16_t next_hop, uint8_t transport,
                             uint8_t *n_deleted_out);

/**
 * Drop routes whose expiry passed.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.6
 */
br_err_t br_route_expire(br_route_table_t *rt, uint32_t now_ms);

/**
 * Step 9b lookup: is (src_id, pre_ctr) in the dedup cache (entries older
 * than BR_DEDUP_TTL_MS count as absent)?
 * @param entry_out  Receives the entry or NULL.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.4 step 9b, 11.5
 */
br_err_t br_dedup_find(br_dedup_table_t *dt, uint16_t src_id, uint32_t pre_ctr, uint32_t now_ms,
                       br_dedup_entry_t **entry_out);

/**
 * Insert (src_id, pre_ctr) FIFO (overwrites the oldest slot). Also used by
 * the origin before its own flood (11.5 origin bookkeeping).
 * @param entry_out  Optional: receives the new entry.
 * @return BR_OK; BR_ERR_ARG on NULL dt.
 * @spec 11.5
 */
br_err_t br_dedup_insert(br_dedup_table_t *dt, uint16_t src_id, uint32_t pre_ctr, uint8_t cost,
                         uint32_t now_ms, br_dedup_entry_t **entry_out);

/**
 * Step 9c: ORIGIN freshness of a flood's pre_ctr. Fresh iff there is no
 * live entry for src_id (TTL 1 h), or pre_ctr >= last_ctr and
 * pre_ctr - last_ctr <= BR_ORIGIN_MAX_JUMP (plain unsigned compare, 3.5).
 * Equal copies are fresh here because dedup (9b) runs first and catches them.
 *
 * @param fresh_out  Receives the verdict (false -> relay_drop_stale).
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.4 step 9c, 11.5, 8.4
 */
br_err_t br_origin_check(const br_origin_table_t *ot, uint16_t src_id, uint32_t pre_ctr,
                         uint32_t now_ms, bool *fresh_out);

/**
 * Step 9e: record pre_ctr as the origin's last_ctr (insert or update;
 * full table: replace the oldest timestamp).
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.5
 */
br_err_t br_origin_update(br_origin_table_t *ot, uint16_t src_id, uint32_t pre_ctr, uint32_t now_ms);

/**
 * Step 9d: take one token from the per-origin bucket (hashed by src_id,
 * depth 6, 2/s) and the node bucket (depth 20, 10/s). Both must have a
 * token; none is taken otherwise.
 * @param granted_out  false -> relay_drop_rate.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 11.4 step 9d, 11.5
 */
br_err_t br_flood_budget_take(br_flood_budget_t *fb, uint16_t src_id, uint32_t now_ms,
                              bool *granted_out);

/**
 * Enqueue a unicast frame for transmission (section 7 classes): when full,
 * a control frame evicts the oldest DATA/PARITY (relay_drop_queue_data); a
 * control frame is dropped only if the queue holds nothing else
 * (relay_drop_queue_ctrl); a DATA/PARITY frame is dropped when full
 * (relay_drop_queue_data).
 * @return BR_OK; BR_ERR_QUEUE_FULL when the new frame was dropped;
 *         BR_ERR_ARG on NULL or len > BR_MAX_FRAME_MESH.
 * @spec 7 (queues), 11.4 step 10d
 */
br_err_t br_fwdq_push(br_fwd_queue_t *q, const uint8_t *frame, uint16_t len, uint8_t transport,
                      const uint8_t *addr, uint8_t addr_len, uint16_t next_hop, br_stats_t *stats);

/**
 * Dequeue the oldest frame.
 * @param slot_out  Receives a pointer valid until the next push; NULL if empty.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 7 (queues), 11.4 step 10e
 */
br_err_t br_fwdq_pop(br_fwd_queue_t *q, const br_fwd_slot_t **slot_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_TABLES_H */
