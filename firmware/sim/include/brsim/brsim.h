// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * brsim.h - deterministic host mesh simulator for Braid (phase 1b).
 *
 * N endpoints share one virtual radio medium (one ESP-NOW-like carrier,
 * transport index 0 on every node). An endpoint is either a real br_node_t
 * (brsim_add_br_node) or a test double (brsim_add_endpoint).
 *
 * Medium model:
 * - Directed per-link parameters brsim_link_t: connected, loss (ppm, drawn
 *   per frame per receiver), delay uniform in [delay_min_us, delay_max_us],
 *   reorder (false: delivery time is clamped to the previous delivery on the
 *   same (from, to) pair, so frames on one link never overtake).
 *   The connectivity matrix is how A and C are kept apart: with no link,
 *   nothing sent by one is ever delivered to the other.
 * - Broadcast (addr NULL) reaches every connected node. Unicast reaches only
 *   the node owning the 6-byte address (ESP-NOW MAC filter: no overhearing)
 *   and, like ESP-NOW, produces an asynchronous delivery report to the
 *   sender (tx_status) after delay_min_us: delivered iff any of
 *   mac_attempts tries survived the loss draw. Unicast to an unconnected or
 *   unknown address reports not delivered.
 * - Node addresses: 02:50:4C:00:<unit_id hi>:<unit_id lo> (locally
 *   administered).
 * - Bench allowlist (SPEC-NOTES N22): if a node's allowlist is enabled, the
 *   sim's adapter applies br_bench_allowlist_admit() before the endpoint
 *   sees the frame (trace verdict "allowlist").
 *
 * Time and randomness:
 * - One virtual clock in microseconds; events run in (time, insertion
 *   order). brsim_init() installs a br_platform_t whose now_us returns that
 *   clock and whose random_bytes draws from the PRNG stream of the node
 *   currently executing (one stream per node), so node-logic changes do not
 *   perturb the medium's loss / delay draws (a separate stream).
 * - Same seed + same scenario calls => identical event order, identical
 *   trace, identical results. No wall clock, no OS randomness.
 * - br_platform_set() is a process-wide singleton: ONE active brsim_t per
 *   process (brsim_init() takes it over; tests run scenarios one after
 *   another).
 *
 * Trace: one line per frame per receiver (and one per TX that reaches no
 * receiver):
 *   "<t_us> <from>><to> L0 <TYPE> seq=<seq> hops=<h> ttl=<t> src=<src>
 *    dst=<dst> len=<n> <verdict>"
 * from / to are carrier-level unit IDs in hex (to = FFFF for a broadcast no
 * one received). Verdicts: lost, noconn, allowlist, rx (test endpoint, or
 * its own text), and for br_node endpoints the pipeline verdict:
 * deliver / forward / flood / deliver+flood / drop:<counter|silent>.
 * Header fields are printed only when the frame is long enough to hold them
 * (dummy frames may be arbitrary bytes).
 *
 * Memory: brsim_t is a large plain struct (event heap with inline frame
 * copies, about 1.2 MB); allocate it statically.
 * Host-only C11; not part of the firmware image.
 */
#ifndef BRSIM_BRSIM_H
#define BRSIM_BRSIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "braid/br_node.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Limits                                                                     */
/* ------------------------------------------------------------------------- */

#define BRSIM_MAX_NODES        16u
#define BRSIM_MAX_EVENTS     4096u
#define BRSIM_MAX_APP_LOG     512u
#define BRSIM_TRACE_LINE_MAX  192u
#define BRSIM_ADDR_LEN          6u
#define BRSIM_NEVER    UINT64_MAX
#define BRSIM_NO_NODE        0xFFu

typedef struct brsim brsim_t;

/* ------------------------------------------------------------------------- */
/* Medium configuration                                                       */
/* ------------------------------------------------------------------------- */

/** Directed link from -> to. A zeroed struct is "not connected". */
typedef struct {
    bool     connected;
    bool     reorder;          /**< allow overtaking on this link */
    uint32_t loss_ppm;         /**< 0..1000000, per frame per receiver (per attempt for unicast) */
    uint32_t delay_min_us;
    uint32_t delay_max_us;     /**< >= delay_min_us */
    int8_t   rssi_dbm;         /**< RSSI reported to the receiver; 0 = default -60 dBm (cost 1, 11.2) */
} brsim_link_t;

/** Counters per directed link (for tolerance checks). */
typedef struct {
    uint32_t sent;             /**< frames offered to this link (broadcast: per connected receiver) */
    uint32_t lost;             /**< dropped by the loss draw */
    uint32_t delivered;        /**< handed to the receiver's adapter */
    uint32_t allowlist_drop;   /**< delivered but dropped by the receiver's bench allowlist */
} brsim_link_stats_t;

/* ------------------------------------------------------------------------- */
/* Endpoints                                                                  */
/* ------------------------------------------------------------------------- */

/**
 * Test-double endpoint. Every callback may be NULL. They run inside
 * brsim_run_*() with the sim clock at the event time; they may call
 * brsim_send() and brsim_schedule().
 */
typedef struct {
    /** A frame arrived (after the allowlist). Write a short verdict for the trace (optional). */
    void (*rx)(brsim_t *sim, uint8_t node, void *user, const uint8_t *frame, size_t len,
               const br_rx_meta_t *meta, char *verdict, size_t verdict_cap);
    /** Timer: return the next absolute deadline (us) or BRSIM_NEVER. Called at the
     *  previous deadline and after every event delivered to this endpoint. */
    uint64_t (*tick)(brsim_t *sim, uint8_t node, void *user, uint64_t now_us);
    /** Unicast delivery report (ESP-NOW send callback). */
    void (*tx_status)(brsim_t *sim, uint8_t node, void *user, const uint8_t *addr,
                      uint8_t addr_len, bool delivered);
} brsim_endpoint_ops_t;

/** App-level record captured from br_node callbacks (inspection hook). */
typedef enum {
    BRSIM_APP_SAMPLES = 1,     /**< on_samples: a = src_id, b = hops, c = seq, bytes = samples */
    BRSIM_APP_ACKED,           /**< on_acked: a = session, c = seq */
    BRSIM_APP_STATE,           /**< on_state: a = session, b = old, c = new */
    BRSIM_APP_BOUND,           /**< on_bound: a = session, c = peer */
    BRSIM_APP_SEEK_RESULT,     /**< on_seek_result: a = session, b = hops, c = probe, err = result */
    BRSIM_APP_MODE,            /**< on_mode: a = session, c = config_id */
    BRSIM_APP_GAP,             /**< on_gap: a = session, c = first_seq, b = count */
    BRSIM_APP_CLOSED,          /**< on_closed: a = session, b = reason */
    BRSIM_APP_EVENT            /**< on_event: c = event, arg = arg */
} brsim_app_kind_t;

typedef struct {
    uint64_t         t_us;
    uint8_t          node;
    brsim_app_kind_t kind;
    uint16_t         a;
    uint16_t         b;
    uint16_t         c;
    int32_t          err;
    uint32_t         arg;
    br_data_hdr_t    hdr;      /**< BRSIM_APP_SAMPLES */
    uint8_t          n_bytes;
    uint8_t          bytes[16]; /**< first sample bytes (BRSIM_APP_SAMPLES) */
} brsim_app_rec_t;

/* ------------------------------------------------------------------------- */
/* Simulator object (complete type for static allocation; fields private)     */
/* ------------------------------------------------------------------------- */

typedef enum {
    BRSIM_EV_DELIVER = 1,
    BRSIM_EV_TX_STATUS,
    BRSIM_EV_TICK,
    BRSIM_EV_CALL
} brsim_ev_kind_t;

typedef void (*brsim_call_fn)(brsim_t *sim, void *arg);

typedef struct {
    uint64_t        t_us;
    uint64_t        order;     /**< insertion counter: tie-break, never pointer order */
    uint8_t         kind;      /**< brsim_ev_kind_t */
    uint8_t         from;
    uint8_t         to;
    uint8_t         delivered; /**< TX_STATUS */
    uint32_t        gen;       /**< TICK generation (stale ticks are skipped) */
    brsim_call_fn   fn;        /**< CALL */
    void           *arg;
    uint16_t        len;
    uint8_t         frame[BR_MAX_FRAME_MESH];
} brsim_event_t;

typedef struct {
    brsim_t                    *sim;       /**< back pointer (callback user pointers point here) */
    bool                        used;
    bool                        is_br_node;
    uint16_t                    unit_id;
    uint8_t                     addr[BRSIM_ADDR_LEN];
    const brsim_endpoint_ops_t *ops;
    void                       *user;
    br_node_t                  *node;      /**< is_br_node */
    br_app_callbacks_t          user_app;  /**< caller's callbacks, chained after logging */
    br_transport_t              tr;        /**< adapter view: send hook + allowlist */
    uint64_t                    next_tick_us;
    uint32_t                    tick_gen;
    uint64_t                    rng;       /**< random_bytes stream */
    uint64_t                    last_deliver_us[BRSIM_MAX_NODES]; /**< no-reorder clamp per from */
} brsim_node_t;

struct brsim {
    uint64_t           now_us;
    uint64_t           order;
    uint64_t           seed;
    uint64_t           rng_medium;
    uint64_t           rng_scenario;
    uint8_t            n_nodes;
    uint8_t            cur_node;            /**< node executing, or BRSIM_NO_NODE */
    uint8_t            mac_attempts;        /**< unicast tries (default 1) */
    brsim_node_t       nodes[BRSIM_MAX_NODES];
    brsim_link_t       link[BRSIM_MAX_NODES][BRSIM_MAX_NODES];
    brsim_link_stats_t lstats[BRSIM_MAX_NODES][BRSIM_MAX_NODES];
    uint32_t           n_events;
    brsim_event_t      heap[BRSIM_MAX_EVENTS];
    uint32_t           heap_overflows;
    void             (*trace)(void *user, const char *line);
    void              *trace_user;
    uint32_t           trace_lines;
    uint64_t           trace_hash;          /**< FNV-1a 64 over every trace line */
    uint32_t           n_app;
    uint32_t           app_overflows;
    brsim_app_rec_t    app[BRSIM_MAX_APP_LOG];
};

/* ------------------------------------------------------------------------- */
/* API                                                                        */
/* ------------------------------------------------------------------------- */

/**
 * Reset the simulator, seed the PRNG streams, set the clock to 0 and
 * install the virtual platform (br_platform_set). Takes over the process
 * platform singleton.
 * @return BR_OK; BR_ERR_ARG if sim is NULL; error from br_platform_set().
 */
br_err_t brsim_init(brsim_t *sim, uint64_t seed);

/**
 * Add a test-double endpoint.
 * @param unit_id  Carrier identity (address 02:50:4C:00:hi:lo); unique.
 * @param idx_out  Receives the node index (0..BRSIM_MAX_NODES - 1).
 * @return BR_OK; BR_ERR_ARG (NULL ops / idx_out, duplicate unit_id);
 *         BR_ERR_QUEUE_FULL when BRSIM_MAX_NODES are in use.
 */
br_err_t brsim_add_endpoint(brsim_t *sim, uint16_t unit_id, const brsim_endpoint_ops_t *ops,
                            void *user, uint8_t *idx_out);

/**
 * Add a real br_node_t. cfg is copied and adapted: transports[0] becomes
 * the sim medium (send hook, max_frame 250, rs_nsym 0, broadcast,
 * mac_retry, addr_len 6, link_cost 1; its allowlist is kept), n_transports
 * is forced to 1, and the app callbacks are chained through the sim's
 * app log (the caller's callbacks still run). Then br_node_init() runs at
 * the current sim time.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_QUEUE_FULL; any br_node_init() error
 *         (the node is not added then; with phase 1b stubs this is
 *         BR_ERR_NOT_IMPLEMENTED).
 */
br_err_t brsim_add_br_node(brsim_t *sim, br_node_t *node, const br_node_config_t *cfg,
                           uint8_t *idx_out);

/** Set the directed link from -> to. @return BR_OK; BR_ERR_ARG (bad index, delay_max < delay_min, loss > 1e6). */
br_err_t brsim_set_link(brsim_t *sim, uint8_t from, uint8_t to, const brsim_link_t *l);

/** brsim_set_link() in both directions. */
br_err_t brsim_set_link_sym(brsim_t *sim, uint8_t a, uint8_t b, const brsim_link_t *l);

/**
 * Bench allowlist of node idx (SPEC-NOTES N22): only frames whose prev_hop
 * is in ids are passed to the endpoint. n == 0 with enable true drops
 * everything; enable false admits everything.
 * @return BR_OK; BR_ERR_ARG (bad index, n > BR_BENCH_ALLOWLIST_MAX, NULL ids with n > 0).
 */
br_err_t brsim_set_allowlist(brsim_t *sim, uint8_t idx, bool enable, const uint16_t *ids, uint8_t n);

/** Unicast tries per frame (ESP-NOW MAC retries), 1..16. Default 1. */
br_err_t brsim_set_mac_attempts(brsim_t *sim, uint8_t attempts);

/**
 * Put a frame on the medium from node `from` (the transport send hook of
 * br_node endpoints calls this). addr NULL = broadcast.
 * @return BR_OK; BR_ERR_ARG (bad index, NULL frame, len 0 or > 250);
 *         BR_ERR_QUEUE_FULL if the event heap is full (counted).
 */
br_err_t brsim_send(brsim_t *sim, uint8_t from, const uint8_t *addr, const uint8_t *frame, size_t len);

/**
 * Run fn(sim, arg) at absolute time at_us (>= now). After it returns every
 * node is ticked (scenario actions such as a button press need no extra
 * call).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_QUEUE_FULL.
 */
br_err_t brsim_schedule(brsim_t *sim, uint64_t at_us, brsim_call_fn fn, void *arg);

/** Process events with t <= t_end_us; the clock ends at t_end_us. @return BR_OK; BR_ERR_ARG. */
br_err_t brsim_run_until(brsim_t *sim, uint64_t t_end_us);

/** brsim_run_until(now + dt_us). */
br_err_t brsim_run_for(brsim_t *sim, uint64_t dt_us);

/** Current virtual time (us). */
uint64_t brsim_now(const brsim_t *sim);

/** Uniform draw in [0, n) from the scenario stream (n > 0; 0 returns 0). */
uint32_t brsim_rand_below(brsim_t *sim, uint32_t n);

/** Install the trace sink (NULL disables printing; the hash is always kept). */
void brsim_set_trace(brsim_t *sim, void (*sink)(void *user, const char *line), void *user);

/** Convenience sink: user is a FILE *; writes the line plus '\n'. */
void brsim_trace_file(void *user, const char *line);

/** FNV-1a 64 over all trace lines so far, and the line count. */
uint64_t brsim_trace_hash(const brsim_t *sim, uint32_t *lines_out);

/** Counters of the directed link from -> to. @return BR_OK; BR_ERR_ARG. */
br_err_t brsim_link_stats(const brsim_t *sim, uint8_t from, uint8_t to, brsim_link_stats_t *out);

/** Node index of a unit ID, or BRSIM_NO_NODE. */
uint8_t brsim_find(const brsim_t *sim, uint16_t unit_id);

/** The 6-byte carrier address of node idx. @return BR_OK; BR_ERR_ARG. */
br_err_t brsim_addr(const brsim_t *sim, uint8_t idx, uint8_t addr_out[BRSIM_ADDR_LEN]);

/** The br_node_t of node idx, or NULL for test doubles / bad index (inspect with br_node_get_*). */
br_node_t *brsim_br_node(brsim_t *sim, uint8_t idx);

/**
 * App log captured from br_node callbacks (all nodes, time order).
 * @param recs_out  Receives the array; *n_out its length.
 * @return BR_OK; BR_ERR_ARG.
 */
br_err_t brsim_app_log(const brsim_t *sim, const brsim_app_rec_t **recs_out, uint32_t *n_out);

#ifdef __cplusplus
}
#endif

#endif /* BRSIM_BRSIM_H */
