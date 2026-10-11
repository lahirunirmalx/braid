// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_node.h - the top-level Braid node: transports, receive pipeline,
 * timers and the application API (spec 1.2, 11.4, Appendix B).
 *
 * One br_node_t is one Braid unit. It is a complete type so it can be
 * allocated statically (`static br_node_t node;`); this replaces Appendix B's
 * br_alloc() / heap br_ctx_t (11.9 last paragraph, Appendix B rules) with
 * caller-owned storage. The only heap use is inside br_node_init():
 * br_crypto_init() lets mbedtls allocate the HMAC state once (br_crypto.h).
 * Nothing allocates after init.
 *
 * Threading (Appendix B task layout): every br_node_* function runs in ONE
 * protocol task. Carrier callbacks (ESP-NOW RX / TX-status on core 0) only
 * copy into a queue with timeout 0 (RX_QUEUE_FRAMES 16; a full queue counts
 * rx_queue_drop via br_node_count_rx_queue_drop()); the protocol task drains
 * the queue into br_node_rx() / br_node_tx_status() and calls
 * br_node_tick() when its deadline passes. The core holds no OS objects.
 *
 * Time and randomness come from br_platform.h (now_us, random_bytes), which
 * must be installed before br_node_init(). The simulator (firmware/sim)
 * feeds a virtual clock through the same table.
 *
 * Deviations from the spec's C API, all deliberate:
 * - Transport (1.2 lines 70-84): send() takes a user pointer; set_rx_cb /
 *   set_tx_cb are replaced by the adapter calling br_node_rx() /
 *   br_node_tx_status() from the protocol task (push model, no globals, N
 *   nodes per process in the simulator).
 * - Callbacks (Appendix B lines 1909-1919): user pointer, hops in the
 *   sample context, on_state / on_acked (br_session.h).
 * - Bench neighbour allowlist on the transport (SPEC-NOTES N22): not in the
 *   spec, bench profile only, compiled out with BR_FIELD_BUILD.
 */
#ifndef BRAID_BR_NODE_H
#define BRAID_BR_NODE_H

#include "braid/br_types.h"
#include "braid/br_frame.h"
#include "braid/br_crypto.h"
#include "braid/br_sample.h"
#include "braid/br_tables.h"
#include "braid/br_arq.h"
#include "braid/br_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Sizes                                                                      */
/* ------------------------------------------------------------------------- */

#ifndef BR_NODE_MAX_TRANSPORTS
#define BR_NODE_MAX_TRANSPORTS   2u
#endif
#define BR_RX_QUEUE_FRAMES      16u   /**< section 7; owned by the port, not the core */
#define BR_NEVER_US     UINT64_MAX    /**< br_node_tick(): nothing scheduled */

/** Appendix B br_role_t. The demo's sender / relay / probe are all BR_ROLE_NODE. */
typedef enum {
    BR_ROLE_NODE = 0,
    BR_ROLE_BRIDGE,
    BR_ROLE_GATEWAY,
    BR_ROLE_LEAF          /**< never forwards (11.4 steps 9e, 10a); 4.4 out of scope */
} br_role_t;

/* ------------------------------------------------------------------------- */
/* Bench neighbour allowlist (SPEC-NOTES N22; not in the spec)                */
/* ------------------------------------------------------------------------- */

/*
 * On a bench every board hears every other one. To force a multi-hop
 * topology (A <-> B <-> C, A and C never in contact) each board's transport
 * adapter drops any frame whose header prev_hop (offset 6, frozen prefix)
 * is not listed, BEFORE br_node_rx() sees it: the core then behaves exactly
 * as if the carrier never delivered the frame (no counter, no table change).
 * prev_hop is not authenticated at that point; this is topology shaping for
 * tests, not security. Field builds (BR_FIELD_BUILD defined) compile it out;
 * br_transport_admit() then admits everything.
 */
#ifndef BR_BENCH_ALLOWLIST_MAX
#define BR_BENCH_ALLOWLIST_MAX   8u
#endif

#ifndef BR_FIELD_BUILD
typedef struct {
    bool     enabled;                          /**< false: admit every frame */
    uint8_t  n;                                /**< entries used in ids[] */
    uint16_t ids[BR_BENCH_ALLOWLIST_MAX];      /**< admitted prev_hop unit IDs */
} br_bench_allowlist_t;

/**
 * Bench adapter filter. Admits the frame iff the list is disabled, or
 * len >= 8 and the LE u16 at offset 6 (prev_hop) is in ids[0..n-1].
 * Frames shorter than 8 bytes are dropped by an enabled list (nothing to
 * attribute them to). Pure function; real (not a stub).
 *
 * @param al     List (NULL admits everything).
 * @param frame  Received bytes (after COBS / RS on RAW links); NULL with len 0 allowed.
 * @param len    Bytes in frame.
 * @return true to pass the frame to br_node_rx(), false to drop it.
 * @spec none (bench mechanism, SPEC-NOTES N22)
 */
bool br_bench_allowlist_admit(const br_bench_allowlist_t *al, const uint8_t *frame, size_t len);
#endif /* !BR_FIELD_BUILD */

/* ------------------------------------------------------------------------- */
/* Transport adapter interface (1.2)                                          */
/* ------------------------------------------------------------------------- */

/**
 * One carrier as the core sees it (1.2 fields; see the deviations above).
 *
 * send(): queue one frame for transmission and return at once (never block
 * the protocol task). addr NULL = broadcast (floods); otherwise addr_len
 * bytes of the next hop's carrier address from the link table. Returns
 * BR_OK if queued, BR_ERR_QUEUE_FULL / BR_ERR_BUSY if not (counted, frame
 * lost). Where mac_retry is true, the adapter later reports the carrier's
 * delivery verdict through br_node_tx_status() (11.6 failover).
 */
typedef struct {
    const char      *name;          /**< "espnow", "sim", ... */
    br_link_class_t  link_class;    /**< PACKET (ESP-NOW) or RAW */
    uint16_t         max_frame;     /**< 250 on mesh carriers (incl. RS parity) */
    uint8_t          rs_nsym;       /**< 0 on PACKET links */
    bool             can_broadcast; /**< floods by broadcast */
    bool             mac_retry;     /**< carrier reports unicast delivery */
    bool             edge_only;     /**< IR: never forwarded (out of scope) */
    uint8_t          link_cost;     /**< fixed cost without RSSI (11.2) */
    uint8_t          addr_len;      /**< 6 ESP-NOW */
    br_err_t       (*send)(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);
    void            *user;          /**< passed to send() */
#ifndef BR_FIELD_BUILD
    br_bench_allowlist_t allowlist; /**< bench only (N22); applied by the adapter */
#endif
} br_transport_t;

/**
 * The adapter-side admission check. Call it on every received frame before
 * queueing it for br_node_rx(); drop the frame when it returns false.
 * In BR_FIELD_BUILD it always returns true, so call sites need no #ifdef.
 */
#ifndef BR_FIELD_BUILD
static inline bool br_transport_admit(const br_transport_t *tr, const uint8_t *frame, size_t len)
{
    return tr == NULL || br_bench_allowlist_admit(&tr->allowlist, frame, len);
}
#else
static inline bool br_transport_admit(const br_transport_t *tr, const uint8_t *frame, size_t len)
{
    (void)tr;
    (void)frame;
    (void)len;
    return true;
}
#endif

/** Carrier facts about one received frame: the "prev_hop hint". */
typedef struct {
    uint8_t addr[BR_ADDR_MAX];      /**< transmitter's carrier address (ESP-NOW src MAC) */
    uint8_t addr_len;               /**< 0 on carriers without addresses (UART, IR) */
    int8_t  rssi;                   /**< dBm, BR_RSSI_UNKNOWN if none */
} br_rx_meta_t;

/* ------------------------------------------------------------------------- */
/* Configuration                                                              */
/* ------------------------------------------------------------------------- */

/** Which persistent counter a reserve-ahead write is for (3.5). */
#define BR_PERSIST_TXSEQ   0u        /**< NVS br/txseq, block 4096 */
#define BR_PERSIST_PRESEQ  1u        /**< NVS br/preseq, block 64 */

typedef struct {
    uint16_t          unit_id;       /**< 0x0010..0xFEFF (demo 0x0101 / 0x0102 / 0x0103) */
    br_role_t         role;
    uint8_t           node_count;    /**< manifest; BOOT_SPREAD_MS (4.1.1). Bench: 3 */
    uint8_t           seek_ttl;      /**< manifest; default BR_SEEK_TTL_DEFAULT */
    uint16_t          caps;          /**< BR_CAP_*; demo HIGH | LOW | ARQ | AUTH | RELAY */
    bool              auth;          /**< FLAG_AUTH on every frame and required on receive */
    bool              cold_boot;     /**< apply the BOOT_SPREAD_MS holdoff to the first SEEK */
    uint16_t          groups[BR_MAX_GROUPS]; /**< groups to listen on at init (probe) */
    uint8_t           n_groups;
    uint8_t           key_epoch;     /**< E */
    const uint8_t    *net_key;       /**< bench: 32 bytes standing in for K_site (8.2); copied */
    size_t            net_key_len;
    br_transport_t    transports[BR_NODE_MAX_TRANSPORTS];
    uint8_t           n_transports;  /**< 1..BR_NODE_MAX_TRANSPORTS */
    br_app_callbacks_t app;
    uint32_t          txseq_start;   /**< resume value from NVS (3.5); first hop_seq used */
    uint32_t          preseq_start;  /**< resume value from NVS (3.5); first pre_ctr used */
    /**
     * Optional (NULL: counters are not persisted, bench only). Called BEFORE
     * a counter crosses its reserved boundary with the new boundary to
     * store; a non-BR_OK return stops transmission (no nonce reuse, 3.5).
     */
    br_err_t        (*persist)(void *user, uint8_t which, uint32_t reserve_to);
    void             *persist_user;
} br_node_config_t;

/* ------------------------------------------------------------------------- */
/* Node object                                                                */
/* ------------------------------------------------------------------------- */

/** What the pipeline did with one received frame (for traces and tests). */
typedef enum {
    BR_RXV_DROP = 0,          /**< dropped; stat says which counter (BR_STAT_NONE: silent) */
    BR_RXV_DELIVER,           /**< delivered locally (step 7, or 9e for a flood I am in) */
    BR_RXV_FORWARD,           /**< unicast forwarded (10e) */
    BR_RXV_FLOOD_PENDING,     /**< flood copy kept for the jittered rebroadcast (9f) */
    BR_RXV_DELIVER_FLOOD      /**< flood delivered locally and kept for rebroadcast */
} br_rx_action_t;

typedef struct {
    br_rx_action_t action;
    br_stat_id_t   stat;      /**< counter incremented by a drop, else BR_STAT_NONE */
    br_reject_t    reject;    /**< 3.6 reason when the validator rejected */
    uint8_t        type;      /**< header type (0 if unparsed) */
    uint8_t        step;      /**< 11.4 pipeline step that decided (1..10), 0 if none */
} br_rx_verdict_t;

/** The node. Treat every field as private; inspect through the accessors. */
typedef struct {
    uint32_t           magic;        /**< set by br_node_init() */
    br_node_config_t   cfg;          /**< copy; cfg.net_key points into keys.k_site */
    br_crypto_t        crypto;
    br_keyring_t       keys;
    br_tables_t        tables;
    br_stats_t         stats;
    br_sender_t        senders[BR_TX_SESSIONS];
    br_probe_t         probe;
    uint32_t           txseq;        /**< next hop_seq */
    uint32_t           txseq_reserved;
    uint32_t           preseq;       /**< next pre_ctr */
    uint32_t           preseq_reserved;
    uint64_t           boot_us;      /**< now_us at init */
    uint64_t           first_seek_not_before_us; /**< BOOT_SPREAD_MS holdoff */
    uint8_t            scratch[BR_MAX_FRAME_MESH]; /**< TX build buffer */
} br_node_t;

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ------------------------------------------------------------------------- */

/**
 * Initialise a node in caller storage: copy cfg, init crypto (the only heap
 * use), derive the bench keyring from net_key at key_epoch, clear the
 * tables, start listening on cfg->groups.
 *
 * @param node       Storage (static).
 * @param node_size  sizeof(br_node_t) as compiled by the caller; refused if
 *                   it differs from the library's (catches mismatched BR_*
 *                   size overrides between translation units).
 * @param cfg        Configuration; copied.
 * @return BR_OK; BR_ERR_ARG (NULL, size mismatch, unit_id not a unit ID,
 *         n_transports 0 or too large, a transport without send(), more
 *         than 8 groups, net_key_len != 32); BR_ERR_STATE if br_platform_set()
 *         has not run; BR_ERR_NO_MEM / BR_ERR_CRYPTO from br_crypto_init().
 * @spec Appendix B br_init / br_add_transport / br_listen, 8.2, 3.5
 */
br_err_t br_node_init(br_node_t *node, size_t node_size, const br_node_config_t *cfg);

/** Wipe keys and free the crypto context. Safe on a zeroed node and NULL. @spec Appendix B */
void br_node_deinit(br_node_t *node);

/* ------------------------------------------------------------------------- */
/* Driving the node (protocol task)                                           */
/* ------------------------------------------------------------------------- */

/**
 * Run the 11.4 receive pipeline on one frame from transport `link`:
 * 1 per-hop decode (RS / COBS on RAW links, CRC), 2-3 br_frame_validate()
 * (endpoint rows when the frame is for me), 4 AUTH policy, 5 hop_tag under
 * the held epoch + br_hop_seq_check() against the link table, 6 learn link
 * (prev_hop, link) -> prev_hop_hint->addr, 7 local delivery to the session
 * layer, 8 overheard drop, 9a-9f floods (echo, dedup, ORIGIN, budget,
 * deliver, jittered rebroadcast), 10a-10e unicast forwarding.
 * The bench allowlist is NOT applied here (br_transport_admit(), adapter).
 *
 * @param node           Initialised node.
 * @param frame          Received bytes (len <= max_frame of the link).
 * @param len            Byte count.
 * @param link           Transport index (0..n_transports - 1).
 * @param prev_hop_hint  Carrier source address and RSSI (may be NULL on
 *                       carriers without addresses: nothing is learnt).
 * @param verdict_out    Optional (may be NULL): what happened.
 * @return BR_OK whatever the verdict (drops are counted, not errors);
 *         BR_ERR_ARG on NULL node / frame or a bad link index;
 *         BR_ERR_STATE if not initialised.
 * @spec 11.4, 3.6, 8.3, 8.4, 11.5
 */
br_err_t br_node_rx(br_node_t *node, const uint8_t *frame, size_t len, uint8_t link,
                    const br_rx_meta_t *prev_hop_hint, br_rx_verdict_t *verdict_out);

/**
 * Carrier delivery report for a unicast send on a mac_retry transport
 * (11.6): feeds the link failure count; LINK_FAIL_MAX failures delete the
 * link and its routes (BR_EVT_LINK_FAIL).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE.
 * @spec 11.6
 */
br_err_t br_node_tx_status(br_node_t *node, uint8_t link, const uint8_t *addr, uint8_t addr_len,
                           bool delivered);

/**
 * Run everything due at now_us (session timers, ARQ, delayed HELLO,
 * jittered flood copies, forwarding queue, table expiry) and report when to
 * call again. May be called at any time, any number of times (idempotent
 * when nothing is due); the simulator calls it after every event it feeds.
 *
 * @param now_us             Same clock as br_platform now_us.
 * @param next_deadline_out  Receives the absolute time of the next due
 *                           work, or BR_NEVER_US. Always written (stubs
 *                           write BR_NEVER_US).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE.
 * @spec 4.1, 4.2, 7, 11.5, 11.6
 */
br_err_t br_node_tick(br_node_t *node, uint64_t now_us, uint64_t *next_deadline_out);

/** Count one frame the port's RX queue had to drop (section 7 rx_queue_drop). @spec 7 (queues), Appendix B br_stats_t */
br_err_t br_node_count_rx_queue_drop(br_node_t *node);

/**
 * Count one frame a segmenting transport adapter (nRF24, C.5) could not
 * reassemble: the spec's `seg_fail` counter (Appendix B br_stats_t). Like
 * rx_queue_drop the event happens outside the core (in the adapter), so the
 * adapter reports it; one call per dropped frame (not per orphan segment,
 * SPEC-NOTES N59). NULL or an uninitialised node is a silent no-op (void:
 * adapters call it from their pump with nothing to do on failure).
 * @spec Appendix B br_stats_t seg_fail, C.5
 */
void br_node_count_seg_fail(br_node_t *node);

/* ------------------------------------------------------------------------- */
/* Application API                                                            */
/* ------------------------------------------------------------------------- */

/**
 * Sender: start a session toward dst_id (group or unit). Asynchronous; the
 * result arrives through on_seek_result / on_state. Seeking continues with
 * the 4.1.8 backoff until success or br_node_close().
 * @param s_out  Receives the session handle (0..BR_TX_SESSIONS - 1).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_BUSY if every sender slot is in use.
 * @spec Appendix B br_seek, 4.1.1
 */
br_err_t br_node_seek(br_node_t *node, uint16_t dst_id, br_session_t *s_out);

/**
 * Probe: replace the subscribed groups (Appendix B br_listen).
 * @return BR_OK; BR_ERR_ARG.
 * @spec 4.1.2
 */
br_err_t br_node_listen(br_node_t *node, const uint16_t *groups, uint8_t n_groups);

/**
 * Sender: set the resolution mode (br_sender_set_mode()). Demo: HIGH, one
 * digital channel of 1 line, arq 1, fec_m 0, keepalive 5000.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE.
 * @spec 6.1
 */
br_err_t br_node_set_mode(br_node_t *node, br_session_t s, const br_mode_t *mode);

/**
 * Sender: send samples as one DATA frame (br_sender_send_samples()).
 * Demo: one sample, vals[0].lines = button state (0 / 1), ack_req true.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE (not STREAMING); BR_ERR_TOO_BIG.
 * @spec 6.2, 7
 */
br_err_t br_node_send_sample(br_node_t *node, br_session_t s, const br_value_t *vals,
                             uint8_t n_samples, uint32_t t_first_us, uint8_t status, bool ack_req);

/**
 * Close a session (sender: CLOSE + CLOSED; probe record: CLOSE + LISTENING).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE.
 * @spec 4.2, 5
 */
br_err_t br_node_close(br_node_t *node, br_session_t s, uint8_t reason);

/* ------------------------------------------------------------------------- */
/* Inspection (tests, simulator, MGMT later)                                  */
/* ------------------------------------------------------------------------- */

/** Copy the counters. @return BR_OK; BR_ERR_ARG; BR_ERR_STATE. @spec Appendix B br_stats_t, 11.10 section 1 */
br_err_t br_node_get_stats(const br_node_t *node, br_stats_t *out);

/** Read-only view of the mesh tables. @return BR_OK; BR_ERR_ARG; BR_ERR_STATE. @spec 11.9 */
br_err_t br_node_get_tables(const br_node_t *node, const br_tables_t **out);

/**
 * Copy the route to dst_id.
 * @param found_out  false if there is no live route.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE.
 * @spec 11.4
 */
br_err_t br_node_route(const br_node_t *node, uint16_t dst_id, br_route_entry_t *out, bool *found_out);

/**
 * State of a session handle (br_snd_state_t for sender handles,
 * br_prb_state_t for probe handles).
 * @return BR_OK; BR_ERR_ARG (bad handle); BR_ERR_STATE.
 * @spec 4
 */
br_err_t br_node_session_state(const br_node_t *node, br_session_t s, uint8_t *state_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_NODE_H */
