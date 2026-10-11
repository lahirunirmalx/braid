// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_session.h - sessions: key schedule, control-message codecs, replay
 * window, sender and probe state machines, app callbacks (spec 4, 4.1, 4.2,
 * 5, 6.1, 7, 8.2-8.4).
 *
 * Layering:
 *   br_node.c   mesh pipeline (11.4), tables, hop_tag, CRC, transports
 *      |  admitted frame for me (step 7 / 9e)      ^ e2e frame to send
 *      v                                           |
 *   br_session  CCM, transcript keys, handshake, MODE, ARQ, keepalive
 *      |  br_app_callbacks_t
 *      v
 *   application
 *
 * The session layer receives frames that passed 3.6 Length / Header /
 * Version and the hop_tag + hop_seq checks (pipeline step 5) and does
 * everything end to end: CCM tag (3.6 CCM row), pre_ctr / index freshness
 * (8.4), matching (8.4 pre-session rules), state changes. It sends by
 * building a complete e2e frame (br_frame_encode() with zero per-hop fields
 * and a zero hop_tag) and handing it to br_sess_env_t.send; the node fills
 * prev_hop, next_hop, ttl_hops, hop_seq, path_mtu / path_cost (SEEK),
 * hop_tag and CRC (11.4 step 10e / 9f). The ARQ keeps that e2e frame for
 * byte-identical retransmission (section 7).
 *
 * Phase 1b demo path: SEEK -> HELLO -> BIND -> BIND_ACK -> MODE / MODE_ACK ->
 * DATA / ACK (ARQ, reorder) -> PING / PONG, CLOSE, session timeouts. Not in
 * this header: PARK / RESUME / leaves (4.4, BR_SND_PARKED / BR_PRB_PARKED are
 * reserved values only), group FEC in sessions, MGMT, BULK data, key rotation
 * (one key epoch; E_old == E_new).
 *
 * Static allocation: every struct below lives inside br_node_t. No heap.
 */
#ifndef BRAID_BR_SESSION_H
#define BRAID_BR_SESSION_H

#include "braid/br_types.h"
#include "braid/br_frame.h"
#include "braid/br_crypto.h"
#include "braid/br_sample.h"
#include "braid/br_tables.h"
#include "braid/br_arq.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Constants (section 9, 4.1, 4.2)                                            */
/* ------------------------------------------------------------------------- */

#define BR_HELLO_WINDOW_MS        50u
#define BR_HELLO_CANDIDATES        4u   /**< fallback HELLOs kept by the sender (4.1.4) */
#define BR_PROBE_OFFERS_MAX        4u   /**< OFFERED entries per probe, one per src_id (4.1.2) */
#define BR_BIND_RETRY_MS          50u
#define BR_BIND_RETRIES            3u
#define BR_RESEEK_JITTER_MS     1000u
#define BR_PENALTY_MS          60000u
#define BR_PENALTY_ENTRIES         4u   /**< first hops remembered (4.2); sizing is ours */
#define BR_FULL_CAP_S           3600u
#define BR_SEEK_HISTORY            5u   /**< last SEEK payloads kept by pre_ctr (4.1.1) */
#define BR_SESSION_IDS_KEPT        8u   /**< last session_ids not reused (4.1.11) */
#define BR_SEEK_NO_PROBE_AFTER     5u   /**< BR_EVT_NO_PROBE after the 5th attempt (4.1.8) */
#define BR_CLOSE_UNKNOWN_GAP_MS 1000u   /**< bench: CLOSE(2) at most once per s per peer (4.1.13) */

/** Session record / stream counts for one node (4.1.12). Same override rule as br_tables.h. */
#ifndef BR_TX_SESSIONS
#define BR_TX_SESSIONS             1u   /**< sessions this node originates as sender (each has an ARQ window) */
#endif
#ifndef BR_RX_RECORDS
#define BR_RX_RECORDS              4u   /**< probe session records (spec default 32; demo 4) */
#endif
#ifndef BR_RX_STREAMS
#define BR_RX_STREAMS              2u   /**< probe stream buffers (spec default 4; demo 2) */
#endif

/** HELLO status (section 5). */
#define BR_HELLO_STATUS_OK         0u
#define BR_HELLO_STATUS_FULL       1u
/** BIND_NAK reason (section 5). */
#define BR_BIND_NAK_BUSY           1u
#define BR_BIND_NAK_CAPS           2u
/** CLOSE reason (section 5). */
#define BR_CLOSE_NORMAL            0u
#define BR_CLOSE_TIMEOUT           1u
#define BR_CLOSE_UNKNOWN_SESSION   2u
#define BR_CLOSE_APPLICATION       3u
#define BR_CLOSE_AUTH_FAILURE      4u
#define BR_CLOSE_REBOOT            5u
#define BR_CLOSE_PARK              6u   /**< reserved in phase 1b */
#define BR_CLOSE_BULK_COMPLETE     7u

/** Events for br_app_callbacks_t.on_event (Appendix B names). */
#define BR_EVT_NO_PROBE            1u   /**< arg: dst_id; after the 5th SEEK attempt */
#define BR_EVT_ID_COLLISION        2u   /**< arg: offending unit_id (11.5) */
#define BR_EVT_LINK_FAIL           3u   /**< arg: (transport << 16) | neighbour unit_id (11.6) */

/* ------------------------------------------------------------------------- */
/* Timer formulas (4.1.8-10, 4.2, 11.7). Real, not stubs: pure arithmetic.    */
/* ------------------------------------------------------------------------- */

/** BIND_RETRY(hops) = max(BIND_RETRY_MS, hops x HOP_DELAY_MS): 60 / 120 / 240 / 480 at 1 / 2 / 4 / 8. */
static inline uint32_t br_bind_retry_ms(uint8_t hops)
{
    uint32_t h = (uint32_t)hops * BR_HOP_DELAY_MS;
    return h > BR_BIND_RETRY_MS ? h : BR_BIND_RETRY_MS;
}

/**
 * BIND_TIMEOUT(hops) = HELLO_WINDOW_MS + (BIND_RETRIES + 2) x BIND_RETRY(hops)
 * + 2 x hops x HOP_DELAY_MS: 470 / 890 / 1730 / 3410 at 1 / 2 / 4 / 8 (4.1.10).
 * IR edge links multiply by IR_TIME_SCALE (not in phase 1b).
 */
static inline uint32_t br_bind_timeout_ms(uint8_t hops)
{
    return BR_HELLO_WINDOW_MS + (BR_BIND_RETRIES + 2u) * br_bind_retry_ms(hops)
           + 2u * (uint32_t)hops * BR_HOP_DELAY_MS;
}

/** SEEK_BASE_MS = HELLO_WINDOW_MS + 2 x seek_ttl x HOP_DELAY_MS (530 at ttl 4). */
static inline uint32_t br_seek_base_ms(uint8_t seek_ttl)
{
    return BR_HELLO_WINDOW_MS + 2u * (uint32_t)seek_ttl * BR_HOP_DELAY_MS;
}

/** SEEK_TIMEOUT jitter bound: min(60000, 600 x 2^n) (4.1.8). */
static inline uint32_t br_seek_jitter_max_ms(uint8_t n)
{
    return (n >= 7u) ? 60000u : ((600u << n) < 60000u ? (600u << n) : 60000u);
}

/** SESSION_TIMEOUT = max(4 x keepalive_ms, 8 x SRTT) (4.2). */
static inline uint32_t br_session_timeout_ms(uint16_t keepalive_ms, const br_rtt_t *rtt)
{
    uint32_t a = 4u * (uint32_t)keepalive_ms;
    uint32_t b = (rtt != NULL && rtt->valid && rtt->srtt_ms < UINT32_MAX / 8u) ? 8u * rtt->srtt_ms : 0u;
    return a > b ? a : b;
}

/* ------------------------------------------------------------------------- */
/* Key schedule (8.2)                                                         */
/* ------------------------------------------------------------------------- */

#define BR_KEY_LEN               32u   /**< K_site, K_mesh, K_hop, K_pair, PRK, T0, T */

/**
 * Keys a node holds for one epoch (phase 1b: one epoch, no rotation).
 * Bench profile (8.2 line 808, 12.1): k_site is br/net_key standing in for
 * K_site and everything is derived locally. Field builds MUST NOT hold
 * K_site; a field keystore is out of scope for phase 1b.
 */
typedef struct {
    uint8_t epoch;                    /**< key_epoch E (E_old == E_new) */
    bool    ready;
    uint8_t k_site[BR_KEY_LEN];       /**< bench only: net_key */
    uint8_t k_mesh[BR_KEY_LEN];       /**< K_mesh(E) */
    uint8_t k_hop[BR_HOP_KEY_LEN];    /**< K_hop(E): hop_tag key */
    uint8_t ke_mesh[BR_AES_KEY_LEN];  /**< Ke_mesh(E): SEEK CCM key */
} br_keyring_t;

/**
 * Bench keyring: k_site = net_key; K_mesh(E) = HKDF(IKM = K_site,
 * salt "Braid-mesh", info E u8, 32); K_hop(E) = Expand(Extract(
 * "Braid-v1", K_mesh(E)), "hop", 32); Ke_mesh(E) = Expand(..., "mesh-enc", 16).
 * Vectors: A.6 (BRV_A6_K_SITE -> BRV_A6_K_MESH_1, BRV_A6_K_HOP_1,
 * BRV_A6_KE_MESH_1 at E = 1).
 *
 * @param c        Initialised crypto context.
 * @param kr       Output keyring.
 * @param net_key  32 bytes.
 * @param epoch    key_epoch.
 * @return BR_OK; BR_ERR_ARG on NULL or net_key_len != 32; BR_ERR_STATE /
 *         BR_ERR_CRYPTO from br_crypto.h.
 * @spec 8.2, 12.1, A.6
 */
br_err_t br_keyring_init_bench(br_crypto_t *c, br_keyring_t *kr, const uint8_t *net_key,
                               size_t net_key_len, uint8_t epoch);

/** Wipe a keyring (br_secure_zero). NULL is a no-op. @spec 8.2, 12.1 (Logging: no key bytes) */
void br_keyring_wipe(br_keyring_t *kr);

/**
 * K_pair(A, B, E) = HKDF(K_site, salt "Braid-pair",
 * info min(A,B) u16 || max(A,B) u16 || E u8, 32), then
 * PRK = Extract(salt "Braid-v1", IKM = K_pair). A.6:
 * BRV_A6_K_PAIR_0042_1234_1, BRV_A6_PRK.
 *
 * @param prk_out  Receives the 32-byte PRK for (a, b) at kr->epoch.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE (keyring not ready); BR_ERR_CRYPTO.
 * @spec 8.2, A.6
 */
br_err_t br_ks_pair_prk(br_crypto_t *c, const br_keyring_t *kr, uint16_t a, uint16_t b,
                        uint8_t prk_out[BR_KEY_LEN]);

/**
 * T0 = SHA-256(SEEK e2e header (10) || SEEK payload (18)) of the copy named
 * by seek_ctr (8.2). The e2e header is bytes 0..5 || session_id || seq ||
 * len of that SEEK (br_ccm_aad() layout without ctr_hi).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_CRYPTO.
 * @spec 8.2, A.9
 */
br_err_t br_ks_t0(const uint8_t seek_e2e[BR_E2E_HDR_LEN], const uint8_t seek_payload[BR_LEN_SEEK],
                  uint8_t t0_out[BR_KEY_LEN]);

/**
 * T = SHA-256(SEEK e2e || SEEK payload || HELLO e2e header (10) || HELLO
 * plaintext payload (28 = clear pre_ctr || 24-byte secret, SPEC-NOTES N17)).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_CRYPTO.
 * @spec 8.2, A.9 (BRV_A9_T)
 */
br_err_t br_ks_t(const uint8_t seek_e2e[BR_E2E_HDR_LEN], const uint8_t seek_payload[BR_LEN_SEEK],
                 const uint8_t hello_e2e[BR_E2E_HDR_LEN], const uint8_t hello_plain[BR_LEN_HELLO],
                 uint8_t t_out[BR_KEY_LEN]);

/** Ke_hello = Expand(PRK, "hello" || S u16 || P u16 || T0, 16). @spec 8.2, A.9 */
br_err_t br_ks_hello(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                     const uint8_t t0[BR_KEY_LEN], uint8_t ke_out[BR_AES_KEY_LEN]);

/** Ke_hs = Expand(PRK, "hs" || S || P || T, 16). @spec 8.2, A.9 */
br_err_t br_ks_hs(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                  const uint8_t t[BR_KEY_LEN], uint8_t ke_out[BR_AES_KEY_LEN]);

/**
 * Ke_s2p = Expand(PRK, "s2p" || S || P || session_id u8 || T, 16); Ke_p2s
 * the same with "p2s".
 * @spec 8.2, A.9, A.10
 */
br_err_t br_ks_session(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                       uint8_t session_id, const uint8_t t[BR_KEY_LEN],
                       uint8_t ke_s2p_out[BR_AES_KEY_LEN], uint8_t ke_p2s_out[BR_AES_KEY_LEN]);

/* ------------------------------------------------------------------------- */
/* Control message payloads (section 5), plaintext form                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t pre_ctr, nonce_s;
    uint16_t caps, max_frame;
    uint8_t  key_epoch, proto_minor;
    uint32_t fw_build;
} br_msg_seek_t;

typedef struct {
    uint32_t pre_ctr, seek_ctr, nonce_s, nonce_p;
    uint16_t caps, max_frame;
    int8_t   rssi;                    /**< -128 unknown */
    uint8_t  status;                  /**< BR_HELLO_STATUS_* */
    uint8_t  path_cost, proto_minor;
    uint32_t fw_build;
} br_msg_hello_t;

typedef struct {
    uint32_t pre_ctr, hello_ctr, nonce_s, nonce_p;
    uint8_t  session_id;
} br_msg_bind_t;

typedef struct { uint32_t pre_ctr, nonce_s, nonce_p; } br_msg_bind_ack_t;
typedef struct { uint32_t pre_ctr, nonce_s; uint8_t reason; } br_msg_bind_nak_t;
typedef struct { uint8_t config_id, status; } br_msg_mode_ack_t;
typedef struct { uint16_t cum_seq; uint32_t bitmap; } br_msg_ack_t;
typedef struct { uint32_t t_tx_us; } br_msg_ping_t;
typedef struct { uint32_t t_echo_us, t_local_us; } br_msg_pong_t;
typedef struct { uint8_t reason; uint16_t park_s; } br_msg_close_t;

/** Fixed-length control message (MODE and DATA are in br_sample.h). */
typedef struct {
    uint8_t type;                     /**< br_msg_type_t */
    union {
        br_msg_seek_t     seek;
        br_msg_hello_t    hello;
        br_msg_bind_t     bind;
        br_msg_bind_ack_t bind_ack;
        br_msg_bind_nak_t bind_nak;
        br_msg_mode_ack_t mode_ack;
        br_msg_ack_t      ack;
        br_msg_ping_t     ping;
        br_msg_pong_t     pong;
        br_msg_close_t    close;
    } u;
} br_msg_t;

/**
 * Serialise a control message to its plaintext payload (clear pre_ctr
 * first where section 5 marks P). Lengths: SEEK 18, HELLO 28, BIND 17,
 * BIND_ACK 12, BIND_NAK 9, MODE_ACK 2, ACK 6, PING 4, PONG 8, CLOSE 3.
 *
 * @return BR_OK; BR_ERR_ARG on NULL or a type not listed above;
 *         BR_ERR_TOO_BIG if cap is short.
 * @spec 5, A.2, A.9
 */
br_err_t br_msg_encode(const br_msg_t *msg, uint8_t *out, size_t cap, size_t *written);

/**
 * Parse a plaintext control payload of the given type.
 * @return BR_OK; BR_ERR_ARG on NULL or an unlisted type; BR_ERR_DECODE if
 *         len is not the exact section 5 length.
 * @spec 5
 */
br_err_t br_msg_decode(uint8_t type, const uint8_t *in, size_t len, br_msg_t *msg_out);

/* ------------------------------------------------------------------------- */
/* Session index and replay window (3.5, 8.4)                                 */
/* ------------------------------------------------------------------------- */

/** Transmit index: (roc << 16) | seq, from 0 at BIND_ACK, +1 per frame of any type. */
typedef struct {
    uint32_t roc;
    uint16_t next_seq;
    uint16_t reserved;
} br_tx_index_t;

/**
 * Take the next transmit index. Retransmitted DATA does not call this
 * (it reuses its index, section 7).
 * @return BR_OK; BR_ERR_ARG on NULL; BR_ERR_TOO_BIG when the 48-bit index
 *         is exhausted (session must close).
 * @spec 3.5
 */
br_err_t br_tx_index_next(br_tx_index_t *tx, uint16_t *seq_out, uint32_t *roc_out);

/** Receive side: SRTP ROC estimate state + 64-entry seen-bitmap (8.4). */
typedef struct {
    uint64_t highest;                 /**< highest accepted 48-bit index */
    uint64_t seen;                    /**< bit i: index highest - i accepted (bit 0 = highest) */
    uint16_t s_l;                     /**< highest seq received (low 16 of highest) */
    uint8_t  any;                     /**< nothing accepted yet when 0 */
    uint8_t  reserved;
} br_rx_index_t;

/**
 * Guess the 48-bit index of a received seq (br_roc_estimate() on s_l / roc)
 * and check the replay window: fresh iff newer than highest, or within 64
 * below it and unseen. Nothing is recorded until br_rx_index_commit(),
 * which the caller runs only after the CCM tag verified under the guessed
 * ROC (A.10).
 *
 * @param roc_out    ROC to put in the nonce.
 * @param fresh_out  false -> replay_dropped.
 * @return BR_OK; BR_ERR_ARG on NULL; BR_ERR_REJECT (index before the
 *         session start) / BR_ERR_TOO_BIG from br_roc_estimate().
 * @spec 3.5, 8.4, A.10
 */
br_err_t br_rx_index_check(const br_rx_index_t *rx, uint16_t seq, uint32_t *roc_out, bool *fresh_out);

/** Record an accepted index ((roc << 16) | seq). @spec 8.4 */
br_err_t br_rx_index_commit(br_rx_index_t *rx, uint16_t seq, uint32_t roc);

/* ------------------------------------------------------------------------- */
/* App interface                                                              */
/* ------------------------------------------------------------------------- */

/**
 * Session handle (Appendix B br_session_t): sender sessions are 0 ..
 * BR_TX_SESSIONS - 1; probe records are BR_SESSION_PROBE | index.
 */
typedef uint8_t br_session_t;
#define BR_SESSION_PROBE   0x80u
#define BR_SESSION_NONE    0xFFu

/** Sender states (4). PARKED reserved for 4.4. */
typedef enum {
    BR_SND_IDLE = 0, BR_SND_SEEKING, BR_SND_BINDING, BR_SND_CONFIGURING,
    BR_SND_STREAMING, BR_SND_PARKED, BR_SND_CLOSED
} br_snd_state_t;

/** Probe record states (4); OFFERED lives in br_offer_t. PARKED reserved. */
typedef enum {
    BR_PRB_LISTENING = 0, BR_PRB_OFFERED, BR_PRB_BOUND, BR_PRB_STREAMING, BR_PRB_PARKED
} br_prb_state_t;

/** Context of one delivered DATA frame (probe side). */
typedef struct {
    br_session_t  session;
    uint16_t      src_id;             /**< sender unit ID */
    uint8_t       session_id;
    uint8_t       hops;               /**< links traversed = header hops at arrival + 1 (A->B->C: 2) */
    uint16_t      seq;
    uint32_t      roc;
    br_data_hdr_t hdr;
    uint64_t      utc_us;             /**< 0 = no network time (time sync out of scope) */
} br_samples_meta_t;

/**
 * Application callbacks (Appendix B br_callbacks_t, plus a user pointer,
 * hops in the sample context, on_state and on_acked; MGMT / bundle
 * callbacks out of scope). Every pointer may be NULL. All run in the
 * protocol task (inside br_node_rx() / br_node_tick() / API calls); they
 * must not call back into the same br_node_t except the br_node_send_* /
 * br_node_set_mode / br_node_close entry points.
 */
typedef struct {
    void *user;
    /** Sender: SEEK finished (BR_OK with the probe that bound, BR_ERR_NO_PROBE as event). */
    void (*on_seek_result)(void *user, br_session_t s, br_err_t result, uint16_t probe_id, uint8_t hops);
    /** Probe: a sender bound (BIND accepted, BIND_ACK sent). */
    void (*on_bound)(void *user, br_session_t s, uint16_t peer_id);
    /** Both: a mode became active (sender: MODE_ACK 0; probe: MODE accepted). */
    void (*on_mode)(void *user, br_session_t s, const br_mode_t *mode);
    /** Probe: in-order DATA samples (encoded; decode with br_sample_decode()). */
    void (*on_samples)(void *user, const br_samples_meta_t *meta, const br_mode_t *mode,
                       const uint8_t *samples, size_t samples_len);
    /** Both: seqs given up (probe: reorder expiry, or control holes below the session's first MODE,
     *  SPEC-NOTES N46; sender: ARQ retries exhausted). */
    void (*on_gap)(void *user, br_session_t s, uint16_t first_seq, uint16_t count);
    /** Sender: a DATA seq was acknowledged by the probe. */
    void (*on_acked)(void *user, br_session_t s, uint16_t seq);
    /** Both: session closed (CLOSE received or sent, or timeout). */
    void (*on_closed)(void *user, br_session_t s, uint8_t reason);
    /** Both: state change (br_snd_state_t or br_prb_state_t values). */
    void (*on_state)(void *user, br_session_t s, uint8_t old_state, uint8_t new_state);
    /** BR_EVT_* */
    void (*on_event)(void *user, uint16_t event, uint32_t arg);
} br_app_callbacks_t;

/* ------------------------------------------------------------------------- */
/* Environment the node gives the session layer                               */
/* ------------------------------------------------------------------------- */

/** An admitted frame addressed to this node (pipeline step 7 or 9e delivery). */
typedef struct {
    const uint8_t         *buf;       /**< whole frame as received (CRC checked) */
    size_t                 len;
    const br_frame_view_t *view;      /**< layout from br_frame_validate() */
    uint8_t                transport; /**< arrival transport index */
    uint8_t                hops;      /**< view->hdr.hops + 1 (links traversed) */
    uint8_t                link_cost; /**< cost of the arrival link (11.2) */
    int8_t                 rssi;      /**< BR_RSSI_UNKNOWN if none */
    uint16_t               prev_hop;  /**< view->hdr.prev_hop */
} br_rx_frame_t;

typedef struct {
    void               *user;         /**< the br_node_t */
    uint16_t            self_id;
    uint16_t            caps;         /**< own caps (BR_CAP_*) */
    uint16_t            own_mtu;      /**< own max_frame - rs_nsym of the mesh transport (11.3) */
    uint8_t             seek_ttl;
    uint8_t             node_count;   /**< BOOT_SPREAD_MS = 600 x node_count */
    bool                auth;         /**< FLAG_AUTH on every frame (bench demo: true) */
    uint32_t            now_ms;
    br_crypto_t        *crypto;
    const br_keyring_t *keys;
    const br_app_callbacks_t *app;
    br_stats_t         *stats;
    /** Send a complete e2e frame (see file header). flood: SEEK (ttl = seek_ttl). */
    br_err_t (*send)(void *user, const uint8_t *frame, size_t len, bool flood);
    /** Allocate the next preseq value (3.5; persisted in blocks of 64 by the node). */
    br_err_t (*next_pre_ctr)(void *user, uint32_t *pre_ctr_out);
    /** Nonce material (4.1.14 hashes it; the node supplies br_platform random_bytes). */
    br_err_t (*random)(void *user, uint8_t *buf, size_t len);
} br_sess_env_t;

/* ------------------------------------------------------------------------- */
/* Sender (4.1 rules 1, 4, 5, 6, 8, 9, 11; 4.2; 6.1; 7)                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t pre_ctr;
    uint8_t  payload[BR_LEN_SEEK];    /**< as sent (clear) */
    uint8_t  used;
    uint8_t  reserved[1];
} br_seek_copy_t;

/** A received HELLO kept as winner or fallback (4.1.4). */
typedef struct {
    uint16_t probe_id;
    uint16_t first_hop;               /**< prev_hop of the HELLO (penalty key, 4.2) */
    uint8_t  transport;
    uint8_t  hops;
    uint8_t  status;
    uint8_t  used;
    uint8_t  seek_idx;                /**< index into br_sender_t.seeks of seek_ctr */
    uint8_t  reserved[3];
    uint32_t hello_ctr;
    uint32_t rx_ms;
    uint8_t  hello_e2e[BR_E2E_HDR_LEN];
    uint8_t  hello_plain[BR_LEN_HELLO];
} br_hello_cand_t;

typedef struct {
    uint16_t first_hop;
    uint8_t  count;                   /**< timeouts in the 10 min window */
    uint8_t  used;
    uint32_t until_ms;
    uint32_t window_start_ms;
} br_penalty_t;

/** One sender session (4: IDLE -> SEEKING -> BINDING -> CONFIGURING -> STREAMING -> CLOSED). */
typedef struct {
    uint8_t         state;            /**< br_snd_state_t */
    uint8_t         session_id;       /**< 1..255 */
    uint8_t         hops;             /**< route hops to the probe (from its HELLO) */
    uint8_t         seek_attempts;    /**< n of SEEK_TIMEOUT(n) */
    uint8_t         full_n;           /**< consecutive all-FULL results (4.1.4) */
    uint8_t         bind_tries;
    uint8_t         cand_cur;         /**< candidate being bound */
    uint8_t         ack_req_unanswered;
    uint16_t        dst_id;           /**< group or unit SEEKed */
    uint16_t        probe_id;
    uint16_t        max_payload;      /**< session cap: path MTU - header - tags - CRC */
    uint16_t        reserved;
    uint32_t        nonce_s, nonce_p;
    br_seek_copy_t  seeks[BR_SEEK_HISTORY];
    br_hello_cand_t cands[1u + BR_HELLO_CANDIDATES];
    uint8_t         t[BR_KEY_LEN];    /**< transcript of the bound HELLO */
    uint8_t         ke_hs[BR_AES_KEY_LEN];
    uint8_t         ke_s2p[BR_AES_KEY_LEN];
    uint8_t         ke_p2s[BR_AES_KEY_LEN];
    br_tx_index_t   tx;
    br_rx_index_t   rx;
    br_mode_t       mode_active;      /**< acknowledged by MODE_ACK */
    br_mode_t       mode_pending;     /**< sent, awaiting MODE_ACK */
    uint8_t         mode_pending_valid;
    uint8_t         recent_ids_n;
    uint8_t         recent_ids[BR_SESSION_IDS_KEPT];
    br_penalty_t    penalty[BR_PENALTY_ENTRIES];
    br_rtt_t        rtt;
    uint32_t        t_deadline_ms;    /**< state timer (SEEK_TIMEOUT, BIND_RETRY, MODE_RETRY) */
    uint32_t        t_bind_sent_ms;   /**< seeds SRTT at BIND_ACK (section 7) */
    uint32_t        t_last_ack_ms;    /**< last ACK / PONG (keepalive, SESSION_TIMEOUT) */
    uint32_t        t_last_tx_ms;
    uint32_t        t_ping_ms;
    br_arq_tx_t     arq;
} br_sender_t;

/** Reset to IDLE (keeps recent_ids and penalty). @return BR_OK; BR_ERR_ARG. @spec 4 */
br_err_t br_sender_init(br_sender_t *s);

/**
 * Start seeking dst_id (group or unit; 4.1.1): fresh nonce_s, SEEK flooded
 * under Ke_mesh(E) with caps, max_frame, key_epoch, proto_minor, fw_build;
 * state SEEKING; retries per SEEK_TIMEOUT(n) forever (4.1.8). The first
 * SEEK after a cold boot waits rand(0..BOOT_SPREAD_MS) (4.1.1).
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE unless IDLE / CLOSED.
 * @spec 4.1.1, 4.1.8, 5
 */
br_err_t br_sender_seek(br_sender_t *s, br_sess_env_t *env, uint16_t dst_id);

/** Stop seeking / close without CLOSE frame and return to IDLE. @spec Appendix B br_seek_cancel */
br_err_t br_sender_cancel(br_sender_t *s, br_sess_env_t *env);

/**
 * Feed an admitted frame addressed to this sender: HELLO (try the kept SEEK
 * copies, 4.1.4 selection, BIND at once), BIND_ACK (session starts, SRTT
 * seeded, MODE sent), BIND_NAK (next candidate, 4.1.6), MODE_ACK, ACK (ARQ,
 * RTT), PONG, CLOSE.
 *
 * @param drop_out  Receives the counter a drop increments (auth_fail,
 *                  replay_dropped, ...) or BR_STAT_NONE.
 * @return BR_OK (consumed or dropped and counted); BR_ERR_REJECT if the
 *         frame does not belong to this sender (caller tries the next one);
 *         BR_ERR_ARG on NULL.
 * @spec 4.1, 4.2, 5, 6.1, 7, 8.3, 8.4
 */
br_err_t br_sender_rx(br_sender_t *s, br_sess_env_t *env, const br_rx_frame_t *f,
                      br_stat_id_t *drop_out);

/**
 * Set the resolution mode (6.1): config_id is assigned here (increments,
 * wraps to 1). Sent at once if STREAMING / CONFIGURING, else after
 * BIND_ACK; resent every RTO until MODE_ACK; DATA keeps the old config_id
 * until then.
 * @return BR_OK; BR_ERR_ARG (NULL, or br_mode_check() status != 0 against
 *         the session MTU once known); BR_ERR_STATE if IDLE / CLOSED.
 * @spec 6.1, 4.2 (MODE_RETRY)
 */
br_err_t br_sender_set_mode(br_sender_t *s, br_sess_env_t *env, const br_mode_t *mode);

/**
 * Send samples as one DATA frame (6.2) under the active mode; ack_req sets
 * FLAG_ACK_REQ. With arq 1 the frame enters the ARQ window.
 * @param vals  n_samples x ch_count values, sample-major.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_STATE unless STREAMING with an active
 *         mode; BR_ERR_TOO_BIG if the samples do not fit max_payload.
 * @spec 6.2, 7
 */
br_err_t br_sender_send_samples(br_sender_t *s, br_sess_env_t *env, const br_value_t *vals,
                                uint8_t n_samples, uint32_t t_first_us, uint8_t status, bool ack_req);

/** Send CLOSE(reason) and go CLOSED (4.2: CLOSE is not acknowledged). @spec 4.2, 5 */
br_err_t br_sender_close(br_sender_t *s, br_sess_env_t *env, uint8_t reason);

/**
 * Run due timers: SEEK_TIMEOUT, BIND_RETRY / candidate fallback, MODE_RETRY,
 * ARQ retransmission and gaps, PING after keepalive_ms without ACK,
 * SESSION_TIMEOUT (CLOSE twice, penalty, re-SEEK after
 * rand(0..RESEEK_JITTER_MS)).
 * @param next_deadline_out  Receives the next time (ms) anything is due, or
 *                           now + 2^30 if nothing is.
 * @return BR_OK; BR_ERR_ARG.
 * @spec 4.1.8-10, 4.2, 7
 */
br_err_t br_sender_tick(br_sender_t *s, br_sess_env_t *env, uint32_t *next_deadline_out);

/* ------------------------------------------------------------------------- */
/* Probe (4.1 rules 2, 3, 5, 6, 7, 9, 12, 13; 4.2; 6.1; 7)                    */
/* ------------------------------------------------------------------------- */

/** OFFERED entry: one per src_id, PROBE_OFFERS_MAX, oldest replaced (4.1.2). */
typedef struct {
    uint16_t src_id;                  /**< 0 = free */
    uint16_t prev_hop;                /**< first hop of the chosen SEEK copy */
    uint8_t  transport;
    uint8_t  hops;                    /**< SEEK header hops + 1 */
    uint8_t  cost;                    /**< path_cost of the chosen copy as received; sent in HELLO (SPEC-NOTES N32, A.9) */
    uint8_t  hello_sent;
    uint16_t sender_caps;
    uint16_t path_mtu;                /**< of the chosen copy */
    uint32_t nonce_s, nonce_p;
    uint32_t seek_ctr;                /**< pre_ctr of the chosen copy */
    uint32_t hello_ctr;               /**< pre_ctr of our HELLO */
    uint32_t hello_due_ms;            /**< end of the rand(0..HELLO_WINDOW_MS) delay */
    uint32_t expiry_ms;               /**< BIND_TIMEOUT(hops) after the HELLO */
    uint8_t  seek_e2e[BR_E2E_HDR_LEN];
    uint8_t  seek_payload[BR_LEN_SEEK];
    uint8_t  hello_plain[BR_LEN_HELLO];
} br_offer_t;

/** Probe session record (4.1.12; about 600 bytes in the spec's estimate). */
typedef struct {
    uint8_t       state;              /**< br_prb_state_t */
    uint8_t       session_id;
    uint8_t       hops;
    uint8_t       stream;             /**< index into br_probe_t.streams or BR_NO_INDEX */
    uint8_t       cfg_active;         /**< 0 / 1 into cfg[], BR_NO_INDEX before MODE */
    uint8_t       reserved;
    uint16_t      src_id;
    uint16_t      max_payload;
    uint16_t      sender_caps;
    uint32_t      nonce_s, nonce_p, hello_ctr;
    uint8_t       ke_hs[BR_AES_KEY_LEN];
    uint8_t       ke_s2p[BR_AES_KEY_LEN];
    uint8_t       ke_p2s[BR_AES_KEY_LEN];
    br_rx_index_t rx;
    br_tx_index_t tx;
    br_mode_t     cfg[2];             /**< last two configs (6.1) */
    br_rtt_t      rtt;
    uint32_t      last_rx_ms;
    uint32_t      last_tx_ms;
} br_probe_record_t;

typedef struct {
    uint16_t          groups[BR_MAX_GROUPS];
    uint8_t           n_groups;
    uint8_t           listening;
    uint16_t          close_reply_peer;   /**< bench CLOSE(2) rate limit (4.1.13) */
    uint32_t          close_reply_ms;
    br_offer_t        offers[BR_PROBE_OFFERS_MAX];
    br_probe_record_t rec[BR_RX_RECORDS];
    br_arq_rx_t       streams[BR_RX_STREAMS];
    uint8_t           stream_owner[BR_RX_STREAMS]; /**< record index or BR_NO_INDEX */
} br_probe_t;

/** Reset: no groups, no offers, every record LISTENING. @return BR_OK; BR_ERR_ARG. @spec 4 */
br_err_t br_probe_init(br_probe_t *p);

/**
 * Subscribe to groups (and implicitly to this node's own unit ID) and
 * answer SEEKs (Appendix B br_listen).
 * @param n_groups  0..BR_MAX_GROUPS; 0 stops listening.
 * @return BR_OK; BR_ERR_ARG on NULL with n_groups > 0, n_groups > 8, or a
 *         non-group ID.
 * @spec 2, 4.1.2, Appendix B
 */
br_err_t br_probe_listen(br_probe_t *p, const uint16_t *groups, uint8_t n_groups);

/** True if dst_id is one of the subscribed groups. @spec 2, 4.1.2 */
br_err_t br_probe_is_member(const br_probe_t *p, uint16_t dst_id, bool *member_out);

/**
 * Feed an admitted frame for this probe: SEEK (Ke_mesh tag, offer, HELLO
 * scheduled after rand(0..HELLO_WINDOW_MS); same nonce_s with newer pre_ctr
 * resends HELLO, 4.1.8), BIND (match offer, BIND_ACK, record BOUND,
 * idempotent repeat 4.1.9, BIND_NAK 4.1.6), MODE (MODE_ACK, SPEC-NOTES N7),
 * DATA (CCM, replay, ARQ reorder, on_samples), PING (PONG), CLOSE.
 * Unknown (src_id, session_id): dropped and counted; bench profile MAY
 * reply CLOSE(2) once per second per peer (4.1.13).
 *
 * @param drop_out  As for br_sender_rx().
 * @return BR_OK (consumed or dropped and counted); BR_ERR_ARG on NULL.
 * @spec 4.1, 4.2, 5, 6, 7, 8.3, 8.4
 */
br_err_t br_probe_rx(br_probe_t *p, br_sess_env_t *env, const br_rx_frame_t *f,
                     br_stat_id_t *drop_out);

/**
 * Run due timers: delayed HELLOs, OFFERED expiry (BIND_TIMEOUT), ACK
 * (ACK_EVERY / keepalive), reorder expiry (on_gap), SESSION_TIMEOUT (free
 * the record and its stream).
 * @param next_deadline_out  As for br_sender_tick().
 * @return BR_OK; BR_ERR_ARG.
 * @spec 4.1.2, 4.1.7, 4.2, 7
 */
br_err_t br_probe_tick(br_probe_t *p, br_sess_env_t *env, uint32_t *next_deadline_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_SESSION_H */
