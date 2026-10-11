// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_arq.h - selective-repeat ARQ: sender window, receiver reorder buffer,
 * ACK bitmap, RTT / RTO (spec section 7; ACK payload section 5).
 *
 * Sequence space (3.5): one 16-bit seq per session and direction, +1 per
 * frame of ANY type (MODE, DATA, PING, CLOSE ...). The ACK reports that
 * space: cum_seq = highest seq such that every seq up to it is received,
 * recovered or expired from the reorder buffer; bitmap bit i (LSB = bit 0)
 * covers cum_seq + 1 + i, set = received (section 5 ACK row). The sender
 * retransmits only DATA it still holds; other cleared seqs are ignored.
 *
 * Sender (br_arq_tx_t): keeps the last ARQ_WINDOW (24; 4 on leaves) DATA
 * frames exactly as first sent (e2e header, ciphertext and auth_tag), so a
 * retransmission is byte-identical under the same nonce; the caller rebuilds
 * only the per-hop fields, hop_tag and CRC (section 7).
 *
 * Receiver (br_arq_rx_t): one stream buffer per ARQ session (4.1.12). Without
 * group FEC the reorder buffer has 4 slots (section 7: "4 without FEC"); group
 * FEC (fec_k + fec_m slots) is out of scope for phase 1b and is not sized here.
 * Delivery is in seq order; a hole still open after REORDER_MS is reported
 * once through on_gap(first_seq, count) and cum_seq moves past it. A hole
 * the session layer proves to be a lost control frame (below the first
 * MODE, SPEC-NOTES N46) is given up at once the same way.
 *
 * Tail-loss (SPEC ambiguity, see the phase 1b report): a DATA sent with
 * FLAG_ACK_REQ that receives no ACK covering it within RTO is treated as
 * reported missing and retransmitted (up to ARQ_MAX_RETRIES), so a single
 * lost press is recovered without waiting for the keepalive ACK.
 *
 * Pure C11, no heap. Times are uint32_t ms (br_tables.h br_ms_before()).
 */
#ifndef BRAID_BR_ARQ_H
#define BRAID_BR_ARQ_H

#include "braid/br_types.h"
#include "braid/br_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Constants (section 9)                                                      */
/* ------------------------------------------------------------------------- */

#ifndef BR_ARQ_WINDOW
#define BR_ARQ_WINDOW            24u   /**< sender DATA frames kept (non-leaf) */
#endif
#define BR_ARQ_WINDOW_LEAF        4u
#define BR_ARQ_RTO_MS           100u
#define BR_ARQ_MAX_RETRIES        3u
#define BR_ACK_EVERY              8u   /**< probe ACKs every 8 frames (4.2) */
#define BR_REORDER_MS_MIN       500u
#ifndef BR_REORDER_SLOTS
#define BR_REORDER_SLOTS          4u   /**< no group FEC (section 7) */
#endif
#define BR_ACK_BITMAP_BITS       32u

/* ------------------------------------------------------------------------- */
/* RTT / RTO (section 7)                                                      */
/* ------------------------------------------------------------------------- */

/** Smoothed RTT. Seeded by the BIND round trip, then 7/8 SRTT + 1/8 RTT. */
typedef struct {
    uint32_t srtt_ms;
    bool     valid;
} br_rtt_t;

/** Seed (first sample) or update SRTT = 7/8 SRTT + 1/8 sample (section 7). */
static inline void br_rtt_sample(br_rtt_t *r, uint32_t sample_ms)
{
    if (!r->valid) {
        r->srtt_ms = sample_ms;
        r->valid = true;
    } else {
        r->srtt_ms = (uint32_t)(((uint64_t)r->srtt_ms * 7u + sample_ms) / 8u);
    }
}

/** RTO = max(ARQ_RTO_MS, 2 x SRTT); also MODE_RETRY (4.2). */
static inline uint32_t br_rto_ms(const br_rtt_t *r)
{
    uint32_t two = (r->valid && r->srtt_ms < UINT32_MAX / 2u) ? 2u * r->srtt_ms : 0u;
    return two > BR_ARQ_RTO_MS ? two : BR_ARQ_RTO_MS;
}

/** REORDER_MS = max(500, 4 x SRTT). */
static inline uint32_t br_reorder_ms(const br_rtt_t *r)
{
    uint32_t four = (r->valid && r->srtt_ms < UINT32_MAX / 4u) ? 4u * r->srtt_ms : 0u;
    return four > BR_REORDER_MS_MIN ? four : BR_REORDER_MS_MIN;
}

/* ------------------------------------------------------------------------- */
/* Sender window                                                              */
/* ------------------------------------------------------------------------- */

/** One kept DATA frame. */
typedef struct {
    uint8_t  frame[BR_MAX_FRAME_MESH]; /**< as first sent; per-hop bytes are don't-care */
    uint16_t len;
    uint16_t seq;
    uint32_t roc;                      /**< index high part, for the trace / RESUME */
    uint32_t sent_ms;                  /**< last (re)transmission */
    uint8_t  retries;                  /**< retransmissions so far */
    uint8_t  flags;                    /**< BR_ARQ_SLOT_* */
    uint16_t reserved;
} br_arq_tx_slot_t;

#define BR_ARQ_SLOT_USED     0x01u
#define BR_ARQ_SLOT_ACKED    0x02u
#define BR_ARQ_SLOT_ACK_REQ  0x04u  /**< sent with FLAG_ACK_REQ (tail-loss timer applies) */

typedef struct {
    br_arq_tx_slot_t slot[BR_ARQ_WINDOW];
    uint8_t          window;           /**< effective size: 24, or 4 on leaves */
    uint8_t          head;             /**< oldest slot */
    uint8_t          count;
    uint8_t          reserved;
} br_arq_tx_t;

/** What br_arq_tx_poll() asks the caller to do. */
typedef enum {
    BR_ARQ_TX_IDLE = 0,    /**< nothing due */
    BR_ARQ_TX_RESEND,      /**< retransmit *slot_out (retries and sent_ms already updated) */
    BR_ARQ_TX_GAVE_UP      /**< *slot_out exhausted ARQ_MAX_RETRIES: report gap, slot freed */
} br_arq_tx_action_t;

/**
 * Reset the window.
 * @param window  1..BR_ARQ_WINDOW (24 non-leaf, 4 leaf).
 * @return BR_OK; BR_ERR_ARG on NULL or window out of range.
 * @spec 7
 */
br_err_t br_arq_tx_init(br_arq_tx_t *tx, uint8_t window);

/**
 * Keep a freshly sent DATA frame. When the window is full the oldest slot is
 * dropped first; if it was still unacknowledged it is reported through
 * evicted_seq_out (the caller raises on_gap and counts gaps).
 *
 * @param frame            Frame as sent (<= BR_MAX_FRAME_MESH bytes).
 * @param ack_req          Sent with FLAG_ACK_REQ.
 * @param evicted_out      Receives true if an unacked frame was dropped.
 * @param evicted_seq_out  Its seq (valid iff *evicted_out).
 * @return BR_OK; BR_ERR_ARG on NULL or len out of range.
 * @spec 7
 */
br_err_t br_arq_tx_push(br_arq_tx_t *tx, uint16_t seq, uint32_t roc, const uint8_t *frame,
                        uint16_t len, bool ack_req, uint32_t now_ms,
                        bool *evicted_out, uint16_t *evicted_seq_out);

/**
 * Apply an ACK: every kept seq <= cum_seq (serial arithmetic, 3.5) or with
 * its bitmap bit set is acknowledged and freed. A slot whose seq is in the
 * bitmap range with a cleared bit is "reported missing" and becomes
 * eligible for retransmission once older than RTO.
 *
 * @param n_acked_out  Optional: frames newly acknowledged.
 * @param rtt_sample_out Optional: RTT of the newest acked frame that was
 *                     never retransmitted (Karn), or UINT32_MAX if none.
 * @return BR_OK; BR_ERR_ARG on NULL tx.
 * @spec 7, 5 (ACK)
 */
br_err_t br_arq_tx_on_ack(br_arq_tx_t *tx, uint16_t cum_seq, uint32_t bitmap, uint32_t now_ms,
                          uint8_t *n_acked_out, uint32_t *rtt_sample_out);

/**
 * Next retransmission due at now_ms: a slot reported missing, or an
 * ACK_REQ slot with no ACK for rto_ms (tail-loss rule above), older than
 * rto_ms. Call repeatedly until BR_ARQ_TX_IDLE.
 *
 * @param slot_out           Receives the slot (RESEND / GAVE_UP).
 * @param action_out         Receives the action.
 * @param next_deadline_out  Optional: earliest time anything becomes due
 *                           (UINT32 serial ms), unchanged if none.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 7
 */
br_err_t br_arq_tx_poll(br_arq_tx_t *tx, uint32_t now_ms, uint32_t rto_ms,
                        const br_arq_tx_slot_t **slot_out, br_arq_tx_action_t *action_out,
                        uint32_t *next_deadline_out);

/* ------------------------------------------------------------------------- */
/* Receiver reorder buffer and ACK state                                      */
/* ------------------------------------------------------------------------- */

/** One buffered out-of-order DATA plaintext payload. */
typedef struct {
    uint8_t  payload[BR_MAX_PAYLOAD_AUTH];
    uint8_t  len;
    uint8_t  used;
    uint16_t seq;
    uint32_t rx_ms;
} br_reorder_slot_t;

typedef struct {
    br_reorder_slot_t slot[BR_REORDER_SLOTS];
    uint16_t cum_seq;          /**< see file header; initial value: see br_arq_rx_init() */
    uint32_t above;            /**< bit i: cum_seq + 1 + i received (the ACK bitmap) */
    uint32_t hole_since_ms;    /**< when the oldest open hole was first seen */
    uint8_t  since_ack;        /**< frames received since our last ACK (ACK_EVERY) */
    uint8_t  ack_req_pending;  /**< a FLAG_ACK_REQ frame is unanswered */
    uint8_t  started;
    uint8_t  reserved;
} br_arq_rx_t;

/** Result of feeding one received session frame. */
typedef enum {
    BR_ARQ_RX_DUP = 0,     /**< already received (retransmission): drop; ACK again if ack_req */
    BR_ARQ_RX_IN_ORDER,    /**< deliver now, then call br_arq_rx_drain() */
    BR_ARQ_RX_BUFFERED,    /**< stored out of order */
    BR_ARQ_RX_TOO_FAR      /**< beyond cum_seq + 32 or no free slot: dropped (sender resends) */
} br_arq_rx_result_t;

/** In-order delivery of a buffered DATA payload. */
typedef void (*br_arq_deliver_fn)(void *user, uint16_t seq, const uint8_t *payload, uint8_t len);
/** A run of seqs given up after REORDER_MS (section 7 on_gap). */
typedef void (*br_arq_gap_fn)(void *user, uint16_t first_seq, uint16_t count);

/**
 * Start the receive side of a session. The session index starts at 0 at
 * BIND_ACK (3.5), so the first frame expected has seq first_seq (0) and
 * cum_seq starts at first_seq - 1 (0xFFFF). SPEC ambiguity: what an ACK
 * reports before any frame arrives; this value is the decision.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 7, 3.5
 */
br_err_t br_arq_rx_init(br_arq_rx_t *rx, uint16_t first_seq, uint32_t now_ms);

/**
 * Feed one session frame that passed CCM and the replay window. Every type
 * advances the seq space; only DATA payloads are buffered (non-DATA:
 * payload NULL, len 0).
 *
 * @param ack_req     Header FLAG_ACK_REQ.
 * @param result_out  What happened.
 * @return BR_OK; BR_ERR_ARG on NULL rx / result_out, or payload NULL with len > 0.
 * @spec 7, 4.2 (ACK triggers)
 */
br_err_t br_arq_rx_on_frame(br_arq_rx_t *rx, uint16_t seq, bool is_data, const uint8_t *payload,
                            uint8_t len, bool ack_req, uint32_t now_ms,
                            br_arq_rx_result_t *result_out);

/**
 * Deliver every buffered payload that is now in order, and give up holes
 * older than reorder_ms (on_gap, cum_seq advances).
 * @return BR_OK; BR_ERR_ARG on NULL rx / deliver.
 * @spec 7
 */
br_err_t br_arq_rx_drain(br_arq_rx_t *rx, uint32_t now_ms, uint32_t reorder_ms,
                         br_arq_deliver_fn deliver, br_arq_gap_fn gap, void *user);

/**
 * ACK payload fields (section 5): cum_seq u16, bitmap u32.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 5, 7
 */
br_err_t br_arq_rx_ack_fields(const br_arq_rx_t *rx, uint16_t *cum_seq_out, uint32_t *bitmap_out);

/**
 * Should the probe send an ACK now (4.2)? Yes on a pending FLAG_ACK_REQ, on
 * ACK_EVERY frames since the last ACK, or when keepalive_ms has passed since
 * its last own frame and something was received since. Call
 * br_arq_rx_ack_sent() after sending.
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 4.2
 */
br_err_t br_arq_rx_ack_due(const br_arq_rx_t *rx, uint32_t now_ms, uint32_t last_own_tx_ms,
                           uint16_t keepalive_ms, bool *due_out);

/** Record that an ACK carrying the current state was sent. @spec 4.2, 7 */
br_err_t br_arq_rx_ack_sent(br_arq_rx_t *rx);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_ARQ_H */
