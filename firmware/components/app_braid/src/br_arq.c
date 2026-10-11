// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_arq.c - sender ARQ window and receiver reorder buffer (spec 7).
 *
 * Sender: the slot array is an unordered pool (count = slots in use); the
 * oldest frame is the one with the smallest seq in serial order relative to
 * the newest. Receiver: cum_seq plus a 32-bit "above" bitmap (bit i = seq
 * cum_seq + 1 + i received), the ACK bitmap of section 5; out-of-order DATA
 * payloads wait in BR_REORDER_SLOTS slots.
 *
 * 16-bit seqs are compared with RFC 1982 serial arithmetic (3.5): the
 * distance (uint16_t)(a - b) is "a after b" when it is in 1..0x7FFF.
 */
#include <string.h>

#include "braid/br_arq.h"

#include "br_internal.h"

/* Private slot flag: a received ACK reported this seq missing (cleared bit). */
#define ARQ_SLOT_MISSING 0x08u

static uint16_t seq_dist(uint16_t a, uint16_t b)
{
    return (uint16_t)(a - b);
}

/* a after b (RFC 1982; the undefined 0x8000 distance counts as not newer). */
static bool seq_newer(uint16_t a, uint16_t b)
{
    uint16_t d = seq_dist(a, b);
    return d != 0u && d < 0x8000u;
}

/* ---- sender --------------------------------------------------------------- */

br_err_t br_arq_tx_init(br_arq_tx_t *tx, uint8_t window)
{
    if (tx == NULL || window == 0u || window > BR_ARQ_WINDOW) {
        return BR_ERR_ARG;
    }
    memset(tx, 0, sizeof *tx);
    tx->window = window;
    return BR_OK;
}

/* Index of the used slot with the oldest seq (serial order), or -1. */
static int arq_oldest(const br_arq_tx_t *tx, uint16_t ref)
{
    int best = -1;
    uint16_t best_d = 0;
    for (int i = 0; i < (int)tx->window; i++) {
        const br_arq_tx_slot_t *s = &tx->slot[i];
        if ((s->flags & BR_ARQ_SLOT_USED) == 0u) {
            continue;
        }
        uint16_t d = seq_dist(ref, s->seq);
        if (best < 0 || d > best_d) {
            best = i;
            best_d = d;
        }
    }
    return best;
}

br_err_t br_arq_tx_push(br_arq_tx_t *tx, uint16_t seq, uint32_t roc, const uint8_t *frame,
                        uint16_t len, bool ack_req, uint32_t now_ms,
                        bool *evicted_out, uint16_t *evicted_seq_out)
{
    if (tx == NULL || frame == NULL || evicted_out == NULL || evicted_seq_out == NULL ||
        len == 0u || len > BR_MAX_FRAME_MESH || tx->window == 0u || tx->window > BR_ARQ_WINDOW) {
        return BR_ERR_ARG;
    }
    *evicted_out = false;
    *evicted_seq_out = 0u;
    int free_i = -1;
    for (int i = 0; i < (int)tx->window && free_i < 0; i++) {
        if ((tx->slot[i].flags & BR_ARQ_SLOT_USED) == 0u) {
            free_i = i;
        }
    }
    if (free_i < 0) {
        free_i = arq_oldest(tx, seq);
        br_arq_tx_slot_t *old = &tx->slot[free_i];
        if ((old->flags & BR_ARQ_SLOT_ACKED) == 0u) {
            *evicted_out = true;
            *evicted_seq_out = old->seq;
        }
        old->flags = 0u;
        tx->count--;
    }
    br_arq_tx_slot_t *s = &tx->slot[free_i];
    memcpy(s->frame, frame, len);
    s->len = len;
    s->seq = seq;
    s->roc = roc;
    s->sent_ms = now_ms;
    s->retries = 0u;
    s->flags = (uint8_t)(BR_ARQ_SLOT_USED | (ack_req ? BR_ARQ_SLOT_ACK_REQ : 0u));
    s->reserved = 0u;
    tx->count++;
    return BR_OK;
}

br_err_t br_arq_tx_on_ack(br_arq_tx_t *tx, uint16_t cum_seq, uint32_t bitmap, uint32_t now_ms,
                          uint8_t *n_acked_out, uint32_t *rtt_sample_out)
{
    if (tx == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t n = 0;
    uint32_t rtt = UINT32_MAX;
    bool have_newest = false;
    uint16_t newest_seq = 0;
    for (int i = 0; i < (int)tx->window && i < (int)BR_ARQ_WINDOW; i++) {
        br_arq_tx_slot_t *s = &tx->slot[i];
        if ((s->flags & BR_ARQ_SLOT_USED) == 0u) {
            continue;
        }
        uint16_t d = seq_dist(s->seq, cum_seq); /* 1..32: inside the bitmap */
        bool acked = (d == 0u) || (d >= 0x8000u);
        if (!acked && d <= BR_ACK_BITMAP_BITS) {
            if (((bitmap >> (d - 1u)) & 1u) != 0u) {
                acked = true;
            } else {
                s->flags = (uint8_t)(s->flags | ARQ_SLOT_MISSING);
            }
        }
        if (!acked) {
            continue;
        }
        /* Karn: only never-retransmitted frames give an RTT sample; the newest wins. */
        if (s->retries == 0u && (!have_newest || seq_newer(s->seq, newest_seq))) {
            have_newest = true;
            newest_seq = s->seq;
            rtt = now_ms - s->sent_ms;
        }
        s->flags = 0u;
        tx->count--;
        n++;
    }
    if (n_acked_out != NULL) {
        *n_acked_out = n;
    }
    if (rtt_sample_out != NULL) {
        *rtt_sample_out = rtt;
    }
    return BR_OK;
}

br_err_t br_arq_tx_poll(br_arq_tx_t *tx, uint32_t now_ms, uint32_t rto_ms,
                        const br_arq_tx_slot_t **slot_out, br_arq_tx_action_t *action_out,
                        uint32_t *next_deadline_out)
{
    if (tx == NULL || slot_out == NULL || action_out == NULL) {
        return BR_ERR_ARG;
    }
    *slot_out = NULL;
    *action_out = BR_ARQ_TX_IDLE;
    int due = -1;
    bool have_next = false;
    uint32_t next = 0;
    for (int i = 0; i < (int)tx->window && i < (int)BR_ARQ_WINDOW; i++) {
        br_arq_tx_slot_t *s = &tx->slot[i];
        if ((s->flags & BR_ARQ_SLOT_USED) == 0u ||
            (s->flags & (ARQ_SLOT_MISSING | BR_ARQ_SLOT_ACK_REQ)) == 0u) {
            continue;
        }
        uint32_t at = s->sent_ms + rto_ms;
        if (!br_ms_before(now_ms, at)) {
            if (due < 0 || seq_newer(tx->slot[due].seq, s->seq)) {
                due = i; /* oldest due slot first */
            }
        } else if (!have_next || br_ms_before(at, next)) {
            next = at;
            have_next = true;
        }
    }
    if (due >= 0) {
        br_arq_tx_slot_t *s = &tx->slot[due];
        *slot_out = s;
        if (s->retries >= BR_ARQ_MAX_RETRIES) {
            /* freed (USED cleared); ACK_REQ is kept so the caller can apply 4.1.13 */
            s->flags = (uint8_t)(s->flags & BR_ARQ_SLOT_ACK_REQ);
            tx->count--;
            *action_out = BR_ARQ_TX_GAVE_UP;
        } else {
            s->retries++;
            s->sent_ms = now_ms;
            *action_out = BR_ARQ_TX_RESEND;
        }
        return BR_OK;
    }
    if (have_next && next_deadline_out != NULL) {
        *next_deadline_out = next;
    }
    return BR_OK;
}

/* ---- receiver ------------------------------------------------------------- */

br_err_t br_arq_rx_init(br_arq_rx_t *rx, uint16_t first_seq, uint32_t now_ms)
{
    if (rx == NULL) {
        return BR_ERR_ARG;
    }
    memset(rx, 0, sizeof *rx);
    rx->cum_seq = (uint16_t)(first_seq - 1u);
    rx->hole_since_ms = now_ms;
    rx->started = 1u;
    return BR_OK;
}

static int reorder_find(const br_arq_rx_t *rx, uint16_t seq)
{
    for (int i = 0; i < (int)BR_REORDER_SLOTS; i++) {
        if (rx->slot[i].used != 0u && rx->slot[i].seq == seq) {
            return i;
        }
    }
    return -1;
}

br_err_t br_arq_rx_on_frame(br_arq_rx_t *rx, uint16_t seq, bool is_data, const uint8_t *payload,
                            uint8_t len, bool ack_req, uint32_t now_ms,
                            br_arq_rx_result_t *result_out)
{
    if (rx == NULL || result_out == NULL || (payload == NULL && len > 0u) ||
        len > BR_MAX_PAYLOAD_AUTH) {
        return BR_ERR_ARG;
    }
    uint16_t d = seq_dist(seq, rx->cum_seq);
    if (ack_req) {
        rx->ack_req_pending = 1u;
    }
    if (d == 0u || d >= 0x8000u || (d <= BR_ACK_BITMAP_BITS && ((rx->above >> (d - 1u)) & 1u))) {
        *result_out = BR_ARQ_RX_DUP;
        return BR_OK;
    }
    if (d > BR_ACK_BITMAP_BITS) {
        *result_out = BR_ARQ_RX_TOO_FAR;
        return BR_OK;
    }
    if (d == 1u) {
        rx->cum_seq = seq;
        rx->above >>= 1;
        if (rx->since_ack < 0xFFu) {
            rx->since_ack++;
        }
        if (rx->above != 0u) {
            rx->hole_since_ms = now_ms; /* the next hole starts being waited for now */
        }
        *result_out = BR_ARQ_RX_IN_ORDER;
        return BR_OK;
    }
    if (is_data) {
        int free_i = -1;
        for (int i = 0; i < (int)BR_REORDER_SLOTS && free_i < 0; i++) {
            if (rx->slot[i].used == 0u) {
                free_i = i;
            }
        }
        if (free_i < 0) {
            *result_out = BR_ARQ_RX_TOO_FAR;
            return BR_OK;
        }
        br_reorder_slot_t *s = &rx->slot[free_i];
        if (len > 0u) {
            memcpy(s->payload, payload, len);
        }
        s->len = len;
        s->used = 1u;
        s->seq = seq;
        s->rx_ms = now_ms;
    }
    if (rx->above == 0u) {
        rx->hole_since_ms = now_ms;
    }
    rx->above |= (1u << (d - 1u));
    if (rx->since_ack < 0xFFu) {
        rx->since_ack++;
    }
    *result_out = BR_ARQ_RX_BUFFERED;
    return BR_OK;
}

br_err_t br_arq_rx_drain(br_arq_rx_t *rx, uint32_t now_ms, uint32_t reorder_ms,
                         br_arq_deliver_fn deliver, br_arq_gap_fn gap, void *user)
{
    if (rx == NULL || deliver == NULL) {
        return BR_ERR_ARG;
    }
    for (;;) {
        bool moved = false;
        while ((rx->above & 1u) != 0u) {
            uint16_t s = (uint16_t)(rx->cum_seq + 1u);
            rx->cum_seq = s;
            rx->above >>= 1;
            moved = true;
            int i = reorder_find(rx, s);
            if (i >= 0) {
                br_reorder_slot_t *sl = &rx->slot[i];
                sl->used = 0u;
                deliver(user, s, sl->payload, sl->len);
            }
        }
        if (moved && rx->above != 0u) {
            rx->hole_since_ms = now_ms;
        }
        if (rx->above == 0u || br_ms_before(now_ms, rx->hole_since_ms + reorder_ms)) {
            break;
        }
        /* The hole at cum_seq + 1 expired: give up the run of missing seqs. */
        uint16_t k = 0;
        while (((rx->above >> k) & 1u) == 0u) {
            k++;
        }
        uint16_t first = (uint16_t)(rx->cum_seq + 1u);
        rx->cum_seq = (uint16_t)(rx->cum_seq + k);
        rx->above >>= k;
        if (gap != NULL) {
            gap(user, first, k);
        }
    }
    return BR_OK;
}

void br_arq_rx_give_up_below(br_arq_rx_t *rx, uint16_t seq, uint32_t now_ms, br_arq_deliver_fn deliver,
                             br_arq_gap_fn gap, void *user)
{
    if (rx == NULL) {
        return;
    }
    uint16_t gap_first = 0;
    uint16_t gap_n = 0;
    bool moved = false;
    /* every seq in (cum_seq, seq) in serial order; a seq that passed
     * br_arq_rx_on_frame() keeps this under BR_ACK_BITMAP_BITS iterations */
    while (seq_newer(seq, (uint16_t)(rx->cum_seq + 1u))) {
        uint16_t s = (uint16_t)(rx->cum_seq + 1u);
        bool have = (rx->above & 1u) != 0u;
        rx->cum_seq = s;
        rx->above >>= 1;
        moved = true;
        if (!have) {
            if (gap_n == 0u) {
                gap_first = s;
            }
            gap_n++;
            continue;
        }
        if (gap_n != 0u && gap != NULL) {
            gap(user, gap_first, gap_n);
        }
        gap_n = 0u;
        int i = reorder_find(rx, s);
        if (i >= 0) {
            br_reorder_slot_t *sl = &rx->slot[i];
            sl->used = 0u;
            if (deliver != NULL) {
                deliver(user, s, sl->payload, sl->len);
            }
        }
    }
    if (gap_n != 0u && gap != NULL) {
        gap(user, gap_first, gap_n);
    }
    if (moved && rx->above != 0u) {
        rx->hole_since_ms = now_ms; /* the next hole starts being waited for now */
    }
}

br_err_t br_arq_rx_ack_fields(const br_arq_rx_t *rx, uint16_t *cum_seq_out, uint32_t *bitmap_out)
{
    if (rx == NULL || cum_seq_out == NULL || bitmap_out == NULL) {
        return BR_ERR_ARG;
    }
    *cum_seq_out = rx->cum_seq;
    *bitmap_out = rx->above;
    return BR_OK;
}

br_err_t br_arq_rx_ack_due(const br_arq_rx_t *rx, uint32_t now_ms, uint32_t last_own_tx_ms,
                           uint16_t keepalive_ms, bool *due_out)
{
    if (rx == NULL || due_out == NULL) {
        return BR_ERR_ARG;
    }
    *due_out = rx->ack_req_pending != 0u || rx->since_ack >= BR_ACK_EVERY ||
               (rx->since_ack > 0u && !br_ms_before(now_ms, last_own_tx_ms + keepalive_ms));
    return BR_OK;
}

br_err_t br_arq_rx_ack_sent(br_arq_rx_t *rx)
{
    if (rx == NULL) {
        return BR_ERR_ARG;
    }
    rx->since_ack = 0u;
    rx->ack_req_pending = 0u;
    return BR_OK;
}
