// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_seg.c - Braid nRF24L01+ segmentation sublayer (see nrf24_seg.h).
 * Portable C11; host-tested by firmware/test/host/test_nrf24_link.c.
 */
#include "nrf24_seg.h"

#include <string.h>

nrf24_seg_err_t nrf24_seg_init(nrf24_seg_t *s, uint8_t src, uint8_t n_slots, uint32_t timeout_ms,
                               nrf24_seg_send_fn send, void *send_ctx, nrf24_seg_frame_fn on_frame,
                               void *frame_ctx)
{
    if (s == NULL || n_slots > NRF24_SEG_SLOTS_MAX) {
        return NRF24_SEG_ERR_ARG;
    }
    memset(s, 0, sizeof *s);
    s->send = send;
    s->send_ctx = send_ctx;
    s->on_frame = on_frame;
    s->frame_ctx = frame_ctx;
    s->src = src;
    s->n_slots = n_slots == 0u ? (uint8_t)NRF24_SEG_SLOTS_DEFAULT : n_slots;
    s->timeout_us = (uint64_t)(timeout_ms == 0u ? NRF24_SEG_TIMEOUT_MS_DEFAULT : timeout_ms) * 1000u;
    return NRF24_SEG_OK;
}

/* ------------------------------------------------------------------------- */
/* Transmit                                                                   */
/* ------------------------------------------------------------------------- */

nrf24_seg_err_t nrf24_seg_tx_begin(nrf24_seg_t *s, nrf24_seg_tx_t *t, const uint8_t *frame, uint16_t len)
{
    if (s == NULL || t == NULL || (frame == NULL && len > 0u)) {
        return NRF24_SEG_ERR_ARG;
    }
    if (len > NRF24_SEG_MAX_FRAME) {
        return NRF24_SEG_ERR_TOO_BIG;
    }
    t->frame = frame;
    t->len = len;
    t->off = 0u;
    t->idx = 0u;
    t->tag = s->next_tag;
    t->done = false;
    s->next_tag++;
    return NRF24_SEG_OK;
}

bool nrf24_seg_tx_next(nrf24_seg_t *s, nrf24_seg_tx_t *t, uint8_t *pkt, uint8_t *len_out)
{
    if (s == NULL || t == NULL || pkt == NULL || len_out == NULL || t->done) {
        return false;
    }
    uint16_t remain = (uint16_t)(t->len - t->off);
    uint8_t plen = remain > NRF24_SEG_PAYLOAD ? (uint8_t)NRF24_SEG_PAYLOAD : (uint8_t)remain;
    bool last = remain <= NRF24_SEG_PAYLOAD;
    pkt[0] = s->src;
    pkt[1] = t->tag;
    pkt[2] = (uint8_t)((t->idx & NRF24_SEG_IDX_MASK) | (last ? NRF24_SEG_LAST : 0u));
    if (plen > 0u) {
        memcpy(pkt + NRF24_SEG_HDR_LEN, t->frame + t->off, plen);
    }
    *len_out = (uint8_t)(NRF24_SEG_HDR_LEN + plen);
    t->off = (uint16_t)(t->off + plen);
    t->idx++;
    s->st.seg_tx++;
    if (last) {
        t->done = true;
        s->st.frames_tx++;
    }
    return true;
}

nrf24_seg_err_t nrf24_seg_send(nrf24_seg_t *s, void *tx_ctx, const uint8_t *frame, uint16_t len)
{
    if (s == NULL || s->send == NULL) {
        return NRF24_SEG_ERR_ARG;
    }
    nrf24_seg_tx_t t;
    nrf24_seg_err_t e = nrf24_seg_tx_begin(s, &t, frame, len);
    if (e != NRF24_SEG_OK) {
        return e;
    }
    uint8_t pkt[NRF24_SEG_PKT_MAX];
    uint8_t plen = 0;
    while (nrf24_seg_tx_next(s, &t, pkt, &plen)) {
        if (!s->send(s->send_ctx, tx_ctx, pkt, plen)) {
            s->st.tx_refused++;
            return NRF24_SEG_ERR_SEND;
        }
    }
    return NRF24_SEG_OK;
}

/* ------------------------------------------------------------------------- */
/* Receive                                                                    */
/* ------------------------------------------------------------------------- */

/* Close a buffer. last_us keeps the time of the last segment actually received (LRU and busy window). */
static void slot_close(nrf24_seg_slot_t *sl)
{
    sl->open = false;
    sl->len = 0u;
    sl->next_idx = 0u;
}

static void drop_open(nrf24_seg_t *s, nrf24_seg_slot_t *sl, uint32_t *counter)
{
    (*counter)++;
    s->st.frames_dropped++;
    slot_close(sl);
}

void nrf24_seg_tick(nrf24_seg_t *s, uint64_t now_us)
{
    if (s == NULL) {
        return;
    }
    for (uint8_t i = 0; i < s->n_slots; i++) {
        nrf24_seg_slot_t *sl = &s->slots[i];
        if (sl->open && now_us >= sl->last_us && now_us - sl->last_us >= s->timeout_us) {
            drop_open(s, sl, &s->st.timeouts);
        }
    }
}

static nrf24_seg_slot_t *find_slot(nrf24_seg_t *s, uint8_t src)
{
    for (uint8_t i = 0; i < s->n_slots; i++) {
        if (s->slots[i].used && s->slots[i].src == src) {
            return &s->slots[i];
        }
    }
    return NULL;
}

/* A never-used slot, else the least recently used closed one, else NULL. */
static nrf24_seg_slot_t *alloc_slot(nrf24_seg_t *s)
{
    nrf24_seg_slot_t *lru = NULL;
    for (uint8_t i = 0; i < s->n_slots; i++) {
        nrf24_seg_slot_t *sl = &s->slots[i];
        if (!sl->used) {
            return sl;
        }
        if (!sl->open && (lru == NULL || sl->last_us < lru->last_us)) {
            lru = sl;
        }
    }
    return lru;
}

void nrf24_seg_rx(nrf24_seg_t *s, const uint8_t *pkt, uint8_t len, uint64_t now_us)
{
    if (s == NULL || pkt == NULL) {
        return;
    }
    if (len < NRF24_SEG_HDR_LEN || len > NRF24_SEG_PKT_MAX) {
        s->st.malformed++;
        return;
    }
    uint8_t src = pkt[0];
    uint8_t tag = pkt[1];
    uint8_t idx = (uint8_t)(pkt[2] & NRF24_SEG_IDX_MASK);
    bool last = (pkt[2] & NRF24_SEG_LAST) != 0u;
    uint8_t plen = (uint8_t)(len - NRF24_SEG_HDR_LEN);
    if (idx >= NRF24_SEG_MAX_SEGS || (!last && plen != NRF24_SEG_PAYLOAD)) {
        s->st.malformed++;
        return;
    }
    s->st.seg_rx++;
    nrf24_seg_tick(s, now_us);

    nrf24_seg_slot_t *sl = find_slot(s, src);
    if (sl != NULL && sl->open) {
        if (tag != sl->tag) {
            drop_open(s, sl, &s->st.foreign_tag);
            /* fall through: the new segment is judged on its own below */
        } else if (idx == sl->next_idx) {
            /* in order: appended below */
        } else if ((uint8_t)(idx + 1u) == sl->next_idx) {
            s->st.dups++;
            return;
        } else {
            drop_open(s, sl, &s->st.gaps);
            return;
        }
    }
    if (sl == NULL || !sl->open) {
        if (idx != 0u) {
            if (sl != NULL && sl->done_valid && tag == sl->done_tag && idx <= sl->done_idx) {
                s->st.dups++;
            } else {
                s->st.orphans++;
            }
            return;
        }
        if (sl == NULL) {
            sl = alloc_slot(s);
            if (sl == NULL) {
                s->st.buffer_full++;
                s->st.frames_dropped++;
                return;
            }
            sl->used = true;
            sl->src = src;
            sl->done_valid = false;
        } else if (sl->done_valid && tag == sl->done_tag) {
            s->st.dups++; /* segment 0 of a frame already delivered */
            return;
        }
        sl->open = true;
        sl->tag = tag;
        sl->next_idx = 0u;
        sl->len = 0u;
    }
    if ((uint16_t)(sl->len + plen) > NRF24_SEG_MAX_FRAME) {
        drop_open(s, sl, &s->st.oversize);
        return;
    }
    if (plen > 0u) {
        memcpy(sl->buf + sl->len, pkt + NRF24_SEG_HDR_LEN, plen);
    }
    sl->len = (uint16_t)(sl->len + plen);
    sl->next_idx = (uint8_t)(idx + 1u);
    sl->last_us = now_us;
    if (last) {
        uint16_t flen = sl->len;
        sl->done_valid = true;
        sl->done_tag = tag;
        sl->done_idx = idx;
        slot_close(sl);
        s->st.frames_rx++;
        if (s->on_frame != NULL) {
            s->on_frame(s->frame_ctx, src, sl->buf, flen);
        }
    }
}

bool nrf24_seg_rx_active(const nrf24_seg_t *s, uint64_t now_us, uint64_t within_us)
{
    if (s == NULL) {
        return false;
    }
    for (uint8_t i = 0; i < s->n_slots; i++) {
        const nrf24_seg_slot_t *sl = &s->slots[i];
        if (!sl->used) {
            continue;
        }
        if (now_us < sl->last_us || now_us - sl->last_us < within_us) {
            return true;
        }
    }
    return false;
}

uint64_t nrf24_seg_next_deadline(const nrf24_seg_t *s)
{
    uint64_t d = UINT64_MAX;
    if (s == NULL) {
        return d;
    }
    for (uint8_t i = 0; i < s->n_slots; i++) {
        const nrf24_seg_slot_t *sl = &s->slots[i];
        if (sl->open && sl->last_us + s->timeout_us < d) {
            d = sl->last_us + s->timeout_us;
        }
    }
    return d;
}

uint8_t nrf24_seg_open_count(const nrf24_seg_t *s)
{
    uint8_t n = 0;
    if (s == NULL) {
        return 0u;
    }
    for (uint8_t i = 0; i < s->n_slots; i++) {
        if (s->slots[i].open) {
            n++;
        }
    }
    return n;
}

void nrf24_seg_get_stats(const nrf24_seg_t *s, nrf24_seg_stats_t *out)
{
    if (s == NULL || out == NULL) {
        return;
    }
    *out = s->st;
}
