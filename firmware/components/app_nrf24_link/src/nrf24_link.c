// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_link.c - Braid nRF24L01+ transport adapter (see nrf24_link.h).
 * Portable C11; host-tested by firmware/test/host/test_nrf24_link.c.
 */
#include "nrf24_link.h"

#include <string.h>

#include "braid/br_frame.h"
#include "braid/br_tables.h"

const uint8_t NRF24_LINK_BCAST_ADDR[NRF24_LINK_ADDR_LEN] = {0x50, 0x4C, 0xFF, 0xFF, 0xA5};

void nrf24_link_unit_addr(uint16_t unit_id, uint8_t out[NRF24_LINK_ADDR_LEN])
{
    out[0] = 0x50;
    out[1] = 0x4C;
    out[2] = (uint8_t)(unit_id >> 8);
    out[3] = (uint8_t)(unit_id & 0xFFu);
    out[4] = 0xA5;
}

/* ------------------------------------------------------------------------- */
/* Set-up                                                                     */
/* ------------------------------------------------------------------------- */

static void rx_frame(void *ctx, uint8_t src, const uint8_t *frame, uint16_t len);

static bool ops_complete(const nrf24_radio_ops_t *o)
{
    return o->set_rx_address != NULL && o->set_tx_address != NULL && o->write_payload != NULL &&
           o->start_tx != NULL && o->read_payload != NULL && o->status != NULL && o->clear_irq != NULL &&
           o->tx_abort != NULL && o->start_listening != NULL && o->stop_listening != NULL;
}

bool nrf24_link_init(nrf24_link_t *l, const nrf24_link_cfg_t *cfg, const nrf24_radio_ops_t *ops)
{
    if (l == NULL || cfg == NULL || ops == NULL || !ops_complete(ops)) {
        return false;
    }
    if (!br_id_is_unit(cfg->unit_id) || cfg->txq_frames > NRF24_LINK_TXQ_MAX ||
        cfg->reasm_slots > NRF24_SEG_SLOTS_MAX) {
        return false;
    }
    memset(l, 0, sizeof *l);
    l->ops = *ops;
    l->cfg = *cfg;
    if (l->cfg.guard_us == 0u) {
        l->cfg.guard_us = NRF24_LINK_GUARD_US;
    }
    if (l->cfg.tx_timeout_us == 0u) {
        l->cfg.tx_timeout_us = NRF24_LINK_TX_TIMEOUT_US;
    }
    if (l->cfg.rx_hold_us == 0u) {
        l->cfg.rx_hold_us = NRF24_LINK_RX_HOLD_US;
    }
    if (l->cfg.poll_us == 0u) {
        l->cfg.poll_us = NRF24_LINK_POLL_US;
    }
    if (l->cfg.tx_poll_us == 0u) {
        l->cfg.tx_poll_us = NRF24_LINK_TX_POLL_US;
    }
    if (l->cfg.txq_frames == 0u) {
        l->cfg.txq_frames = NRF24_LINK_TXQ_DEFAULT;
    }
    nrf24_link_unit_addr(cfg->unit_id, l->own_addr);
    (void)nrf24_seg_init(&l->seg, (uint8_t)(cfg->unit_id & 0xFFu), cfg->reasm_slots, cfg->reasm_timeout_ms, NULL,
                         NULL, rx_frame, l);
    l->tx_state = NRF24_TX_IDLE;
    return true;
}

void nrf24_link_fill_transport(nrf24_link_t *l, br_transport_t *tr)
{
    if (tr == NULL) {
        return;
    }
    tr->name = "nrf24";
    tr->link_class = BR_LINK_PACKET;
    tr->max_frame = NRF24_LINK_MAX_FRAME;
    tr->rs_nsym = BR_RS_NSYM_PACKET;
    tr->can_broadcast = true;
    tr->mac_retry = true;
    tr->edge_only = false;
    tr->link_cost = NRF24_LINK_COST;
    tr->addr_len = NRF24_LINK_ADDR_LEN;
    tr->send = nrf24_link_send;
    tr->user = l;
}

br_err_t nrf24_link_register(nrf24_link_t *l, br_node_config_t *nc, const nrf24_link_cfg_t *cfg,
                             const nrf24_radio_ops_t *ops)
{
    if (l == NULL || nc == NULL || cfg == NULL || ops == NULL) {
        return BR_ERR_ARG;
    }
    if (nc->n_transports >= BR_NODE_MAX_TRANSPORTS) {
        return BR_ERR_TOO_BIG;
    }
    if (!nrf24_link_init(l, cfg, ops)) {
        return BR_ERR_ARG;
    }
    l->link = nc->n_transports;
    nrf24_link_fill_transport(l, &nc->transports[l->link]);
    nc->n_transports++;
    return BR_OK;
}

bool nrf24_link_start(nrf24_link_t *l)
{
    if (l == NULL) {
        return false;
    }
    void *r = l->ops.radio;
    if (!l->ops.set_rx_address(r, 0u, l->own_addr) || !l->ops.set_rx_address(r, 1u, NRF24_LINK_BCAST_ADDR) ||
        !l->ops.start_listening(r)) {
        return false;
    }
    l->started = true;
    l->tx_state = NRF24_TX_IDLE;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Transmit queue                                                             */
/* ------------------------------------------------------------------------- */

br_err_t nrf24_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    nrf24_link_t *l = (nrf24_link_t *)user;
    if (l == NULL || frame == NULL || len == 0u) {
        if (l != NULL) {
            l->st.tx_bad_len++;
        }
        return BR_ERR_ARG;
    }
    if (len > NRF24_LINK_MAX_FRAME) {
        l->st.tx_bad_len++;
        return BR_ERR_TOO_BIG;
    }
    if (!l->started) {
        return BR_ERR_STATE;
    }
    if (l->txq_count >= l->cfg.txq_frames) {
        l->st.tx_refused++;
        return BR_ERR_QUEUE_FULL;
    }
    uint8_t at = (uint8_t)((l->txq_head + l->txq_count) % l->cfg.txq_frames);
    nrf24_txq_entry_t *e = &l->txq[at];
    e->bcast = addr == NULL;
    memcpy(e->addr, e->bcast ? NRF24_LINK_BCAST_ADDR : addr, NRF24_LINK_ADDR_LEN);
    e->len = len;
    memcpy(e->data, frame, len);
    l->txq_count++;
    l->st.tx_queued++;
    return BR_OK;
}

static nrf24_txq_entry_t *txq_front(nrf24_link_t *l)
{
    return l->txq_count > 0u ? &l->txq[l->txq_head] : NULL;
}

static void txq_pop(nrf24_link_t *l)
{
    if (l->txq_count > 0u) {
        l->txq_head = (uint8_t)((l->txq_head + 1u) % l->cfg.txq_frames);
        l->txq_count--;
    }
}

/* Report a unicast verdict to the node (outside any br_node_* call). */
static void report(nrf24_link_t *l, br_node_t *node, const nrf24_txq_entry_t *e, bool delivered)
{
    if (e->bcast) {
        return;
    }
    if (delivered) {
        l->st.tx_status_ok++;
    } else {
        l->st.tx_status_fail++;
    }
    if (node != NULL) {
        (void)br_node_tx_status(node, l->link, e->addr, NRF24_LINK_ADDR_LEN, delivered);
    }
}

/* Frame finished (any outcome): drop it, back to PRX, guard. */
static void finish_frame(nrf24_link_t *l, uint64_t now_us)
{
    txq_pop(l);
    if (!l->ops.start_listening(l->ops.radio)) {
        l->st.tx_radio_err++;
    }
    l->tx_state = NRF24_TX_GUARD;
    l->guard_until_us = now_us + l->cfg.guard_us;
}

/* Hand the next segment to the radio. Returns false when the radio refused. */
static bool push_segment(nrf24_link_t *l, const nrf24_txq_entry_t *e, uint64_t now_us)
{
    uint8_t plen = 0;
    if (!nrf24_seg_tx_next(&l->seg, &l->tx_it, l->pkt, &plen)) {
        return false;
    }
    if (!l->ops.write_payload(l->ops.radio, l->pkt, plen, e->bcast) || !l->ops.start_tx(l->ops.radio)) {
        return false;
    }
    l->st.tx_segments++;
    l->tx_seg_started_us = now_us;
    return true;
}

static void abort_frame(nrf24_link_t *l, br_node_t *node, const nrf24_txq_entry_t *e, uint64_t now_us)
{
    (void)l->ops.tx_abort(l->ops.radio);
    report(l, node, e, false);
    finish_frame(l, now_us);
}

static void start_frame(nrf24_link_t *l, br_node_t *node, nrf24_txq_entry_t *e, uint64_t now_us)
{
    void *r = l->ops.radio;
    if (!l->ops.stop_listening(r) || !l->ops.set_tx_address(r, e->addr) ||
        nrf24_seg_tx_begin(&l->seg, &l->tx_it, e->data, e->len) != NRF24_SEG_OK) {
        l->st.tx_radio_err++;
        abort_frame(l, node, e, now_us);
        return;
    }
    (void)l->ops.clear_irq(r, NRF24_ST_TX_DS | NRF24_ST_MAX_RT);
    if (!push_segment(l, e, now_us)) {
        l->st.tx_radio_err++;
        abort_frame(l, node, e, now_us);
        return;
    }
    l->tx_state = NRF24_TX_SENDING;
}

static void tx_step(nrf24_link_t *l, br_node_t *node, uint64_t now_us, uint64_t *deadline)
{
    nrf24_txq_entry_t *e = txq_front(l);
    if (l->tx_state == NRF24_TX_SENDING) {
        if (e == NULL) { /* cannot happen: the frame in flight is the queue front */
            l->tx_state = NRF24_TX_IDLE;
            return;
        }
        uint8_t st = l->ops.status(l->ops.radio);
        if (st == NRF24_ST_INVALID) {
            l->st.tx_radio_err++;
            abort_frame(l, node, e, now_us);
        } else if ((st & NRF24_ST_MAX_RT) != 0u) {
            l->st.tx_max_rt++;
            abort_frame(l, node, e, now_us);
        } else if ((st & NRF24_ST_TX_DS) != 0u) {
            (void)l->ops.clear_irq(l->ops.radio, NRF24_ST_TX_DS);
            if (l->tx_it.done) {
                l->st.tx_frames++;
                if (e->bcast) {
                    l->st.tx_bcast++;
                } else {
                    l->st.tx_unicast++;
                }
                report(l, node, e, true);
                finish_frame(l, now_us);
            } else if (!push_segment(l, e, now_us)) {
                l->st.tx_radio_err++;
                abort_frame(l, node, e, now_us);
            }
        } else if (now_us - l->tx_seg_started_us >= l->cfg.tx_timeout_us) {
            l->st.tx_stuck++;
            abort_frame(l, node, e, now_us);
        }
        if (l->tx_state == NRF24_TX_SENDING) {
            uint64_t t = now_us + l->cfg.tx_poll_us;
            uint64_t to = l->tx_seg_started_us + l->cfg.tx_timeout_us;
            if (to < t) {
                t = to;
            }
            if (t < *deadline) {
                *deadline = t;
            }
            return;
        }
    }
    if (l->tx_state == NRF24_TX_GUARD) {
        if (now_us < l->guard_until_us) {
            if (l->guard_until_us < *deadline) {
                *deadline = l->guard_until_us;
            }
            return;
        }
        l->tx_state = NRF24_TX_IDLE;
    }
    e = txq_front(l);
    if (e == NULL) {
        return;
    }
    if (nrf24_seg_rx_active(&l->seg, now_us, l->cfg.rx_hold_us)) {
        l->st.tx_deferred++;
        uint64_t t = now_us + l->cfg.tx_poll_us;
        if (t < *deadline) {
            *deadline = t;
        }
        return;
    }
    if (l->tx_gate != NULL && !l->tx_gate(l->tx_gate_ctx, now_us)) {
        /* 12.4 bridge: the other radio is busy; the gate counts and caps the hold */
        uint64_t t = now_us + l->cfg.tx_poll_us;
        if (t < *deadline) {
            *deadline = t;
        }
        return;
    }
    start_frame(l, node, e, now_us);
    if (l->tx_state == NRF24_TX_SENDING) {
        uint64_t t = now_us + l->cfg.tx_poll_us;
        if (t < *deadline) {
            *deadline = t;
        }
    } else if (l->guard_until_us < *deadline) {
        *deadline = l->guard_until_us;
    }
}

/* ------------------------------------------------------------------------- */
/* Receive                                                                    */
/* ------------------------------------------------------------------------- */

static void rx_frame(void *ctx, uint8_t src, const uint8_t *frame, uint16_t len)
{
    nrf24_link_t *l = (nrf24_link_t *)ctx;
    if (l == NULL || l->node == NULL) {
        return;
    }
    const br_transport_t *tr = &l->node->cfg.transports[l->link];
    if (!br_transport_admit(tr, frame, len)) {
        l->st.rx_admit_drop++;
        return;
    }
    br_rx_meta_t m;
    memset(&m, 0, sizeof m);
    m.rssi = (int8_t)BR_RSSI_UNKNOWN;
    if (len >= BR_OFF_PREV_HOP + 2u) {
        uint16_t prev_hop = br_rd_le16(frame + BR_OFF_PREV_HOP);
        if ((uint8_t)(prev_hop & 0xFFu) != src) {
            l->st.rx_src_mismatch++;
        }
        nrf24_link_unit_addr(prev_hop, m.addr);
        m.addr_len = NRF24_LINK_ADDR_LEN;
    }
    l->st.rx_frames++;
    (void)br_node_rx(l->node, frame, len, l->link, &m, NULL);
}

#define NRF24_LINK_RX_DRAIN_MAX 16u

static void rx_drain(nrf24_link_t *l, uint64_t now_us)
{
    void *r = l->ops.radio;
    bool any = false;
    for (unsigned i = 0; i < NRF24_LINK_RX_DRAIN_MAX; i++) {
        uint8_t st = l->ops.status(r);
        if (st == NRF24_ST_INVALID) {
            l->st.rx_radio_err++;
            break;
        }
        uint8_t pipe_no = (uint8_t)((st & NRF24_ST_RX_P_NO_MASK) >> NRF24_ST_RX_P_NO_SHIFT);
        if (pipe_no == NRF24_ST_RX_P_NO_EMPTY) {
            break;
        }
        uint8_t pipe = 0;
        uint8_t len = 0;
        if (!l->ops.read_payload(r, &pipe, l->pkt, &len)) {
            l->st.rx_radio_err++;
            break;
        }
        any = true;
        l->st.rx_segments++;
        if (pipe > 1u) {
            l->st.rx_bad_pipe++;
            continue;
        }
        nrf24_seg_rx(&l->seg, l->pkt, len, now_us);
    }
    if (any) {
        (void)l->ops.clear_irq(r, NRF24_ST_RX_DR);
    }
}

uint64_t nrf24_link_pump(nrf24_link_t *l, br_node_t *node, uint64_t now_us)
{
    if (l == NULL || !l->started) {
        return UINT64_MAX;
    }
    l->node = node;
    uint64_t deadline = now_us + l->cfg.poll_us;
    rx_drain(l, now_us);
    nrf24_seg_tick(&l->seg, now_us);
    /* reassembly drops since the last pump -> the spec's seg_fail (one per frame, N59) */
    for (uint32_t d = l->seg.st.frames_dropped; l->seg_dropped_reported != d; l->seg_dropped_reported++) {
        br_node_count_seg_fail(node);
    }
    tx_step(l, node, now_us, &deadline);
    uint64_t sd = nrf24_seg_next_deadline(&l->seg);
    if (sd < deadline) {
        deadline = sd;
    }
    return deadline;
}

bool nrf24_link_radio_busy(const nrf24_link_t *l, uint64_t now_us)
{
    if (l == NULL || !l->started) {
        return false;
    }
    return l->tx_state == NRF24_TX_SENDING || nrf24_seg_rx_active(&l->seg, now_us, l->cfg.rx_hold_us);
}

void nrf24_link_set_tx_gate(nrf24_link_t *l, nrf24_link_tx_gate_fn gate, void *ctx)
{
    if (l == NULL) {
        return;
    }
    l->tx_gate = gate;
    l->tx_gate_ctx = gate != NULL ? ctx : NULL;
}

uint8_t nrf24_link_tx_pending(const nrf24_link_t *l)
{
    return l == NULL ? 0u : l->txq_count;
}

void nrf24_link_get_stats(const nrf24_link_t *l, nrf24_link_stats_t *out)
{
    if (l == NULL || out == NULL) {
        return;
    }
    *out = l->st;
}

void nrf24_link_get_seg_stats(const nrf24_link_t *l, nrf24_seg_stats_t *out)
{
    if (l == NULL || out == NULL) {
        return;
    }
    nrf24_seg_get_stats(&l->seg, out);
}
