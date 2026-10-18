// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * uart_link.c - Braid UART transport adapter (see uart_link.h).
 * Portable C11; host-tested by firmware/test/host/test_uart_link.c.
 */
#include "uart_link.h"

#include <string.h>

#include "braid/br_rs.h"
#include "braid/br_tables.h"

bool uart_link_init(uart_link_t *l, uart_link_write_fn write, void *write_ctx, uart_link_frame_fn on_frame,
                    void *frame_ctx)
{
    if (l == NULL || write == NULL || on_frame == NULL) {
        return false;
    }
    memset(l, 0, sizeof *l);
    l->write = write;
    l->write_ctx = write_ctx;
    l->on_frame = on_frame;
    l->frame_ctx = frame_ctx;
    return true;
}

bool uart_link_start(uart_link_t *l)
{
    static const uint8_t delim = BR_COBS_DELIM;
    if (l == NULL || l->write == NULL) {
        return false;
    }
    return l->write(l->write_ctx, &delim, 1u);
}

void uart_link_fill_transport(uart_link_t *l, br_transport_t *tr)
{
    if (tr == NULL) {
        return;
    }
    tr->name = "uart";
    tr->link_class = BR_LINK_RAW;
    tr->max_frame = UART_LINK_MAX_FRAME;
    tr->rs_nsym = UART_LINK_RS_NSYM;
    tr->can_broadcast = false;
    tr->mac_retry = false;
    tr->edge_only = false;
    tr->link_cost = UART_LINK_COST;
    tr->addr_len = 0u;
    tr->send = uart_link_send;
    tr->user = l;
}

br_err_t uart_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    uart_link_t *l = (uart_link_t *)user;
    (void)addr; /* point to point: the only peer */
    if (l == NULL || frame == NULL || len == 0u) {
        if (l != NULL) {
            l->st.tx_bad_len++;
        }
        return BR_ERR_ARG;
    }
    if (len > UART_LINK_MAX_FRAME) {
        l->st.tx_bad_len++;
        return BR_ERR_TOO_BIG;
    }
    size_t n = 0;
    if (br_cobs_encode(frame, len, l->tx, sizeof l->tx, &n) != BR_OK) {
        l->st.tx_bad_len++;
        return BR_ERR_TOO_BIG;
    }
    if (!l->write(l->write_ctx, l->tx, n)) {
        l->st.tx_refused++;
        return BR_ERR_QUEUE_FULL;
    }
    l->st.tx_frames++;
    l->st.tx_bytes += (uint32_t)n;
    l->tx_ok_pending++;
    return BR_OK;
}

/* A delimiter ended the block acc[0..acc_len). */
static void end_block(uart_link_t *l)
{
    size_t enc = l->acc_len;
    l->acc_len = 0u;
    if (enc == 0u) {
        return; /* 0x00 0x00: idle delimiter, nothing to deliver */
    }
    size_t out = 0;
    if (br_cobs_decode(l->acc, enc, l->dec, sizeof l->dec, &out) != BR_OK || out == 0u) {
        l->st.cobs_err++;
        return;
    }
    l->st.rx_frames++;
    l->on_frame(l->frame_ctx, l->dec, out);
}

void uart_link_feed(uart_link_t *l, const uint8_t *bytes, size_t n)
{
    if (l == NULL || bytes == NULL) {
        return;
    }
    l->st.rx_bytes += (uint32_t)n;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = bytes[i];
        if (b == BR_COBS_DELIM) {
            if (l->discarding) {
                l->discarding = false;
                l->acc_len = 0u;
                l->st.resyncs++;
            } else {
                end_block(l);
            }
            continue;
        }
        if (l->discarding) {
            continue;
        }
        if (l->acc_len >= sizeof l->acc) {
            l->st.oversize++;
            l->acc_len = 0u;
            l->discarding = true;
            continue;
        }
        l->acc[l->acc_len] = b;
        l->acc_len++;
    }
}

void uart_link_rx_lost(uart_link_t *l)
{
    if (l == NULL) {
        return;
    }
    l->st.rx_lost++;
    if (l->acc_len > 0u) {
        l->acc_len = 0u;
        l->discarding = true;
    }
}

bool uart_link_deliver(uart_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr,
                       const uint8_t *frame, size_t len, br_rx_verdict_t *verdict_out)
{
    if (l == NULL || node == NULL || frame == NULL) {
        return false;
    }
    bool check = true;
    const uint8_t *view = frame;
#ifndef BR_FIELD_BUILD
    if (tr != NULL && tr->allowlist.enabled && tr->rs_nsym > 0u && len > tr->rs_nsym &&
        len <= sizeof l->rs_scratch) {
        memcpy(l->rs_scratch, frame, len);
        uint8_t fixed = 0;
        if (br_rs_decode(l->rs_scratch, len, tr->rs_nsym, NULL, 0u, &fixed) == BR_OK) {
            view = l->rs_scratch;
        } else {
            check = false; /* uncorrectable: the node drops and counts it (rs_fail) */
        }
    }
#endif
    if (check && !br_transport_admit(tr, view, len)) {
        l->st.allowlist_drop++;
        return false;
    }
    br_rx_meta_t m;
    memset(&m, 0, sizeof m);
    m.addr_len = 0u;
    m.rssi = (int8_t)BR_RSSI_UNKNOWN;
    (void)br_node_rx(node, frame, len, link, &m, verdict_out);
    return true;
}

uint32_t uart_link_report_tx_status(uart_link_t *l, br_node_t *node, uint8_t link)
{
    if (l == NULL || node == NULL) {
        return 0u;
    }
    uint32_t n = l->tx_ok_pending;
    l->tx_ok_pending = 0u;
    for (uint32_t i = 0; i < n; i++) {
        (void)br_node_tx_status(node, link, NULL, 0u, true);
    }
    l->st.tx_status += n;
    return n;
}

void uart_link_get_stats(const uart_link_t *l, uart_link_stats_t *out)
{
    if (l == NULL || out == NULL) {
        return;
    }
    *out = l->st;
}
