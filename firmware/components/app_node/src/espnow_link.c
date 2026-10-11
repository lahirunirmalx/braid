// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * espnow_link.c - ESP-NOW transmit deferral for the 12.4 bridge arbitration
 * (see espnow_link.h). Portable C11; host-tested by
 * firmware/test/host/test_radio_arb.c.
 */
#include "espnow_link.h"

#include <string.h>

#include "braid/br_platform.h"

bool espnow_link_init(espnow_link_t *l, espnow_link_raw_send_fn raw, void *raw_user, radio_arb_t *arb)
{
    if (l == NULL || raw == NULL) {
        return false;
    }
    memset(l, 0, sizeof *l);
    l->raw = raw;
    l->raw_user = raw_user;
    l->arb = arb;
    return true;
}

static bool now_us(uint64_t *out)
{
    br_platform_t p;
    if (br_platform_get(&p) != BR_OK || p.now_us == NULL) {
        return false;
    }
    *out = p.now_us(p.user);
    return true;
}

static void enqueue(espnow_link_t *l, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    espnow_txq_entry_t *e = &l->q[(uint8_t)((l->head + l->count) % ESPNOW_LINK_TXQ)];
    e->bcast = addr == NULL;
    if (addr != NULL) {
        memcpy(e->addr, addr, ESPNOW_LINK_ADDR_LEN);
    } else {
        memset(e->addr, 0xFF, ESPNOW_LINK_ADDR_LEN);
    }
    e->len = len;
    memcpy(e->data, frame, len);
    l->count++;
    l->st.deferred++;
}

/* Hand queued frames to the raw send, front first, while the arbiter allows. */
static void drain(espnow_link_t *l, uint64_t now)
{
    while (l->count > 0u && radio_arb_espnow_may_start(l->arb, now)) {
        const espnow_txq_entry_t *e = &l->q[l->head];
        br_err_t rc = l->raw(l->raw_user, e->bcast ? NULL : e->addr, e->data, e->len);
        if (rc == BR_OK) {
            l->st.drained++;
        } else {
            l->st.drain_err++;
        }
        l->head = (uint8_t)((l->head + 1u) % ESPNOW_LINK_TXQ);
        l->count--;
    }
}

br_err_t espnow_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    espnow_link_t *l = (espnow_link_t *)user;
    if (l == NULL || l->raw == NULL) {
        return BR_ERR_ARG;
    }
    if (frame == NULL || len == 0u || len > ESPNOW_LINK_MAX_FRAME) {
        l->st.bad_len++;
        return len > ESPNOW_LINK_MAX_FRAME ? BR_ERR_TOO_BIG : BR_ERR_ARG;
    }
    uint64_t now = 0;
    if (!now_us(&now)) {
        l->st.direct++;
        return l->raw(l->raw_user, addr, frame, len);
    }
    if (l->count == 0u) {
        if (radio_arb_espnow_may_start(l->arb, now)) {
            l->st.direct++;
            return l->raw(l->raw_user, addr, frame, len);
        }
    } else {
        drain(l, now); /* frames held earlier go first, if they may now */
        if (l->count == 0u && radio_arb_espnow_may_start(l->arb, now)) {
            l->st.direct++;
            return l->raw(l->raw_user, addr, frame, len);
        }
    }
    if (l->count >= ESPNOW_LINK_TXQ) {
        l->st.qfull++;
        return BR_ERR_QUEUE_FULL;
    }
    enqueue(l, addr, frame, len);
    return BR_OK;
}

uint64_t espnow_link_pump(espnow_link_t *l, uint64_t now)
{
    if (l == NULL || l->raw == NULL) {
        return UINT64_MAX;
    }
    drain(l, now);
    return l->count > 0u ? now + RADIO_ARB_RECHECK_US : UINT64_MAX;
}

uint8_t espnow_link_pending(const espnow_link_t *l)
{
    return l == NULL ? 0u : l->count;
}

void espnow_link_get_stats(const espnow_link_t *l, espnow_link_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    if (l == NULL) {
        memset(out, 0, sizeof *out);
        return;
    }
    *out = l->st;
}
