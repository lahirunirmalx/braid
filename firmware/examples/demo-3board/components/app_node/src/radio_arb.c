// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * radio_arb.c - 12.4 bridge radio arbitration (see radio_arb.h).
 * Portable C11; host-tested by firmware/test/host/test_radio_arb.c.
 */
#include "radio_arb.h"

#include <stddef.h>
#include <string.h>

void radio_arb_default_cfg(radio_arb_cfg_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof *cfg);
    cfg->cap_us = RADIO_ARB_CAP_US_DEFAULT;
}

bool radio_arb_init(radio_arb_t *a, const radio_arb_cfg_t *cfg)
{
    if (a == NULL || cfg == NULL) {
        return false;
    }
    memset(a, 0, sizeof *a);
    a->cfg = *cfg;
    if (a->cfg.cap_us == 0u) {
        a->cfg.cap_us = RADIO_ARB_CAP_US_DEFAULT;
    }
    return true;
}

bool radio_arb_is_bridge(const radio_arb_t *a)
{
    return a != NULL && a->cfg.nrf_busy != NULL && a->cfg.espnow_busy != NULL;
}

/*
 * One direction: `other_busy` is the other radio's signal right now.
 * Returns true when the start may go.
 */
static bool may_start(radio_arb_t *a, radio_arb_dir_t *d, bool other_busy, uint64_t now_us, uint32_t *hold_ctr)
{
    if (!other_busy) {
        d->holding = false;
        d->stale = false;
        return true;
    }
    if (d->stale) {
        a->st.timeout++;
        return true;
    }
    if (!d->holding) {
        d->holding = true;
        d->since_us = now_us;
        (*hold_ctr)++;
    }
    if (now_us - d->since_us >= a->cfg.cap_us) {
        d->holding = false;
        d->stale = true;
        a->st.timeout++;
        return true;
    }
    return false;
}

bool radio_arb_espnow_may_start(radio_arb_t *a, uint64_t now_us)
{
    if (!radio_arb_is_bridge(a)) {
        return true;
    }
    bool busy = a->cfg.nrf_busy(a->cfg.nrf_ctx, now_us);
    return may_start(a, &a->espnow, busy, now_us, &a->st.hold_espnow);
}

bool radio_arb_nrf_may_start(void *ctx, uint64_t now_us)
{
    radio_arb_t *a = (radio_arb_t *)ctx;
    if (!radio_arb_is_bridge(a)) {
        return true;
    }
    bool busy = a->cfg.espnow_busy(a->cfg.espnow_ctx, now_us);
    return may_start(a, &a->nrf, busy, now_us, &a->st.hold_nrf);
}

void radio_arb_get_stats(const radio_arb_t *a, radio_arb_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    if (a == NULL) {
        memset(out, 0, sizeof *out);
        return;
    }
    *out = a->st;
}
