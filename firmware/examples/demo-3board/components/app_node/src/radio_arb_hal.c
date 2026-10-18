// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * radio_arb_hal.c - device glue for the 12.4 bridge arbitration (see
 * radio_arb_hal.h). Not host-compiled.
 */
#include "radio_arb_hal.h"

#include <stddef.h>

#include "hal_radio.h"

bool radio_arb_hal_espnow_busy(void *ctx, uint64_t now_us)
{
    (void)ctx;
    (void)now_us;
    return hal_radio_tx_inflight() > 0u;
}

bool radio_arb_hal_nrf24_busy(void *ctx, uint64_t now_us)
{
    return nrf24_link_radio_busy((const nrf24_link_t *)ctx, now_us);
}

bool radio_arb_setup_board(radio_arb_t *a, bool espnow, nrf24_link_t *nrf)
{
    if (a == NULL) {
        return false;
    }
    radio_arb_cfg_t cfg;
    radio_arb_default_cfg(&cfg);
    if (espnow) {
        cfg.espnow_busy = radio_arb_hal_espnow_busy;
        cfg.espnow_ctx = NULL;
    }
    if (nrf != NULL) {
        cfg.nrf_busy = radio_arb_hal_nrf24_busy;
        cfg.nrf_ctx = nrf;
    }
    if (!radio_arb_init(a, &cfg)) {
        return false;
    }
    if (nrf != NULL) {
        nrf24_link_set_tx_gate(nrf, radio_arb_nrf_may_start, a);
    }
    return true;
}
