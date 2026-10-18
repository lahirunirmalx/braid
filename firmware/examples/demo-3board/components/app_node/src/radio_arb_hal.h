// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * radio_arb_hal.h - device glue for the 12.4 bridge arbitration: wires
 * radio_arb (portable) to the two real busy signals, hal_radio_tx_inflight()
 * (ESP-NOW, port_espnow.cpp) and nrf24_link_radio_busy() (nRF24 adapter),
 * and installs the arbiter as the nRF24 pump's transmit gate.
 *
 * The only arbitration file that includes a HAL header; host tests never
 * compile it (they wire fakes through radio_arb_init() directly).
 * Integration lines for node_app.cpp: firmware/RADIO-ARB.txt.
 */
#ifndef RADIO_ARB_HAL_H
#define RADIO_ARB_HAL_H

#include <stdbool.h>
#include <stdint.h>

#include "nrf24_link.h"
#include "radio_arb.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * radio_arb_init() for this board: ESP-NOW present when `espnow` is true,
 * nRF24 present when `nrf` is non-NULL (then the arbiter is also installed
 * as its transmit gate, nrf24_link_set_tx_gate()). Call after
 * nrf24_link_register() (its init clears the gate) and before the first
 * frame is sent. Either radio absent: every start goes at once.
 * @return false on NULL a.
 */
bool radio_arb_setup_board(radio_arb_t *a, bool espnow, nrf24_link_t *nrf);

/** radio_arb_busy_fn for ESP-NOW: hal_radio_tx_inflight() > 0 (ctx unused). */
bool radio_arb_hal_espnow_busy(void *ctx, uint64_t now_us);

/** radio_arb_busy_fn for nRF24: nrf24_link_radio_busy(ctx, now_us). */
bool radio_arb_hal_nrf24_busy(void *ctx, uint64_t now_us);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_ARB_HAL_H */
