// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_link_hal.h - the nrf24_radio_ops_t table that drives hal_nrf24.h
 * (device only; see nrf24_link_hal.c). node_app passes it to
 * nrf24_link_register() after hal_nrf24_init() succeeded.
 */
#ifndef NRF24_LINK_HAL_H
#define NRF24_LINK_HAL_H

#include "nrf24_link.h"

#ifdef __cplusplus
extern "C" {
#endif

const nrf24_radio_ops_t *nrf24_link_hal_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* NRF24_LINK_HAL_H */
