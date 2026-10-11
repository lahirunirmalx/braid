// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_link_hal.c - device glue: nrf24_radio_ops_t over hal_nrf24.h.
 *
 * The only file of this component that includes a HAL header; host tests
 * never compile it. hal_nrf24 is a singleton (one radio per board), so the
 * `radio` instance pointer is ignored.
 */
#include "nrf24_link_hal.h"

#include "hal_nrf24.h"

static bool g_set_rx_address(void *radio, uint8_t pipe, const uint8_t *addr)
{
    (void)radio;
    return hal_nrf24_set_rx_address(pipe, addr, true) == HAL_OK;
}

static bool g_set_tx_address(void *radio, const uint8_t *addr)
{
    (void)radio;
    return hal_nrf24_set_tx_address(addr) == HAL_OK;
}

static bool g_write_payload(void *radio, const uint8_t *buf, uint8_t len, bool no_ack)
{
    (void)radio;
    return hal_nrf24_write_payload(buf, len, no_ack) == HAL_OK;
}

static bool g_start_tx(void *radio)
{
    (void)radio;
    return hal_nrf24_start_tx() == HAL_OK;
}

static bool g_read_payload(void *radio, uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out)
{
    (void)radio;
    return hal_nrf24_read_payload(pipe_out, buf, len_out) == HAL_OK;
}

static uint8_t g_status(void *radio)
{
    (void)radio;
    return hal_nrf24_status();
}

static bool g_clear_irq(void *radio, uint8_t mask)
{
    (void)radio;
    return hal_nrf24_clear_irq(mask) == HAL_OK;
}

static bool g_tx_abort(void *radio)
{
    (void)radio;
    return hal_nrf24_tx_abort() == HAL_OK;
}

static bool g_start_listening(void *radio)
{
    (void)radio;
    return hal_nrf24_start_listening() == HAL_OK;
}

static bool g_stop_listening(void *radio)
{
    (void)radio;
    return hal_nrf24_stop_listening() == HAL_OK;
}

static const nrf24_radio_ops_t g_ops = {
    NULL,
    g_set_rx_address,
    g_set_tx_address,
    g_write_payload,
    g_start_tx,
    g_read_payload,
    g_status,
    g_clear_irq,
    g_tx_abort,
    g_start_listening,
    g_stop_listening,
};

const nrf24_radio_ops_t *nrf24_link_hal_ops(void)
{
    return &g_ops;
}
