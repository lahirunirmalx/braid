// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * espnow_link.h - ESP-NOW transmit deferral for the 12.4 bridge arbitration
 * (firmware/RADIO-ARB.txt, radio_arb.h). Portable C11: no ESP-IDF, FreeRTOS
 * or HAL header. It sits between the node and the existing ESP-NOW send
 * function (node_app.cpp tr_send -> hal_radio_send), which is injected as
 * `raw`, so the same file is host-tested (firmware/test/host/
 * test_radio_arb.c includes espnow_link.c) and on the device wraps the
 * unchanged port.
 *
 * espnow_link_send() is the br_transport_t.send of the "espnow" transport:
 *   - queue empty and radio_arb_espnow_may_start() true: raw send at once,
 *     its result returned unchanged (single-radio boards always take this
 *     path: zero added latency, the queue is never used);
 *   - otherwise (the nRF24 radio is busy, or older frames are still queued
 *     and order must be kept): the frame is copied into a static FIFO of
 *     ESPNOW_LINK_TXQ frames and BR_OK is returned. A held BIND / HELLO /
 *     SEEK is thus delayed, never refused (a refusal would cost a whole
 *     retry round; ARQ would only cover DATA);
 *   - FIFO full: BR_ERR_QUEUE_FULL, the code tr_send already returns for a
 *     busy radio (HAL_ERR_BUSY), counted in `qfull`.
 * espnow_link_pump() drains the FIFO in order while the arbiter allows it;
 * call it from the protocol task next to nrf24_link_pump() and cap the
 * task's queue wait at its return value. A queued frame the raw send then
 * refuses is dropped and counted in `drain_err` (the node was already told
 * BR_OK; the raw send still counts its own refusal, node_app g_send_refused).
 *
 * The clock for send() is br_platform now_us (br_platform_set() must have
 * run, as for the core); without it frames pass straight through.
 *
 * Threading: one owner task (Braid: the protocol task). send() is
 * called by the core from that task; the pump from the same task.
 */
#ifndef ESPNOW_LINK_H
#define ESPNOW_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "braid/br_types.h"
#include "radio_arb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESPNOW_LINK_ADDR_LEN   6u
#define ESPNOW_LINK_MAX_FRAME  250u   /**< ESP-NOW v1 payload = Braid max_frame on mesh carriers */
#define ESPNOW_LINK_TXQ        4u     /**< deferred frames (static, 4 x ~260 B) */

/** The wrapped send, br_transport_t.send signature (addr NULL = broadcast). */
typedef br_err_t (*espnow_link_raw_send_fn)(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);

typedef struct {
    uint32_t direct;       /**< frames handed to the raw send at once from send() */
    uint32_t deferred;     /**< frames queued instead (BRSTAT arb_defer) */
    uint32_t drained;      /**< queued frames handed to the raw send later */
    uint32_t qfull;        /**< send() refused, FIFO full (BR_ERR_QUEUE_FULL; BRSTAT arb_qfull) */
    uint32_t drain_err;    /**< queued frames the raw send refused (dropped; BRSTAT arb_derr) */
    uint32_t bad_len;      /**< send() with len 0 / > 250 / NULL frame (raw send never called) */
} espnow_link_stats_t;

typedef struct {
    uint8_t  addr[ESPNOW_LINK_ADDR_LEN];
    bool     bcast;
    uint16_t len;
    uint8_t  data[ESPNOW_LINK_MAX_FRAME];
} espnow_txq_entry_t;

/** Wrapper state. Treat every field as private. Statically allocatable. */
typedef struct {
    espnow_link_raw_send_fn raw;
    void                   *raw_user;
    radio_arb_t            *arb;        /**< NULL = no arbitration (pure pass-through) */
    espnow_txq_entry_t      q[ESPNOW_LINK_TXQ];
    uint8_t                 head;
    uint8_t                 count;
    espnow_link_stats_t     st;
} espnow_link_t;

/**
 * Reset the wrapper. `arb` may be NULL (pass-through) or an arbiter that
 * radio_arb_init() sets up later (an all-zero radio_arb_t allows every
 * start, so the order of the two inits does not matter).
 * @return false on NULL l or raw.
 */
bool espnow_link_init(espnow_link_t *l, espnow_link_raw_send_fn raw, void *raw_user, radio_arb_t *arb);

/** br_transport_t.send (user = the espnow_link_t). See the file header. */
br_err_t espnow_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);

/**
 * Drain queued frames while the arbiter allows. Call from the owner task,
 * outside any br_node_* call, on every wake-up.
 * @return Absolute time by which it wants to run again: now +
 *         RADIO_ARB_RECHECK_US while frames are held, UINT64_MAX when the
 *         FIFO is empty.
 */
uint64_t espnow_link_pump(espnow_link_t *l, uint64_t now_us);

/** Frames waiting in the FIFO. */
uint8_t espnow_link_pending(const espnow_link_t *l);

/** Copy the counters (zeros for NULL l). */
void espnow_link_get_stats(const espnow_link_t *l, espnow_link_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ESPNOW_LINK_H */
