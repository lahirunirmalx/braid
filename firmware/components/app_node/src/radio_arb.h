// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * radio_arb.h - 12.4 bridge radio arbitration (PROTOCOL.md v0.8 12.4: "a
 * bridge never starts a transmission on one radio while the other is
 * mid-reception of a multi-segment frame"; SPEC-NOTES N60, N62).
 *
 * Portable C11: no ESP-IDF, FreeRTOS, HAL or adapter header. The two radios
 * are seen only through injected "busy" queries, so the same file is
 * host-tested (firmware/test/host/test_radio_arb.c includes radio_arb.c)
 * and on the device is wired by radio_arb_hal.c (radio_arb_setup_board()).
 * Design and integration lines: firmware/RADIO-ARB.txt.
 *
 * What each side can observe (the fidelity table of RADIO-ARB.txt):
 *   - nRF24 busy (nrf24_link_radio_busy()): own transmit in progress, or
 *     less than 1 ms since the last received segment (a neighbour is
 *     mid-frame to us, N60). Good fidelity.
 *   - ESP-NOW busy (hal_radio_tx_inflight() > 0): a frame of ours between
 *     esp_now_send() and its send callback. Transmit only: ESP-NOW reception
 *     is invisible to the application.
 *   - WiFi STA (LAN side, lwIP): nothing is observable; not arbitrated.
 *
 * Decisions: radio_arb_espnow_may_start() (asked by espnow_link before every
 * ESP-NOW start) and radio_arb_nrf_may_start() (installed as the nRF24
 * pump's transmit gate). Both run in the one protocol task ("br"), so the
 * state below needs no atomics; the busy queries read whatever the radios
 * publish (the ESP-NOW count is a std::atomic inside the port).
 *
 * Hold rule, per direction: while the OTHER radio reads busy, a start is
 * refused (the frame stays queued; hold_* counts once per held frame).
 * Bounded hold: once one hold has lasted cap_us (default 20 ms, a 9-segment
 * nRF24 frame at 2 ms polling is about 18 ms busy), the start goes ahead
 * and counts `timeout`, and that busy signal is treated as STALE: further
 * starts in the same direction go at once (each also counts `timeout`)
 * until the signal is read idle once (deliberately not expired by time: a
 * wedged signal then costs one cap in total, not one per traffic burst; the
 * price is that a stale state can outlive a quiet period and let one start
 * through that a fresh hold would have held, counted in `timeout`). This
 * bounds the cost of a wedged
 * signal (an ESP-NOW send callback that never runs, a dropped event) to one
 * cap instead of one cap per frame. `timeout` therefore counts exactly the
 * starts that were made while the other radio read busy.
 *
 * Single radio (one query NULL): the other direction has nothing to wait
 * for; both may_start calls return true at once and count nothing.
 */
#ifndef RADIO_ARB_H
#define RADIO_ARB_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RADIO_ARB_CAP_US_DEFAULT  20000u   /**< longest single hold (~9 nRF24 segments at 2 ms polling) */
#define RADIO_ARB_RECHECK_US      500u     /**< re-ask period while held (= nRF24 tx_poll_us) */

/** "Is this radio busy right now?" Called from the protocol task only. */
typedef bool (*radio_arb_busy_fn)(void *ctx, uint64_t now_us);

typedef struct {
    radio_arb_busy_fn nrf_busy;       /**< NULL: no nRF24 link on this board */
    void             *nrf_ctx;
    radio_arb_busy_fn espnow_busy;    /**< NULL: no ESP-NOW link on this board */
    void             *espnow_ctx;
    uint32_t          cap_us;         /**< 0 = RADIO_ARB_CAP_US_DEFAULT */
} radio_arb_cfg_t;

typedef struct {
    uint32_t hold_espnow;   /**< ESP-NOW frames held because the nRF24 radio was busy (BRSTAT arb_hold_e) */
    uint32_t hold_nrf;      /**< nRF24 frames held because ESP-NOW TX was in flight (BRSTAT arb_hold_n) */
    uint32_t timeout;       /**< starts made while the other radio read busy (cap / stale; BRSTAT arb_to) */
} radio_arb_stats_t;

/** One direction's hold state. Private. */
typedef struct {
    bool     holding;       /**< a frame is being held */
    bool     stale;         /**< the other radio's busy signal is ignored until it reads idle */
    uint64_t since_us;      /**< start of the current hold */
} radio_arb_dir_t;

/** Arbiter state. Treat every field as private. Statically allocatable; all-zero = no radios. */
typedef struct {
    radio_arb_cfg_t   cfg;
    radio_arb_dir_t   espnow;   /**< ESP-NOW starts waiting for the nRF24 radio */
    radio_arb_dir_t   nrf;      /**< nRF24 starts waiting for ESP-NOW */
    radio_arb_stats_t st;
} radio_arb_t;

/** Fill cfg with no radios and the default cap. */
void radio_arb_default_cfg(radio_arb_cfg_t *cfg);

/**
 * Reset the arbiter and copy cfg (cap 0 = default). A zero-initialised
 * radio_arb_t that was never initialised behaves like "no radios" (every
 * start allowed), so callers work before init.
 * @return false on NULL arguments.
 */
bool radio_arb_init(radio_arb_t *a, const radio_arb_cfg_t *cfg);

/** true when both radios are present (only then can anything be held). */
bool radio_arb_is_bridge(const radio_arb_t *a);

/**
 * ESP-NOW side: may an ESP-NOW transmission start now? false = hold it
 * (ask again within RADIO_ARB_RECHECK_US). NULL a = true.
 */
bool radio_arb_espnow_may_start(radio_arb_t *a, uint64_t now_us);

/**
 * nRF24 side, with the nrf24_link_tx_gate_fn signature (ctx = the
 * radio_arb_t): may an nRF24 frame start now? NULL ctx = true.
 */
bool radio_arb_nrf_may_start(void *ctx, uint64_t now_us);

/** Copy the counters (zeros for NULL a). */
void radio_arb_get_stats(const radio_arb_t *a, radio_arb_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* RADIO_ARB_H */
