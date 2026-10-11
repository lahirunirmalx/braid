// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_link.h - Braid nRF24L01+ transport adapter (PACKET link class,
 * spec 1.2 nRF24 row, 11.3, 11.6, 11.11, 12.4, Appendix C.5). Portable C11:
 * no ESP-IDF, FreeRTOS or HAL header. The radio below it is an injected
 * payload-level ops table (nrf24_radio_ops_t) so the same file is
 * host-tested with a fake ESB medium (firmware/test/host/test_nrf24_link.c
 * includes nrf24_link.c directly) and on the device sits on hal_nrf24.h
 * through nrf24_link_hal.c (nrf24_link_hal_ops()).
 *
 * Transport facts (nrf24_link_fill_transport(), spec 1.2 table):
 *   link_class PACKET, max_frame 250 (segmentation is link-local, C.5; the
 *   path MTU never sees 32, 11.3), rs_nsym 0, can_broadcast true (floods on
 *   the shared broadcast address with NO_ACK), mac_retry true (ESB auto-ACK
 *   with ARC retries; MAX_RT is the 11.6 failover signal), edge_only false,
 *   link_cost 2 (no RSSI, 11.2), addr_len 5.
 *
 * Addresses (C.5): unit U listens on `50 4C U_hi U_lo A5` (pipe 0, auto-ACK)
 * and every node listens on `50 4C FF FF A5` (pipe 1, floods). The link
 * table address is derived from the unit ID, never learnt: the RX hint
 * passed to br_node_rx() is the address of the header prev_hop (bytes 6..7,
 * frozen prefix), addr_len 5, rssi BR_RSSI_UNKNOWN.
 *
 * Transmit: send() only queues the frame (NRF24_LINK_TXQ_DEFAULT frames)
 * and returns; nrf24_link_pump() runs the half-duplex state machine from
 * the owner task: leave PRX, program TX_ADDR (+ pipe 0 for the ACK), send
 * the segments one at a time (TX_DS -> next segment; MAX_RT -> abort the
 * frame, FLUSH_TX, delivered = false), then back to PRX with a guard of
 * NRF_GUARD_MS (2 ms, C.5) before the next frame. Unicast frames report
 * br_node_tx_status(delivered) once per frame, from the pump, never from
 * inside send() (br_node_rx() may call send() synchronously). Broadcast
 * segments use W_TX_PAYLOAD_NO_ACK and report nothing. While the chip is in
 * PTX it hears nothing: a neighbour's auto-ACK segments to us are retried by
 * its ESB (ARC 15 x ARD 500 us = 7.5 ms) which covers our 3-4 ms frames.
 *
 * Receive: the pump drains the RX FIFO (pipes 0 and 1), feeds the segments
 * to nrf24_seg, and each reassembled frame goes br_transport_admit() (bench
 * allowlist, N22) -> br_node_rx() with the prev_hop hint. The nRF24 RX FIFO
 * is 3 payloads deep; the ESB grace above means the pump must run at least
 * every ~5 ms while listening: use the IRQ pin to wake the task, or poll
 * at cfg.poll_us (default 2 ms). Reassembly drops (nrf24_seg_stats_t
 * frames_dropped: timeout, gap, foreign tag, oversize, buffer full) are
 * reported to the core's seg_fail counter through br_node_count_seg_fail(),
 * one call per dropped frame, from the pump; orphan segments are not
 * (SPEC-NOTES N59). The detailed counters stay here.
 *
 * Collision avoidance on one half-duplex radio (no carrier sense in ESB):
 * the pump does not start a frame within cfg.rx_hold_us (1 ms) of the last
 * segment received, open frame or just completed. An open frame means the
 * neighbour is mid-transmission to us; a just-completed one may be followed
 * by a retransmit of its LAST segment when our ACK was lost (ARD 500 us),
 * which the hardware acknowledges only while we are in PRX. The hold is
 * shorter than the transmitter's guard (2 ms), so a reply always starts
 * inside the peer's guard and its first segment opens a buffer there before
 * the peer's next frame is due. A head-on start (both in PTX, both deaf)
 * remains possible when two ACKs in a row are lost; it ends in MAX_RT on
 * both sides after ARC x ARD (7.5 ms) and is reported through 11.6.
 *
 * 12.4 coexistence hooks: nrf24_link_radio_busy() is true while this radio
 * is mid-transmit or within that hold; a bridge that also owns the ESP-NOW
 * radio consults it before starting an ESP-NOW transmit. The other
 * direction is nrf24_link_set_tx_gate(): an optional gate the pump asks
 * right before it starts a frame (never between the segments of a frame
 * already started); while the gate says no, the frame stays queued and the
 * pump retries every tx_poll_us. The policy (what is "busy", the hold cap)
 * lives in the caller (app_node radio_arb.c, firmware/RADIO-ARB.txt); no
 * gate = today's behaviour.
 *
 * Threading: one owner task (Braid: the protocol task). send() is
 * called by the core from that same task. Not reentrant across tasks.
 */
#ifndef NRF24_LINK_H
#define NRF24_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nrf24_regs.h"
#include "nrf24_seg.h"
#include "braid/br_node.h"
#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NRF24_LINK_MAX_FRAME      NRF24_SEG_MAX_FRAME   /**< 250 */
#define NRF24_LINK_ADDR_LEN       5u
#define NRF24_LINK_COST           2u                    /**< C.5 / 11.2 */
#define NRF24_LINK_TXQ_MAX        8u
#define NRF24_LINK_TXQ_DEFAULT    4u
#define NRF24_LINK_GUARD_US       2000u                 /**< C.5 NRF_GUARD_MS */
#define NRF24_LINK_TX_TIMEOUT_US  20000u                /**< no TX_DS / MAX_RT: chip or bus stuck */
#define NRF24_LINK_RX_HOLD_US     1000u                 /**< post-RX hold and 12.4 "mid-reception" window; < guard */
#define NRF24_LINK_POLL_US        2000u                 /**< RX poll period while listening */
#define NRF24_LINK_TX_POLL_US     500u                  /**< status poll period mid-frame */
#define NRF24_LINK_CH_MIN         76u                   /**< C.5 */
#define NRF24_LINK_CH_MAX         83u                   /**< 82..83 only below 2 Mbps */
#define NRF24_LINK_CH_MAX_2M      81u

/** The shared broadcast address (C.5). */
extern const uint8_t NRF24_LINK_BCAST_ADDR[NRF24_LINK_ADDR_LEN];

/** C.5 unicast address of a unit: 50 4C U_hi U_lo A5. */
void nrf24_link_unit_addr(uint16_t unit_id, uint8_t out[NRF24_LINK_ADDR_LEN]);

/**
 * Payload-level radio operations (one radio instance = `radio`). All return
 * true on success. status() returns the STATUS byte (NRF24_ST_* bits,
 * NRF24_ST_INVALID on a bus failure). read_payload() returns false when the
 * RX FIFO is empty or on error. tx_abort() flushes the TX FIFO and clears
 * MAX_RT | TX_DS (MAX_RT recovery). On the device nrf24_link_hal_ops() maps
 * these onto hal_nrf24.h.
 */
typedef struct {
    void    *radio;
    bool    (*set_rx_address)(void *radio, uint8_t pipe, const uint8_t *addr);
    bool    (*set_tx_address)(void *radio, const uint8_t *addr);
    bool    (*write_payload)(void *radio, const uint8_t *buf, uint8_t len, bool no_ack);
    bool    (*start_tx)(void *radio);
    bool    (*read_payload)(void *radio, uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out);
    uint8_t (*status)(void *radio);
    bool    (*clear_irq)(void *radio, uint8_t mask);
    bool    (*tx_abort)(void *radio);
    bool    (*start_listening)(void *radio);
    bool    (*stop_listening)(void *radio);
} nrf24_radio_ops_t;

typedef struct {
    uint16_t unit_id;            /**< our unit ID: own address and segment src byte */
    uint8_t  reasm_slots;        /**< 0 = NRF24_SEG_SLOTS_DEFAULT (4) */
    uint32_t reasm_timeout_ms;   /**< 0 = NRF24_SEG_TIMEOUT_MS_DEFAULT (50) */
    uint32_t guard_us;           /**< 0 = NRF24_LINK_GUARD_US */
    uint32_t tx_timeout_us;      /**< 0 = NRF24_LINK_TX_TIMEOUT_US */
    uint32_t rx_hold_us;         /**< 0 = NRF24_LINK_RX_HOLD_US */
    uint32_t poll_us;            /**< 0 = NRF24_LINK_POLL_US */
    uint32_t tx_poll_us;         /**< 0 = NRF24_LINK_TX_POLL_US */
    uint8_t  txq_frames;         /**< 0 = NRF24_LINK_TXQ_DEFAULT, <= NRF24_LINK_TXQ_MAX */
} nrf24_link_cfg_t;

typedef struct {
    uint32_t tx_queued;          /**< frames accepted by send() */
    uint32_t tx_frames;          /**< frames whose every segment got TX_DS */
    uint32_t tx_unicast;         /**< of tx_frames */
    uint32_t tx_bcast;           /**< of tx_frames */
    uint32_t tx_segments;        /**< segments handed to the radio */
    uint32_t tx_refused;         /**< send() refused: queue full (frame lost, BR_ERR_QUEUE_FULL) */
    uint32_t tx_bad_len;         /**< send() with len 0 or > 250 */
    uint32_t tx_max_rt;          /**< unicast frames abandoned on MAX_RT */
    uint32_t tx_stuck;           /**< frames abandoned: no TX_DS / MAX_RT within tx_timeout_us */
    uint32_t tx_radio_err;       /**< radio op failures during transmit (frame abandoned) */
    uint32_t tx_deferred;        /**< pump passes that held a frame back because a neighbour was mid-frame */
    uint32_t tx_status_ok;       /**< br_node_tx_status(delivered = true) reports */
    uint32_t tx_status_fail;     /**< br_node_tx_status(delivered = false) reports */
    uint32_t rx_segments;        /**< payloads read from the RX FIFO */
    uint32_t rx_frames;          /**< frames handed to br_node_rx() */
    uint32_t rx_admit_drop;      /**< frames refused by the bench allowlist (N22) */
    uint32_t rx_src_mismatch;    /**< segment src byte != low byte of header prev_hop (delivered anyway, the CRC decides) */
    uint32_t rx_bad_pipe;        /**< payloads on a pipe other than 0 / 1 (discarded) */
    uint32_t rx_radio_err;       /**< status / read failures while draining */
} nrf24_link_stats_t;

typedef enum { NRF24_TX_IDLE = 0, NRF24_TX_SENDING, NRF24_TX_GUARD } nrf24_tx_state_t;

/**
 * 12.4 transmit gate: return true to let the pump start the frame at the
 * queue front now, false to hold it (asked again at the next pump pass,
 * at most tx_poll_us later). Called from the pump only (owner task).
 */
typedef bool (*nrf24_link_tx_gate_fn)(void *ctx, uint64_t now_us);

typedef struct {
    uint8_t  addr[NRF24_LINK_ADDR_LEN];
    bool     bcast;
    uint16_t len;
    uint8_t  data[NRF24_LINK_MAX_FRAME];
} nrf24_txq_entry_t;

/** Adapter state. Treat every field as private. Statically allocatable. */
typedef struct {
    nrf24_radio_ops_t  ops;
    nrf24_link_cfg_t   cfg;
    nrf24_seg_t        seg;
    uint8_t            own_addr[NRF24_LINK_ADDR_LEN];
    uint8_t            link;             /**< transport index in the node */
    bool               started;
    br_node_t         *node;             /**< set by the pump for the frame callback */
    nrf24_txq_entry_t  txq[NRF24_LINK_TXQ_MAX];
    uint8_t            txq_head;
    uint8_t            txq_count;
    nrf24_tx_state_t   tx_state;
    nrf24_seg_tx_t     tx_it;
    uint64_t           tx_seg_started_us;
    uint64_t           guard_until_us;
    uint8_t            pkt[NRF24_SEG_PKT_MAX];
    uint32_t           seg_dropped_reported; /**< frames_dropped already passed to br_node_count_seg_fail() */
    nrf24_link_tx_gate_fn tx_gate;       /**< 12.4 gate, NULL = none (nrf24_link_set_tx_gate()) */
    void              *tx_gate_ctx;
    nrf24_link_stats_t st;
} nrf24_link_t;

/**
 * Reset the adapter: copy cfg (defaults for zero fields) and ops, derive
 * the own address, set up reassembly. The radio itself must already be
 * initialised (hal_nrf24_init() on the device).
 * @return false on NULL arguments, a missing op, a non-unit unit_id or
 *         txq_frames / reasm_slots out of range.
 */
bool nrf24_link_init(nrf24_link_t *l, const nrf24_link_cfg_t *cfg, const nrf24_radio_ops_t *ops);

/**
 * Fill the 1.2 transport fields for this link (name "nrf24", see the file
 * header) with send = nrf24_link_send and user = l. The allowlist is left
 * untouched (the caller sets it).
 */
void nrf24_link_fill_transport(nrf24_link_t *l, br_transport_t *tr);

/**
 * nrf24_link_init() + fill the next free slot of nc->transports (its index
 * becomes the adapter's link index) and bump nc->n_transports.
 * @return BR_OK; BR_ERR_ARG on bad arguments; BR_ERR_TOO_BIG when every
 *         BR_NODE_MAX_TRANSPORTS slot is taken.
 */
br_err_t nrf24_link_register(nrf24_link_t *l, br_node_config_t *nc, const nrf24_link_cfg_t *cfg,
                             const nrf24_radio_ops_t *ops);

/**
 * Program pipe 0 = own address, pipe 1 = broadcast and enter PRX. Call
 * after br_node_init(); send() refuses frames (BR_ERR_STATE) before it.
 * @return false if a radio op failed.
 */
bool nrf24_link_start(nrf24_link_t *l);

/**
 * br_transport_t.send: queue one frame. addr NULL = broadcast (NO_ACK
 * segments); otherwise the 5-byte next-hop address (auto-ACK segments).
 * @return BR_OK queued; BR_ERR_ARG NULL user / frame or len 0;
 *         BR_ERR_TOO_BIG len > 250; BR_ERR_STATE not started;
 *         BR_ERR_QUEUE_FULL queue full (counted, frame lost).
 */
br_err_t nrf24_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);

/**
 * Drive the radio from the owner task, outside any br_node_* call: drain
 * the RX FIFO into reassembly (frames reach br_node_rx()), expire
 * reassembly buffers, advance the transmit state machine, report
 * delivery verdicts (br_node_tx_status()). Call on every wake-up (IRQ
 * event, queue event, deadline) and at least every cfg.poll_us while
 * listening.
 *
 * @param now_us  Same clock as br_platform now_us.
 * @return Absolute time by which the pump wants to run again (never later
 *         than now + poll_us while started); UINT64_MAX if not started.
 */
uint64_t nrf24_link_pump(nrf24_link_t *l, br_node_t *node, uint64_t now_us);

/** 12.4 hook: true while transmitting or while a neighbour is mid-frame to us. */
bool nrf24_link_radio_busy(const nrf24_link_t *l, uint64_t now_us);

/**
 * 12.4 hook, other direction: install (gate != NULL) or remove (NULL) the
 * transmit gate described in the file header. Call after nrf24_link_init()
 * / nrf24_link_register() (init clears it).
 */
void nrf24_link_set_tx_gate(nrf24_link_t *l, nrf24_link_tx_gate_fn gate, void *ctx);

/** Frames waiting in the TX queue (including the one in flight). */
uint8_t nrf24_link_tx_pending(const nrf24_link_t *l);

/** Copy the adapter counters. */
void nrf24_link_get_stats(const nrf24_link_t *l, nrf24_link_stats_t *out);

/** Copy the reassembly counters. */
void nrf24_link_get_seg_stats(const nrf24_link_t *l, nrf24_seg_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NRF24_LINK_H */
