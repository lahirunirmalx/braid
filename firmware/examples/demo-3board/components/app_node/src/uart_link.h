// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * uart_link.h - Braid UART transport adapter (RAW link class, spec 1.2
 * UART row, 3.2, 11.3, 11.11, Appendix C.2). Portable C11: no ESP-IDF,
 * FreeRTOS or HAL header; the byte pipe below it is injected as a write
 * function, so the same file is host-tested
 * (firmware/test/host/test_uart_link.c includes uart_link.c directly) and on
 * the device sits on hal_uart_link.h (node_app.cpp wires it).
 *
 * Per-hop layering on a UART hop (3.2 transmit order frame -> CRC -> RS ->
 * COBS + 0x00):
 *   - the node (br_node.c node_tx / step 1) adds and checks the RS(8) parity
 *     (SPEC-NOTES N42: RS in the node, COBS in the adapter);
 *   - this adapter COBS-encodes the RS block, appends the 0x00 delimiter and
 *     writes it; on receive it splits the byte stream at 0x00, COBS-decodes
 *     each block and hands it (RS parity still attached) to br_node_rx().
 *   COBS bytes are outside max_frame (1.2): a 250-byte RS block is at most
 *   252 bytes on the wire (1 code byte + 250 + delimiter).
 *
 * Transport facts (uart_link_fill_transport(), spec 1.2 table):
 *   link_class RAW, max_frame 250 (incl. 8 RS bytes, so the path MTU through
 *   a UART hop is 242, 11.3), rs_nsym 8, can_broadcast false (point to
 *   point: a "broadcast" goes to the single peer and the node never floods
 *   back over the arrival link, 11.11), mac_retry false, edge_only false,
 *   link_cost 1 (no RSSI, 11.2), addr_len 0 (no carrier address: the
 *   neighbour is known only by the unit ID in the header prev_hop, which the
 *   node learns itself at step 6).
 *
 * Delivery status: a wire has no MAC acknowledgement. Every frame the byte
 * pipe accepted counts as delivered: uart_link_report_tx_status() later
 * calls br_node_tx_status(delivered = true, addr_len 0) once per accepted
 * frame. It is NOT called from inside send() (that would re-enter the node
 * from inside node_tx()). With mac_retry false and addr_len 0 the core
 * ignores the report (br_node.c), so the 11.6 link deletion never fires on
 * UART; a dead cable is detected by the higher layers instead: ARQ retries
 * and N37 (3 unanswered ACK_REQ), keepalive and session timeout, route and
 * link expiry (11.9), then a new SEEK.
 *
 * Receive reassembly (C.2 "resynchronise on any 0x00"):
 *   - bytes accumulate until 0x00; the block is COBS-decoded and delivered;
 *   - an empty block (0x00 0x00) is ignored (the adapter sends one lone
 *     0x00 at start so the peer drops whatever partial frame it holds);
 *   - a block that is not valid COBS is dropped (cobs_err);
 *   - more than UART_LINK_ENC_MAX bytes without a delimiter: the frame is
 *     dropped (oversize) and everything up to the next 0x00 is discarded;
 *   - uart_link_rx_lost() (the byte pipe reported lost bytes) drops a
 *     partial frame the same way;
 *   - each discard that ends at a delimiter counts one resync.
 *   A corrupted 0x00 or COBS code byte breaks framing before RS can act
 *   (3.2): such frames are lost or arrive malformed and are then dropped
 *   by RS / CRC in the node; ARQ recovers them.
 *
 * Bench allowlist (SPEC-NOTES N22, N43): uart_link_deliver() applies
 * br_transport_admit() BEFORE br_node_rx(), as every adapter must. Its
 * prev_hop check is made on an RS-corrected scratch copy (br_bench_allowlist_admit()
 * is specified "after COBS / RS on RAW links"), so line noise on bytes 6..7
 * does not turn into a bogus allowlist drop. If that RS decode fails the
 * frame is passed on unchecked and the node counts it as rs_fail. The node
 * always receives the bytes as they came off the wire and does its own RS.
 *
 * Threading: one owner task for the whole object (Braid: the protocol
 * task; on the device the HAL receive callback only copies byte chunks into
 * the event queue and "br" calls uart_link_feed()). Not reentrant across
 * tasks.
 */
#ifndef UART_LINK_H
#define UART_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "braid/br_cobs.h"
#include "braid/br_node.h"
#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UART_LINK_MAX_FRAME   BR_MAX_FRAME_MESH                         /**< 250, incl. RS parity */
#define UART_LINK_RS_NSYM     BR_RS_NSYM_UART                           /**< 8 */
#define UART_LINK_COST        1u                                        /**< 11.2 fixed cost */
#define UART_LINK_WIRE_MAX    BR_COBS_MAX_ENCODED(UART_LINK_MAX_FRAME)  /**< 252, delimiter included */
#define UART_LINK_ENC_MAX     (UART_LINK_WIRE_MAX - 1u)                 /**< 251 bytes between delimiters */

/**
 * Byte pipe write: queue all len bytes or none, never block.
 * @return true if every byte was queued.
 */
typedef bool (*uart_link_write_fn)(void *ctx, const uint8_t *data, size_t len);

/** One decoded block (RS block: frame || parity), len 1..UART_LINK_MAX_FRAME. */
typedef void (*uart_link_frame_fn)(void *ctx, const uint8_t *frame, size_t len);

typedef struct {
    uint32_t tx_frames;       /**< blocks written (COBS + delimiter) */
    uint32_t tx_bytes;        /**< wire bytes written */
    uint32_t tx_refused;      /**< byte pipe full: frame lost (send() returned BR_ERR_QUEUE_FULL) */
    uint32_t tx_bad_len;      /**< send() with len 0 or > max_frame */
    uint32_t rx_bytes;        /**< bytes fed */
    uint32_t rx_frames;       /**< blocks decoded and handed on */
    uint32_t cobs_err;        /**< delimited block that is not valid COBS (dropped) */
    uint32_t oversize;        /**< > UART_LINK_ENC_MAX bytes without a delimiter (dropped) */
    uint32_t resyncs;         /**< discards that ended on a delimiter */
    uint32_t rx_lost;         /**< loss reports from the byte pipe */
    uint32_t allowlist_drop;  /**< blocks refused by the bench allowlist (N22) */
    uint32_t tx_status;       /**< delivered = true reports passed to the node */
} uart_link_stats_t;

/** Adapter state. Treat every field as private. Statically allocatable. */
typedef struct {
    uart_link_write_fn  write;
    void               *write_ctx;
    uart_link_frame_fn  on_frame;
    void               *frame_ctx;
    uint16_t            acc_len;
    bool                discarding;       /**< hunting for the next 0x00 */
    uint32_t            tx_ok_pending;    /**< accepted frames not yet reported */
    uint8_t             acc[UART_LINK_ENC_MAX];
    uint8_t             dec[UART_LINK_MAX_FRAME];
    uint8_t             tx[UART_LINK_WIRE_MAX];
    uint8_t             rs_scratch[UART_LINK_MAX_FRAME];
    uart_link_stats_t   st;
} uart_link_t;

/**
 * Reset the adapter and install the byte pipe and the frame sink.
 * @return false on NULL arguments (link unchanged).
 */
bool uart_link_init(uart_link_t *l, uart_link_write_fn write, void *write_ctx, uart_link_frame_fn on_frame,
                    void *frame_ctx);

/**
 * Write one lone 0x00 so the peer drops any partial frame (call once after
 * the byte pipe is up). @return the write result.
 */
bool uart_link_start(uart_link_t *l);

/**
 * Fill the 1.2 transport fields for this link (name "uart", see the file
 * header) with send = uart_link_send and user = l. The allowlist is left
 * untouched (the caller sets it).
 */
void uart_link_fill_transport(uart_link_t *l, br_transport_t *tr);

/**
 * br_transport_t.send: COBS-encode frame (an RS block from the node), append
 * 0x00 and write it. addr is ignored (point to point, addr_len 0).
 * @return BR_OK written; BR_ERR_ARG NULL user / frame or len 0;
 *         BR_ERR_TOO_BIG len > UART_LINK_MAX_FRAME; BR_ERR_QUEUE_FULL the
 *         byte pipe refused it (counted, frame lost).
 */
br_err_t uart_link_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len);

/** Feed received bytes (any chunking). Calls on_frame for each complete block. */
void uart_link_feed(uart_link_t *l, const uint8_t *bytes, size_t n);

/** The byte pipe lost bytes: drop the partial frame, hunt for the next 0x00. */
void uart_link_rx_lost(uart_link_t *l);

/**
 * Bench allowlist check (RS-corrected copy, see the file header) and
 * br_node_rx() with a hint carrying no address (addr_len 0, rssi unknown).
 *
 * @param tr           The node's copy of this transport (its allowlist); may be NULL (admit).
 * @param link         Transport index of this adapter in the node.
 * @param verdict_out  Optional, written only when the frame reached the node.
 * @return true if the frame reached br_node_rx(), false if the allowlist
 *         refused it (counted) or the arguments are bad.
 */
bool uart_link_deliver(uart_link_t *l, br_node_t *node, uint8_t link, const br_transport_t *tr,
                       const uint8_t *frame, size_t len, br_rx_verdict_t *verdict_out);

/**
 * Report every frame accepted by the byte pipe since the last call as
 * delivered (br_node_tx_status(delivered = true, addr_len 0)). Call from the
 * owner task outside any br_node_* call. @return reports made.
 */
uint32_t uart_link_report_tx_status(uart_link_t *l, br_node_t *node, uint8_t link);

/** Copy the counters. */
void uart_link_get_stats(const uart_link_t *l, uart_link_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* UART_LINK_H */
