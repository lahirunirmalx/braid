// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_seg.h - Braid nRF24L01+ link-local segmentation sublayer
 * (spec Appendix C.5, 11.3 last paragraph, 1.2 nRF24 row).
 *
 * Portable C11: no ESP-IDF, FreeRTOS, HAL or braid header. The 32-byte
 * ESB payload pipe below it is injected as a send callback and the
 * reassembled frames leave through a frame callback, so the same file is
 * host-tested (firmware/test/host/test_nrf24_link.c includes nrf24_seg.c
 * directly) and on the device sits under nrf24_link.c.
 *
 * Segment layout (C.5 "src u8, tag u8, idx:7 | LAST:1, up to 29 bytes"):
 *
 *     byte 0   src   low byte of the transmitter's unit ID (= header prev_hop
 *                    low byte of every frame it transmits)
 *     byte 1   tag   per-transmitter frame counter, +1 per frame (wraps)
 *     byte 2   bit 7 LAST (1 on the final segment of the frame)
 *              bits 6..0 idx, 0 for the first segment, +1 per segment
 *     bytes 3..31     frame bytes: exactly 29 on every segment except the
 *                     LAST one, which carries the remainder (0..29)
 *
 *   A frame of n bytes goes as ceil(n / 29) segments, 9 for 250 bytes; a
 *   0-byte frame goes as one LAST segment with no payload (3 bytes on the
 *   air). Decisions not spelled out by C.5 (bit position of LAST, the empty
 *   frame, duplicates, buffer-full) are listed in firmware/NRF24-LINK.txt as
 *   SPEC-NOTES candidates.
 *
 * Reassembly (C.5): one buffer per neighbour (keyed by src), N buffers
 * (NRF24_SEG_SLOTS_DEFAULT 4), opened by segment 0 and fed in order. Dropped
 * whole (counted, nothing delivered) on: a gap (idx is not the next one), a
 * foreign tag from the same src before LAST, NRF24_SEG_TIMEOUT_MS_DEFAULT
 * (50 ms) without a segment, more than NRF24_SEG_MAX_FRAME bytes, or a
 * segment 0 from a new src when every buffer is busy. Segments with idx > 0
 * that find no open frame (the tail of a dropped frame, or a frame whose
 * segment 0 was lost) are counted per segment as orphans. A repeat of the last
 * accepted segment (same src, tag, idx) is ignored and counted as a
 * duplicate (the ESB PID filter normally removes those in hardware). Two
 * neighbours whose unit IDs share a low byte still interleave; the frame CRC
 * in the node drops both (C.5 known limitation).
 *
 * Time comes in as an argument (now_us, same clock as br_platform now_us)
 * so timeouts are host-testable; nothing here reads a clock.
 *
 * Threading: one owner task for the whole object. Not reentrant.
 */
#ifndef NRF24_SEG_H
#define NRF24_SEG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NRF24_SEG_PKT_MAX              32u   /**< ESB payload with dynamic length */
#define NRF24_SEG_HDR_LEN               3u   /**< src, tag, idx|LAST */
#define NRF24_SEG_PAYLOAD              29u   /**< frame bytes per full segment */
#define NRF24_SEG_MAX_FRAME           250u   /**< transport max_frame (1.2), path MTU unchanged (11.3) */
#define NRF24_SEG_MAX_SEGS              9u   /**< ceil(250 / 29) */
#define NRF24_SEG_LAST               0x80u   /**< byte 2 bit 7 */
#define NRF24_SEG_IDX_MASK           0x7Fu   /**< byte 2 bits 6..0 */
#define NRF24_SEG_SLOTS_MAX             8u   /**< compile-time reassembly buffers */
#define NRF24_SEG_SLOTS_DEFAULT         4u   /**< C.5 NRF_REASM */
#define NRF24_SEG_TIMEOUT_MS_DEFAULT   50u   /**< C.5 NRF_REASM_TIMEOUT_MS */

typedef enum {
    NRF24_SEG_OK = 0,
    NRF24_SEG_ERR_ARG,       /**< NULL pointer, bad slot count */
    NRF24_SEG_ERR_TOO_BIG,   /**< frame longer than NRF24_SEG_MAX_FRAME */
    NRF24_SEG_ERR_SEND       /**< the pipe refused a segment (frame abandoned, receiver drops it) */
} nrf24_seg_err_t;

/**
 * 32-byte pipe write: send one ESB payload of len (3..32) bytes.
 * tx_ctx is the per-frame opaque pointer given to nrf24_seg_send()
 * (destination address and NO_ACK choice live there).
 * @return true if the radio accepted the payload.
 */
typedef bool (*nrf24_seg_send_fn)(void *ctx, void *tx_ctx, const uint8_t *pkt, uint8_t len);

/** One reassembled frame of len (0..250) bytes from the neighbour with low ID byte src. */
typedef void (*nrf24_seg_frame_fn)(void *ctx, uint8_t src, const uint8_t *frame, uint16_t len);

typedef struct {
    uint32_t seg_tx;         /**< segments produced */
    uint32_t seg_rx;         /**< well-formed segments received (any outcome) */
    uint32_t frames_tx;      /**< frames fully segmented */
    uint32_t frames_rx;      /**< frames reassembled and delivered */
    uint32_t tx_refused;     /**< frames abandoned because the pipe refused a segment */
    uint32_t timeouts;       /**< open frames dropped by the reassembly timeout */
    uint32_t gaps;           /**< open frames dropped: idx was not the next one */
    uint32_t orphans;        /**< segments with idx > 0 and no open frame from that src (the rest of a dropped
                                  frame, or a frame whose segment 0 was lost); per segment, not a frame drop */
    uint32_t foreign_tag;    /**< open frames dropped: another tag from the same src arrived first */
    uint32_t dups;           /**< repeats of the last accepted segment, ignored */
    uint32_t malformed;      /**< segments < 3 bytes, idx > 8, or a non-LAST segment not carrying 29 bytes */
    uint32_t oversize;       /**< frames dropped: more than 250 bytes */
    uint32_t buffer_full;    /**< frames dropped: segment 0 from a new src, every buffer busy */
    uint32_t frames_dropped; /**< timeouts + gaps + foreign_tag + oversize + buffer_full */
} nrf24_seg_stats_t;

/** One reassembly buffer (private). */
typedef struct {
    bool     used;           /**< ever assigned to a src */
    bool     open;           /**< a frame is being reassembled */
    uint8_t  src;
    uint8_t  tag;
    uint8_t  next_idx;
    bool     done_valid;     /**< done_tag / done_idx hold the last completed segment */
    uint8_t  done_tag;
    uint8_t  done_idx;
    uint16_t len;
    uint64_t last_us;        /**< last segment (open) or completion time (closed): LRU key */
    uint8_t  buf[NRF24_SEG_MAX_FRAME];
} nrf24_seg_slot_t;

/** Segmenter + reassembler state. Treat every field as private. Statically allocatable. */
typedef struct {
    nrf24_seg_send_fn   send;
    void               *send_ctx;
    nrf24_seg_frame_fn  on_frame;
    void               *frame_ctx;
    uint8_t             src;         /**< our src byte */
    uint8_t             next_tag;
    uint8_t             n_slots;
    uint64_t            timeout_us;
    nrf24_seg_slot_t    slots[NRF24_SEG_SLOTS_MAX];
    nrf24_seg_stats_t   st;
} nrf24_seg_t;

/** Per-frame transmit iterator (for radios that take one payload at a time). */
typedef struct {
    const uint8_t *frame;
    uint16_t       len;
    uint16_t       off;
    uint8_t        idx;
    uint8_t        tag;
    bool           done;
} nrf24_seg_tx_t;

/** Segments needed for a frame of len bytes (1 for len 0). */
static inline uint8_t nrf24_seg_count(uint16_t len)
{
    return len == 0u ? 1u : (uint8_t)((len + NRF24_SEG_PAYLOAD - 1u) / NRF24_SEG_PAYLOAD);
}

/**
 * Reset the object. src is our segment source byte (low byte of our unit
 * ID). n_slots 1..NRF24_SEG_SLOTS_MAX (0 = default 4); timeout_ms 0 =
 * default 50. send may be NULL if only the iterator API is used; on_frame
 * may be NULL if the object only transmits.
 * @return NRF24_SEG_OK; NRF24_SEG_ERR_ARG on NULL s or n_slots too large.
 */
nrf24_seg_err_t nrf24_seg_init(nrf24_seg_t *s, uint8_t src, uint8_t n_slots, uint32_t timeout_ms,
                               nrf24_seg_send_fn send, void *send_ctx, nrf24_seg_frame_fn on_frame,
                               void *frame_ctx);

/**
 * Start segmenting one frame (0..250 bytes; the buffer must stay valid until
 * the iterator is done). Takes the next tag.
 * @return NRF24_SEG_OK; NRF24_SEG_ERR_ARG; NRF24_SEG_ERR_TOO_BIG.
 */
nrf24_seg_err_t nrf24_seg_tx_begin(nrf24_seg_t *s, nrf24_seg_tx_t *t, const uint8_t *frame, uint16_t len);

/**
 * Produce the next segment into pkt (NRF24_SEG_PKT_MAX bytes), len_out 3..32.
 * @return true if a segment was produced, false once the frame is done
 *         (frames_tx is counted when the LAST segment is produced).
 */
bool nrf24_seg_tx_next(nrf24_seg_t *s, nrf24_seg_tx_t *t, uint8_t *pkt, uint8_t *len_out);

/**
 * Segment a whole frame through the send callback (one call per segment,
 * tx_ctx passed through). Stops at the first refused segment.
 * @return NRF24_SEG_OK; NRF24_SEG_ERR_ARG (NULL s / frame with len > 0 / no
 *         send callback); NRF24_SEG_ERR_TOO_BIG; NRF24_SEG_ERR_SEND.
 */
nrf24_seg_err_t nrf24_seg_send(nrf24_seg_t *s, void *tx_ctx, const uint8_t *frame, uint16_t len);

/**
 * Feed one received ESB payload (len bytes as reported by the radio).
 * Expires timed-out buffers first. Calls on_frame when a frame completes.
 */
void nrf24_seg_rx(nrf24_seg_t *s, const uint8_t *pkt, uint8_t len, uint64_t now_us);

/** Expire open buffers older than the timeout (call when idle; rx does it too). */
void nrf24_seg_tick(nrf24_seg_t *s, uint64_t now_us);

/**
 * True if some neighbour is, or just was, mid-frame: a buffer received a
 * segment within the last within_us, open (12.4 "mid-reception of a
 * multi-segment frame") or closed since (its LAST segment may be
 * retransmitted when the peer missed our ACK; staying in PRX lets the
 * hardware acknowledge the repeat instead of colliding head-on with it).
 */
bool nrf24_seg_rx_active(const nrf24_seg_t *s, uint64_t now_us, uint64_t within_us);

/** Absolute time of the earliest reassembly timeout, or UINT64_MAX when nothing is open. */
uint64_t nrf24_seg_next_deadline(const nrf24_seg_t *s);

/** Number of open (mid-frame) buffers. */
uint8_t nrf24_seg_open_count(const nrf24_seg_t *s);

/** Copy the counters. */
void nrf24_seg_get_stats(const nrf24_seg_t *s, nrf24_seg_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NRF24_SEG_H */
