// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_sample.h - resolution modes and sample codec (spec 6.1 MODE, 6.2 DATA).
 *
 * Covers the plaintext side of section 6 only:
 * - br_mode_t, the MODE descriptor (6.1; Appendix B layout), and its payload
 *   codec with the MODE_ACK status a receiver must answer (3.6 line 302,
 *   SPEC-NOTES N7);
 * - the 7-byte DATA payload header (6.2);
 * - the HIGH / LOW per-channel sample codec (6.2 table), including LOW
 *   quantization (A.13 vector: BRV_A13_* in test/host/vectors_generated.h).
 *
 * Encryption, sequence numbers and framing are not here (br_session.h,
 * br_node.h). BULK (mode 2) is decoded / encoded as a descriptor only; the
 * BULK data path is out of scope for phase 1b.
 *
 * Digital channels (6.2): lossless in both modes. A digital channel carries
 * fmt = number of lines (1..32); line i is bit i of br_value_t.lines.
 *   HIGH: 4 bytes, u32 LE, line i = bit i.
 *   LOW:  ceil(lines / 8) bytes, line i = byte i/8, bit i%8.
 * Bench demo: one digital channel, 1 line (the button). HIGH sample = 4
 * bytes, LOW sample = 1 byte.
 *
 * Pure C11, no heap, reentrant. All multi-byte fields little-endian.
 */
#ifndef BRAID_BR_SAMPLE_H
#define BRAID_BR_SAMPLE_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Constants (6.1, 6.2)                                                       */
/* ------------------------------------------------------------------------- */

#define BR_MODE_HIGH             0u
#define BR_MODE_LOW              1u
#define BR_MODE_BULK             2u   /**< 12.7; descriptor only in phase 1b. */

#define BR_CH_KIND_DIGITAL       0u
#define BR_CH_KIND_ANALOG        1u
#define BR_CH_FMT_U32            0u   /**< analog fmt */
#define BR_CH_FMT_I32            1u   /**< analog fmt */
#define BR_CH_FMT_F32            2u   /**< analog fmt */
#define BR_DIGITAL_LINES_MIN     1u   /**< digital fmt range */
#define BR_DIGITAL_LINES_MAX    32u

#define BR_MAX_CHANNELS         16u   /**< ch_count 1..16 (0 in mode 2). */
#define BR_MODE_FLAG_PERIOD_MS  0x01u /**< flags bit0: period unit ms (else us). */
#define BR_MODE_FLAGS_RESERVED  0xFEu /**< flags bits 1..7: 0. */

#define BR_KEEPALIVE_MIN_MS   1000u
#define BR_KEEPALIVE_MAX_MS  60000u
#define BR_KEEPALIVE_DEFAULT_MS 5000u

/** Encoded MODE descriptor sizes (6.1). */
#define BR_MODE_CH_DESC_LEN      2u   /**< kind u8, fmt u8 */
#define BR_MODE_CH_LOW_EXTRA     8u   /**< LOW analog: scale f32, offset f32 */
#define BR_MODE_BULK_LEN        40u   /**< bulk_size u32, sha256[32], fw_build u32 */
/** Largest MODE payload: 13 + 16 x (2 + 8) = 173 (6.1). */
#define BR_MODE_MAX_LEN         (BR_LEN_MODE_FIXED + BR_MAX_CHANNELS * (BR_MODE_CH_DESC_LEN + BR_MODE_CH_LOW_EXTRA))

/** MODE_ACK status (section 5). */
#define BR_MODE_ACK_OK           0u
#define BR_MODE_ACK_UNSUPPORTED  1u
#define BR_MODE_ACK_TOO_BIG      2u
#define BR_MODE_ACK_BAD_ARG      3u

/** DATA status bits (6.2). */
#define BR_DATA_ST_CLIP          0x01u
#define BR_DATA_ST_OVERRUN       0x02u
#define BR_DATA_ST_INVALID       0x04u
#define BR_DATA_ST_UNSYNCED      0x08u
#define BR_DATA_ST_RESERVED      0xF0u

#define BR_DATA_HDR_LEN          BR_LEN_DATA_FIXED  /**< 7: config_id, status, t_first_us, n_samples */
#define BR_DATA_MAX_SAMPLES    255u

/** LOW quantization (6.2): q in -32767..32767; -32768 = INVALID. */
#define BR_LOW_Q_MAX         32767
#define BR_LOW_Q_INVALID    (-32768)

/* ------------------------------------------------------------------------- */
/* Types                                                                      */
/* ------------------------------------------------------------------------- */

/** One channel descriptor (6.1). scale / offset are used by LOW analog only. */
typedef struct {
    uint8_t kind;    /**< BR_CH_KIND_* */
    uint8_t fmt;     /**< analog: BR_CH_FMT_*; digital: lines 1..32 */
    float   scale;   /**< LOW analog: value = offset + q x scale */
    float   offset;
} br_ch_desc_t;

/** BULK descriptor (6.1, mode 2). */
typedef struct {
    uint32_t size;
    uint8_t  sha256[32];
    uint32_t fw_build;
} br_bulk_desc_t;

/**
 * Resolution mode, as in Appendix B br_mode_t (field order of 6.1).
 * config_id 1..255 (never 0); it increments on every change and wraps to 1.
 */
typedef struct {
    uint8_t        config_id;
    uint8_t        mode;          /**< BR_MODE_HIGH / LOW / BULK */
    uint8_t        ch_count;      /**< 1..16; 0 in mode 2 */
    uint32_t       period;        /**< us, or ms with BR_MODE_FLAG_PERIOD_MS */
    uint8_t        fec_k;         /**< 2..16, ignored if fec_m == 0 */
    uint8_t        fec_m;         /**< 0 = no group FEC (phase 1b bench: always 0) */
    uint8_t        arq;           /**< 0 fire-and-forget, 1 retransmit on ACK gaps */
    uint8_t        flags;         /**< BR_MODE_FLAG_* */
    uint16_t       keepalive_ms;  /**< 1000..60000 */
    br_ch_desc_t   ch[BR_MAX_CHANNELS];
    br_bulk_desc_t bulk;          /**< mode 2 only */
} br_mode_t;

/**
 * One channel value of one sample, in host form.
 * - digital: .lines (bit i = line i; bits >= fmt must be 0 on encode);
 * - analog HIGH: .u32 / .i32 / .f32 per fmt;
 * - analog LOW: encode reads the value per fmt and converts it to float
 *   before quantizing; decode always returns .f32 = offset + q x scale.
 */
typedef union {
    uint32_t lines;
    uint32_t u32;
    int32_t  i32;
    float    f32;
} br_value_t;

/** DATA payload header (6.2), 7 bytes on the wire. */
typedef struct {
    uint8_t  config_id;
    uint8_t  status;       /**< BR_DATA_ST_* */
    uint32_t t_first_us;   /**< sender session clock (6.5); mode 2: byte offset */
    uint8_t  n_samples;    /**< 1..255 */
} br_data_hdr_t;

/* ------------------------------------------------------------------------- */
/* MODE descriptor codec (6.1)                                                */
/* ------------------------------------------------------------------------- */

/**
 * Encoded MODE payload length for a descriptor: 13 + per channel 2
 * (+ 8 for LOW analog), or 13 + 40 for mode 2.
 *
 * @param mode     Descriptor (not validated beyond what the length needs).
 * @param len_out  Receives the length.
 * @return BR_OK; BR_ERR_ARG on NULL or ch_count > 16.
 * @spec 6.1
 */
br_err_t br_mode_encoded_len(const br_mode_t *mode, size_t *len_out);

/**
 * Check a descriptor against 6.1 and return the MODE_ACK status a probe
 * would answer. Rules: config_id != 0; mode 0..2 (else UNSUPPORTED);
 * ch_count 1..16 (0 for mode 2); per channel kind 0/1, analog fmt 0..2,
 * digital lines 1..32; fec_m 0..4 and, if fec_m > 0, fec_k 2..16;
 * arq 0/1; reserved flag bits 0; keepalive_ms 1000..60000 -> else BAD_ARG.
 * One complete sample must fit a DATA frame of max_payload bytes
 * (7 + sample size <= max_payload, minus BR_FEC_PAYLOAD_RESERVE when
 * fec_m > 0) and the encoded MODE must fit max_payload -> else TOO_BIG.
 * A local capability gap (e.g. FEC requested from a probe without it) is
 * UNSUPPORTED.
 *
 * @param mode         Descriptor.
 * @param max_payload  Session path payload cap (217 with AUTH on a 250 path).
 * @param caps         Receiver's caps (BR_CAP_*), for UNSUPPORTED.
 * @param status_out   Receives BR_MODE_ACK_*.
 * @return BR_OK (status_out may still be non-zero); BR_ERR_ARG on NULL.
 * @spec 6.1, 6.2, 3.6 (MODE row, SPEC-NOTES N7)
 */
br_err_t br_mode_check(const br_mode_t *mode, size_t max_payload, uint16_t caps,
                       uint8_t *status_out);

/**
 * Serialise a MODE payload (6.1 order, LE).
 *
 * @param mode     Descriptor (caller ran br_mode_check()).
 * @param out      Output.
 * @param cap      Capacity of out.
 * @param written  Receives br_mode_encoded_len().
 * @return BR_OK; BR_ERR_ARG on NULL or ch_count > 16; BR_ERR_TOO_BIG if cap
 *         is too small.
 * @spec 6.1
 */
br_err_t br_mode_encode(const br_mode_t *mode, uint8_t *out, size_t cap, size_t *written);

/**
 * Parse a MODE payload. Never counts bad_frame (SPEC-NOTES N7): every
 * failure is reported as a MODE_ACK status for the caller to send.
 *
 * @param in           Plaintext MODE payload.
 * @param len          Its length.
 * @param max_payload  As for br_mode_check().
 * @param caps         As for br_mode_check().
 * @param mode_out     Receives the descriptor (fields past a parse error
 *                     unspecified).
 * @param status_out   BR_MODE_ACK_OK, or the status to answer: BAD_ARG for
 *                     len < 13 or a length that does not match ch_count /
 *                     kinds; otherwise as br_mode_check().
 * @return BR_OK if status is OK; BR_ERR_REJECT otherwise; BR_ERR_ARG on NULL.
 * @spec 6.1, 3.6 line 302
 */
br_err_t br_mode_decode(const uint8_t *in, size_t len, size_t max_payload, uint16_t caps,
                        br_mode_t *mode_out, uint8_t *status_out);

/* ------------------------------------------------------------------------- */
/* Sample codec (6.2)                                                         */
/* ------------------------------------------------------------------------- */

/**
 * Bytes of one complete sample (all channels, descriptor order) under mode:
 * HIGH: 4 per channel; LOW: analog 2, digital ceil(lines / 8).
 *
 * @param mode       HIGH or LOW descriptor.
 * @param bytes_out  Receives the size.
 * @return BR_OK; BR_ERR_ARG on NULL, mode 2, or an invalid channel.
 * @spec 6.2
 */
br_err_t br_sample_size(const br_mode_t *mode, size_t *bytes_out);

/**
 * How many samples fit one DATA frame: floor((max_payload - 7) / size),
 * capped at 255 (minus BR_FEC_PAYLOAD_RESERVE from max_payload if fec_m > 0).
 *
 * @return BR_OK; BR_ERR_ARG; BR_ERR_TOO_BIG if not even one fits (the
 *         MODE_ACK status 2 case).
 * @spec 6.1 ("one complete sample must fit"), 6.2, 3.3
 */
br_err_t br_sample_max_per_frame(const br_mode_t *mode, size_t max_payload, uint8_t *n_out);

/**
 * LOW quantization of one value (6.2):
 *   q = clamp(round((v - offset) / scale), -32767, 32767), CLIP if clamped;
 *   NaN / Inf -> q = -32768 (INVALID).
 * Rounding is half away from zero (C roundf). scale must be finite and > 0.
 * A.13 (scale 5.03555406e-05, offset 1.65): 0.00 -> -32767, 1.65 -> 0,
 * 3.30 -> 32767, 4.00 -> 32767 with CLIP.
 *
 * @param v            Input value.
 * @param scale        > 0.
 * @param offset       Any finite value.
 * @param q_out        Receives q.
 * @param status_out   Receives BR_DATA_ST_CLIP, BR_DATA_ST_INVALID or 0.
 * @return BR_OK; BR_ERR_ARG on NULL or a bad scale / offset.
 * @spec 6.2, A.13
 */
br_err_t br_low_quantize(float v, float scale, float offset, int16_t *q_out, uint8_t *status_out);

/**
 * LOW dequantization: value = offset + q x scale; q = -32768 -> INVALID
 * (v_out set to NaN).
 *
 * @return BR_OK; BR_ERR_ARG on NULL.
 * @spec 6.2
 */
br_err_t br_low_dequantize(int16_t q, float scale, float offset, float *v_out, bool *invalid_out);

/**
 * Encode one sample (ch_count values, descriptor order) per the 6.2 table.
 *
 * @param mode        HIGH or LOW descriptor.
 * @param vals        ch_count values.
 * @param out         Output.
 * @param cap         Capacity; >= br_sample_size().
 * @param written     Receives br_sample_size().
 * @param status_io   OR-ed with BR_DATA_ST_CLIP / _INVALID raised by LOW
 *                    quantization (caller starts from 0 per DATA frame).
 * @return BR_OK; BR_ERR_ARG on NULL, mode 2, or a digital value with bits
 *         set at or above its line count; BR_ERR_TOO_BIG if cap is short.
 * @spec 6.2
 */
br_err_t br_sample_encode(const br_mode_t *mode, const br_value_t *vals,
                          uint8_t *out, size_t cap, size_t *written, uint8_t *status_io);

/**
 * Decode one sample.
 *
 * @param mode      HIGH or LOW descriptor.
 * @param in        Encoded sample.
 * @param len       >= br_sample_size().
 * @param vals_out  Receives ch_count values (LOW analog as .f32; INVALID as NaN).
 * @return BR_OK; BR_ERR_ARG on NULL or mode 2; BR_ERR_DECODE if len is short
 *         or a LOW digital byte has bits set above its line count.
 * @spec 6.2
 */
br_err_t br_sample_decode(const br_mode_t *mode, const uint8_t *in, size_t len, br_value_t *vals_out);

/* ------------------------------------------------------------------------- */
/* DATA payload (6.2)                                                         */
/* ------------------------------------------------------------------------- */

/**
 * Write the 7-byte DATA header.
 * @return BR_OK; BR_ERR_ARG on NULL or n_samples == 0; BR_ERR_TOO_BIG if cap < 7.
 * @spec 6.2
 */
br_err_t br_data_hdr_encode(const br_data_hdr_t *hdr, uint8_t *out, size_t cap);

/**
 * Read the 7-byte DATA header and check the payload length against the
 * active mode: len == 7 + n_samples x br_sample_size(mode) (3.6 DATA row).
 *
 * @param in        Plaintext DATA payload.
 * @param len       Its length (>= 7).
 * @param mode      Descriptor named by config_id (caller looks it up among
 *                  the two kept configs); NULL skips the length check.
 * @param hdr_out   Receives the header.
 * @return BR_OK; BR_ERR_ARG on NULL in / hdr_out; BR_ERR_DECODE on a short
 *         payload, n_samples == 0, or a length mismatch.
 * @spec 6.2, 3.6
 */
br_err_t br_data_hdr_decode(const uint8_t *in, size_t len, const br_mode_t *mode,
                            br_data_hdr_t *hdr_out);

/**
 * Build a whole DATA plaintext payload: header + n_samples encoded samples.
 * The status byte written is hdr->status OR-ed with CLIP / INVALID raised
 * while encoding.
 *
 * @param mode     Active descriptor (hdr->config_id must equal mode->config_id).
 * @param hdr      Header; n_samples samples are read from vals.
 * @param vals     n_samples x ch_count values, sample-major.
 * @param out      Output.
 * @param cap      Capacity (the session max payload).
 * @param written     Receives 7 + n_samples x sample size.
 * @param status_out  Optional (may be NULL): receives the status byte written.
 * @return BR_OK; BR_ERR_ARG; BR_ERR_TOO_BIG if it does not fit cap.
 * @spec 6.2
 */
br_err_t br_data_build(const br_mode_t *mode, const br_data_hdr_t *hdr, const br_value_t *vals,
                       uint8_t *out, size_t cap, size_t *written, uint8_t *status_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_SAMPLE_H */
