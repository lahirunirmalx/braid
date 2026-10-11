// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_sample.c - MODE descriptor and HIGH / LOW sample codec (spec 6.1, 6.2).
 *
 * Pure C11, no heap, no libm calls (rounding and finiteness checks use the
 * <math.h> classification macros and plain arithmetic, so the host build
 * needs no -lm). Every multi-byte field is little-endian (br_frame.h).
 */
#include <math.h>
#include <string.h>

#include "braid/br_frame.h"
#include "braid/br_sample.h"

#include "br_internal.h"

/* ---- helpers -------------------------------------------------------------- */

static float rd_f32(const uint8_t *p)
{
    float f;
    memcpy(&f, p, sizeof f);
    return f;
}

static void wr_f32(uint8_t *p, float f)
{
    memcpy(p, &f, sizeof f);
}

/* Bytes of one channel of one sample (6.2 table). 0 = invalid channel. */
static size_t ch_sample_bytes(uint8_t mode, const br_ch_desc_t *ch)
{
    if (ch->kind == BR_CH_KIND_DIGITAL) {
        if (ch->fmt < BR_DIGITAL_LINES_MIN || ch->fmt > BR_DIGITAL_LINES_MAX) {
            return 0u;
        }
        return (mode == BR_MODE_HIGH) ? 4u : (size_t)((ch->fmt + 7u) / 8u);
    }
    if (ch->kind == BR_CH_KIND_ANALOG) {
        if (ch->fmt > BR_CH_FMT_F32) {
            return 0u;
        }
        return (mode == BR_MODE_HIGH) ? 4u : 2u;
    }
    return 0u;
}

/* Descriptor bytes of one channel in the MODE payload (6.1). */
static size_t ch_desc_bytes(uint8_t mode, const br_ch_desc_t *ch)
{
    size_t n = BR_MODE_CH_DESC_LEN;
    if (mode == BR_MODE_LOW && ch->kind == BR_CH_KIND_ANALOG) {
        n += BR_MODE_CH_LOW_EXTRA;
    }
    return n;
}

/* br_sample.h: scale must be finite and > 0 (3.6 says "finite and non-zero";
 * a negative scale is refused too so br_low_quantize() never sees one). */
static bool scale_ok(float scale)
{
    return isfinite(scale) && scale > 0.0f;
}

/* ---- MODE descriptor (6.1) ------------------------------------------------- */

br_err_t br_mode_encoded_len(const br_mode_t *mode, size_t *len_out)
{
    if (mode == NULL || len_out == NULL || mode->ch_count > BR_MAX_CHANNELS) {
        return BR_ERR_ARG;
    }
    size_t n = BR_LEN_MODE_FIXED;
    if (mode->mode == BR_MODE_BULK) {
        n += BR_MODE_BULK_LEN;
    } else {
        for (uint8_t i = 0; i < mode->ch_count; i++) {
            n += ch_desc_bytes(mode->mode, &mode->ch[i]);
        }
    }
    *len_out = n;
    return BR_OK;
}

br_err_t br_mode_check(const br_mode_t *mode, size_t max_payload, uint16_t caps,
                       uint8_t *status_out)
{
    if (mode == NULL || status_out == NULL) {
        return BR_ERR_ARG;
    }
    *status_out = BR_MODE_ACK_OK;
    if (mode->config_id == 0u) {
        *status_out = BR_MODE_ACK_BAD_ARG;
        return BR_OK;
    }
    if (mode->mode > BR_MODE_BULK) {
        *status_out = BR_MODE_ACK_UNSUPPORTED;
        return BR_OK;
    }
    /* BAD_ARG rows (6.1, 3.6 MODE row). */
    bool bad = false;
    if (mode->mode == BR_MODE_BULK) {
        bad = mode->ch_count != 0u;
    } else {
        bad = mode->ch_count < 1u || mode->ch_count > BR_MAX_CHANNELS;
        for (uint8_t i = 0; !bad && i < mode->ch_count; i++) {
            const br_ch_desc_t *ch = &mode->ch[i];
            if (ch_sample_bytes(mode->mode, ch) == 0u) {
                bad = true;
            } else if (mode->mode == BR_MODE_LOW && ch->kind == BR_CH_KIND_ANALOG) {
                bad = !scale_ok(ch->scale) || !isfinite(ch->offset);
            }
        }
    }
    bad = bad || mode->period == 0u;
    bad = bad || mode->fec_m > BR_FEC_M_MAX;
    bad = bad || (mode->fec_m > 0u && (mode->fec_k < BR_FEC_K_MIN || mode->fec_k > BR_FEC_K_MAX));
    bad = bad || mode->arq > 1u;
    bad = bad || (mode->flags & BR_MODE_FLAGS_RESERVED) != 0u;
    bad = bad || mode->keepalive_ms < BR_KEEPALIVE_MIN_MS || mode->keepalive_ms > BR_KEEPALIVE_MAX_MS;
    if (bad) {
        *status_out = BR_MODE_ACK_BAD_ARG;
        return BR_OK;
    }
    /* Local capability gaps -> UNSUPPORTED. */
    if ((mode->mode == BR_MODE_HIGH && (caps & BR_CAP_HIGH) == 0u) ||
        (mode->mode == BR_MODE_LOW && (caps & BR_CAP_LOW) == 0u) ||
        (mode->fec_m > 0u && (caps & BR_CAP_FEC) == 0u) ||
        (mode->arq != 0u && (caps & BR_CAP_ARQ) == 0u)) {
        *status_out = BR_MODE_ACK_UNSUPPORTED;
        return BR_OK;
    }
    /* Size rows -> TOO_BIG. */
    size_t enc = 0;
    (void)br_mode_encoded_len(mode, &enc);
    size_t cap = max_payload;
    if (mode->fec_m > 0u) {
        cap = cap > BR_FEC_PAYLOAD_RESERVE ? cap - BR_FEC_PAYLOAD_RESERVE : 0u;
    }
    size_t ss = 1u; /* mode 2: one image byte */
    if (mode->mode != BR_MODE_BULK && br_sample_size(mode, &ss) != BR_OK) {
        *status_out = BR_MODE_ACK_BAD_ARG;
        return BR_OK;
    }
    if (BR_DATA_HDR_LEN + ss > cap || enc > max_payload) {
        *status_out = BR_MODE_ACK_TOO_BIG;
    }
    return BR_OK;
}

br_err_t br_mode_encode(const br_mode_t *mode, uint8_t *out, size_t cap, size_t *written)
{
    size_t need = 0;
    if (out == NULL || written == NULL || br_mode_encoded_len(mode, &need) != BR_OK) {
        return BR_ERR_ARG;
    }
    if (cap < need) {
        return BR_ERR_TOO_BIG;
    }
    out[0] = mode->config_id;
    out[1] = mode->mode;
    out[2] = mode->ch_count;
    br_wr_le32(out + 3, mode->period);
    out[7] = mode->fec_k;
    out[8] = mode->fec_m;
    out[9] = mode->arq;
    out[10] = mode->flags;
    br_wr_le16(out + 11, mode->keepalive_ms);
    size_t o = BR_LEN_MODE_FIXED;
    if (mode->mode == BR_MODE_BULK) {
        br_wr_le32(out + o, mode->bulk.size);
        memcpy(out + o + 4u, mode->bulk.sha256, sizeof mode->bulk.sha256);
        br_wr_le32(out + o + 36u, mode->bulk.fw_build);
        o += BR_MODE_BULK_LEN;
    } else {
        for (uint8_t i = 0; i < mode->ch_count; i++) {
            const br_ch_desc_t *ch = &mode->ch[i];
            out[o] = ch->kind;
            out[o + 1u] = ch->fmt;
            o += BR_MODE_CH_DESC_LEN;
            if (mode->mode == BR_MODE_LOW && ch->kind == BR_CH_KIND_ANALOG) {
                wr_f32(out + o, ch->scale);
                wr_f32(out + o + 4u, ch->offset);
                o += BR_MODE_CH_LOW_EXTRA;
            }
        }
    }
    *written = o;
    return BR_OK;
}

br_err_t br_mode_decode(const uint8_t *in, size_t len, size_t max_payload, uint16_t caps,
                        br_mode_t *mode_out, uint8_t *status_out)
{
    if (in == NULL || mode_out == NULL || status_out == NULL) {
        return BR_ERR_ARG;
    }
    memset(mode_out, 0, sizeof *mode_out);
    *status_out = BR_MODE_ACK_BAD_ARG;
    if (len < BR_LEN_MODE_FIXED) {
        return BR_ERR_REJECT;
    }
    mode_out->config_id = in[0];
    mode_out->mode = in[1];
    mode_out->ch_count = in[2];
    mode_out->period = br_rd_le32(in + 3);
    mode_out->fec_k = in[7];
    mode_out->fec_m = in[8];
    mode_out->arq = in[9];
    mode_out->flags = in[10];
    mode_out->keepalive_ms = br_rd_le16(in + 11);
    if (mode_out->mode > BR_MODE_BULK) {
        *status_out = BR_MODE_ACK_UNSUPPORTED;
        return BR_ERR_REJECT;
    }
    size_t o = BR_LEN_MODE_FIXED;
    if (mode_out->mode == BR_MODE_BULK) {
        if (mode_out->ch_count != 0u || len != BR_LEN_MODE_FIXED + BR_MODE_BULK_LEN) {
            return BR_ERR_REJECT;
        }
        mode_out->bulk.size = br_rd_le32(in + o);
        memcpy(mode_out->bulk.sha256, in + o + 4u, sizeof mode_out->bulk.sha256);
        mode_out->bulk.fw_build = br_rd_le32(in + o + 36u);
    } else {
        if (mode_out->ch_count < 1u || mode_out->ch_count > BR_MAX_CHANNELS) {
            return BR_ERR_REJECT;
        }
        for (uint8_t i = 0; i < mode_out->ch_count; i++) {
            br_ch_desc_t *ch = &mode_out->ch[i];
            if (len - o < BR_MODE_CH_DESC_LEN) {
                return BR_ERR_REJECT;
            }
            ch->kind = in[o];
            ch->fmt = in[o + 1u];
            o += BR_MODE_CH_DESC_LEN;
            if (mode_out->mode == BR_MODE_LOW && ch->kind == BR_CH_KIND_ANALOG) {
                if (len - o < BR_MODE_CH_LOW_EXTRA) {
                    return BR_ERR_REJECT;
                }
                ch->scale = rd_f32(in + o);
                ch->offset = rd_f32(in + o + 4u);
                o += BR_MODE_CH_LOW_EXTRA;
            }
        }
        if (o != len) {
            return BR_ERR_REJECT;
        }
    }
    br_err_t rc = br_mode_check(mode_out, max_payload, caps, status_out);
    if (rc != BR_OK) {
        return rc;
    }
    return (*status_out == BR_MODE_ACK_OK) ? BR_OK : BR_ERR_REJECT;
}

/* ---- sample codec (6.2) ---------------------------------------------------- */

br_err_t br_sample_size(const br_mode_t *mode, size_t *bytes_out)
{
    if (mode == NULL || bytes_out == NULL || mode->mode > BR_MODE_LOW ||
        mode->ch_count < 1u || mode->ch_count > BR_MAX_CHANNELS) {
        return BR_ERR_ARG;
    }
    size_t n = 0;
    for (uint8_t i = 0; i < mode->ch_count; i++) {
        size_t b = ch_sample_bytes(mode->mode, &mode->ch[i]);
        if (b == 0u) {
            return BR_ERR_ARG;
        }
        n += b;
    }
    *bytes_out = n;
    return BR_OK;
}

br_err_t br_sample_max_per_frame(const br_mode_t *mode, size_t max_payload, uint8_t *n_out)
{
    size_t ss = 0;
    if (n_out == NULL || br_sample_size(mode, &ss) != BR_OK) {
        return BR_ERR_ARG;
    }
    size_t cap = max_payload;
    if (mode->fec_m > 0u) {
        cap = cap > BR_FEC_PAYLOAD_RESERVE ? cap - BR_FEC_PAYLOAD_RESERVE : 0u;
    }
    if (cap < BR_DATA_HDR_LEN + ss) {
        *n_out = 0;
        return BR_ERR_TOO_BIG;
    }
    size_t n = (cap - BR_DATA_HDR_LEN) / ss;
    *n_out = (uint8_t)(n > BR_DATA_MAX_SAMPLES ? BR_DATA_MAX_SAMPLES : n);
    return BR_OK;
}

br_err_t br_low_quantize(float v, float scale, float offset, int16_t *q_out, uint8_t *status_out)
{
    if (q_out == NULL || status_out == NULL || !scale_ok(scale) || !isfinite(offset)) {
        return BR_ERR_ARG;
    }
    *status_out = 0u;
    if (!isfinite(v)) {
        *q_out = (int16_t)BR_LOW_Q_INVALID;
        *status_out = BR_DATA_ST_INVALID;
        return BR_OK;
    }
    float x = (v - offset) / scale; /* float32 arithmetic per 6.2 */
    if (!isfinite(x) || x >= 32767.5f || x <= -32767.5f) {
        *q_out = (int16_t)((x > 0.0f) ? BR_LOW_Q_MAX : -BR_LOW_Q_MAX);
        *status_out = BR_DATA_ST_CLIP;
        return BR_OK;
    }
    /* round half away from zero (as roundf); |x| < 32767.5, done in double so
     * x + 0.5 cannot round up a value just below .5 */
    double d = (double)x;
    int32_t q = (d >= 0.0) ? (int32_t)(d + 0.5) : -(int32_t)(-d + 0.5);
    *q_out = (int16_t)q;
    return BR_OK;
}

br_err_t br_low_dequantize(int16_t q, float scale, float offset, float *v_out, bool *invalid_out)
{
    if (v_out == NULL || invalid_out == NULL) {
        return BR_ERR_ARG;
    }
    if (q == (int16_t)BR_LOW_Q_INVALID) {
        *v_out = NAN;
        *invalid_out = true;
        return BR_OK;
    }
    *v_out = offset + (float)q * scale;
    *invalid_out = false;
    return BR_OK;
}

static uint32_t lines_mask(uint8_t lines)
{
    return (lines >= 32u) ? 0xFFFFFFFFu : ((1u << lines) - 1u);
}

br_err_t br_sample_encode(const br_mode_t *mode, const br_value_t *vals,
                          uint8_t *out, size_t cap, size_t *written, uint8_t *status_io)
{
    size_t ss = 0;
    if (vals == NULL || out == NULL || written == NULL || status_io == NULL ||
        br_sample_size(mode, &ss) != BR_OK) {
        return BR_ERR_ARG;
    }
    /* Validate every channel before writing (no partial output on ARG). */
    for (uint8_t i = 0; i < mode->ch_count; i++) {
        const br_ch_desc_t *ch = &mode->ch[i];
        if (ch->kind == BR_CH_KIND_DIGITAL && (vals[i].lines & ~lines_mask(ch->fmt)) != 0u) {
            return BR_ERR_ARG;
        }
        if (mode->mode == BR_MODE_LOW && ch->kind == BR_CH_KIND_ANALOG &&
            (!scale_ok(ch->scale) || !isfinite(ch->offset))) {
            return BR_ERR_ARG;
        }
    }
    if (cap < ss) {
        return BR_ERR_TOO_BIG;
    }
    size_t o = 0;
    uint8_t st = 0;
    for (uint8_t i = 0; i < mode->ch_count; i++) {
        const br_ch_desc_t *ch = &mode->ch[i];
        if (mode->mode == BR_MODE_HIGH) {
            br_wr_le32(out + o, vals[i].u32); /* lines, u32, i32 and f32 share the 4 bytes */
            o += 4u;
        } else if (ch->kind == BR_CH_KIND_DIGITAL) {
            size_t nb = (size_t)((ch->fmt + 7u) / 8u);
            for (size_t b = 0; b < nb; b++) {
                out[o + b] = (uint8_t)(vals[i].lines >> (8u * b));
            }
            o += nb;
        } else {
            float f;
            if (ch->fmt == BR_CH_FMT_U32) {
                f = (float)vals[i].u32;
            } else if (ch->fmt == BR_CH_FMT_I32) {
                f = (float)vals[i].i32;
            } else {
                f = vals[i].f32;
            }
            int16_t q = 0;
            uint8_t qs = 0;
            (void)br_low_quantize(f, ch->scale, ch->offset, &q, &qs);
            st = (uint8_t)(st | qs);
            br_wr_le16(out + o, (uint16_t)q);
            o += 2u;
        }
    }
    *status_io = (uint8_t)(*status_io | st);
    *written = o;
    return BR_OK;
}

br_err_t br_sample_decode(const br_mode_t *mode, const uint8_t *in, size_t len, br_value_t *vals_out)
{
    size_t ss = 0;
    if (in == NULL || vals_out == NULL || br_sample_size(mode, &ss) != BR_OK) {
        return BR_ERR_ARG;
    }
    if (len < ss) {
        return BR_ERR_DECODE;
    }
    size_t o = 0;
    for (uint8_t i = 0; i < mode->ch_count; i++) {
        const br_ch_desc_t *ch = &mode->ch[i];
        if (mode->mode == BR_MODE_HIGH) {
            vals_out[i].u32 = br_rd_le32(in + o);
            o += 4u;
        } else if (ch->kind == BR_CH_KIND_DIGITAL) {
            size_t nb = (size_t)((ch->fmt + 7u) / 8u);
            uint32_t v = 0;
            for (size_t b = 0; b < nb; b++) {
                v |= (uint32_t)in[o + b] << (8u * b);
            }
            if ((v & ~lines_mask(ch->fmt)) != 0u) {
                return BR_ERR_DECODE;
            }
            vals_out[i].lines = v;
            o += nb;
        } else {
            int16_t q = (int16_t)br_rd_le16(in + o);
            bool inv = false;
            float f = 0.0f;
            (void)br_low_dequantize(q, ch->scale, ch->offset, &f, &inv);
            vals_out[i].f32 = f;
            o += 2u;
        }
    }
    return BR_OK;
}

/* ---- DATA payload (6.2) ---------------------------------------------------- */

br_err_t br_data_hdr_encode(const br_data_hdr_t *hdr, uint8_t *out, size_t cap)
{
    if (hdr == NULL || out == NULL || hdr->n_samples == 0u) {
        return BR_ERR_ARG;
    }
    if (cap < BR_DATA_HDR_LEN) {
        return BR_ERR_TOO_BIG;
    }
    out[0] = hdr->config_id;
    out[1] = hdr->status;
    br_wr_le32(out + 2, hdr->t_first_us);
    out[6] = hdr->n_samples;
    return BR_OK;
}

br_err_t br_data_hdr_decode(const uint8_t *in, size_t len, const br_mode_t *mode,
                            br_data_hdr_t *hdr_out)
{
    if (in == NULL || hdr_out == NULL) {
        return BR_ERR_ARG;
    }
    if (len < BR_DATA_HDR_LEN) {
        return BR_ERR_DECODE;
    }
    hdr_out->config_id = in[0];
    hdr_out->status = in[1];
    hdr_out->t_first_us = br_rd_le32(in + 2);
    hdr_out->n_samples = in[6];
    if (hdr_out->n_samples == 0u) {
        return BR_ERR_DECODE;
    }
    if (mode != NULL) {
        size_t per = 1u; /* mode 2: raw image bytes */
        if (mode->mode != BR_MODE_BULK && br_sample_size(mode, &per) != BR_OK) {
            return BR_ERR_DECODE;
        }
        if (len != BR_DATA_HDR_LEN + (size_t)hdr_out->n_samples * per) {
            return BR_ERR_DECODE;
        }
    }
    return BR_OK;
}

br_err_t br_data_build(const br_mode_t *mode, const br_data_hdr_t *hdr, const br_value_t *vals,
                       uint8_t *out, size_t cap, size_t *written, uint8_t *status_out)
{
    size_t ss = 0;
    if (hdr == NULL || vals == NULL || out == NULL || written == NULL ||
        br_sample_size(mode, &ss) != BR_OK || hdr->n_samples == 0u ||
        hdr->config_id != mode->config_id) {
        return BR_ERR_ARG;
    }
    size_t need = BR_DATA_HDR_LEN + (size_t)hdr->n_samples * ss;
    if (cap < need) {
        return BR_ERR_TOO_BIG;
    }
    uint8_t st = hdr->status;
    size_t o = BR_DATA_HDR_LEN;
    for (uint8_t i = 0; i < hdr->n_samples; i++) {
        size_t w = 0;
        br_err_t rc = br_sample_encode(mode, vals + (size_t)i * mode->ch_count, out + o, cap - o, &w, &st);
        if (rc != BR_OK) {
            return rc;
        }
        o += w;
    }
    br_data_hdr_t h = *hdr;
    h.status = st;
    (void)br_data_hdr_encode(&h, out, cap);
    *written = o;
    if (status_out != NULL) {
        *status_out = st;
    }
    return BR_OK;
}
