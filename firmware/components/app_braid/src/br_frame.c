// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_frame.c - header codec, frame layout and the 3.6 receiver validator.
 *
 * Receive order (SPEC-NOTES N5): minimum length -> (RS, caller) -> CRC ->
 * Length row (with N6 BR_REJ_LEN_MAX_FRAME first) -> Header -> SEEK hop
 * fields -> Version. Every read is bounds-checked against len before it
 * happens; field access is memcpy-based (br_rd_le16 / br_rd_le32).
 */
#include <string.h>

#include "braid/br_crc16.h"
#include "braid/br_fec.h"
#include "braid/br_frame.h"

#include "br_internal.h"

/* ------------------------------------------------------------------------- */
/* Header                                                                     */
/* ------------------------------------------------------------------------- */

static bool nibbles_ok(uint8_t version, uint8_t flags, uint8_t ttl, uint8_t hops)
{
    return version <= 0x0Fu && flags <= 0x0Fu && ttl <= 0x0Fu && hops <= 0x0Fu;
}

/* Writes the header for hdr->type with the given len byte; caller checked cap. */
static size_t hdr_write(const br_hdr_t *hdr, uint8_t len_byte, uint8_t *buf)
{
    const bool seek = (hdr->type == (uint8_t)BR_TYPE_SEEK);
    buf[BR_OFF_VER_FLAGS] = (uint8_t)((unsigned)(hdr->version << 4) | hdr->flags);
    buf[BR_OFF_TYPE] = hdr->type;
    br_wr_le16(&buf[BR_OFF_SRC_ID], hdr->src_id);
    br_wr_le16(&buf[BR_OFF_DST_ID], hdr->dst_id);
    br_wr_le16(&buf[BR_OFF_PREV_HOP], hdr->prev_hop);
    br_wr_le16(&buf[BR_OFF_NEXT_HOP], hdr->next_hop);
    buf[BR_OFF_TTL_HOPS] = (uint8_t)((unsigned)(hdr->ttl << 4) | hdr->hops);
    br_wr_le32(&buf[BR_OFF_HOP_SEQ], hdr->hop_seq);
    if (seek) {
        br_wr_le16(&buf[BR_OFF_PATH_MTU], hdr->path_mtu);
        buf[BR_OFF_PATH_COST] = hdr->path_cost;
        buf[BR_OFF_SESSION_ID_SEEK] = hdr->session_id;
        br_wr_le16(&buf[BR_OFF_SEQ_SEEK], hdr->seq);
        buf[BR_OFF_LEN_SEEK] = len_byte;
        return BR_HDR_LEN_SEEK;
    }
    buf[BR_OFF_SESSION_ID] = hdr->session_id;
    br_wr_le16(&buf[BR_OFF_SEQ], hdr->seq);
    buf[BR_OFF_LEN] = len_byte;
    return BR_HDR_LEN;
}

/* Parses a header; caller guarantees len >= 2 and len >= header length. */
static size_t hdr_read(const uint8_t *buf, br_hdr_t *hdr)
{
    const uint8_t type = buf[BR_OFF_TYPE];
    memset(hdr, 0, sizeof *hdr);
    hdr->version = (uint8_t)(buf[BR_OFF_VER_FLAGS] >> 4);
    hdr->flags = (uint8_t)(buf[BR_OFF_VER_FLAGS] & BR_FLAGS_MASK);
    hdr->type = type;
    hdr->src_id = br_rd_le16(&buf[BR_OFF_SRC_ID]);
    hdr->dst_id = br_rd_le16(&buf[BR_OFF_DST_ID]);
    hdr->prev_hop = br_rd_le16(&buf[BR_OFF_PREV_HOP]);
    hdr->next_hop = br_rd_le16(&buf[BR_OFF_NEXT_HOP]);
    hdr->ttl = (uint8_t)(buf[BR_OFF_TTL_HOPS] >> 4);
    hdr->hops = (uint8_t)(buf[BR_OFF_TTL_HOPS] & 0x0Fu);
    hdr->hop_seq = br_rd_le32(&buf[BR_OFF_HOP_SEQ]);
    if (type == (uint8_t)BR_TYPE_SEEK) {
        hdr->path_mtu = br_rd_le16(&buf[BR_OFF_PATH_MTU]);
        hdr->path_cost = buf[BR_OFF_PATH_COST];
        hdr->session_id = buf[BR_OFF_SESSION_ID_SEEK];
        hdr->seq = br_rd_le16(&buf[BR_OFF_SEQ_SEEK]);
        hdr->len = buf[BR_OFF_LEN_SEEK];
        return BR_HDR_LEN_SEEK;
    }
    hdr->session_id = buf[BR_OFF_SESSION_ID];
    hdr->seq = br_rd_le16(&buf[BR_OFF_SEQ]);
    hdr->len = buf[BR_OFF_LEN];
    return BR_HDR_LEN;
}

br_err_t br_hdr_encode(const br_hdr_t *hdr, uint8_t *buf, size_t cap, size_t *written)
{
    if (hdr == NULL || buf == NULL || written == NULL ||
        !nibbles_ok(hdr->version, hdr->flags, hdr->ttl, hdr->hops)) {
        return BR_ERR_ARG;
    }
    if (cap < br_hdr_len_for_type(hdr->type)) {
        return BR_ERR_TOO_BIG;
    }
    *written = hdr_write(hdr, hdr->len, buf);
    return BR_OK;
}

br_err_t br_hdr_decode(const uint8_t *buf, size_t len, br_hdr_t *hdr, size_t *hdr_len)
{
    if (buf == NULL || hdr == NULL || hdr_len == NULL) {
        return BR_ERR_ARG;
    }
    if (len < 2u || len < br_hdr_len_for_type(buf[BR_OFF_TYPE])) {
        return BR_ERR_DECODE;
    }
    *hdr_len = hdr_read(buf, hdr);
    return BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Whole frame                                                                */
/* ------------------------------------------------------------------------- */

br_err_t br_frame_encode(const br_hdr_t *hdr, const uint8_t *payload, size_t payload_len,
                         const uint8_t *auth_tag, const uint8_t *hop_tag,
                         uint8_t *buf, size_t cap, size_t *out_len)
{
    if (hdr == NULL || buf == NULL || out_len == NULL ||
        (payload == NULL && payload_len > 0u) ||
        !nibbles_ok(hdr->version, hdr->flags, hdr->ttl, hdr->hops)) {
        return BR_ERR_ARG;
    }
    const bool auth = (hdr->flags & BR_FLAG_AUTH) != 0u;
    if (auth) {
        if (auth_tag == NULL || hop_tag == NULL) {
            return BR_ERR_ARG;
        }
    } else if (auth_tag != NULL || hop_tag != NULL) {
        return BR_ERR_ARG;
    }
    const size_t max_payload = auth ? BR_MAX_PAYLOAD_AUTH : BR_MAX_PAYLOAD_NOAUTH;
    if (payload_len > max_payload) {
        return BR_ERR_TOO_BIG;
    }
    const size_t hl = br_hdr_len_for_type(hdr->type);
    const size_t total = hl + payload_len + (auth ? BR_TAGS_LEN : 0u) + BR_CRC_LEN;
    if (cap < total) {
        return BR_ERR_TOO_BIG;
    }

    size_t w = hdr_write(hdr, (uint8_t)payload_len, buf);
    if (payload_len > 0u) {
        memcpy(&buf[w], payload, payload_len);
        w += payload_len;
    }
    if (auth) {
        memcpy(&buf[w], auth_tag, BR_AUTH_TAG_LEN);
        w += BR_AUTH_TAG_LEN;
        memcpy(&buf[w], hop_tag, BR_HOP_TAG_LEN);
        w += BR_HOP_TAG_LEN;
    }
    br_wr_le16(&buf[w], br_crc16_raw((uint16_t)BR_CRC16_INIT, buf, w));
    w += BR_CRC_LEN;
    *out_len = w;
    return BR_OK;
}

br_err_t br_frame_seal_crc(uint8_t *buf, size_t body_len, size_t cap, size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return BR_ERR_ARG;
    }
    if (cap < BR_CRC_LEN || body_len > cap - BR_CRC_LEN) {
        return BR_ERR_TOO_BIG;
    }
    br_wr_le16(&buf[body_len], br_crc16_raw((uint16_t)BR_CRC16_INIT, buf, body_len));
    *out_len = body_len + BR_CRC_LEN;
    return BR_OK;
}

br_err_t br_frame_set_hop_fields(uint8_t *buf, size_t len, const br_hop_fields_t *hf)
{
    if (buf == NULL || hf == NULL || hf->ttl > 0x0Fu || hf->hops > 0x0Fu) {
        return BR_ERR_ARG;
    }
    if (len < 2u || len < br_hdr_len_for_type(buf[BR_OFF_TYPE])) {
        return BR_ERR_DECODE;
    }
    br_wr_le16(&buf[BR_OFF_PREV_HOP], hf->prev_hop);
    br_wr_le16(&buf[BR_OFF_NEXT_HOP], hf->next_hop);
    buf[BR_OFF_TTL_HOPS] = (uint8_t)((unsigned)(hf->ttl << 4) | hf->hops);
    br_wr_le32(&buf[BR_OFF_HOP_SEQ], hf->hop_seq);
    if (buf[BR_OFF_TYPE] == (uint8_t)BR_TYPE_SEEK) {
        br_wr_le16(&buf[BR_OFF_PATH_MTU], hf->path_mtu);
        buf[BR_OFF_PATH_COST] = hf->path_cost;
    }
    return BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Receiver validation (3.6)                                                  */
/* ------------------------------------------------------------------------- */

br_err_t br_reject_counter(br_reject_t reason, br_counter_t *counter_out)
{
    if (counter_out == NULL) {
        return BR_ERR_ARG;
    }
    switch (reason) {
    case BR_REJ_NONE:
        *counter_out = BR_CNT_NONE;
        return BR_OK;
    case BR_REJ_LEN_SHORT:
    case BR_REJ_LEN_MISMATCH:
    case BR_REJ_LEN_PAYLOAD:
    case BR_REJ_LEN_MAX_FRAME:
    case BR_REJ_TTL:
    case BR_REJ_HOPS:
    case BR_REJ_PREV_HOP:
    case BR_REJ_SRC_ID:
    case BR_REJ_NEXT_HOP:
    case BR_REJ_DST_ID:
    case BR_REJ_PATH_MTU:
    case BR_REJ_PATH_COST:
    case BR_REJ_PRE_CTR_SEQ:
    case BR_REJ_TYPE_LEN:
        *counter_out = BR_CNT_BAD_FRAME;
        return BR_OK;
    case BR_REJ_CRC:
        *counter_out = BR_CNT_CRC_FAIL;
        return BR_OK;
    case BR_REJ_VERSION:
        *counter_out = BR_CNT_BAD_VERSION;
        return BR_OK;
    case BR_REJ_HOP_TAG:
        *counter_out = BR_CNT_HOP_TAG_FAIL;
        return BR_OK;
    case BR_REJ_HOP_REPLAY:
        *counter_out = BR_CNT_HOP_REPLAY;
        return BR_OK;
    case BR_REJ_AUTH:
        *counter_out = BR_CNT_AUTH_FAIL;
        return BR_OK;
    case BR_REJ_REPLAY:
        *counter_out = BR_CNT_REPLAY_DROPPED;
        return BR_OK;
    default:
        return BR_ERR_ARG;
    }
}

static bool id_unit_or_manager(uint16_t id)
{
    return br_id_is_unit(id) || br_id_is_manager(id);
}

static br_err_t reject(br_reject_t why, br_reject_t *reason_out)
{
    *reason_out = why;
    return BR_ERR_REJECT;
}

br_err_t br_frame_validate(const uint8_t *buf, size_t len, const br_link_params_t *link,
                           bool endpoint, br_frame_view_t *view_out, br_reject_t *reason_out)
{
    if (buf == NULL || link == NULL || reason_out == NULL) {
        return BR_ERR_ARG;
    }
    if ((uint16_t)link->rs_nsym >= link->max_frame) {
        return BR_ERR_ARG;
    }

    br_frame_view_t local;
    br_frame_view_t *v = (view_out != NULL) ? view_out : &local;
    memset(v, 0, sizeof *v);
    *reason_out = BR_REJ_NONE;

    const size_t rs_nsym = link->rs_nsym;

    /* 1. Minimum length: header for the type at buf[1] + CRC + RS parity. */
    if (len < 2u) {
        return reject(BR_REJ_LEN_SHORT, reason_out);
    }
    const size_t hl = br_hdr_len_for_type(buf[BR_OFF_TYPE]);
    if (len < hl + BR_CRC_LEN + rs_nsym) {
        return reject(BR_REJ_LEN_SHORT, reason_out);
    }

    /* Header is in bounds now; parse it for the view (syntax only). */
    v->hdr_len = hdr_read(buf, &v->hdr);
    v->payload_off = v->hdr_len;
    v->payload_len = v->hdr.len;
    v->has_auth = (v->hdr.flags & BR_FLAG_AUTH) != 0u;
    v->rs_nsym = link->rs_nsym;
    v->total_len = len;

    /* 2. CRC: fixed position from the end, independent of the len field (N5). */
    const size_t crc_pos = len - rs_nsym - BR_CRC_LEN;
    const uint16_t crc_rx = br_rd_le16(&buf[crc_pos]);
    v->crc = crc_rx;
    if (br_crc16_raw((uint16_t)BR_CRC16_INIT, buf, crc_pos) != crc_rx) {
        return reject(BR_REJ_CRC, reason_out);
    }

    /* 3. Length row. */
    if (len > link->max_frame) {
        return reject(BR_REJ_LEN_MAX_FRAME, reason_out);
    }
    const size_t tags = v->has_auth ? BR_TAGS_LEN : 0u;
    const size_t expect = hl + (size_t)v->hdr.len + tags + BR_CRC_LEN + rs_nsym;
    if (len != expect) {
        return reject(BR_REJ_LEN_MISMATCH, reason_out);
    }
    const size_t pay_cap = v->has_auth ? BR_MAX_PAYLOAD_AUTH : BR_MAX_PAYLOAD_NOAUTH;
    if ((size_t)v->hdr.len + rs_nsym > pay_cap) {
        return reject(BR_REJ_LEN_PAYLOAD, reason_out);
    }
    if (v->has_auth) {
        v->auth_tag_off = hl + v->hdr.len;
        v->hop_tag_off = v->auth_tag_off + BR_AUTH_TAG_LEN;
    }
    v->crc_off = crc_pos;
    v->rs_off = crc_pos + BR_CRC_LEN;

    /* 4. Header row. */
    const br_hdr_t *h = &v->hdr;
    if (h->ttl > BR_MAX_HOPS) {
        return reject(BR_REJ_TTL, reason_out);
    }
    if (h->hops >= BR_MAX_HOPS) {
        return reject(BR_REJ_HOPS, reason_out);
    }
    if (!id_unit_or_manager(h->prev_hop)) {
        return reject(BR_REJ_PREV_HOP, reason_out);
    }
    if (!id_unit_or_manager(h->src_id)) {
        return reject(BR_REJ_SRC_ID, reason_out);
    }
    if (!id_unit_or_manager(h->next_hop) && h->next_hop != BR_ID_FLOOD) {
        return reject(BR_REJ_NEXT_HOP, reason_out);
    }
    if (h->dst_id == BR_ID_UNASSIGNED) {
        return reject(BR_REJ_DST_ID, reason_out);
    }

    /* 5. SEEK hop fields. */
    if (h->type == (uint8_t)BR_TYPE_SEEK) {
        const unsigned mtu_max = (unsigned)link->max_frame - (unsigned)link->rs_nsym;
        if (h->path_mtu < BR_MIN_PATH_MTU || h->path_mtu > mtu_max) {
            return reject(BR_REJ_PATH_MTU, reason_out);
        }
        if (h->path_cost > BR_MAX_PATH_COST) {
            return reject(BR_REJ_PATH_COST, reason_out);
        }
    }

    /* 6. Version (endpoints only; forwarders accept any version, frozen prefix). */
    if (endpoint && (h->version < BR_PROTO_VERSION_MIN || h->version > BR_PROTO_VERSION)) {
        return reject(BR_REJ_VERSION, reason_out);
    }

    return BR_OK;
}

br_err_t br_hop_seq_check(bool have_last, uint32_t last, uint32_t rx, br_reject_t *reason_out)
{
    if (reason_out == NULL) {
        return BR_ERR_ARG;
    }
    if (have_last && (rx <= last || rx - last > BR_HOP_MAX_JUMP)) {
        *reason_out = BR_REJ_HOP_REPLAY;
        return BR_ERR_REJECT;
    }
    *reason_out = BR_REJ_NONE;
    return BR_OK;
}

br_err_t br_frame_check_type_len(uint8_t type, size_t payload_len, br_reject_t *reason_out)
{
    if (reason_out == NULL) {
        return BR_ERR_ARG;
    }
    size_t exact = 0u;
    size_t min = 0u;
    switch (type) {
    case BR_TYPE_SEEK:       exact = BR_LEN_SEEK; break;
    case BR_TYPE_HELLO:      exact = BR_LEN_HELLO; break;
    case BR_TYPE_BIND:       exact = BR_LEN_BIND; break;
    case BR_TYPE_BIND_ACK:   exact = BR_LEN_BIND_ACK; break;
    case BR_TYPE_BIND_NAK:   exact = BR_LEN_BIND_NAK; break;
    case BR_TYPE_MODE_ACK:   exact = BR_LEN_MODE_ACK; break;
    case BR_TYPE_ACK:        exact = BR_LEN_ACK; break;
    case BR_TYPE_RESUME_ACK: exact = BR_LEN_RESUME_ACK; break;
    case BR_TYPE_PING:       exact = BR_LEN_PING; break;
    case BR_TYPE_PONG:       exact = BR_LEN_PONG; break;
    case BR_TYPE_CLOSE:      exact = BR_LEN_CLOSE; break;
    case BR_TYPE_RESUME:     exact = BR_LEN_RESUME; break;
    case BR_TYPE_MGMT_REQ:   min = BR_LEN_MGMT_REQ_FIXED; break;
    case BR_TYPE_MGMT_RESP:  min = BR_LEN_MGMT_RESP_FIXED; break;
    case BR_TYPE_MODE:       min = BR_LEN_MODE_FIXED; break;
    case BR_TYPE_DATA:       min = BR_LEN_DATA_FIXED; break;
    case BR_TYPE_PARITY:     min = BR_FEC_PARITY_HDR_LEN; break;
    default:
        *reason_out = BR_REJ_NONE; /* unknown types are dropped elsewhere */
        return BR_OK;
    }
    const bool ok = (exact != 0u) ? (payload_len == exact) : (payload_len >= min);
    if (!ok) {
        *reason_out = BR_REJ_TYPE_LEN;
        return BR_ERR_REJECT;
    }
    *reason_out = BR_REJ_NONE;
    return BR_OK;
}

br_err_t br_frame_clear_len(uint8_t type, uint8_t session_id, size_t payload_len, size_t *clear_out)
{
    if (clear_out == NULL) {
        return BR_ERR_ARG;
    }
    if (type == (uint8_t)BR_TYPE_SEEK || type == (uint8_t)BR_TYPE_RESUME) {
        *clear_out = payload_len;
        return BR_OK;
    }
    if (session_id == 0u) {
        if (payload_len < BR_LEN_PRE_CTR) {
            return BR_ERR_DECODE;
        }
        *clear_out = BR_LEN_PRE_CTR;
        return BR_OK;
    }
    *clear_out = 0u;
    return BR_OK;
}

br_err_t br_frame_pre_ctr(const uint8_t *buf, const br_frame_view_t *view,
                          uint32_t *pre_ctr_out, br_reject_t *reason_out)
{
    if (buf == NULL || view == NULL || pre_ctr_out == NULL || reason_out == NULL) {
        return BR_ERR_ARG;
    }
    const br_hdr_t *h = &view->hdr;
    if (h->session_id != 0u && h->type != (uint8_t)BR_TYPE_RESUME) {
        return BR_ERR_ARG; /* session frame: no clear pre_ctr */
    }
    if (view->payload_len < BR_LEN_PRE_CTR) {
        *reason_out = BR_REJ_TYPE_LEN;
        return BR_ERR_REJECT;
    }
    /* Defensive: the view must describe bytes that exist. */
    if (view->payload_off > view->total_len ||
        view->total_len - view->payload_off < BR_LEN_PRE_CTR) {
        return BR_ERR_ARG;
    }
    const uint32_t pre_ctr = br_rd_le32(&buf[view->payload_off]);
    *pre_ctr_out = pre_ctr;
    if (h->session_id == 0u && (uint16_t)(pre_ctr & 0xFFFFu) != h->seq) {
        *reason_out = BR_REJ_PRE_CTR_SEQ;
        return BR_ERR_REJECT;
    }
    *reason_out = BR_REJ_NONE;
    return BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Counters (3.5)                                                             */
/* ------------------------------------------------------------------------- */

br_err_t br_seq16_newer(uint16_t a, uint16_t b, bool *newer_out)
{
    if (newer_out == NULL) {
        return BR_ERR_ARG;
    }
    const uint16_t d = (uint16_t)(a - b);
    *newer_out = (d != 0u) && (d < 0x8000u);
    return BR_OK;
}

br_err_t br_roc_estimate(uint16_t seq, uint16_t s_l, uint32_t roc, uint32_t *roc_out)
{
    if (roc_out == NULL) {
        return BR_ERR_ARG;
    }
    const int32_t iseq = (int32_t)seq;
    const int32_t isl = (int32_t)s_l;
    if (isl < 32768 && iseq - isl > 32768) {
        if (roc == 0u) {
            return BR_ERR_REJECT; /* N8: index before the session start */
        }
        *roc_out = roc - 1u;
        return BR_OK;
    }
    if (isl >= 32768 && isl - 32768 > iseq) {
        if (roc == UINT32_MAX) {
            return BR_ERR_TOO_BIG; /* N8: 48-bit index exhausted */
        }
        *roc_out = roc + 1u;
        return BR_OK;
    }
    *roc_out = roc;
    return BR_OK;
}
