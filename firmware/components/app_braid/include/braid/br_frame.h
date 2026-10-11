// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_frame.h - frame header codec, layout and the receiver validator (spec 3, 3.5, 3.6).
 *
 * Wire layout (section 3), all multi-byte fields little-endian:
 *
 *   Off Size Field                                         (SEEK offsets in [])
 *   0   1    ver_flags  bits 7..4 version, 3..0 flags
 *   1   1    type       br_msg_type_t
 *   2   2    src_id
 *   4   2    dst_id
 *   6   2    prev_hop
 *   8   2    next_hop   0xFFFF = flood
 *   10  1    ttl_hops   bits 7..4 ttl (hops remaining), 3..0 hops done
 *   11  4    hop_seq    transmitter's txseq, full 32 bits
 *  [15  2    path_mtu   SEEK only]
 *  [17  1    path_cost  SEEK only]
 *   15 [18] 1 session_id
 *   16 [19] 2 seq
 *   18 [21] 1 len        payload length 0..255
 *   19 [22] len payload
 *   ..  8    auth_tag   iff FLAG_AUTH
 *   ..  4    hop_tag    iff FLAG_AUTH
 *   ..  2    crc16      over byte 0 .. end of hop_tag (end of payload without AUTH)
 *   ..  n    rs_parity  rs_nsym bytes on RAW links (computed over frame incl. CRC)
 *
 * All field access uses memcpy() into native integers (section 3: never cast a
 * uint32_t * into the buffer). Both targets and every supported host are
 * little-endian; a big-endian build fails at compile time below.
 *
 * Vectors: A.2 (SEEK, no tags), A.7 / A.8 (DATA and SEEK with tags), A.11 (RESUME).
 */
#ifndef BRAID_BR_FRAME_H
#define BRAID_BR_FRAME_H

#include <string.h>

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Braid br_frame.h: memcpy-based LE access requires a little-endian target"
#endif
#endif

/* ------------------------------------------------------------------------- */
/* Little-endian field access (section 3). Unaligned-safe, no UB.             */
/* ------------------------------------------------------------------------- */

/** Read a little-endian u16 at p (any alignment). */
static inline uint16_t br_rd_le16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

/** Read a little-endian u32 at p (any alignment). */
static inline uint32_t br_rd_le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

/** Write v little-endian at p (any alignment). */
static inline void br_wr_le16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, sizeof v);
}

/** Write v little-endian at p (any alignment). */
static inline void br_wr_le32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof v);
}

/* ------------------------------------------------------------------------- */
/* Header                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * Decoded header. One struct covers both layouts:
 * - 19-byte header: every type except SEEK; path_mtu / path_cost are ignored
 *   on encode and set to 0 on decode.
 * - 22-byte SEEK header (type == BR_TYPE_SEEK): path_mtu / path_cost present.
 *
 * Nibble fields hold the unpacked values: version and flags from ver_flags,
 * ttl and hops from ttl_hops; each must be 0..15 on encode.
 */
typedef struct {
    uint8_t  version;     /**< ver_flags bits 7..4. */
    uint8_t  flags;       /**< ver_flags bits 3..0 (BR_FLAG_*). */
    uint8_t  type;        /**< br_msg_type_t value; any byte accepted by the codec. */
    uint16_t src_id;      /**< end-to-end */
    uint16_t dst_id;      /**< end-to-end */
    uint16_t prev_hop;    /**< per hop */
    uint16_t next_hop;    /**< per hop */
    uint8_t  ttl;         /**< per hop, ttl_hops bits 7..4 */
    uint8_t  hops;        /**< per hop, ttl_hops bits 3..0 */
    uint32_t hop_seq;     /**< per hop */
    uint16_t path_mtu;    /**< per hop, SEEK only */
    uint8_t  path_cost;   /**< per hop, SEEK only */
    uint8_t  session_id;  /**< end-to-end; 0 in SEEK/HELLO/BIND/BIND_ACK/BIND_NAK/MGMT */
    uint16_t seq;         /**< end-to-end; low 16 bits of pre_ctr when session_id == 0 */
    uint8_t  len;         /**< payload length */
} br_hdr_t;

/**
 * Header length for a message type: BR_HDR_LEN_SEEK (22) for BR_TYPE_SEEK,
 * BR_HDR_LEN (19) for every other byte value (including unknown types: the
 * SEEK hop fields are part of the frozen prefix, so type 0x01 is the only
 * type with the long header in every version).
 *
 * @spec 3 (line 165, frozen prefix line 178)
 */
static inline size_t br_hdr_len_for_type(uint8_t type)
{
    return (type == (uint8_t)BR_TYPE_SEEK) ? (size_t)BR_HDR_LEN_SEEK : (size_t)BR_HDR_LEN;
}

/**
 * Serialise a header.
 *
 * Writes br_hdr_len_for_type(hdr->type) bytes. Reserved flag bits are written
 * as given (callers send 0, section 3).
 *
 * @param hdr      Header; version, flags, ttl, hops must each be <= 15.
 * @param buf      Output.
 * @param cap      Capacity of buf.
 * @param written  Receives 19 or 22.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or a nibble field > 15;
 *         BR_ERR_TOO_BIG if cap is smaller than the header.
 * @spec 3
 */
br_err_t br_hdr_encode(const br_hdr_t *hdr, uint8_t *buf, size_t cap, size_t *written);

/**
 * Parse a header (syntax only: no range checks; see br_frame_validate()).
 *
 * @param buf      Received bytes.
 * @param len      Bytes available; must cover the header for the type at buf[1].
 * @param hdr      Receives the fields (path_mtu / path_cost = 0 unless SEEK).
 * @param hdr_len  Receives 19 or 22.
 * @return BR_OK; BR_ERR_ARG on NULL pointers; BR_ERR_DECODE if len < 2 or len is
 *         shorter than the header for that type.
 * @spec 3
 */
br_err_t br_hdr_decode(const uint8_t *buf, size_t len, br_hdr_t *hdr, size_t *hdr_len);

/* ------------------------------------------------------------------------- */
/* Whole frame                                                                */
/* ------------------------------------------------------------------------- */

/** Offsets of the parts of a parsed frame; all offsets are from buf[0]. */
typedef struct {
    br_hdr_t hdr;
    size_t   hdr_len;       /**< 19 or 22 */
    size_t   payload_off;   /**< == hdr_len */
    size_t   payload_len;   /**< == hdr.len */
    bool     has_auth;      /**< hdr.flags & BR_FLAG_AUTH */
    size_t   auth_tag_off;  /**< valid iff has_auth */
    size_t   hop_tag_off;   /**< valid iff has_auth; also == bytes covered by the hop_tag (8.3) */
    size_t   crc_off;       /**< CRC covers [0, crc_off) */
    uint16_t crc;           /**< CRC as received */
    size_t   rs_off;        /**< start of RS parity (== crc_off + 2) */
    uint8_t  rs_nsym;       /**< parity bytes after the CRC */
    size_t   total_len;     /**< whole received buffer incl. RS parity */
} br_frame_view_t;

/**
 * Build a complete frame: header || payload || [auth_tag || hop_tag] || CRC.
 * No RS parity (append it with br_rs_encode() over the returned bytes).
 *
 * hdr->len is ignored; payload_len is written in the len field.
 * The CRC is computed over everything before it and stored little-endian.
 *
 * Typical sender flow with FLAG_AUTH: call once with zeroed tag placeholders
 * to lay out the header, compute the CCM tag (br_crypto.h) over the AAD built
 * from those bytes, then the hop_tag over [0, hop_tag_off), then call again
 * (or patch the tags and call br_frame_seal_crc()).
 *
 * @param hdr          Header fields (see br_hdr_encode()).
 * @param payload      Clear prefix + ciphertext as it goes on the wire; NULL only if payload_len == 0.
 * @param payload_len  0..255.
 * @param auth_tag     8 bytes; required iff hdr->flags has BR_FLAG_AUTH, else must be NULL.
 * @param hop_tag      4 bytes; same rule as auth_tag.
 * @param buf          Output; must not overlap the inputs.
 * @param cap          Capacity of buf.
 * @param out_len      Receives the frame length (header + payload + 12 if AUTH + 2).
 * @return BR_OK; BR_ERR_ARG on NULL pointers, tag pointers inconsistent with
 *         FLAG_AUTH, or invalid header nibbles; BR_ERR_TOO_BIG if cap is too
 *         small or payload_len exceeds the 3.6 cap for rs_nsym 0
 *         (229 without AUTH, 217 with AUTH).
 * @spec 3, 3.1, 8.3
 */
br_err_t br_frame_encode(const br_hdr_t *hdr, const uint8_t *payload, size_t payload_len,
                         const uint8_t *auth_tag, const uint8_t *hop_tag,
                         uint8_t *buf, size_t cap, size_t *out_len);

/**
 * Append the CRC-16 over buf[0 .. body_len-1] at buf[body_len] (little-endian).
 *
 * Used after rewriting per-hop fields and the hop_tag of a forwarded frame.
 *
 * @param buf       Frame body (header .. end of hop_tag).
 * @param body_len  Bytes covered by the CRC.
 * @param cap       Capacity of buf; >= body_len + 2.
 * @param out_len   Receives body_len + 2.
 * @return BR_OK; BR_ERR_ARG on NULL pointers; BR_ERR_TOO_BIG if cap < body_len + 2.
 * @spec 3, 3.1
 */
br_err_t br_frame_seal_crc(uint8_t *buf, size_t body_len, size_t cap, size_t *out_len);

/** Per-hop fields a forwarder rewrites (section 11; 3 "per hop" scope). */
typedef struct {
    uint16_t prev_hop;
    uint16_t next_hop;
    uint8_t  ttl;        /**< 0..15 */
    uint8_t  hops;       /**< 0..15 */
    uint32_t hop_seq;
    uint16_t path_mtu;   /**< written only if the frame is a SEEK */
    uint8_t  path_cost;  /**< written only if the frame is a SEEK */
} br_hop_fields_t;

/**
 * Overwrite the per-hop header fields in place. End-to-end fields, payload,
 * tags and CRC are untouched: the caller recomputes hop_tag (br_hop_tag())
 * and the CRC (br_frame_seal_crc()) afterwards.
 *
 * @param buf  Frame; at least br_hdr_len_for_type(buf[1]) bytes.
 * @param len  Bytes in buf.
 * @param hf   New per-hop values.
 * @return BR_OK; BR_ERR_ARG on NULL pointers or ttl/hops > 15;
 *         BR_ERR_DECODE if len is shorter than the header.
 * @spec 3, 11.2
 */
br_err_t br_frame_set_hop_fields(uint8_t *buf, size_t len, const br_hop_fields_t *hf);

/* ------------------------------------------------------------------------- */
/* Receiver validation (3.6, normative)                                       */
/* ------------------------------------------------------------------------- */

/**
 * Reject reasons. Each maps to exactly one br_stats_t counter
 * (br_reject_counter()). Stage in brackets is the 3.6 row.
 */
typedef enum {
    BR_REJ_NONE = 0,          /**< Accepted. */
    /* [Length] -> bad_frame */
    BR_REJ_LEN_SHORT,         /**< Buffer shorter than header (for its type) + CRC + rs_nsym. */
    BR_REJ_LEN_MISMATCH,      /**< received length != hdr + len + (12 if AUTH) + 2 + rs_nsym. */
    BR_REJ_LEN_PAYLOAD,       /**< len > 229 - rs_nsym (no AUTH) or > 217 - rs_nsym (AUTH). */
    BR_REJ_LEN_MAX_FRAME,     /**< received length > link max_frame (implementation addition). */
    /* [frame layer, 3.1/3.2] -> crc_fail */
    BR_REJ_CRC,               /**< CRC-16 mismatch. */
    /* [Header] -> bad_frame */
    BR_REJ_TTL,               /**< ttl > MAX_HOPS. */
    BR_REJ_HOPS,              /**< hops >= MAX_HOPS. */
    BR_REJ_PREV_HOP,          /**< prev_hop not a unit or manager ID. */
    BR_REJ_SRC_ID,            /**< src_id not a unit or manager ID. */
    BR_REJ_NEXT_HOP,          /**< next_hop not a unit ID, manager ID or 0xFFFF. */
    BR_REJ_DST_ID,            /**< dst_id == 0. */
    /* [SEEK hop fields] -> bad_frame */
    BR_REJ_PATH_MTU,          /**< path_mtu < 48 or > (max_frame - rs_nsym) of the arrival link. */
    BR_REJ_PATH_COST,         /**< path_cost > 250. */
    /* [Version] -> bad_version */
    BR_REJ_VERSION,           /**< endpoint: version not in BR_PROTO_VERSION_MIN..BR_PROTO_VERSION. */
    /* [hop_tag] */
    BR_REJ_HOP_TAG,           /**< hop_tag invalid under every held K_hop epoch -> hop_tag_fail. */
    BR_REJ_HOP_REPLAY,        /**< hop_seq not newer, or > HOP_MAX_JUMP ahead -> hop_replay. */
    /* [CCM tag] */
    BR_REJ_AUTH,              /**< CCM tag invalid -> auth_fail. */
    BR_REJ_PRE_CTR_SEQ,       /**< session_id 0: header seq != low 16 bits of pre_ctr -> bad_frame. */
    /* [per-type rows] -> bad_frame */
    BR_REJ_TYPE_LEN,          /**< Payload length wrong for the type. */
    /* [8.4 session window] -> replay_dropped */
    BR_REJ_REPLAY             /**< Session index duplicate or below the 64-entry window. */
} br_reject_t;

/** Properties of the link a frame arrived on (1.2 transport fields). */
typedef struct {
    uint16_t max_frame;   /**< Carrier max_frame incl. RS parity (250 mesh, 80 IR). */
    uint8_t  rs_nsym;     /**< 0 PACKET, 8 UART, 6 IR. */
} br_link_params_t;

/**
 * Map a reject reason to the br_stats_t counter it increments (3.6 column
 * "Counter"; BR_REJ_CRC -> crc_fail, BR_REJ_REPLAY -> replay_dropped).
 *
 * @param reason       Any br_reject_t.
 * @param counter_out  Receives the counter (BR_CNT_NONE for BR_REJ_NONE).
 * @return BR_OK; BR_ERR_ARG if counter_out is NULL or reason is not a
 *         br_reject_t value.
 * @spec 3.6, Appendix B br_stats_t
 */
br_err_t br_reject_counter(br_reject_t reason, br_counter_t *counter_out);

/**
 * Stateless receive validation: frame-layer CRC plus the 3.6 rows that need
 * no key and no table (Length, Header, SEEK hop fields, Version).
 *
 * Input: the frame as received, AFTER RS decoding on RAW links (corrected in
 * place, parity bytes still at the end, so len includes rs_nsym exactly as in
 * the 3.6 Length formula) and after COBS decoding on UART.
 *
 * Checks run in this order; the first failure is reported:
 *   1. BR_REJ_LEN_SHORT    len < br_hdr_len_for_type(buf[1]) + 2 + rs_nsym
 *                          (also when len < 2).
 *   2. BR_REJ_CRC          CRC-16 at [len - rs_nsym - 2] (LE) over
 *                          [0, len - rs_nsym - 2). Checked before the Length
 *                          row because its position does not depend on the
 *                          len field, so line noise counts as crc_fail.
 *   3. Length row:         BR_REJ_LEN_MAX_FRAME (len > link->max_frame),
 *                          BR_REJ_LEN_MISMATCH, BR_REJ_LEN_PAYLOAD.
 *   4. Header row, in order: BR_REJ_TTL (ttl > 8), BR_REJ_HOPS (hops >= 8),
 *                          BR_REJ_PREV_HOP, BR_REJ_SRC_ID (each must satisfy
 *                          br_id_is_unit() || br_id_is_manager()),
 *                          BR_REJ_NEXT_HOP (unit, manager, or 0xFFFF),
 *                          BR_REJ_DST_ID (dst_id == 0).
 *   5. SEEK hop fields (type == SEEK only): BR_REJ_PATH_MTU
 *                          (path_mtu < 48 || path_mtu > max_frame - rs_nsym),
 *                          BR_REJ_PATH_COST (path_cost > 250).
 *   6. Version (endpoint only): BR_REJ_VERSION. Forwarders skip it.
 *
 * Reserved flag bits (2, 3) are ignored. Unknown types are not rejected here.
 * The hop_tag, CCM and per-type rows are separate calls (br_hop_seq_check(),
 * br_crypto.h, br_frame_check_type_len(), br_frame_pre_ctr()).
 *
 * @param buf         Received frame.
 * @param len         Received length incl. RS parity.
 * @param link        Arrival link parameters; requires rs_nsym < max_frame.
 * @param endpoint    true at an endpoint (applies the Version row), false at a forwarder.
 * @param view_out    Optional (may be NULL). On BR_OK: full layout. On
 *                    BR_ERR_REJECT: filled as far as parsing got (contents
 *                    unspecified for BR_REJ_LEN_SHORT).
 * @param reason_out  Receives BR_REJ_NONE on BR_OK, the reason on BR_ERR_REJECT.
 * @return BR_OK if accepted; BR_ERR_REJECT if rejected (see *reason_out);
 *         BR_ERR_ARG if buf, link or reason_out is NULL or link is inconsistent.
 * @spec 3, 3.1, 3.2, 3.6, 11.2
 */
br_err_t br_frame_validate(const uint8_t *buf, size_t len, const br_link_params_t *link,
                           bool endpoint, br_frame_view_t *view_out, br_reject_t *reason_out);

/**
 * hop_seq freshness (3.6 hop_tag row; 3.5; 8.4). Run after the hop_tag
 * verified, before learning or forwarding.
 *
 * Accept iff rx > last (plain unsigned 32-bit compare, no wrap: 3.5) and
 * rx - last <= BR_HOP_MAX_JUMP. With have_last == false (no link-table entry
 * for (prev_hop, transport), e.g. after LINK_TTL_MS expiry) every rx is
 * accepted (known limitation, 8.4).
 *
 * @param have_last   Whether the link table holds a value.
 * @param last        Stored hop_seq for (prev_hop, transport).
 * @param rx          Received hop_seq.
 * @param reason_out  BR_REJ_NONE or BR_REJ_HOP_REPLAY.
 * @return BR_OK; BR_ERR_REJECT; BR_ERR_ARG if reason_out is NULL.
 * @spec 3.5, 3.6, 8.4
 */
br_err_t br_hop_seq_check(bool have_last, uint32_t last, uint32_t rx, br_reject_t *reason_out);

/**
 * Per-type payload length (3.6 rows SEEK .. MGMT, length column only).
 *
 * Exact: SEEK 18, HELLO 28, BIND 17, BIND_ACK 12, BIND_NAK 9, MODE_ACK 2,
 * ACK 6, RESUME_ACK 6, PING 4, PONG 8, CLOSE 3, RESUME 5.
 * Minimum: MGMT_REQ >= 22, MGMT_RESP >= 33, MODE >= 13, DATA >= 7,
 * PARITY >= 8 (exact values depend on mode / session state; checked later).
 * Unknown types: BR_OK (endpoints drop them elsewhere).
 * Lengths are payload bytes on the wire (clear prefix + ciphertext); CCM
 * does not change the length.
 * MODE exception (3.6 line 302): a MODE that fails validation is answered
 * with MODE_ACK status 3 (bad arg) or 2 (too big), NOT counted as bad_frame.
 * This function still returns BR_REJ_TYPE_LEN for a MODE shorter than 13;
 * the caller must map that to MODE_ACK status 3 instead of
 * br_reject_counter().
 *
 * @param type        Header type.
 * @param payload_len Header len.
 * @param reason_out  BR_REJ_NONE or BR_REJ_TYPE_LEN.
 * @return BR_OK; BR_ERR_REJECT; BR_ERR_ARG if reason_out is NULL.
 * @spec 3.6, 5
 */
br_err_t br_frame_check_type_len(uint8_t type, size_t payload_len, br_reject_t *reason_out);

/**
 * Number of clear (unencrypted, AAD-only) payload bytes at the start of the
 * payload (5, 8.3):
 * - SEEK and RESUME: the whole payload;
 * - other types with session_id == 0 (HELLO, BIND, BIND_ACK, BIND_NAK, MGMT):
 *   4 (pre_ctr);
 * - session frames: 0.
 *
 * @param type         Header type.
 * @param session_id   Header session_id.
 * @param payload_len  Header len.
 * @param clear_out    Receives the count (<= payload_len).
 * @return BR_OK; BR_ERR_ARG if clear_out is NULL; BR_ERR_DECODE if a
 *         pre_ctr is required but payload_len < 4.
 * @spec 5, 8.3
 */
br_err_t br_frame_clear_len(uint8_t type, uint8_t session_id, size_t payload_len, size_t *clear_out);

/**
 * Read the clear pre_ctr (first 4 payload bytes, LE) and, for session_id 0
 * frames, enforce header seq == low 16 bits of pre_ctr (3.6 CCM row).
 * RESUME (session_id != 0) carries pre_ctr too but its seq is the session
 * seq, so the seq check is skipped for it.
 *
 * @param buf          Validated frame.
 * @param view         Its layout from br_frame_validate().
 * @param pre_ctr_out  Receives pre_ctr.
 * @param reason_out   BR_REJ_NONE, BR_REJ_PRE_CTR_SEQ, or BR_REJ_TYPE_LEN
 *                     (payload shorter than 4 bytes).
 * @return BR_OK; BR_ERR_REJECT; BR_ERR_ARG on NULL pointers or a frame type
 *         that has no pre_ctr (session frames other than RESUME).
 * @spec 3.5, 3.6, 5, 8.3
 */
br_err_t br_frame_pre_ctr(const uint8_t *buf, const br_frame_view_t *view,
                          uint32_t *pre_ctr_out, br_reject_t *reason_out);

/* ------------------------------------------------------------------------- */
/* Counters (3.5)                                                             */
/* ------------------------------------------------------------------------- */

/**
 * RFC 1982 serial-number comparison for the 16-bit seq: is a newer than b?
 *
 * newer iff a != b and ((a - b) mod 2^16) < 2^15. The case
 * (a - b) mod 2^16 == 2^15 is undefined in RFC 1982 and reported as NOT newer.
 *
 * @param a, b       16-bit sequence numbers.
 * @param newer_out  Receives the result.
 * @return BR_OK; BR_ERR_ARG if newer_out is NULL.
 * @spec 3.5
 */
br_err_t br_seq16_newer(uint16_t a, uint16_t b, bool *newer_out);

/**
 * SRTP-style ROC estimate (3.5, RFC 3711 3.3.1) for a received session seq.
 *
 * With s_l the highest seq received and roc the current estimate:
 *   - roc - 1 if s_l < 32768 and (int)seq - (int)s_l > 32768;
 *   - roc + 1 if s_l >= 32768 and s_l - 32768 > seq;
 *   - roc otherwise.
 * The CCM tag confirms the guess (A.10).
 * Vectors (A.10), (seq, s_l, roc) -> roc used:
 *   (0x0005, 0xFFF0, 0) -> 1; (0xFFF0, 0x0005, 1) -> 0;
 *   (0x8001, 0x0000, 3) -> 2; (0x7FFF, 0xFFFF, 3) -> 3.
 *
 * @param seq      Received header seq.
 * @param s_l      Highest seq received so far in this session/direction.
 * @param roc      Current ROC.
 * @param roc_out  Receives the ROC to use.
 * @return BR_OK; BR_ERR_ARG if roc_out is NULL; BR_ERR_REJECT if the rule
 *         yields roc - 1 while roc == 0 (index before the session start:
 *         caller drops, counter replay_dropped); BR_ERR_TOO_BIG if it yields
 *         roc + 1 while roc == UINT32_MAX (48-bit index exhausted).
 * @spec 3.5, 8.4, A.10
 */
br_err_t br_roc_estimate(uint16_t seq, uint16_t s_l, uint32_t roc, uint32_t *roc_out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_FRAME_H */
