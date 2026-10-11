// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_types.h - Braid core: status codes, IDs, message types, limits.
 *
 * Spec: PROTOCOL.md v0.9 (Braid). Section numbers in comments refer to it.
 *
 * Pure C11. No ESP-IDF, FreeRTOS or OS includes. Builds on the host and on
 * ESP32 / ESP32-S3 with one constant table (12.12: no constant may depend on
 * the chip).
 */
#ifndef BRAID_BR_TYPES_H
#define BRAID_BR_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Status codes (Appendix B, line 1890)                                       */
/* ------------------------------------------------------------------------- */

/**
 * Status returned by every Braid function.
 *
 * Values 0..8 are exactly the Appendix B enum, in its order. Values from 16
 * up are additions of this implementation (the spec's enum has no code for
 * them); they never appear on the wire.
 */
typedef enum {
    BR_OK                  = 0,  /**< Success. */
    BR_ERR_ARG             = 1,  /**< Invalid argument (NULL pointer, out-of-range value). */
    BR_ERR_STATE           = 2,  /**< Call not valid in the current state (e.g. ctx not initialised). */
    BR_ERR_NO_PROBE        = 3,  /**< Event only (B): SEEK found no probe. */
    BR_ERR_TIMEOUT         = 4,  /**< Operation timed out. */
    BR_ERR_BUSY            = 5,  /**< Resource busy. */
    BR_ERR_TOO_BIG         = 6,  /**< Output buffer too small, or input exceeds a protocol limit. */
    BR_ERR_AUTH            = 7,  /**< Authentication failed (CCM tag, hop_tag, compare mismatch). */
    BR_ERR_QUEUE_FULL      = 8,  /**< Queue full. */

    /* --- additions (not in Appendix B) --- */
    BR_ERR_NOT_IMPLEMENTED = 16, /**< Stub: function declared but not implemented yet. */
    BR_ERR_NO_MEM          = 17, /**< Allocation failed (only possible inside *_init functions). */
    BR_ERR_CRC             = 18, /**< CRC-16 mismatch (3.1). */
    BR_ERR_DECODE          = 19, /**< Malformed encoding (e.g. COBS: zero byte or code past end). */
    BR_ERR_UNCORRECTABLE   = 20, /**< RS / FEC: more damage than the parity can repair (3.2, 3.3). */
    BR_ERR_CRYPTO          = 21, /**< Crypto backend (mbedtls) returned an unexpected error. */
    BR_ERR_REJECT          = 22  /**< Frame rejected by a 3.6 check; the reason is in a br_reject_t out-param. */
} br_err_t;

/* ------------------------------------------------------------------------- */
/* Device IDs (section 2)                                                     */
/* ------------------------------------------------------------------------- */

#define BR_ID_UNASSIGNED       0x0000u /**< Never valid on the air. */
#define BR_ID_GATEWAY          0x0001u /**< Gateway / manager. */
#define BR_ID_PROV_STATION     0x0002u /**< Provisioning station (UART recovery manager, 12.2). */
#define BR_ID_RECOVERY_FIRST   0x0003u /**< First recovery-holder (phone) ID (6.4). */
#define BR_ID_RECOVERY_LAST    0x000Fu /**< Last recovery-holder (phone) ID. */
#define BR_ID_UNIT_FIRST       0x0010u /**< First unit (node) ID. */
#define BR_ID_UNIT_LAST        0xFEFFu /**< Last unit (node) ID. */
#define BR_ID_GROUP_FIRST      0xFF00u /**< First group (destination) ID. */
#define BR_ID_GROUP_LAST       0xFFFEu /**< Last group ID. */
#define BR_ID_FLOOD            0xFFFFu /**< Flood (dst_id / next_hop). */

/**
 * Manager ID range used by the 3.6 Header row ("unit IDs or manager IDs").
 * Interpretation (spec ambiguity, see lines 107-109 and 294): every ID below
 * the unit range except 0x0000, i.e. gateway 0x0001, provisioning station
 * 0x0002 and recovery holders 0x0003..0x000F.
 */
#define BR_ID_MANAGER_FIRST    0x0001u
#define BR_ID_MANAGER_LAST     0x000Fu

/** True if id is a unit (node) ID, 0x0010..0xFEFF (section 2). */
static inline bool br_id_is_unit(uint16_t id)
{
    return id >= BR_ID_UNIT_FIRST && id <= BR_ID_UNIT_LAST;
}

/** True if id is a manager ID, 0x0001..0x000F (see BR_ID_MANAGER_FIRST). */
static inline bool br_id_is_manager(uint16_t id)
{
    return id >= BR_ID_MANAGER_FIRST && id <= BR_ID_MANAGER_LAST;
}

/** True if id is a group ID, 0xFF00..0xFFFE (section 2). */
static inline bool br_id_is_group(uint16_t id)
{
    return id >= BR_ID_GROUP_FIRST && id <= BR_ID_GROUP_LAST;
}

/* ------------------------------------------------------------------------- */
/* Message types (section 5)                                                  */
/* ------------------------------------------------------------------------- */

typedef enum {
    BR_TYPE_SEEK       = 0x01, /**< Flooded; 22-byte header; payload fully clear (18 bytes). */
    BR_TYPE_HELLO      = 0x02, /**< Payload 28. */
    BR_TYPE_BIND       = 0x03, /**< Payload 17. */
    BR_TYPE_BIND_ACK   = 0x04, /**< Payload 12. */
    BR_TYPE_MODE       = 0x05, /**< Payload 13 + descriptor (6.1). */
    BR_TYPE_MODE_ACK   = 0x06, /**< Payload 2. */
    BR_TYPE_BIND_NAK   = 0x07, /**< Payload 9. */
    BR_TYPE_DATA       = 0x10, /**< Payload 6.2. */
    BR_TYPE_PARITY     = 0x11, /**< Payload 3.3: 8-byte PARITY header + parity[block_len]. */
    BR_TYPE_ACK        = 0x12, /**< Payload 6. */
    BR_TYPE_PING       = 0x20, /**< Payload 4. */
    BR_TYPE_PONG       = 0x21, /**< Payload 8. */
    BR_TYPE_CLOSE      = 0x30, /**< Payload 3. */
    BR_TYPE_RESUME     = 0x31, /**< Flooded; payload fully clear (5). */
    BR_TYPE_RESUME_ACK = 0x32, /**< Payload 6. */
    BR_TYPE_MGMT_REQ   = 0x40, /**< Fixed part 22 + TLVs (11.10). */
    BR_TYPE_MGMT_RESP  = 0x41  /**< Fixed part 33 + TLVs (11.10). */
} br_msg_type_t;

/* Fixed payload lengths from the 3.6 table (lines 299-306). */
#define BR_LEN_SEEK             18u
#define BR_LEN_HELLO            28u
#define BR_LEN_BIND             17u
#define BR_LEN_BIND_ACK         12u
#define BR_LEN_BIND_NAK          9u
#define BR_LEN_MODE_ACK          2u
#define BR_LEN_ACK               6u
#define BR_LEN_RESUME_ACK        6u
#define BR_LEN_PING              4u
#define BR_LEN_PONG              8u
#define BR_LEN_CLOSE             3u
#define BR_LEN_RESUME            5u
#define BR_LEN_MGMT_REQ_FIXED   22u  /**< Minimum; TLVs follow. */
#define BR_LEN_MGMT_RESP_FIXED  33u  /**< Minimum; TLVs follow. */
#define BR_LEN_MODE_FIXED       13u  /**< Plus descriptor bytes (mode 2: +40). */
#define BR_LEN_DATA_FIXED        7u  /**< Plus n_samples x sample bytes. */
#define BR_LEN_PRE_CTR           4u  /**< Clear pre_ctr u32 prefix on session_id 0 frames and RESUME (5, 8.3). */

/* ------------------------------------------------------------------------- */
/* Frame format constants (section 3)                                         */
/* ------------------------------------------------------------------------- */

#define BR_PROTO_VERSION        1u   /**< N: ver_flags bits 7..4 (section 3). */
/**
 * Oldest version an ENDPOINT accepts (3.6 Version row: {N, N-1}; 12.7).
 * Interpretation: N-1 only counts once it exists. v1 is the first version
 * ever defined, so endpoints accept exactly {1} until N becomes 2. Forwarders
 * accept any version (frozen prefix).
 */
#define BR_PROTO_VERSION_MIN    1u

#define BR_FLAG_ACK_REQ         0x01u /**< ver_flags bit 0. */
#define BR_FLAG_AUTH            0x02u /**< ver_flags bit 1: auth_tag + hop_tag present. */
#define BR_FLAG_RESERVED_MASK   0x0Cu /**< Bits 2, 3: 0 on send, ignored on receive. */
#define BR_FLAGS_MASK           0x0Fu

#define BR_HDR_LEN              19u  /**< Header length, every type except SEEK. */
#define BR_HDR_LEN_SEEK         22u  /**< SEEK header length (adds path_mtu u16, path_cost u8). */
#define BR_AUTH_TAG_LEN          8u  /**< AES-CCM tag (8.3). */
#define BR_HOP_TAG_LEN           4u  /**< Truncated HMAC-SHA256 (8.3). */
#define BR_TAGS_LEN             (BR_AUTH_TAG_LEN + BR_HOP_TAG_LEN) /**< 12, present iff FLAG_AUTH. */
#define BR_CRC_LEN               2u  /**< CRC-16 trailer, little-endian. */
#define BR_FIXED_OVERHEAD       (BR_HDR_LEN + BR_CRC_LEN) /**< 21 (section 3, line 165). */

/* Header field offsets (section 3 table). Bytes 0..14 are the frozen prefix. */
#define BR_OFF_VER_FLAGS         0u
#define BR_OFF_TYPE              1u
#define BR_OFF_SRC_ID            2u
#define BR_OFF_DST_ID            4u
#define BR_OFF_PREV_HOP          6u
#define BR_OFF_NEXT_HOP          8u
#define BR_OFF_TTL_HOPS         10u
#define BR_OFF_HOP_SEQ          11u
#define BR_OFF_PATH_MTU         15u  /**< SEEK only. */
#define BR_OFF_PATH_COST        17u  /**< SEEK only. */
#define BR_OFF_SESSION_ID       15u  /**< Non-SEEK; SEEK: 18. */
#define BR_OFF_SEQ              16u  /**< Non-SEEK; SEEK: 19. */
#define BR_OFF_LEN              18u  /**< Non-SEEK; SEEK: 21. */
#define BR_OFF_SESSION_ID_SEEK  18u
#define BR_OFF_SEQ_SEEK         19u
#define BR_OFF_LEN_SEEK         21u
#define BR_E2E_HDR_LEN          10u  /**< bytes 0..5 + session_id + seq + len (8.3 AAD). */

#define BR_MAX_PAYLOAD_NOAUTH  229u  /**< Minus rs_nsym (section 3, line 166; 3.6 Length row). */
#define BR_MAX_PAYLOAD_AUTH    217u  /**< Minus rs_nsym. */
#define BR_FEC_PAYLOAD_RESERVE   9u  /**< DATA payload cap is max_payload - 9 with fec_m > 0 (3.3). */

/* Carriers (1.2) */
#define BR_MAX_FRAME_MESH      250u  /**< ESP-NOW, UDP, nRF24 (reassembled), UART (incl. RS). */
#define BR_MAX_FRAME_IR         80u  /**< IR, incl. 6 RS bytes. */
#define BR_RS_NSYM_PACKET        0u
#define BR_RS_NSYM_UART          8u
#define BR_RS_NSYM_IR            6u

/** Link class (1.1, 1.2). */
typedef enum { BR_LINK_PACKET = 0, BR_LINK_RAW = 1 } br_link_class_t;

/* ------------------------------------------------------------------------- */
/* Mesh and counter constants (sections 3.5, 9, 11.2)                         */
/* ------------------------------------------------------------------------- */

#define BR_MAX_HOPS              8u        /**< 9, 11.2. */
#define BR_MIN_PATH_MTU         48u        /**< 9, 3.6. */
#define BR_MAX_PATH_COST       250u        /**< 3.6 SEEK hop fields row. */
#define BR_HOP_MAX_JUMP     65536u         /**< 2^16; 3.5, 8.4, 9. */
#define BR_ORIGIN_MAX_JUMP  65536u         /**< 9. */
#define BR_REPLAY_WINDOW        64u        /**< 3.5 seen-bitmap, 9. */
#define BR_TXSEQ_BLOCK        4096u        /**< NVS reserve-ahead block (3.5). */
#define BR_PRESEQ_BLOCK         64u        /**< NVS reserve-ahead block (3.5). */
#define BR_MAX_GROUPS            8u        /**< 2, 9. */
#define BR_MAX_SESSIONS         32u        /**< 9 (sink: node_count). */
#define BR_MAX_STREAMS           4u        /**< 9. */

/* Group FEC (3.3, 9) */
#define BR_FEC_K_DEFAULT         8u
#define BR_FEC_M_DEFAULT         2u
#define BR_FEC_K_MIN             2u        /**< MODE fec_k range when fec_m > 0. */
#define BR_FEC_K_MAX            16u
#define BR_FEC_M_MAX             4u
#define BR_FEC_FLUSH_MS        100u

/* caps bits (section 5) */
#define BR_CAP_HIGH            (1u << 0)
#define BR_CAP_LOW             (1u << 1)
#define BR_CAP_ARQ             (1u << 2)
#define BR_CAP_AUTH            (1u << 3)
#define BR_CAP_FEC             (1u << 4)
#define BR_CAP_RELAY           (1u << 5)
#define BR_CAP_MULTI           (1u << 6)
#define BR_CAP_RESERVED_MASK   0xFF80u

/* ------------------------------------------------------------------------- */
/* Stats counters that the 3.6 validator can increment (Appendix B br_stats_t) */
/* ------------------------------------------------------------------------- */

/** Which br_stats_t counter a rejection increments (3.6 "Counter" column). */
typedef enum {
    BR_CNT_NONE = 0,
    BR_CNT_BAD_FRAME,
    BR_CNT_BAD_VERSION,
    BR_CNT_CRC_FAIL,
    BR_CNT_HOP_TAG_FAIL,
    BR_CNT_HOP_REPLAY,
    BR_CNT_AUTH_FAIL,
    BR_CNT_REPLAY_DROPPED
} br_counter_t;

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_TYPES_H */
