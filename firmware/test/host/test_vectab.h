// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_vectab.h - table of every complete frame vector in vectors_generated.h
 * (name, bytes, CRC, RS parity, link class). Shared by test_crc16, test_frame
 * and test_fuzz_validator. Not a test itself (the CMake glob only picks
 * test_*.c).
 */
#ifndef BR_TEST_VECTAB_H
#define BR_TEST_VECTAB_H

#include "braid/br_frame.h"
#include "test_util.h"
#include "vectors_generated.h"

typedef struct {
    const char *name;
    const uint8_t *frame;  /* header .. CRC, no RS parity */
    size_t len;
    uint16_t crc;          /* expected CRC from the generated header */
    uint8_t rs_nsym;       /* 0 packet, 8 UART, 6 IR */
    const uint8_t *parity; /* rs_nsym bytes or NULL */
    uint16_t max_frame;    /* arrival link max_frame */
} tu_frame_vec_t;

static const tu_frame_vec_t TU_FRAME_VECS[] = {
    {"A.2 SEEK (ESP-NOW, no tags)", BRV_A2_FRAME, BRV_A2_FRAME_LEN, BRV_A2_CRC, 0, NULL, 250},
    {"A.3 SEEK (UART, RS 8)", BRV_A3_FRAME, BRV_A3_FRAME_LEN, BRV_A3_CRC, 8, BRV_A3_RS_PARITY, 250},
    {"A.7 DATA direct", BRV_A7_FRAME, BRV_A7_FRAME_LEN, BRV_A7_CRC, 0, NULL, 250},
    {"A.8 SEEK hop 1", BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, BRV_A8_SEEK_HOP1_CRC, 0, NULL, 250},
    {"A.8 SEEK hop 2", BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, BRV_A8_SEEK_HOP2_CRC, 0, NULL, 250},
    {"A.8 DATA hop 1", BRV_A8_DATA_HOP1_FRAME, BRV_A8_DATA_HOP1_FRAME_LEN, BRV_A8_DATA_HOP1_CRC, 0, NULL, 250},
    {"A.8 DATA hop 2", BRV_A8_DATA_HOP2_FRAME, BRV_A8_DATA_HOP2_FRAME_LEN, BRV_A8_DATA_HOP2_CRC, 0, NULL, 250},
    {"A.8 DATA hop 2 K_hop(0)", BRV_A8_DATA_HOP2_K0_FRAME, BRV_A8_DATA_HOP2_K0_FRAME_LEN, BRV_A8_DATA_HOP2_K0_CRC, 0, NULL, 250},
    {"A.9 HELLO", BRV_A9_HELLO_FRAME, BRV_A9_HELLO_FRAME_LEN, BRV_A9_HELLO_CRC, 0, NULL, 250},
    {"A.9 BIND", BRV_A9_BIND_FRAME, BRV_A9_BIND_FRAME_LEN, BRV_A9_BIND_CRC, 0, NULL, 250},
    {"A.10 DATA ROC 1", BRV_A10_DATA_ROC1_FRAME, BRV_A10_DATA_ROC1_FRAME_LEN, BRV_A10_DATA_ROC1_CRC, 0, NULL, 250},
    {"A.11 RESUME", BRV_A11_RESUME_FRAME, BRV_A11_RESUME_FRAME_LEN, BRV_A11_RESUME_CRC, 0, NULL, 250},
    {"A.12 MGMT_REQ", BRV_A12_REQ_FRAME, BRV_A12_REQ_FRAME_LEN, BRV_A12_REQ_CRC, 0, NULL, 250},
    {"A.12 MGMT_RESP", BRV_A12_RESP_FRAME, BRV_A12_RESP_FRAME_LEN, BRV_A12_RESP_CRC, 0, NULL, 250},
    {"A.15 IR SEEK (RS 6)", BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN, BRV_A15_SEEK_CRC, 6, BRV_A15_SEEK_RS_PARITY, 80},
    {"A.15 IR HELLO (RS 6)", BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN, BRV_A15_HELLO_CRC, 6, BRV_A15_HELLO_RS_PARITY, 80},
};
#define TU_N_FRAME_VECS (sizeof TU_FRAME_VECS / sizeof TU_FRAME_VECS[0])

/** Concatenate frame || RS parity into out (>= 255 bytes); returns the on-air length. */
static inline size_t tu_vec_wire(const tu_frame_vec_t *v, uint8_t *out)
{
    memcpy(out, v->frame, v->len);
    if (v->rs_nsym) {
        memcpy(out + v->len, v->parity, v->rs_nsym);
    }
    return v->len + v->rs_nsym;
}

/** Map the private tu_ref_validate() codes (TU_R_*) to br_reject_t. */
static inline br_reject_t tu_map_reason(int r)
{
    static const br_reject_t map[] = {
        BR_REJ_NONE, BR_REJ_LEN_SHORT, BR_REJ_LEN_MISMATCH, BR_REJ_LEN_PAYLOAD, BR_REJ_LEN_MAX_FRAME,
        BR_REJ_CRC, BR_REJ_TTL, BR_REJ_HOPS, BR_REJ_PREV_HOP, BR_REJ_SRC_ID, BR_REJ_NEXT_HOP, BR_REJ_DST_ID,
        BR_REJ_PATH_MTU, BR_REJ_PATH_COST, BR_REJ_VERSION};
    return map[r];
}

static inline const char *tu_rej_name(int r)
{
    static const char *const names[] = {
        "NONE", "LEN_SHORT", "LEN_MISMATCH", "LEN_PAYLOAD", "LEN_MAX_FRAME", "CRC", "TTL", "HOPS", "PREV_HOP",
        "SRC_ID", "NEXT_HOP", "DST_ID", "PATH_MTU", "PATH_COST", "VERSION", "HOP_TAG", "HOP_REPLAY", "AUTH",
        "PRE_CTR_SEQ", "TYPE_LEN", "REPLAY"};
    return (r >= 0 && r <= (int)BR_REJ_REPLAY) ? names[r] : "(not a br_reject_t)";
}

#endif /* BR_TEST_VECTAB_H */
