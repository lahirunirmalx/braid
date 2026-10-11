// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_internal.h - private helpers for the Braid core sources.
 *
 * Not a public header: only sources inside components/app_braid see it
 * (PRIV_INCLUDE_DIRS "src"). Nothing here is part of the frozen API.
 */
#ifndef BRAID_BR_INTERNAL_H
#define BRAID_BR_INTERNAL_H

#include "braid/br_types.h"

/** Silence unused-parameter warnings in stubs. */
#define BR_UNUSED(x) ((void)(x))

/**
 * CRC-16/CCITT-FALSE register update without argument checks.
 * data may be NULL only if len == 0. (br_crc16.c)
 */
uint16_t br_crc16_raw(uint16_t crc, const uint8_t *data, size_t len);

/**
 * Erasure-only RS correction (br_rs.c), used by group FEC (3.3).
 *
 * Fills the n_erase positions of codeword from the other len - n_erase
 * symbols, which are trusted (no error search). Only the erased positions are
 * written. Caller guarantees: 1 <= nsym <= BR_RS_MAX_NSYM, nsym < len <= 255,
 * 1 <= n_erase <= nsym, erase_pos distinct and < len.
 *
 * @return BR_OK; BR_ERR_UNCORRECTABLE if the erasure locator is degenerate
 *         (cannot happen with distinct in-range positions).
 */
br_err_t br_rs_erasure_fill(uint8_t *codeword, size_t len, uint8_t nsym,
                            const uint8_t *erase_pos, uint8_t n_erase);

/* ---- session <-> node glue (phase 1b; not public API) ------------------- */

#include "braid/br_session.h"

/**
 * br_sender_t.reserved carries the sender's handle (index in br_node_t
 * senders[]), written by br_node_init(); br_sender_init() preserves it.
 */
#define BR_SND_HANDLE(s) ((br_session_t)((s)->reserved & 0x7Fu))

/**
 * SPEC-NOTES N46: the probe record's "DATA floor", the lowest session index
 * (low 16 bits) that may still carry DATA of this session. Kept in the
 * probe record's br_tx_index_t.reserved (the public header is frozen; the
 * index code never touches that field). 0 at BIND (N23: the first session
 * seq is 0). Raised to mode_seq + 1 whenever a MODE is accepted whose
 * config_id is the only config the record holds: the sender sends DATA
 * only in STREAMING (4.1), which it enters on the MODE_ACK of that first
 * config, so nothing below such a MODE can be DATA. Consumed by the stream
 * seeding at the first DATA (4.1.12 / N31: the reorder buffer does not
 * exist before that).
 */
#define BR_PRB_DATA_BASE(r) ((r)->tx.reserved)

/**
 * SPEC-NOTES N46 (br_arq.c): give up every hole below `seq` at once, without
 * waiting REORDER_MS: cum_seq advances to seq - 1 (serial order), buffered
 * payloads passed on the way are delivered in order, runs of missing seqs
 * are reported through gap(first, count). No-op when seq is not newer than
 * cum_seq + 1. Used when a MODE at `seq` proves that nothing below it is
 * DATA (see BR_PRB_DATA_BASE).
 */
void br_arq_rx_give_up_below(br_arq_rx_t *rx, uint16_t seq, uint32_t now_ms, br_arq_deliver_fn deliver,
                             br_arq_gap_fn gap, void *user);

/**
 * 11.4 step 9b / SPEC-NOTES N28: a later copy of a flood already delivered
 * (same src_id, pre_ctr) arrived cheaper inside the HELLO delay window.
 * Updates the matching OFFERED entry's per-hop data (first hop, transport,
 * hops, path_cost, path_mtu) so the HELLO reports the lowest-cost copy.
 * No-op when no offer matches or its HELLO is already sent. The caller has
 * already decided "cheaper" on path_cost + link cost (dedup best_cost, 11.4
 * row 1); path_cost is the copy's header field as received, which is what
 * the HELLO carries (SPEC-NOTES N32, A.9). All values come from
 * hop_tag-verified per-hop fields.
 */
void br_probe_offer_copy(br_probe_t *p, uint16_t src_id, uint32_t pre_ctr, uint16_t prev_hop,
                         uint8_t transport, uint8_t hops, uint8_t path_cost, uint16_t path_mtu);

/**
 * Probe side of br_node_close(): send CLOSE(reason) under Ke_p2s and free
 * record idx (LISTENING, on_state, on_closed).
 * @return BR_OK; BR_ERR_ARG (bad index); BR_ERR_STATE (record not bound).
 */
br_err_t br_probe_close(br_probe_t *p, br_sess_env_t *env, uint8_t idx, uint8_t reason);

#endif /* BRAID_BR_INTERNAL_H */
