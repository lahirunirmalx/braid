// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_session.c - key schedule, control-message codecs, session index and
 * replay window, sender and probe state machines (spec 4, 5, 6.1, 7, 8.2-8.4).
 *
 * Frame contract with br_node.c (br_session.h file header): every frame is
 * built here with its FINAL end-to-end fields (flags, type, src, dst,
 * session_id, seq, len, payload, auth_tag) and zeroed per-hop fields; the
 * node fills prev_hop / next_hop / ttl_hops / hop_seq / SEEK path fields,
 * the hop_tag and the CRC. Received frames arrive after pipeline step 5.
 *
 * Order on receive (3.6, 8.4): pre_ctr / seq consistency, CCM tag, then
 * freshness (pre-session: matching; session: ARQ duplicate, replay window),
 * then the per-type rows, then any state change. Nothing is changed and
 * nothing is sent for a frame that fails a check (R10).
 *
 * Stack: one frame buffer (250) or one plaintext buffer (<= 255) per call
 * level, AAD <= 64 bytes; keys and transcripts are 16 / 32-byte locals,
 * wiped before return.
 */
#include <string.h>

#include "mbedtls/sha256.h"

#include "braid/br_session.h"

#include "br_internal.h"

/** Far deadline: now + 2^30 ms (documented "nothing due"). */
#define BR_SESS_FAR_MS 0x40000000u

#define BR_PENALTY_WINDOW_MS  600000u  /* 4.2: 3 timeouts within 10 min ... */
#define BR_PENALTY_EXCLUDE_MS 600000u  /* ... exclude the first hop for 10 min */
#define BR_PENALTY_EXCLUDE_N  3u
#define BR_SESS_AAD_MAX       64u      /* 14 + clear prefix (SEEK 18) */
#define BR_PTBUF              256u

/* KDF labels (8.2): BR_LABEL_* in br_crypto.h, the one definition. */

/* ========================================================================= */
/* Small helpers                                                              */
/* ========================================================================= */

static bool due(uint32_t now, uint32_t t)
{
    return !br_ms_before(now, t);
}

static void next_min(uint32_t now, uint32_t *next, uint32_t t)
{
    /* keep the earliest; deadlines in the past count as "now" */
    uint32_t tt = br_ms_before(t, now) ? now : t;
    if (br_ms_before(tt, *next)) {
        *next = tt;
    }
}

static uint32_t sess_rand32(br_sess_env_t *env)
{
    uint8_t b[4] = { 0, 0, 0, 0 };
    if (env->random != NULL) {
        (void)env->random(env->user, b, sizeof b);
    }
    return br_rd_le32(b);
}

/* Uniform-ish draw in 0..max inclusive. */
static uint32_t sess_rand_upto(br_sess_env_t *env, uint32_t max)
{
    uint32_t r = sess_rand32(env);
    return (max == UINT32_MAX) ? r : r % (max + 1u);
}

static size_t tags_len(const br_sess_env_t *env)
{
    return env->auth ? (size_t)BR_TAGS_LEN : 0u;
}

/* Session payload cap for a path MTU (max_frame - rs_nsym): 217 at 250 with AUTH. */
static uint16_t payload_cap(const br_sess_env_t *env, uint16_t mtu)
{
    size_t over = BR_HDR_LEN + tags_len(env) + BR_CRC_LEN;
    size_t cap = mtu > over ? (size_t)mtu - over : 0u;
    size_t lim = env->auth ? BR_MAX_PAYLOAD_AUTH : BR_MAX_PAYLOAD_NOAUTH;
    return (uint16_t)(cap < lim ? cap : lim);
}

static const br_app_callbacks_t *appcb(const br_sess_env_t *env)
{
    return env->app;
}

static void cb_state(br_sess_env_t *env, br_session_t h, uint8_t from, uint8_t to)
{
    const br_app_callbacks_t *a = appcb(env);
    if (a != NULL && a->on_state != NULL && from != to) {
        a->on_state(a->user, h, from, to);
    }
}

static void cb_closed(br_sess_env_t *env, br_session_t h, uint8_t reason)
{
    const br_app_callbacks_t *a = appcb(env);
    if (a != NULL && a->on_closed != NULL) {
        a->on_closed(a->user, h, reason);
    }
}

static void cb_gap(br_sess_env_t *env, br_session_t h, uint16_t first, uint16_t count)
{
    const br_app_callbacks_t *a = appcb(env);
    if (a != NULL && a->on_gap != NULL) {
        a->on_gap(a->user, h, first, count);
    }
}

static void cb_event(br_sess_env_t *env, uint16_t ev, uint32_t arg)
{
    const br_app_callbacks_t *a = appcb(env);
    if (a != NULL && a->on_event != NULL) {
        a->on_event(a->user, ev, arg);
    }
}

static void set_drop(br_stat_id_t *drop_out, br_stat_id_t id)
{
    if (drop_out != NULL) {
        *drop_out = id;
    }
}

/* ========================================================================= */
/* Key schedule (8.2)                                                         */
/* ========================================================================= */

br_err_t br_keyring_init_bench(br_crypto_t *c, br_keyring_t *kr, const uint8_t *net_key,
                               size_t net_key_len, uint8_t epoch)
{
    if (c == NULL || kr == NULL || net_key == NULL || net_key_len != BR_KEY_LEN) {
        return BR_ERR_ARG;
    }
    br_keyring_wipe(kr);
    uint8_t prk[BR_SHA256_LEN];
    memcpy(kr->k_site, net_key, BR_KEY_LEN);
    br_err_t rc = br_hkdf_sha256(c, BR_LABEL_U8(BR_LABEL_MESH), BR_LABEL_LEN(BR_LABEL_MESH), kr->k_site, BR_KEY_LEN,
                                 &epoch, 1u, kr->k_mesh, BR_KEY_LEN);
    if (rc == BR_OK) {
        rc = br_hkdf_extract(c, BR_LABEL_U8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), kr->k_mesh, BR_KEY_LEN, prk);
    }
    if (rc == BR_OK) {
        rc = br_hkdf_expand(c, prk, sizeof prk, (const uint8_t *)"hop", 3u, kr->k_hop, BR_HOP_KEY_LEN);
    }
    if (rc == BR_OK) {
        rc = br_hkdf_expand(c, prk, sizeof prk, (const uint8_t *)"mesh-enc", 8u, kr->ke_mesh,
                            BR_AES_KEY_LEN);
    }
    br_secure_zero(prk, sizeof prk);
    if (rc != BR_OK) {
        br_keyring_wipe(kr);
        return rc;
    }
    kr->epoch = epoch;
    kr->ready = true;
    return BR_OK;
}

void br_keyring_wipe(br_keyring_t *kr)
{
    if (kr != NULL) {
        br_secure_zero(kr, sizeof *kr);
    }
}

br_err_t br_ks_pair_prk(br_crypto_t *c, const br_keyring_t *kr, uint16_t a, uint16_t b,
                        uint8_t prk_out[BR_KEY_LEN])
{
    if (c == NULL || kr == NULL || prk_out == NULL) {
        return BR_ERR_ARG;
    }
    if (!kr->ready) {
        return BR_ERR_STATE;
    }
    uint8_t info[5];
    uint16_t lo = a < b ? a : b;
    uint16_t hi = a < b ? b : a;
    br_wr_le16(info, lo);
    br_wr_le16(info + 2, hi);
    info[4] = kr->epoch;
    uint8_t k_pair[BR_KEY_LEN];
    br_err_t rc = br_hkdf_sha256(c, BR_LABEL_U8(BR_LABEL_PAIR), BR_LABEL_LEN(BR_LABEL_PAIR), kr->k_site, BR_KEY_LEN,
                                 info, sizeof info, k_pair, sizeof k_pair);
    if (rc == BR_OK) {
        rc = br_hkdf_extract(c, BR_LABEL_U8(BR_LABEL_V1), BR_LABEL_LEN(BR_LABEL_V1), k_pair, sizeof k_pair, prk_out);
    }
    br_secure_zero(k_pair, sizeof k_pair);
    return rc;
}

static br_err_t sha256_parts(const uint8_t *p0, size_t l0, const uint8_t *p1, size_t l1,
                             const uint8_t *p2, size_t l2, const uint8_t *p3, size_t l3,
                             uint8_t out[BR_SHA256_LEN])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int r = mbedtls_sha256_starts(&ctx, 0);
    if (r == 0 && l0 > 0u) {
        r = mbedtls_sha256_update(&ctx, p0, l0);
    }
    if (r == 0 && l1 > 0u) {
        r = mbedtls_sha256_update(&ctx, p1, l1);
    }
    if (r == 0 && l2 > 0u) {
        r = mbedtls_sha256_update(&ctx, p2, l2);
    }
    if (r == 0 && l3 > 0u) {
        r = mbedtls_sha256_update(&ctx, p3, l3);
    }
    if (r == 0) {
        r = mbedtls_sha256_finish(&ctx, out);
    }
    mbedtls_sha256_free(&ctx);
    return r == 0 ? BR_OK : BR_ERR_CRYPTO;
}

br_err_t br_ks_t0(const uint8_t seek_e2e[BR_E2E_HDR_LEN], const uint8_t seek_payload[BR_LEN_SEEK],
                  uint8_t t0_out[BR_KEY_LEN])
{
    if (seek_e2e == NULL || seek_payload == NULL || t0_out == NULL) {
        return BR_ERR_ARG;
    }
    return sha256_parts(seek_e2e, BR_E2E_HDR_LEN, seek_payload, BR_LEN_SEEK, NULL, 0u, NULL, 0u, t0_out);
}

br_err_t br_ks_t(const uint8_t seek_e2e[BR_E2E_HDR_LEN], const uint8_t seek_payload[BR_LEN_SEEK],
                 const uint8_t hello_e2e[BR_E2E_HDR_LEN], const uint8_t hello_plain[BR_LEN_HELLO],
                 uint8_t t_out[BR_KEY_LEN])
{
    if (seek_e2e == NULL || seek_payload == NULL || hello_e2e == NULL || hello_plain == NULL ||
        t_out == NULL) {
        return BR_ERR_ARG;
    }
    return sha256_parts(seek_e2e, BR_E2E_HDR_LEN, seek_payload, BR_LEN_SEEK, hello_e2e,
                        BR_E2E_HDR_LEN, hello_plain, BR_LEN_HELLO, t_out);
}

/* Expand(PRK, label || S || P || [session_id] || T, 16) */
static br_err_t ks_expand(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], const char *label,
                          size_t label_len, uint16_t s, uint16_t p, bool with_sid, uint8_t sid,
                          const uint8_t t[BR_KEY_LEN], uint8_t ke_out[BR_AES_KEY_LEN])
{
    if (c == NULL || prk == NULL || t == NULL || ke_out == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t info[8u + 4u + 1u + BR_KEY_LEN];
    size_t o = 0;
    memcpy(info, label, label_len);
    o += label_len;
    br_wr_le16(info + o, s);
    br_wr_le16(info + o + 2u, p);
    o += 4u;
    if (with_sid) {
        info[o++] = sid;
    }
    memcpy(info + o, t, BR_KEY_LEN);
    o += BR_KEY_LEN;
    br_err_t rc = br_hkdf_expand(c, prk, BR_KEY_LEN, info, o, ke_out, BR_AES_KEY_LEN);
    br_secure_zero(info, sizeof info);
    return rc;
}

br_err_t br_ks_hello(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                     const uint8_t t0[BR_KEY_LEN], uint8_t ke_out[BR_AES_KEY_LEN])
{
    return ks_expand(c, prk, "hello", 5u, s, p, false, 0u, t0, ke_out);
}

br_err_t br_ks_hs(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                  const uint8_t t[BR_KEY_LEN], uint8_t ke_out[BR_AES_KEY_LEN])
{
    return ks_expand(c, prk, "hs", 2u, s, p, false, 0u, t, ke_out);
}

br_err_t br_ks_session(br_crypto_t *c, const uint8_t prk[BR_KEY_LEN], uint16_t s, uint16_t p,
                       uint8_t session_id, const uint8_t t[BR_KEY_LEN],
                       uint8_t ke_s2p_out[BR_AES_KEY_LEN], uint8_t ke_p2s_out[BR_AES_KEY_LEN])
{
    if (ke_s2p_out == NULL || ke_p2s_out == NULL) {
        return BR_ERR_ARG;
    }
    br_err_t rc = ks_expand(c, prk, "s2p", 3u, s, p, true, session_id, t, ke_s2p_out);
    if (rc == BR_OK) {
        rc = ks_expand(c, prk, "p2s", 3u, s, p, true, session_id, t, ke_p2s_out);
    }
    if (rc != BR_OK) {
        br_secure_zero(ke_s2p_out, BR_AES_KEY_LEN);
        br_secure_zero(ke_p2s_out, BR_AES_KEY_LEN);
    }
    return rc;
}

/* ========================================================================= */
/* Control message codecs (section 5)                                         */
/* ========================================================================= */

static size_t msg_len(uint8_t type)
{
    switch (type) {
    case BR_TYPE_SEEK:     return BR_LEN_SEEK;
    case BR_TYPE_HELLO:    return BR_LEN_HELLO;
    case BR_TYPE_BIND:     return BR_LEN_BIND;
    case BR_TYPE_BIND_ACK: return BR_LEN_BIND_ACK;
    case BR_TYPE_BIND_NAK: return BR_LEN_BIND_NAK;
    case BR_TYPE_MODE_ACK: return BR_LEN_MODE_ACK;
    case BR_TYPE_ACK:      return BR_LEN_ACK;
    case BR_TYPE_PING:     return BR_LEN_PING;
    case BR_TYPE_PONG:     return BR_LEN_PONG;
    case BR_TYPE_CLOSE:    return BR_LEN_CLOSE;
    default:               return 0u;
    }
}

br_err_t br_msg_encode(const br_msg_t *msg, uint8_t *out, size_t cap, size_t *written)
{
    if (msg == NULL || out == NULL || written == NULL) {
        return BR_ERR_ARG;
    }
    size_t n = msg_len(msg->type);
    if (n == 0u) {
        return BR_ERR_ARG;
    }
    if (cap < n) {
        return BR_ERR_TOO_BIG;
    }
    switch (msg->type) {
    case BR_TYPE_SEEK: {
        const br_msg_seek_t *m = &msg->u.seek;
        br_wr_le32(out, m->pre_ctr);
        br_wr_le32(out + 4, m->nonce_s);
        br_wr_le16(out + 8, m->caps);
        br_wr_le16(out + 10, m->max_frame);
        out[12] = m->key_epoch;
        out[13] = m->proto_minor;
        br_wr_le32(out + 14, m->fw_build);
        break;
    }
    case BR_TYPE_HELLO: {
        const br_msg_hello_t *m = &msg->u.hello;
        br_wr_le32(out, m->pre_ctr);
        br_wr_le32(out + 4, m->seek_ctr);
        br_wr_le32(out + 8, m->nonce_s);
        br_wr_le32(out + 12, m->nonce_p);
        br_wr_le16(out + 16, m->caps);
        br_wr_le16(out + 18, m->max_frame);
        out[20] = (uint8_t)m->rssi;
        out[21] = m->status;
        out[22] = m->path_cost;
        out[23] = m->proto_minor;
        br_wr_le32(out + 24, m->fw_build);
        break;
    }
    case BR_TYPE_BIND: {
        const br_msg_bind_t *m = &msg->u.bind;
        br_wr_le32(out, m->pre_ctr);
        br_wr_le32(out + 4, m->hello_ctr);
        br_wr_le32(out + 8, m->nonce_s);
        br_wr_le32(out + 12, m->nonce_p);
        out[16] = m->session_id;
        break;
    }
    case BR_TYPE_BIND_ACK:
        br_wr_le32(out, msg->u.bind_ack.pre_ctr);
        br_wr_le32(out + 4, msg->u.bind_ack.nonce_s);
        br_wr_le32(out + 8, msg->u.bind_ack.nonce_p);
        break;
    case BR_TYPE_BIND_NAK:
        br_wr_le32(out, msg->u.bind_nak.pre_ctr);
        br_wr_le32(out + 4, msg->u.bind_nak.nonce_s);
        out[8] = msg->u.bind_nak.reason;
        break;
    case BR_TYPE_MODE_ACK:
        out[0] = msg->u.mode_ack.config_id;
        out[1] = msg->u.mode_ack.status;
        break;
    case BR_TYPE_ACK:
        br_wr_le16(out, msg->u.ack.cum_seq);
        br_wr_le32(out + 2, msg->u.ack.bitmap);
        break;
    case BR_TYPE_PING:
        br_wr_le32(out, msg->u.ping.t_tx_us);
        break;
    case BR_TYPE_PONG:
        br_wr_le32(out, msg->u.pong.t_echo_us);
        br_wr_le32(out + 4, msg->u.pong.t_local_us);
        break;
    case BR_TYPE_CLOSE:
    default:
        out[0] = msg->u.close.reason;
        br_wr_le16(out + 1, msg->u.close.park_s);
        break;
    }
    *written = n;
    return BR_OK;
}

br_err_t br_msg_decode(uint8_t type, const uint8_t *in, size_t len, br_msg_t *msg_out)
{
    if (in == NULL || msg_out == NULL) {
        return BR_ERR_ARG;
    }
    size_t n = msg_len(type);
    if (n == 0u) {
        return BR_ERR_ARG;
    }
    if (len != n) {
        return BR_ERR_DECODE;
    }
    memset(msg_out, 0, sizeof *msg_out);
    msg_out->type = type;
    switch (type) {
    case BR_TYPE_SEEK: {
        br_msg_seek_t *m = &msg_out->u.seek;
        m->pre_ctr = br_rd_le32(in);
        m->nonce_s = br_rd_le32(in + 4);
        m->caps = br_rd_le16(in + 8);
        m->max_frame = br_rd_le16(in + 10);
        m->key_epoch = in[12];
        m->proto_minor = in[13];
        m->fw_build = br_rd_le32(in + 14);
        break;
    }
    case BR_TYPE_HELLO: {
        br_msg_hello_t *m = &msg_out->u.hello;
        m->pre_ctr = br_rd_le32(in);
        m->seek_ctr = br_rd_le32(in + 4);
        m->nonce_s = br_rd_le32(in + 8);
        m->nonce_p = br_rd_le32(in + 12);
        m->caps = br_rd_le16(in + 16);
        m->max_frame = br_rd_le16(in + 18);
        m->rssi = (int8_t)in[20];
        m->status = in[21];
        m->path_cost = in[22];
        m->proto_minor = in[23];
        m->fw_build = br_rd_le32(in + 24);
        break;
    }
    case BR_TYPE_BIND: {
        br_msg_bind_t *m = &msg_out->u.bind;
        m->pre_ctr = br_rd_le32(in);
        m->hello_ctr = br_rd_le32(in + 4);
        m->nonce_s = br_rd_le32(in + 8);
        m->nonce_p = br_rd_le32(in + 12);
        m->session_id = in[16];
        break;
    }
    case BR_TYPE_BIND_ACK:
        msg_out->u.bind_ack.pre_ctr = br_rd_le32(in);
        msg_out->u.bind_ack.nonce_s = br_rd_le32(in + 4);
        msg_out->u.bind_ack.nonce_p = br_rd_le32(in + 8);
        break;
    case BR_TYPE_BIND_NAK:
        msg_out->u.bind_nak.pre_ctr = br_rd_le32(in);
        msg_out->u.bind_nak.nonce_s = br_rd_le32(in + 4);
        msg_out->u.bind_nak.reason = in[8];
        break;
    case BR_TYPE_MODE_ACK:
        msg_out->u.mode_ack.config_id = in[0];
        msg_out->u.mode_ack.status = in[1];
        break;
    case BR_TYPE_ACK:
        msg_out->u.ack.cum_seq = br_rd_le16(in);
        msg_out->u.ack.bitmap = br_rd_le32(in + 2);
        break;
    case BR_TYPE_PING:
        msg_out->u.ping.t_tx_us = br_rd_le32(in);
        break;
    case BR_TYPE_PONG:
        msg_out->u.pong.t_echo_us = br_rd_le32(in);
        msg_out->u.pong.t_local_us = br_rd_le32(in + 4);
        break;
    case BR_TYPE_CLOSE:
    default:
        msg_out->u.close.reason = in[0];
        msg_out->u.close.park_s = br_rd_le16(in + 1);
        break;
    }
    return BR_OK;
}

/* ========================================================================= */
/* Session index and replay window (3.5, 8.4)                                 */
/* ========================================================================= */

br_err_t br_tx_index_next(br_tx_index_t *tx, uint16_t *seq_out, uint32_t *roc_out)
{
    if (tx == NULL || seq_out == NULL || roc_out == NULL) {
        return BR_ERR_ARG;
    }
    if (tx->roc == UINT32_MAX && tx->next_seq == 0xFFFFu) {
        return BR_ERR_TOO_BIG; /* 48-bit index exhausted: the session must close */
    }
    *seq_out = tx->next_seq;
    *roc_out = tx->roc;
    tx->next_seq++;
    if (tx->next_seq == 0u) {
        tx->roc++;
    }
    return BR_OK;
}

br_err_t br_rx_index_check(const br_rx_index_t *rx, uint16_t seq, uint32_t *roc_out, bool *fresh_out)
{
    if (rx == NULL || roc_out == NULL || fresh_out == NULL) {
        return BR_ERR_ARG;
    }
    *fresh_out = false;
    uint32_t roc_cur = rx->any ? (uint32_t)(rx->highest >> 16) : 0u;
    uint16_t s_l = rx->any ? rx->s_l : 0u;
    uint32_t roc = 0;
    br_err_t rc = br_roc_estimate(seq, s_l, roc_cur, &roc);
    if (rc != BR_OK) {
        return rc;
    }
    *roc_out = roc;
    if (!rx->any) {
        *fresh_out = true;
        return BR_OK;
    }
    uint64_t idx = ((uint64_t)roc << 16) | seq;
    if (idx > rx->highest) {
        *fresh_out = true;
    } else {
        uint64_t back = rx->highest - idx;
        *fresh_out = back < BR_REPLAY_WINDOW && ((rx->seen >> back) & 1u) == 0u;
    }
    return BR_OK;
}

br_err_t br_rx_index_commit(br_rx_index_t *rx, uint16_t seq, uint32_t roc)
{
    if (rx == NULL) {
        return BR_ERR_ARG;
    }
    uint64_t idx = ((uint64_t)roc << 16) | seq;
    if (!rx->any) {
        rx->highest = idx;
        rx->seen = 1u;
        rx->any = 1u;
    } else if (idx > rx->highest) {
        uint64_t shift = idx - rx->highest;
        rx->seen = (shift >= 64u) ? 1u : ((rx->seen << shift) | 1u);
        rx->highest = idx;
    } else {
        uint64_t back = rx->highest - idx;
        if (back < 64u) {
            rx->seen |= (1ull << back);
        }
    }
    rx->s_l = (uint16_t)(rx->highest & 0xFFFFu);
    return BR_OK;
}

/* ========================================================================= */
/* Frame build / open                                                         */
/* ========================================================================= */

typedef struct {
    uint8_t        type;
    uint16_t       dst;
    uint8_t        session_id;
    uint16_t       seq;
    bool           ack_req;
    uint32_t       ctr_hi;
    uint8_t        dir;
    const uint8_t *key;        /* 16 bytes (Ke_*) */
    size_t         clear_len;  /* clear prefix of pt (pre_ctr; whole SEEK) */
} sess_tx_t;

/* Lay out an e2e frame in buf (zero per-hop fields) and seal it under t->key. */
static br_err_t sess_build(br_sess_env_t *env, const sess_tx_t *t, const uint8_t *pt, size_t pt_len,
                           uint8_t *buf, size_t cap, size_t *len_out)
{
    static const uint8_t zero_tags[BR_AUTH_TAG_LEN] = { 0 };
    br_hdr_t h;
    memset(&h, 0, sizeof h);
    h.version = (uint8_t)BR_PROTO_VERSION;
    h.flags = (uint8_t)((env->auth ? BR_FLAG_AUTH : 0u) | (t->ack_req ? BR_FLAG_ACK_REQ : 0u));
    h.type = t->type;
    h.src_id = env->self_id;
    h.dst_id = t->dst;
    h.session_id = t->session_id;
    h.seq = t->seq;
    if (t->clear_len > pt_len) {
        return BR_ERR_ARG;
    }
    size_t len = 0;
    br_err_t rc = br_frame_encode(&h, pt, pt_len, env->auth ? zero_tags : NULL,
                                  env->auth ? zero_tags : NULL, buf, cap, &len);
    if (rc != BR_OK || !env->auth) {
        *len_out = len;
        return rc;
    }
    size_t hl = br_hdr_len_for_type(t->type);
    uint8_t aad[BR_SESS_AAD_MAX];
    size_t aad_len = 0;
    uint8_t nonce[BR_CCM_NONCE_LEN];
    rc = br_ccm_aad(buf, len, t->ctr_hi, t->clear_len, aad, sizeof aad, &aad_len);
    if (rc == BR_OK) {
        rc = br_ccm_nonce(t->dir, env->self_id, t->dst, t->session_id, t->ctr_hi, t->seq, nonce);
    }
    if (rc == BR_OK) {
        uint8_t *ct = buf + hl + t->clear_len;
        rc = br_ccm_encrypt(env->crypto, t->key, nonce, aad, aad_len, ct, pt_len - t->clear_len, ct,
                            buf + hl + pt_len);
    }
    *len_out = len;
    return rc;
}

static br_err_t sess_send(br_sess_env_t *env, const sess_tx_t *t, const uint8_t *pt, size_t pt_len,
                          bool flood)
{
    uint8_t buf[BR_MAX_FRAME_MESH];
    size_t len = 0;
    br_err_t rc = sess_build(env, t, pt, pt_len, buf, sizeof buf, &len);
    if (rc == BR_OK) {
        rc = env->send(env->user, buf, len, flood);
    }
    return rc;
}

/* Verify and decrypt the payload of f past clear_len into pt_out. */
static br_err_t sess_open(br_sess_env_t *env, const br_rx_frame_t *f, const uint8_t *key, uint8_t dir,
                          uint32_t ctr_hi, size_t clear_len, uint8_t *pt_out, size_t cap, size_t *pt_len)
{
    const br_frame_view_t *v = f->view;
    if (clear_len > v->payload_len) {
        return BR_ERR_DECODE;
    }
    size_t ct_len = v->payload_len - clear_len;
    if (ct_len > cap) {
        return BR_ERR_TOO_BIG;
    }
    const uint8_t *ct = f->buf + v->payload_off + clear_len;
    *pt_len = ct_len;
    if (!v->has_auth) {
        if (env->auth) {
            return BR_ERR_AUTH;
        }
        if (ct_len > 0u) {
            memcpy(pt_out, ct, ct_len);
        }
        return BR_OK;
    }
    uint8_t aad[BR_SESS_AAD_MAX];
    size_t aad_len = 0;
    uint8_t nonce[BR_CCM_NONCE_LEN];
    br_err_t rc = br_ccm_aad(f->buf, f->len, ctr_hi, clear_len, aad, sizeof aad, &aad_len);
    if (rc == BR_OK) {
        rc = br_ccm_nonce(dir, v->hdr.src_id, v->hdr.dst_id, v->hdr.session_id, ctr_hi, v->hdr.seq, nonce);
    }
    if (rc == BR_OK) {
        rc = br_ccm_decrypt(env->crypto, key, nonce, aad, aad_len, ct, ct_len,
                            f->buf + v->auth_tag_off, pt_out);
    }
    if (rc != BR_OK && rc != BR_ERR_AUTH) {
        rc = BR_ERR_AUTH; /* DECODE / TOO_BIG of the AAD: treat as unauthenticated */
    }
    return rc;
}

/* e2e header (10 bytes) of a frame as this node built it (T0 / T inputs). */
static void own_e2e(const br_sess_env_t *env, uint8_t out[BR_E2E_HDR_LEN], uint8_t type,
                    uint16_t dst, uint32_t pre_ctr, uint8_t len)
{
    out[0] = (uint8_t)((BR_PROTO_VERSION << 4) | (env->auth ? BR_FLAG_AUTH : 0u));
    out[1] = type;
    br_wr_le16(out + 2, env->self_id);
    br_wr_le16(out + 4, dst);
    out[6] = 0u;
    br_wr_le16(out + 7, (uint16_t)(pre_ctr & 0xFFFFu));
    out[9] = len;
}

/* e2e header of a received frame (br_ccm_aad layout, first 10 bytes). */
static br_err_t rx_e2e(const br_rx_frame_t *f, uint8_t out[BR_E2E_HDR_LEN])
{
    uint8_t aad[BR_SESS_AAD_MAX];
    size_t n = 0;
    br_err_t rc = br_ccm_aad(f->buf, f->len, 0u, 0u, aad, sizeof aad, &n);
    if (rc == BR_OK) {
        memcpy(out, aad, BR_E2E_HDR_LEN);
    }
    return rc;
}

/* Clear pre_ctr of a session_id 0 frame (3.6 CCM row: seq == low 16 bits). */
static bool rx_pre_ctr(const br_rx_frame_t *f, uint32_t *pre_ctr, br_stat_id_t *drop_out)
{
    br_reject_t why = BR_REJ_NONE;
    if (f->view->hdr.session_id != 0u ||
        br_frame_pre_ctr(f->buf, f->view, pre_ctr, &why) != BR_OK) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return false;
    }
    return true;
}

/* ========================================================================= */
/* Sender (4.1, 4.2, 6.1, 7)                                                  */
/* ========================================================================= */

static void snd_state(br_sender_t *s, br_sess_env_t *env, uint8_t st)
{
    uint8_t old = s->state;
    s->state = st;
    cb_state(env, BR_SND_HANDLE(s), old, st);
}

static void snd_wipe_keys(br_sender_t *s)
{
    br_secure_zero(s->t, sizeof s->t);
    br_secure_zero(s->ke_hs, sizeof s->ke_hs);
    br_secure_zero(s->ke_s2p, sizeof s->ke_s2p);
    br_secure_zero(s->ke_p2s, sizeof s->ke_p2s);
}

br_err_t br_sender_init(br_sender_t *s)
{
    if (s == NULL) {
        return BR_ERR_ARG;
    }
    uint8_t ids[BR_SESSION_IDS_KEPT];
    br_penalty_t pen[BR_PENALTY_ENTRIES];
    uint8_t n_ids = s->recent_ids_n;
    uint16_t handle = s->reserved;
    memcpy(ids, s->recent_ids, sizeof ids);
    memcpy(pen, s->penalty, sizeof pen);
    br_secure_zero(s, sizeof *s);
    memcpy(s->recent_ids, ids, sizeof ids);
    memcpy(s->penalty, pen, sizeof pen);
    s->recent_ids_n = n_ids <= BR_SESSION_IDS_KEPT ? n_ids : (uint8_t)BR_SESSION_IDS_KEPT;
    s->reserved = handle;
    s->state = BR_SND_IDLE;
    return BR_OK;
}

/* ---- penalty list (4.2) --------------------------------------------------- */

static br_penalty_t *pen_find(br_sender_t *s, uint16_t hop)
{
    for (size_t i = 0; i < BR_PENALTY_ENTRIES; i++) {
        if (s->penalty[i].used != 0u && s->penalty[i].first_hop == hop) {
            return &s->penalty[i];
        }
    }
    return NULL;
}

static bool pen_active(br_sender_t *s, uint16_t hop, uint32_t now, bool excluded_only)
{
    br_penalty_t *p = pen_find(s, hop);
    if (p == NULL || !br_ms_before(now, p->until_ms)) {
        return false;
    }
    return !excluded_only || p->count >= BR_PENALTY_EXCLUDE_N;
}

static void pen_record(br_sender_t *s, uint16_t hop, uint32_t now)
{
    if (hop == 0u) {
        return;
    }
    br_penalty_t *p = pen_find(s, hop);
    if (p == NULL) {
        for (size_t i = 0; i < BR_PENALTY_ENTRIES && p == NULL; i++) {
            if (s->penalty[i].used == 0u || !br_ms_before(now, s->penalty[i].until_ms)) {
                p = &s->penalty[i];
            }
        }
        if (p == NULL) {
            p = &s->penalty[0];
            for (size_t i = 1; i < BR_PENALTY_ENTRIES; i++) {
                if (br_ms_before(s->penalty[i].until_ms, p->until_ms)) {
                    p = &s->penalty[i];
                }
            }
        }
        memset(p, 0, sizeof *p);
        p->used = 1u;
        p->first_hop = hop;
        p->window_start_ms = now;
    }
    if (!br_ms_before(now, p->window_start_ms + BR_PENALTY_WINDOW_MS)) {
        p->count = 0u;
        p->window_start_ms = now;
    }
    if (p->count < 0xFFu) {
        p->count++;
    }
    p->until_ms = now + ((p->count >= BR_PENALTY_EXCLUDE_N) ? BR_PENALTY_EXCLUDE_MS : BR_PENALTY_MS);
}

/* ---- session ids (4.1.11) ------------------------------------------------- */

static uint8_t snd_new_session_id(br_sender_t *s, br_sess_env_t *env)
{
    uint8_t id = 0;
    for (int tries = 0; tries < 32 && id == 0u; tries++) {
        uint8_t c = (uint8_t)(1u + sess_rand_upto(env, 254u));
        bool used = false;
        for (uint8_t i = 0; i < s->recent_ids_n && i < BR_SESSION_IDS_KEPT; i++) {
            used = used || s->recent_ids[i] == c;
        }
        if (!used) {
            id = c;
        }
    }
    for (uint16_t c = 1; c <= 255u && id == 0u; c++) {
        bool used = false;
        for (uint8_t i = 0; i < s->recent_ids_n && i < BR_SESSION_IDS_KEPT; i++) {
            used = used || s->recent_ids[i] == (uint8_t)c;
        }
        if (!used) {
            id = (uint8_t)c;
        }
    }
    /* remember it: shift the list, newest first */
    for (size_t i = BR_SESSION_IDS_KEPT - 1u; i > 0u; i--) {
        s->recent_ids[i] = s->recent_ids[i - 1u];
    }
    s->recent_ids[0] = id;
    if (s->recent_ids_n < BR_SESSION_IDS_KEPT) {
        s->recent_ids_n++;
    }
    return id;
}

/* ---- SEEK (4.1.1, 4.1.8) -------------------------------------------------- */

static void snd_seek_e2e(const br_sender_t *s, const br_sess_env_t *env, const br_seek_copy_t *c,
                         uint8_t out[BR_E2E_HDR_LEN])
{
    own_e2e(env, out, (uint8_t)BR_TYPE_SEEK, s->dst_id, c->pre_ctr, (uint8_t)BR_LEN_SEEK);
}

static br_err_t snd_send_seek(br_sender_t *s, br_sess_env_t *env)
{
    uint32_t pre = 0;
    br_err_t rc = env->next_pre_ctr(env->user, &pre);
    if (rc != BR_OK) {
        return rc;
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_SEEK;
    m.u.seek.pre_ctr = pre;
    m.u.seek.nonce_s = s->nonce_s;
    m.u.seek.caps = env->caps;
    m.u.seek.max_frame = env->own_mtu;
    m.u.seek.key_epoch = env->keys->epoch;
    m.u.seek.proto_minor = 0u;
    m.u.seek.fw_build = 0u;
    uint8_t pl[BR_LEN_SEEK];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    /* keep the payload keyed by pre_ctr: an unused slot, else the oldest */
    br_seek_copy_t *slot = NULL;
    for (size_t i = 0; i < BR_SEEK_HISTORY && slot == NULL; i++) {
        if (s->seeks[i].used == 0u) {
            slot = &s->seeks[i];
        }
    }
    if (slot == NULL) {
        slot = &s->seeks[0];
        for (size_t i = 1; i < BR_SEEK_HISTORY; i++) {
            if (s->seeks[i].pre_ctr < slot->pre_ctr) {
                slot = &s->seeks[i];
            }
        }
    }
    slot->pre_ctr = pre;
    memcpy(slot->payload, pl, sizeof pl);
    slot->used = 1u;
    sess_tx_t t = { (uint8_t)BR_TYPE_SEEK, s->dst_id, 0u, (uint16_t)(pre & 0xFFFFu), false,
                    pre >> 16, BR_DIR_TO_PROBE, env->keys->ke_mesh, BR_LEN_SEEK };
    return sess_send(env, &t, pl, sizeof pl, true);
}

static void snd_clear_cands(br_sender_t *s)
{
    memset(s->cands, 0, sizeof s->cands);
    s->cand_cur = 0u;
}

/* Enter SEEKING; the first SEEK goes out at `at` (tick sends it). */
static void snd_enter_seeking(br_sender_t *s, br_sess_env_t *env, uint32_t at)
{
    snd_clear_cands(s);
    s->bind_tries = 0u;
    s->t_deadline_ms = at;
    if (s->state != BR_SND_SEEKING) {
        snd_state(s, env, BR_SND_SEEKING);
    }
}

br_err_t br_sender_seek(br_sender_t *s, br_sess_env_t *env, uint16_t dst_id)
{
    if (s == NULL || env == NULL || dst_id == 0u || dst_id == BR_ID_FLOOD || env->keys == NULL ||
        env->send == NULL || env->next_pre_ctr == NULL) {
        return BR_ERR_ARG;
    }
    if (s->state != BR_SND_IDLE && s->state != BR_SND_CLOSED) {
        return BR_ERR_STATE;
    }
    s->dst_id = dst_id;
    s->nonce_s = sess_rand32(env);
    s->seek_attempts = 0u;
    s->full_n = 0u;
    memset(s->seeks, 0, sizeof s->seeks);
    snd_enter_seeking(s, env, env->now_ms);
    return BR_OK;
}

br_err_t br_sender_cancel(br_sender_t *s, br_sess_env_t *env)
{
    if (s == NULL || env == NULL) {
        return BR_ERR_ARG;
    }
    snd_wipe_keys(s);
    snd_clear_cands(s);
    s->mode_pending_valid = 0u;
    if (s->state != BR_SND_IDLE) {
        snd_state(s, env, BR_SND_IDLE);
    }
    return BR_OK;
}

/* ---- BIND (4.1.5, 4.1.9) -------------------------------------------------- */

static br_err_t snd_send_bind(br_sender_t *s, br_sess_env_t *env)
{
    const br_hello_cand_t *c = &s->cands[s->cand_cur];
    uint32_t pre = 0;
    br_err_t rc = env->next_pre_ctr(env->user, &pre);
    if (rc != BR_OK) {
        return rc;
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_BIND;
    m.u.bind.pre_ctr = pre;
    m.u.bind.hello_ctr = c->hello_ctr;
    m.u.bind.nonce_s = s->nonce_s;
    m.u.bind.nonce_p = s->nonce_p;
    m.u.bind.session_id = s->session_id;
    uint8_t pl[BR_LEN_BIND];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    sess_tx_t t = { (uint8_t)BR_TYPE_BIND, c->probe_id, 0u, (uint16_t)(pre & 0xFFFFu), false,
                    pre >> 16, BR_DIR_TO_PROBE, s->ke_hs, BR_LEN_PRE_CTR };
    s->t_bind_sent_ms = env->now_ms;
    rc = sess_send(env, &t, pl, sizeof pl, false);
    br_secure_zero(pl, sizeof pl);
    return rc;
}

/* Bind candidate idx at once (4.1.4, 4.1.5): transcript, Ke_hs, session_id. */
static br_err_t snd_start_bind(br_sender_t *s, br_sess_env_t *env, uint8_t idx)
{
    br_hello_cand_t *c = &s->cands[idx];
    if (c->seek_idx >= BR_SEEK_HISTORY || s->seeks[c->seek_idx].used == 0u ||
        s->seeks[c->seek_idx].pre_ctr != br_rd_le32(c->hello_plain + 4)) {
        c->used = 0u; /* the SEEK copy it answers is gone */
        return BR_ERR_STATE;
    }
    uint8_t e2e[BR_E2E_HDR_LEN];
    uint8_t prk[BR_KEY_LEN];
    snd_seek_e2e(s, env, &s->seeks[c->seek_idx], e2e);
    br_err_t rc = br_ks_t(e2e, s->seeks[c->seek_idx].payload, c->hello_e2e, c->hello_plain, s->t);
    if (rc == BR_OK) {
        rc = br_ks_pair_prk(env->crypto, env->keys, env->self_id, c->probe_id, prk);
    }
    if (rc == BR_OK) {
        rc = br_ks_hs(env->crypto, prk, env->self_id, c->probe_id, s->t, s->ke_hs);
    }
    br_secure_zero(prk, sizeof prk);
    if (rc != BR_OK) {
        return rc;
    }
    s->cand_cur = idx;
    s->nonce_p = br_rd_le32(c->hello_plain + 12);
    s->hops = c->hops;
    s->session_id = snd_new_session_id(s, env);
    s->bind_tries = 0u;
    s->t_deadline_ms = env->now_ms + br_bind_retry_ms(c->hops);
    if (s->state != BR_SND_BINDING) {
        snd_state(s, env, BR_SND_BINDING);
    }
    return snd_send_bind(s, env);
}

/* Rule 6: the next usable candidate, or SEEK again. */
static void snd_next_candidate(br_sender_t *s, br_sess_env_t *env)
{
    uint8_t cur = s->cand_cur;
    s->cands[cur].used = 0u;
    for (;;) {
        int best = -1;
        bool best_pen = true;
        for (int i = 0; i < (int)(1u + BR_HELLO_CANDIDATES); i++) {
            const br_hello_cand_t *c = &s->cands[i];
            if (c->used == 0u || c->status != BR_HELLO_STATUS_OK ||
                pen_active(s, c->first_hop, env->now_ms, true)) {
                continue;
            }
            bool pen = pen_active(s, c->first_hop, env->now_ms, false);
            if (best < 0 || (best_pen && !pen) ||
                (pen == best_pen && br_ms_before(c->rx_ms, s->cands[best].rx_ms))) {
                best = i;
                best_pen = pen;
            }
        }
        if (best < 0) {
            snd_enter_seeking(s, env, env->now_ms); /* same nonce_s: a retry (4.1.8) */
            return;
        }
        if (snd_start_bind(s, env, (uint8_t)best) == BR_OK) {
            return;
        }
        s->cands[best].used = 0u;
    }
}

/* ---- session start / failover -------------------------------------------- */

static uint16_t snd_keepalive(const br_sender_t *s)
{
    if (s->mode_active.config_id != 0u) {
        return s->mode_active.keepalive_ms;
    }
    if (s->mode_pending_valid != 0u) {
        return s->mode_pending.keepalive_ms;
    }
    return (uint16_t)BR_KEEPALIVE_DEFAULT_MS;
}

static br_err_t snd_send_session(br_sender_t *s, br_sess_env_t *env, uint8_t type,
                                 const uint8_t *pt, size_t pt_len, bool ack_req,
                                 uint8_t *frame_out, size_t *frame_len, uint16_t *seq_out,
                                 uint32_t *roc_out)
{
    uint16_t seq = 0;
    uint32_t roc = 0;
    br_err_t rc = br_tx_index_next(&s->tx, &seq, &roc);
    if (rc != BR_OK) {
        return rc;
    }
    sess_tx_t t = { type, s->probe_id, s->session_id, seq, ack_req, roc, BR_DIR_TO_PROBE, s->ke_s2p, 0u };
    uint8_t local[BR_MAX_FRAME_MESH];
    uint8_t *buf = frame_out != NULL ? frame_out : local;
    size_t len = 0;
    rc = sess_build(env, &t, pt, pt_len, buf, BR_MAX_FRAME_MESH, &len);
    if (rc != BR_OK) {
        return rc;
    }
    if (frame_len != NULL) {
        *frame_len = len;
    }
    if (seq_out != NULL) {
        *seq_out = seq;
    }
    if (roc_out != NULL) {
        *roc_out = roc;
    }
    s->t_last_tx_ms = env->now_ms;
    return env->send(env->user, buf, len, false);
}

static br_err_t snd_send_mode(br_sender_t *s, br_sess_env_t *env)
{
    uint8_t pl[BR_MODE_MAX_LEN];
    size_t n = 0;
    br_err_t rc = br_mode_encode(&s->mode_pending, pl, sizeof pl, &n);
    if (rc == BR_OK) {
        rc = snd_send_session(s, env, (uint8_t)BR_TYPE_MODE, pl, n, false, NULL, NULL, NULL, NULL);
    }
    s->t_deadline_ms = env->now_ms + br_rto_ms(&s->rtt);
    return rc;
}

static void snd_send_close(br_sender_t *s, br_sess_env_t *env, uint8_t reason)
{
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_CLOSE;
    m.u.close.reason = reason;
    uint8_t pl[BR_LEN_CLOSE];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    (void)snd_send_session(s, env, (uint8_t)BR_TYPE_CLOSE, pl, n, false, NULL, NULL, NULL, NULL);
}

static void snd_to_closed(br_sender_t *s, br_sess_env_t *env, uint8_t reason)
{
    snd_wipe_keys(s);
    memset(&s->arq, 0, sizeof s->arq);
    snd_state(s, env, BR_SND_CLOSED);
    cb_closed(env, BR_SND_HANDLE(s), reason);
}

/* 4.2 sender failover: CLOSE twice, penalty on the first hop, re-SEEK after jitter. */
static void snd_failover(br_sender_t *s, br_sess_env_t *env)
{
    snd_send_close(s, env, BR_CLOSE_TIMEOUT);
    snd_send_close(s, env, BR_CLOSE_TIMEOUT);
    pen_record(s, s->cands[s->cand_cur].first_hop, env->now_ms);
    snd_to_closed(s, env, BR_CLOSE_TIMEOUT);
    if (s->state != BR_SND_CLOSED) {
        return; /* the app re-seeked or cancelled from inside on_closed */
    }
    s->nonce_s = sess_rand32(env);
    s->seek_attempts = 0u;
    memset(s->seeks, 0, sizeof s->seeks);
    snd_enter_seeking(s, env, env->now_ms + sess_rand_upto(env, BR_RESEEK_JITTER_MS));
}

static void snd_session_start(br_sender_t *s, br_sess_env_t *env)
{
    const br_hello_cand_t *c = &s->cands[s->cand_cur];
    uint8_t prk[BR_KEY_LEN];
    br_err_t rc = br_ks_pair_prk(env->crypto, env->keys, env->self_id, c->probe_id, prk);
    if (rc == BR_OK) {
        rc = br_ks_session(env->crypto, prk, env->self_id, c->probe_id, s->session_id, s->t,
                           s->ke_s2p, s->ke_p2s);
    }
    br_secure_zero(prk, sizeof prk);
    if (rc != BR_OK) {
        snd_next_candidate(s, env);
        return;
    }
    uint16_t hello_mf = br_rd_le16(c->hello_plain + 18);
    uint16_t mtu = env->own_mtu < hello_mf ? env->own_mtu : hello_mf;
    s->probe_id = c->probe_id;
    s->hops = c->hops;
    s->max_payload = payload_cap(env, mtu);
    memset(&s->tx, 0, sizeof s->tx);
    memset(&s->rx, 0, sizeof s->rx);
    (void)br_arq_tx_init(&s->arq, (uint8_t)BR_ARQ_WINDOW);
    memset(&s->rtt, 0, sizeof s->rtt);
    br_rtt_sample(&s->rtt, env->now_ms - s->t_bind_sent_ms);
    s->t_last_ack_ms = env->now_ms;
    s->t_last_tx_ms = env->now_ms;
    s->t_ping_ms = env->now_ms;
    s->full_n = 0u;
    s->seek_attempts = 0u;
    s->ack_req_unanswered = 0u;
    s->t_deadline_ms = env->now_ms + BR_SESS_FAR_MS;
    if (s->mode_pending_valid == 0u && s->mode_active.config_id != 0u) {
        s->mode_pending = s->mode_active; /* failover: a new MODE on the new path (11.3) */
        s->mode_pending_valid = 1u;
    }
    s->mode_active.config_id = 0u;
    snd_state(s, env, BR_SND_CONFIGURING);
    const br_app_callbacks_t *a = appcb(env);
    if (a != NULL && a->on_seek_result != NULL) {
        a->on_seek_result(a->user, BR_SND_HANDLE(s), BR_OK, s->probe_id, s->hops);
    }
    if (s->state == BR_SND_CONFIGURING && s->mode_pending_valid != 0u) {
        uint8_t st = 0;
        (void)br_mode_check(&s->mode_pending, s->max_payload, env->caps, &st);
        if (st != BR_MODE_ACK_OK) {
            s->mode_pending_valid = 0u; /* does not fit the new path; the app sets another */
        } else {
            (void)snd_send_mode(s, env);
        }
    }
}

/* ---- receive -------------------------------------------------------------- */

static br_err_t snd_rx_hello(br_sender_t *s, br_sess_env_t *env, const br_rx_frame_t *f,
                             br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    if ((s->state != BR_SND_SEEKING && s->state != BR_SND_BINDING) || h->dst_id != env->self_id) {
        return BR_ERR_REJECT; /* no outstanding SEEK here (8.4 matching) */
    }
    uint32_t pre = 0;
    if (!rx_pre_ctr(f, &pre, drop_out) || f->view->payload_len != BR_LEN_HELLO ||
        !br_id_is_unit(h->src_id)) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    if (pen_active(s, f->prev_hop, env->now_ms, true)) {
        return BR_OK; /* first hop excluded for 10 min (4.2): ignore, nothing to count */
    }
    uint8_t prk[BR_KEY_LEN];
    if (br_ks_pair_prk(env->crypto, env->keys, env->self_id, h->src_id, prk) != BR_OK) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_ERR_REJECT;
    }
    uint8_t plain[BR_LEN_HELLO];
    int hit = -1;
    for (int i = 0; i < (int)BR_SEEK_HISTORY && hit < 0; i++) {
        const br_seek_copy_t *c = &s->seeks[i];
        if (c->used == 0u) {
            continue;
        }
        uint8_t e2e[BR_E2E_HDR_LEN];
        uint8_t t0[BR_KEY_LEN];
        uint8_t ke[BR_AES_KEY_LEN];
        size_t n = 0;
        snd_seek_e2e(s, env, c, e2e);
        if (br_ks_t0(e2e, c->payload, t0) == BR_OK &&
            br_ks_hello(env->crypto, prk, env->self_id, h->src_id, t0, ke) == BR_OK &&
            sess_open(env, f, ke, BR_DIR_FROM_PROBE, pre >> 16, BR_LEN_PRE_CTR, plain + 4,
                      sizeof plain - 4u, &n) == BR_OK && n == BR_LEN_HELLO - 4u) {
            hit = i;
        }
        br_secure_zero(ke, sizeof ke);
    }
    br_secure_zero(prk, sizeof prk);
    if (hit < 0) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_ERR_REJECT; /* maybe another sender's SEEK */
    }
    br_wr_le32(plain, pre);
    br_msg_t m;
    (void)br_msg_decode((uint8_t)BR_TYPE_HELLO, plain, sizeof plain, &m);
    if (m.u.hello.seek_ctr != s->seeks[hit].pre_ctr || m.u.hello.nonce_s != s->nonce_s ||
        m.u.hello.status > BR_HELLO_STATUS_FULL || m.u.hello.max_frame < BR_MIN_PATH_MTU) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        br_secure_zero(plain, sizeof plain);
        return BR_OK;
    }
    /* Candidate bookkeeping (4.1.4): one entry per probe; a newer HELLO replaces it. */
    int slot = -1;
    for (int i = 0; i < (int)(1u + BR_HELLO_CANDIDATES) && slot < 0; i++) {
        if (s->cands[i].used != 0u && s->cands[i].probe_id == h->src_id) {
            slot = i;
        }
    }
    bool same_as_bound = (slot >= 0 && s->state == BR_SND_BINDING && (uint8_t)slot == s->cand_cur);
    if (slot >= 0 && !(pre > s->cands[slot].hello_ctr)) {
        br_secure_zero(plain, sizeof plain);
        return BR_OK; /* older or equal HELLO of a probe we already hold */
    }
    if (slot < 0) {
        for (int i = 0; i < (int)(1u + BR_HELLO_CANDIDATES) && slot < 0; i++) {
            if (s->cands[i].used == 0u) {
                slot = i;
            }
        }
    }
    if (slot < 0 && m.u.hello.status == BR_HELLO_STATUS_OK) {
        /* full: a status-0 HELLO may take the place of a FULL one */
        for (int i = 0; i < (int)(1u + BR_HELLO_CANDIDATES) && slot < 0; i++) {
            if (s->cands[i].status != BR_HELLO_STATUS_OK &&
                !(s->state == BR_SND_BINDING && (uint8_t)i == s->cand_cur)) {
                slot = i;
            }
        }
    }
    if (slot < 0) {
        br_secure_zero(plain, sizeof plain);
        return BR_OK; /* no room: dropped, it is a fallback only */
    }
    br_hello_cand_t *c = &s->cands[slot];
    memset(c, 0, sizeof *c);
    c->probe_id = h->src_id;
    c->first_hop = f->prev_hop;
    c->transport = f->transport;
    c->hops = f->hops;
    c->status = m.u.hello.status;
    c->used = 1u;
    c->seek_idx = (uint8_t)hit;
    c->hello_ctr = pre;
    c->rx_ms = env->now_ms;
    (void)rx_e2e(f, c->hello_e2e);
    memcpy(c->hello_plain, plain, sizeof plain);
    br_secure_zero(plain, sizeof plain);
    if (c->status != BR_HELLO_STATUS_OK) {
        return BR_OK; /* FULL: counted at SEEK_TIMEOUT (4.1.4 backoff) */
    }
    if (s->state == BR_SND_SEEKING || same_as_bound) {
        /* first status-0 HELLO wins and BIND goes out at once; a newer HELLO of the
         * probe being bound carries its new transcript (4.1.8 resent HELLO) */
        if (snd_start_bind(s, env, (uint8_t)slot) != BR_OK) {
            c->used = 0u;
        }
    }
    return BR_OK;
}

static br_err_t snd_rx_bind_reply(br_sender_t *s, br_sess_env_t *env, const br_rx_frame_t *f,
                                  br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    if (s->state != BR_SND_BINDING || s->cands[s->cand_cur].used == 0u ||
        h->src_id != s->cands[s->cand_cur].probe_id || h->dst_id != env->self_id) {
        return BR_ERR_REJECT;
    }
    uint32_t pre = 0;
    size_t want = (h->type == (uint8_t)BR_TYPE_BIND_ACK) ? BR_LEN_BIND_ACK : BR_LEN_BIND_NAK;
    if (!rx_pre_ctr(f, &pre, drop_out) || f->view->payload_len != want) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    uint8_t plain[BR_LEN_BIND_ACK];
    size_t n = 0;
    if (sess_open(env, f, s->ke_hs, BR_DIR_FROM_PROBE, pre >> 16, BR_LEN_PRE_CTR, plain + 4,
                  sizeof plain - 4u, &n) != BR_OK) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_OK;
    }
    br_wr_le32(plain, pre);
    br_msg_t m;
    (void)br_msg_decode(h->type, plain, want, &m);
    if (h->type == (uint8_t)BR_TYPE_BIND_ACK) {
        if (m.u.bind_ack.nonce_s != s->nonce_s || m.u.bind_ack.nonce_p != s->nonce_p) {
            set_drop(drop_out, BR_STAT_BAD_FRAME);
            return BR_OK;
        }
        snd_session_start(s, env);
        return BR_OK;
    }
    if (m.u.bind_nak.nonce_s != s->nonce_s) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    snd_next_candidate(s, env); /* 4.1.6 */
    return BR_OK;
}

typedef struct {
    br_session_t   h;
    br_sess_env_t *env;
} snd_ack_ctx_t;

static br_err_t snd_rx_session(br_sender_t *s, br_sess_env_t *env, const br_rx_frame_t *f,
                               br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    if ((s->state != BR_SND_CONFIGURING && s->state != BR_SND_STREAMING) ||
        h->src_id != s->probe_id || h->session_id != s->session_id || h->session_id == 0u ||
        h->dst_id != env->self_id) {
        return BR_ERR_REJECT;
    }
    uint32_t roc = 0;
    bool fresh = false;
    if (br_rx_index_check(&s->rx, h->seq, &roc, &fresh) != BR_OK) {
        set_drop(drop_out, BR_STAT_REPLAY_DROPPED);
        return BR_OK;
    }
    uint8_t plain[BR_PTBUF];
    size_t n = 0;
    if (sess_open(env, f, s->ke_p2s, BR_DIR_FROM_PROBE, roc, 0u, plain, sizeof plain, &n) != BR_OK) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_OK;
    }
    if (!fresh) {
        set_drop(drop_out, BR_STAT_REPLAY_DROPPED);
        return BR_OK;
    }
    br_msg_t m;
    if (br_msg_decode(h->type, plain, n, &m) != BR_OK) {
        (void)br_rx_index_commit(&s->rx, h->seq, roc);
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    if (h->type == (uint8_t)BR_TYPE_ACK) {
        /* 3.6: cum_seq inside the ARQ window: not ahead of the last seq sent */
        uint16_t last = (uint16_t)(s->tx.next_seq - 1u);
        if ((uint16_t)(last - m.u.ack.cum_seq) >= 0x8000u) {
            (void)br_rx_index_commit(&s->rx, h->seq, roc);
            set_drop(drop_out, BR_STAT_BAD_FRAME);
            return BR_OK;
        }
    }
    (void)br_rx_index_commit(&s->rx, h->seq, roc);
    s->t_last_ack_ms = env->now_ms; /* any authentic frame from the probe proves liveness */
    br_session_t hd = BR_SND_HANDLE(s);
    switch (h->type) {
    case BR_TYPE_ACK: {
        uint16_t seqs[BR_ARQ_WINDOW];
        uint8_t was[BR_ARQ_WINDOW];
        for (size_t i = 0; i < BR_ARQ_WINDOW; i++) {
            seqs[i] = s->arq.slot[i].seq;
            was[i] = (uint8_t)(s->arq.slot[i].flags & BR_ARQ_SLOT_USED);
        }
        uint8_t na = 0;
        uint32_t rtt = UINT32_MAX;
        (void)br_arq_tx_on_ack(&s->arq, m.u.ack.cum_seq, m.u.ack.bitmap, env->now_ms, &na, &rtt);
        if (rtt != UINT32_MAX) {
            br_rtt_sample(&s->rtt, rtt);
        }
        s->ack_req_unanswered = 0u;
        const br_app_callbacks_t *a = appcb(env);
        for (size_t i = 0; i < BR_ARQ_WINDOW && na > 0u; i++) {
            if (was[i] != 0u && (s->arq.slot[i].flags & BR_ARQ_SLOT_USED) == 0u && a != NULL &&
                a->on_acked != NULL) {
                a->on_acked(a->user, hd, seqs[i]);
            }
        }
        break;
    }
    case BR_TYPE_MODE_ACK:
        if (s->mode_pending_valid != 0u && m.u.mode_ack.config_id == s->mode_pending.config_id) {
            s->mode_pending_valid = 0u;
            s->t_deadline_ms = env->now_ms + BR_SESS_FAR_MS;
            if (m.u.mode_ack.status == BR_MODE_ACK_OK) {
                s->mode_active = s->mode_pending;
                const br_app_callbacks_t *a = appcb(env);
                if (s->state == BR_SND_CONFIGURING) {
                    snd_state(s, env, BR_SND_STREAMING);
                }
                if (a != NULL && a->on_mode != NULL) {
                    a->on_mode(a->user, hd, &s->mode_active);
                }
            }
            /* non-zero status: the pending mode is dropped; DATA keeps the old one */
        }
        break;
    case BR_TYPE_PONG: {
        uint32_t now_us32 = env->now_ms * 1000u;
        uint32_t rtt_ms = (now_us32 - m.u.pong.t_echo_us) / 1000u;
        if (rtt_ms < 60000u) {
            br_rtt_sample(&s->rtt, rtt_ms);
        }
        break;
    }
    case BR_TYPE_CLOSE:
        snd_to_closed(s, env, m.u.close.reason);
        break;
    default:
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        break;
    }
    return BR_OK;
}

br_err_t br_sender_rx(br_sender_t *s, br_sess_env_t *env, const br_rx_frame_t *f,
                      br_stat_id_t *drop_out)
{
    if (s == NULL || env == NULL || f == NULL || f->view == NULL || f->buf == NULL) {
        return BR_ERR_ARG;
    }
    set_drop(drop_out, BR_STAT_NONE);
    switch (f->view->hdr.type) {
    case BR_TYPE_HELLO:
        return snd_rx_hello(s, env, f, drop_out);
    case BR_TYPE_BIND_ACK:
    case BR_TYPE_BIND_NAK:
        return snd_rx_bind_reply(s, env, f, drop_out);
    case BR_TYPE_MODE_ACK:
    case BR_TYPE_ACK:
    case BR_TYPE_PONG:
    case BR_TYPE_CLOSE:
        return snd_rx_session(s, env, f, drop_out);
    default:
        return BR_ERR_REJECT;
    }
}

/* ---- app calls ------------------------------------------------------------ */

br_err_t br_sender_set_mode(br_sender_t *s, br_sess_env_t *env, const br_mode_t *mode)
{
    if (s == NULL || env == NULL || mode == NULL) {
        return BR_ERR_ARG;
    }
    if (s->state == BR_SND_IDLE || s->state == BR_SND_CLOSED) {
        return BR_ERR_STATE;
    }
    uint8_t last = s->mode_pending_valid != 0u ? s->mode_pending.config_id : s->mode_active.config_id;
    br_mode_t m = *mode;
    m.config_id = (uint8_t)(last >= 255u ? 1u : last + 1u);
    bool live = (s->state == BR_SND_CONFIGURING || s->state == BR_SND_STREAMING);
    size_t cap = live ? s->max_payload : (env->auth ? BR_MAX_PAYLOAD_AUTH : BR_MAX_PAYLOAD_NOAUTH);
    uint8_t st = 0;
    if (br_mode_check(&m, cap, env->caps, &st) != BR_OK || st != BR_MODE_ACK_OK) {
        return BR_ERR_ARG;
    }
    s->mode_pending = m;
    s->mode_pending_valid = 1u;
    if (live) {
        return snd_send_mode(s, env);
    }
    return BR_OK;
}

br_err_t br_sender_send_samples(br_sender_t *s, br_sess_env_t *env, const br_value_t *vals,
                                uint8_t n_samples, uint32_t t_first_us, uint8_t status, bool ack_req)
{
    if (s == NULL || env == NULL || vals == NULL || n_samples == 0u) {
        return BR_ERR_ARG;
    }
    if (s->state != BR_SND_STREAMING || s->mode_active.config_id == 0u) {
        return BR_ERR_STATE;
    }
    uint8_t pl[BR_PTBUF];
    size_t n = 0;
    br_data_hdr_t dh = { s->mode_active.config_id, (uint8_t)(status & ~BR_DATA_ST_RESERVED),
                         t_first_us, n_samples };
    size_t cap = s->max_payload < sizeof pl ? s->max_payload : sizeof pl;
    br_err_t rc = br_data_build(&s->mode_active, &dh, vals, pl, cap, &n, NULL);
    if (rc != BR_OK) {
        return rc;
    }
    uint8_t frame[BR_MAX_FRAME_MESH];
    size_t flen = 0;
    uint16_t seq = 0;
    uint32_t roc = 0;
    rc = snd_send_session(s, env, (uint8_t)BR_TYPE_DATA, pl, n, ack_req, frame, &flen, &seq, &roc);
    if (rc == BR_ERR_TOO_BIG || flen == 0u) {
        return rc; /* index exhausted / not built */
    }
    if (s->mode_active.arq != 0u) {
        bool ev = false;
        uint16_t ev_seq = 0;
        (void)br_arq_tx_push(&s->arq, seq, roc, frame, (uint16_t)flen, ack_req, env->now_ms, &ev, &ev_seq);
        if (ev) {
            br_stats_inc(env->stats, BR_STAT_GAPS);
            cb_gap(env, BR_SND_HANDLE(s), ev_seq, 1u);
        }
    }
    return BR_OK; /* a send failure is recovered by ARQ / timeouts */
}

br_err_t br_sender_close(br_sender_t *s, br_sess_env_t *env, uint8_t reason)
{
    if (s == NULL || env == NULL) {
        return BR_ERR_ARG;
    }
    if (s->state == BR_SND_IDLE || s->state == BR_SND_CLOSED) {
        return BR_ERR_STATE;
    }
    if (s->state == BR_SND_CONFIGURING || s->state == BR_SND_STREAMING) {
        snd_send_close(s, env, reason);
    }
    s->mode_pending_valid = 0u;
    memset(&s->mode_active, 0, sizeof s->mode_active);
    snd_to_closed(s, env, reason);
    return BR_OK;
}

/* ---- timers ----------------------------------------------------------------- */

static void snd_tick_seeking(br_sender_t *s, br_sess_env_t *env)
{
    uint32_t now = env->now_ms;
    if (!due(now, s->t_deadline_ms)) {
        return;
    }
    bool any_full = false;
    for (size_t i = 0; i < 1u + BR_HELLO_CANDIDATES; i++) {
        any_full = any_full || (s->cands[i].used != 0u && s->cands[i].status == BR_HELLO_STATUS_FULL);
    }
    if (any_full) {
        /* 4.1.4: every HELLO said FULL: back off rand(0, min(3600, 60 x 2^n)) s */
        uint32_t cap_s = (s->full_n >= 6u) ? BR_FULL_CAP_S : (60u << s->full_n);
        if (cap_s > BR_FULL_CAP_S) {
            cap_s = BR_FULL_CAP_S;
        }
        if (s->full_n < 0xFFu) {
            s->full_n++;
        }
        snd_clear_cands(s);
        s->t_deadline_ms = now + sess_rand_upto(env, cap_s * 1000u);
        return;
    }
    if (s->seek_attempts == BR_SEEK_NO_PROBE_AFTER) {
        cb_event(env, BR_EVT_NO_PROBE, s->dst_id); /* once, after the 5th attempt */
    }
    uint8_t n = s->seek_attempts;
    (void)snd_send_seek(s, env);
    if (s->seek_attempts < 0xFFu) {
        s->seek_attempts++;
    }
    s->t_deadline_ms = now + br_seek_base_ms(env->seek_ttl) +
                       sess_rand_upto(env, br_seek_jitter_max_ms(n));
}

static void snd_tick_binding(br_sender_t *s, br_sess_env_t *env)
{
    if (!due(env->now_ms, s->t_deadline_ms)) {
        return;
    }
    if (s->bind_tries < BR_BIND_RETRIES) {
        s->bind_tries++;
        s->t_deadline_ms = env->now_ms + br_bind_retry_ms(s->hops);
        (void)snd_send_bind(s, env);
        return;
    }
    snd_next_candidate(s, env); /* 4.1.9 -> rule 6 */
}

static void snd_tick_session(br_sender_t *s, br_sess_env_t *env)
{
    uint32_t now = env->now_ms;
    br_session_t hd = BR_SND_HANDLE(s);
    /* MODE_RETRY = RTO (4.2) */
    if (s->mode_pending_valid != 0u && due(now, s->t_deadline_ms)) {
        (void)snd_send_mode(s, env);
    }
    /* ARQ (section 7, SPEC-NOTES N24) */
    for (int guard = 0; guard < 2 * (int)BR_ARQ_WINDOW + 2 && s->state == BR_SND_STREAMING; guard++) {
        const br_arq_tx_slot_t *slot = NULL;
        br_arq_tx_action_t act = BR_ARQ_TX_IDLE;
        (void)br_arq_tx_poll(&s->arq, now, br_rto_ms(&s->rtt), &slot, &act, NULL);
        if (act == BR_ARQ_TX_IDLE || slot == NULL) {
            break;
        }
        if (act == BR_ARQ_TX_RESEND) {
            uint8_t frame[BR_MAX_FRAME_MESH];
            uint16_t len = slot->len <= sizeof frame ? slot->len : (uint16_t)sizeof frame;
            memcpy(frame, slot->frame, len);
            br_stats_inc(env->stats, BR_STAT_ARQ_RETX);
            s->t_last_tx_ms = now;
            (void)env->send(env->user, frame, len, false);
            continue;
        }
        bool was_req = (slot->flags & BR_ARQ_SLOT_ACK_REQ) != 0u;
        uint16_t gseq = slot->seq;
        br_stats_inc(env->stats, BR_STAT_GAPS);
        cb_gap(env, hd, gseq, 1u);
        if (was_req && s->state == BR_SND_STREAMING) {
            /* 4.1.13: close after ARQ_MAX_RETRIES unanswered ACK requests in a row */
            if (s->ack_req_unanswered < 0xFFu) {
                s->ack_req_unanswered++;
            }
            if (s->ack_req_unanswered >= BR_ARQ_MAX_RETRIES) {
                snd_failover(s, env);
                return;
            }
        }
    }
    if (s->state != BR_SND_CONFIGURING && s->state != BR_SND_STREAMING) {
        return;
    }
    /* SESSION_TIMEOUT (4.2) */
    uint16_t ka = snd_keepalive(s);
    if (due(now, s->t_last_ack_ms + br_session_timeout_ms(ka, &s->rtt))) {
        snd_failover(s, env);
        return;
    }
    /* PING when no ACK for keepalive_ms (4.2), then once per keepalive */
    if (due(now, s->t_last_ack_ms + ka) && due(now, s->t_ping_ms + ka)) {
        br_msg_t m;
        memset(&m, 0, sizeof m);
        m.type = BR_TYPE_PING;
        m.u.ping.t_tx_us = now * 1000u;
        uint8_t pl[BR_LEN_PING];
        size_t n = 0;
        (void)br_msg_encode(&m, pl, sizeof pl, &n);
        s->t_ping_ms = now;
        (void)snd_send_session(s, env, (uint8_t)BR_TYPE_PING, pl, n, false, NULL, NULL, NULL, NULL);
    }
}

br_err_t br_sender_tick(br_sender_t *s, br_sess_env_t *env, uint32_t *next_deadline_out)
{
    if (s == NULL || env == NULL || next_deadline_out == NULL) {
        return BR_ERR_ARG;
    }
    uint32_t now = env->now_ms;
    switch (s->state) {
    case BR_SND_SEEKING:
        snd_tick_seeking(s, env);
        break;
    case BR_SND_BINDING:
        snd_tick_binding(s, env);
        break;
    case BR_SND_CONFIGURING:
    case BR_SND_STREAMING:
        snd_tick_session(s, env);
        break;
    default:
        break;
    }
    uint32_t next = now + BR_SESS_FAR_MS;
    switch (s->state) {
    case BR_SND_SEEKING:
    case BR_SND_BINDING:
        next_min(now, &next, s->t_deadline_ms);
        break;
    case BR_SND_CONFIGURING:
    case BR_SND_STREAMING: {
        uint16_t ka = snd_keepalive(s);
        if (s->mode_pending_valid != 0u) {
            next_min(now, &next, s->t_deadline_ms);
        }
        next_min(now, &next, s->t_last_ack_ms + br_session_timeout_ms(ka, &s->rtt));
        uint32_t ping_at = s->t_last_ack_ms + ka;
        if (br_ms_before(ping_at, s->t_ping_ms + ka)) {
            ping_at = s->t_ping_ms + ka;
        }
        next_min(now, &next, ping_at);
        /* The tick body polled the ARQ until idle at this same `now`, so this poll
         * only reports the next deadline (it mutates a slot only when one is due). */
        uint32_t arq_next = now + BR_SESS_FAR_MS;
        const br_arq_tx_slot_t *sl = NULL;
        br_arq_tx_action_t act = BR_ARQ_TX_IDLE;
        if (s->state == BR_SND_STREAMING && s->arq.count > 0u) {
            (void)br_arq_tx_poll(&s->arq, now, br_rto_ms(&s->rtt), &sl, &act, &arq_next);
        }
        next_min(now, &next, arq_next);
        break;
    }
    default:
        break;
    }
    *next_deadline_out = next;
    return BR_OK;
}

/* ========================================================================= */
/* Probe (4.1, 4.2, 6.1, 7)                                                   */
/* ========================================================================= */

static br_session_t prb_handle(const br_probe_t *p, const br_probe_record_t *r)
{
    return (br_session_t)(BR_SESSION_PROBE | (uint8_t)(r - p->rec));
}

static bool rec_bound(const br_probe_record_t *r)
{
    return r->state == BR_PRB_BOUND || r->state == BR_PRB_STREAMING;
}

br_err_t br_probe_init(br_probe_t *p)
{
    if (p == NULL) {
        return BR_ERR_ARG;
    }
    br_secure_zero(p, sizeof *p);
    for (size_t i = 0; i < BR_RX_RECORDS; i++) {
        p->rec[i].state = BR_PRB_LISTENING;
        p->rec[i].stream = BR_NO_INDEX;
        p->rec[i].cfg_active = BR_NO_INDEX;
    }
    for (size_t i = 0; i < BR_RX_STREAMS; i++) {
        p->stream_owner[i] = BR_NO_INDEX;
    }
    return BR_OK;
}

br_err_t br_probe_listen(br_probe_t *p, const uint16_t *groups, uint8_t n_groups)
{
    if (p == NULL || n_groups > BR_MAX_GROUPS || (groups == NULL && n_groups > 0u)) {
        return BR_ERR_ARG;
    }
    for (uint8_t i = 0; i < n_groups; i++) {
        if (!br_id_is_group(groups[i])) {
            return BR_ERR_ARG;
        }
    }
    memset(p->groups, 0, sizeof p->groups);
    for (uint8_t i = 0; i < n_groups; i++) {
        p->groups[i] = groups[i];
    }
    p->n_groups = n_groups;
    p->listening = n_groups > 0u ? 1u : 0u;
    return BR_OK;
}

br_err_t br_probe_is_member(const br_probe_t *p, uint16_t dst_id, bool *member_out)
{
    if (p == NULL || member_out == NULL) {
        return BR_ERR_ARG;
    }
    *member_out = false;
    for (uint8_t i = 0; i < p->n_groups && i < BR_MAX_GROUPS; i++) {
        if (p->groups[i] == dst_id) {
            *member_out = true;
        }
    }
    return BR_OK;
}

static br_probe_record_t *prb_find_src(br_probe_t *p, uint16_t src)
{
    for (size_t i = 0; i < BR_RX_RECORDS; i++) {
        if (rec_bound(&p->rec[i]) && p->rec[i].src_id == src) {
            return &p->rec[i];
        }
    }
    return NULL;
}

static br_probe_record_t *prb_find_session(br_probe_t *p, uint16_t src, uint8_t sid)
{
    for (size_t i = 0; i < BR_RX_RECORDS; i++) {
        if (rec_bound(&p->rec[i]) && p->rec[i].src_id == src && p->rec[i].session_id == sid) {
            return &p->rec[i];
        }
    }
    return NULL;
}

static br_offer_t *prb_find_offer(br_probe_t *p, uint16_t src)
{
    for (size_t i = 0; i < BR_PROBE_OFFERS_MAX; i++) {
        if (p->offers[i].src_id == src && src != 0u) {
            return &p->offers[i];
        }
    }
    return NULL;
}

static int prb_free_stream(const br_probe_t *p)
{
    for (int i = 0; i < (int)BR_RX_STREAMS; i++) {
        if (p->stream_owner[i] == BR_NO_INDEX) {
            return i;
        }
    }
    return -1;
}

static int prb_free_record(const br_probe_t *p)
{
    for (int i = 0; i < (int)BR_RX_RECORDS; i++) {
        if (p->rec[i].state == BR_PRB_LISTENING) {
            return i;
        }
    }
    return -1;
}

/* 4.1.12: no free record, or no free stream for a sender with ARQ / FEC caps.
 * A record (and stream) already held by the same sender counts as free: its
 * BIND replaces it (4.1.3). */
static bool prb_full(const br_probe_t *p, const br_probe_record_t *same, uint16_t sender_caps)
{
    bool rec_ok = (same != NULL) || prb_free_record(p) >= 0;
    bool need_stream = (sender_caps & (BR_CAP_ARQ | BR_CAP_FEC)) != 0u;
    bool str_ok = !need_stream || prb_free_stream(p) >= 0 || (same != NULL && same->stream != BR_NO_INDEX);
    return !(rec_ok && str_ok);
}

static void prb_free_rec(br_probe_t *p, br_probe_record_t *r)
{
    if (r->stream != BR_NO_INDEX && r->stream < BR_RX_STREAMS) {
        p->stream_owner[r->stream] = BR_NO_INDEX;
        memset(&p->streams[r->stream], 0, sizeof p->streams[r->stream]);
    }
    br_secure_zero(r, sizeof *r);
    r->state = BR_PRB_LISTENING;
    r->stream = BR_NO_INDEX;
    r->cfg_active = BR_NO_INDEX;
}

static void prb_close_rec(br_probe_t *p, br_sess_env_t *env, br_probe_record_t *r, uint8_t reason)
{
    br_session_t h = prb_handle(p, r);
    uint8_t old = r->state;
    prb_free_rec(p, r);
    cb_state(env, h, old, BR_PRB_LISTENING);
    cb_closed(env, h, reason);
}

static br_err_t prb_send_pre(br_sess_env_t *env, uint8_t type, uint16_t dst, const uint8_t *key,
                             uint8_t *pl, size_t len, uint32_t pre)
{
    sess_tx_t t = { type, dst, 0u, (uint16_t)(pre & 0xFFFFu), false, pre >> 16, BR_DIR_FROM_PROBE,
                    key, BR_LEN_PRE_CTR };
    br_err_t rc = sess_send(env, &t, pl, len, false);
    br_secure_zero(pl, len);
    return rc;
}

/* HELLO for an offer (status 0) or a FULL answer without state (status 1). */
static br_err_t prb_send_hello(br_sess_env_t *env, uint16_t sender, const uint8_t seek_e2e[BR_E2E_HDR_LEN],
                               const uint8_t seek_payload[BR_LEN_SEEK], uint32_t nonce_p, uint16_t mtu,
                               uint8_t cost, uint8_t status, uint32_t *hello_ctr_out,
                               uint8_t hello_plain_out[BR_LEN_HELLO])
{
    uint8_t prk[BR_KEY_LEN];
    uint8_t t0[BR_KEY_LEN];
    uint8_t ke[BR_AES_KEY_LEN];
    uint32_t pre = 0;
    br_err_t rc = env->next_pre_ctr(env->user, &pre);
    if (rc == BR_OK) {
        rc = br_ks_pair_prk(env->crypto, env->keys, sender, env->self_id, prk);
    }
    if (rc == BR_OK) {
        rc = br_ks_t0(seek_e2e, seek_payload, t0);
    }
    if (rc == BR_OK) {
        rc = br_ks_hello(env->crypto, prk, sender, env->self_id, t0, ke);
    }
    br_secure_zero(prk, sizeof prk);
    if (rc != BR_OK) {
        br_secure_zero(ke, sizeof ke);
        return rc;
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_HELLO;
    m.u.hello.pre_ctr = pre;
    m.u.hello.seek_ctr = br_rd_le32(seek_payload);
    m.u.hello.nonce_s = br_rd_le32(seek_payload + 4);
    m.u.hello.nonce_p = nonce_p;
    m.u.hello.caps = env->caps;
    m.u.hello.max_frame = env->own_mtu < mtu ? env->own_mtu : mtu;
    m.u.hello.rssi = (int8_t)BR_RSSI_UNKNOWN;
    m.u.hello.status = status;
    m.u.hello.path_cost = cost;
    uint8_t pl[BR_LEN_HELLO];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    if (hello_plain_out != NULL) {
        memcpy(hello_plain_out, pl, sizeof pl);
    }
    if (hello_ctr_out != NULL) {
        *hello_ctr_out = pre;
    }
    rc = prb_send_pre(env, (uint8_t)BR_TYPE_HELLO, sender, ke, pl, sizeof pl, pre);
    br_secure_zero(ke, sizeof ke);
    return rc;
}

static br_err_t prb_rx_seek(br_probe_t *p, br_sess_env_t *env, const br_rx_frame_t *f,
                            br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    bool member = false;
    (void)br_probe_is_member(p, h->dst_id, &member);
    if (p->listening == 0u || (!member && h->dst_id != env->self_id)) {
        return BR_OK; /* not for a group of mine: nothing to answer */
    }
    uint32_t pre = 0;
    if (!rx_pre_ctr(f, &pre, drop_out)) {
        return BR_OK;
    }
    br_msg_t m;
    if (br_msg_decode((uint8_t)BR_TYPE_SEEK, f->buf + f->view->payload_off, f->view->payload_len, &m) != BR_OK) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    if (m.u.seek.key_epoch != env->keys->epoch) {
        set_drop(drop_out, BR_STAT_BAD_FRAME); /* 3.6 SEEK row: not a live epoch */
        return BR_OK;
    }
    uint8_t none[1];
    size_t n = 0;
    if (sess_open(env, f, env->keys->ke_mesh, BR_DIR_TO_PROBE, pre >> 16, BR_LEN_SEEK, none, 0u, &n) != BR_OK) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_OK;
    }
    if ((m.u.seek.caps & BR_CAP_RESERVED_MASK) != 0u || m.u.seek.max_frame < BR_MIN_PATH_MTU ||
        !br_id_is_unit(h->src_id) || h->src_id == env->self_id) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    uint16_t mtu = h->path_mtu < m.u.seek.max_frame ? h->path_mtu : m.u.seek.max_frame;
    /* SPEC-NOTES N32 (A.9): HELLO carries the chosen copy's path_cost as
     * received. The comparison cost (path_cost + link cost, 11.4 row 1) is
     * decided by the node (dedup best_cost) before br_probe_offer_copy();
     * copies below -90 dBm never get here (br_node.c drops them). */
    uint8_t cost = h->path_cost;
    br_offer_t *o = prb_find_offer(p, h->src_id);
    if (o != NULL && o->nonce_s == m.u.seek.nonce_s) {
        if (!(pre > o->seek_ctr)) {
            return BR_OK; /* older copy of a SEEK we already answer */
        }
        /* 4.1.8: same nonce_s, newer pre_ctr: our HELLO was lost; HELLO again */
    }
    br_probe_record_t *same = prb_find_src(p, h->src_id);
    if (prb_full(p, same, m.u.seek.caps)) {
        /* 4.1.2: still answer, status 1, keep no state */
        if (o != NULL) {
            memset(o, 0, sizeof *o);
        }
        uint8_t e2e[BR_E2E_HDR_LEN];
        if (rx_e2e(f, e2e) == BR_OK) {
            (void)prb_send_hello(env, h->src_id, e2e, f->buf + f->view->payload_off,
                                 sess_rand32(env), mtu, cost, BR_HELLO_STATUS_FULL, NULL, NULL);
        }
        return BR_OK;
    }
    if (o == NULL || o->nonce_s != m.u.seek.nonce_s) {
        if (o == NULL) {
            for (size_t i = 0; i < BR_PROBE_OFFERS_MAX && o == NULL; i++) {
                if (p->offers[i].src_id == 0u) {
                    o = &p->offers[i];
                }
            }
        }
        if (o == NULL) {
            o = &p->offers[0]; /* oldest replaced (4.1.2) */
            for (size_t i = 1; i < BR_PROBE_OFFERS_MAX; i++) {
                if (br_ms_before(p->offers[i].hello_due_ms, o->hello_due_ms)) {
                    o = &p->offers[i];
                }
            }
        }
        memset(o, 0, sizeof *o);
        o->src_id = h->src_id;
        o->nonce_s = m.u.seek.nonce_s;
        o->nonce_p = sess_rand32(env);
    }
    o->prev_hop = f->prev_hop;
    o->transport = f->transport;
    o->hops = f->hops;
    o->cost = cost;
    o->hello_sent = 0u;
    o->sender_caps = m.u.seek.caps;
    o->path_mtu = mtu;
    o->seek_ctr = pre;
    (void)rx_e2e(f, o->seek_e2e);
    memcpy(o->seek_payload, f->buf + f->view->payload_off, BR_LEN_SEEK);
    o->hello_due_ms = env->now_ms + sess_rand_upto(env, BR_HELLO_WINDOW_MS);
    o->expiry_ms = o->hello_due_ms + br_bind_timeout_ms(o->hops);
    return BR_OK;
}

void br_probe_offer_copy(br_probe_t *p, uint16_t src_id, uint32_t pre_ctr, uint16_t prev_hop,
                         uint8_t transport, uint8_t hops, uint8_t path_cost, uint16_t path_mtu)
{
    if (p == NULL) {
        return;
    }
    br_offer_t *o = prb_find_offer(p, src_id);
    /* No cost compare here: the caller only calls for a copy whose
     * path_cost + link cost beat the dedup best_cost (11.4 row 1), and
     * path_cost alone does not order copies that arrived on different links. */
    if (o == NULL || o->hello_sent != 0u || o->seek_ctr != pre_ctr) {
        return;
    }
    uint16_t sender_mf = br_rd_le16(o->seek_payload + 10);
    o->prev_hop = prev_hop;
    o->transport = transport;
    o->hops = hops;
    o->cost = path_cost;
    o->path_mtu = path_mtu < sender_mf ? path_mtu : sender_mf;
}

static br_err_t prb_send_bind_reply(br_sess_env_t *env, uint8_t type, uint16_t sender, const uint8_t *ke_hs,
                                    uint32_t nonce_s, uint32_t nonce_p, uint8_t reason)
{
    uint32_t pre = 0;
    br_err_t rc = env->next_pre_ctr(env->user, &pre);
    if (rc != BR_OK) {
        return rc;
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = type;
    uint8_t pl[BR_LEN_BIND_ACK];
    size_t n = 0;
    if (type == (uint8_t)BR_TYPE_BIND_ACK) {
        m.u.bind_ack.pre_ctr = pre;
        m.u.bind_ack.nonce_s = nonce_s;
        m.u.bind_ack.nonce_p = nonce_p;
    } else {
        m.u.bind_nak.pre_ctr = pre;
        m.u.bind_nak.nonce_s = nonce_s;
        m.u.bind_nak.reason = reason;
    }
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    return prb_send_pre(env, type, sender, ke_hs, pl, n, pre);
}

static br_err_t prb_rx_bind(br_probe_t *p, br_sess_env_t *env, const br_rx_frame_t *f,
                            br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    uint32_t pre = 0;
    if (!rx_pre_ctr(f, &pre, drop_out)) {
        return BR_OK;
    }
    if (f->view->payload_len != BR_LEN_BIND || h->dst_id != env->self_id) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
    br_offer_t *o = prb_find_offer(p, h->src_id);
    if (o != NULL && o->hello_sent == 0u) {
        o = NULL; /* no HELLO yet: nothing a BIND can name */
    }
    br_probe_record_t *r = prb_find_src(p, h->src_id);
    if (o == NULL && r == NULL) {
        return BR_OK; /* 4.1.7: a LISTENING probe ignores any BIND naming it */
    }
    uint8_t plain[BR_LEN_BIND];
    size_t n = 0;
    bool fresh_offer = false;
    uint8_t t[BR_KEY_LEN];
    uint8_t ke_hs[BR_AES_KEY_LEN];
    uint8_t prk[BR_KEY_LEN];
    bool have_prk = br_ks_pair_prk(env->crypto, env->keys, h->src_id, env->self_id, prk) == BR_OK;
    if (o != NULL && have_prk) {
        uint8_t he2e[BR_E2E_HDR_LEN];
        own_e2e(env, he2e, (uint8_t)BR_TYPE_HELLO, o->src_id, o->hello_ctr, (uint8_t)BR_LEN_HELLO);
        if (br_ks_t(o->seek_e2e, o->seek_payload, he2e, o->hello_plain, t) == BR_OK &&
            br_ks_hs(env->crypto, prk, h->src_id, env->self_id, t, ke_hs) == BR_OK &&
            sess_open(env, f, ke_hs, BR_DIR_TO_PROBE, pre >> 16, BR_LEN_PRE_CTR, plain + 4,
                      sizeof plain - 4u, &n) == BR_OK) {
            fresh_offer = true;
        }
    }
    bool repeat = false;
    if (!fresh_offer && r != NULL &&
        sess_open(env, f, r->ke_hs, BR_DIR_TO_PROBE, pre >> 16, BR_LEN_PRE_CTR, plain + 4,
                  sizeof plain - 4u, &n) == BR_OK) {
        repeat = true;
    }
    br_err_t ret = BR_OK;
    if (!fresh_offer && !repeat) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        goto out;
    }
    br_wr_le32(plain, pre);
    br_msg_t m;
    (void)br_msg_decode((uint8_t)BR_TYPE_BIND, plain, sizeof plain, &m);
    if (repeat) {
        /* 4.1.9: already BOUND to these nonces: BIND_ACK again, no state change */
        if (m.u.bind.nonce_s != r->nonce_s || m.u.bind.nonce_p != r->nonce_p ||
            m.u.bind.hello_ctr != r->hello_ctr || m.u.bind.session_id != r->session_id) {
            set_drop(drop_out, BR_STAT_BAD_FRAME);
            goto out;
        }
        (void)prb_send_bind_reply(env, (uint8_t)BR_TYPE_BIND_ACK, r->src_id, r->ke_hs, r->nonce_s,
                                  r->nonce_p, 0u);
        goto out;
    }
    if (m.u.bind.hello_ctr != o->hello_ctr || m.u.bind.nonce_s != o->nonce_s ||
        m.u.bind.nonce_p != o->nonce_p || m.u.bind.session_id == 0u) {
        set_drop(drop_out, BR_STAT_BAD_FRAME); /* 4.1.6: nonces match no OFFERED entry */
        goto out;
    }
    {
        /* capacity (4.1.6, 4.1.12): the sender's own record / stream may be reused */
        bool need_stream = (o->sender_caps & (BR_CAP_ARQ | BR_CAP_FEC)) != 0u;
        if (prb_full(p, r, o->sender_caps)) {
            (void)prb_send_bind_reply(env, (uint8_t)BR_TYPE_BIND_NAK, o->src_id, ke_hs, o->nonce_s, 0u,
                                      BR_BIND_NAK_BUSY);
            memset(o, 0, sizeof *o);
            goto out;
        }
        if (r != NULL) {
            /* 4.1.3: a BIND under the new Ke_hs replaces the old session with this sender */
            prb_close_rec(p, env, r, BR_CLOSE_NORMAL);
        }
        int ri = prb_free_record(p);
        if (ri < 0 || (need_stream && prb_free_stream(p) < 0)) {
            memset(o, 0, sizeof *o); /* a callback took the capacity meanwhile */
            goto out;
        }
        br_probe_record_t *nr = &p->rec[ri];
        memset(nr, 0, sizeof *nr);
        nr->session_id = m.u.bind.session_id;
        nr->hops = o->hops;
        nr->src_id = o->src_id;
        nr->max_payload = payload_cap(env, o->path_mtu < env->own_mtu ? o->path_mtu : env->own_mtu);
        nr->sender_caps = o->sender_caps;
        nr->nonce_s = o->nonce_s;
        nr->nonce_p = o->nonce_p;
        nr->hello_ctr = o->hello_ctr;
        memcpy(nr->ke_hs, ke_hs, sizeof ke_hs);
        if (br_ks_session(env->crypto, prk, o->src_id, env->self_id, nr->session_id, t, nr->ke_s2p,
                          nr->ke_p2s) != BR_OK) {
            prb_free_rec(p, nr);
            set_drop(drop_out, BR_STAT_AUTH_FAIL);
            goto out;
        }
        nr->stream = BR_NO_INDEX; /* taken at the first DATA (4.1.12) */
        nr->cfg_active = BR_NO_INDEX;
        nr->last_rx_ms = env->now_ms;
        nr->last_tx_ms = env->now_ms;
        nr->state = BR_PRB_BOUND;
        memset(o, 0, sizeof *o);
        (void)prb_send_bind_reply(env, (uint8_t)BR_TYPE_BIND_ACK, nr->src_id, nr->ke_hs, nr->nonce_s,
                                  nr->nonce_p, 0u);
        br_session_t hd = prb_handle(p, nr);
        cb_state(env, hd, BR_PRB_LISTENING, BR_PRB_BOUND);
        const br_app_callbacks_t *a = appcb(env);
        if (a != NULL && a->on_bound != NULL && rec_bound(nr)) {
            a->on_bound(a->user, hd, nr->src_id);
        }
    }
out:
    br_secure_zero(plain, sizeof plain);
    br_secure_zero(t, sizeof t);
    br_secure_zero(ke_hs, sizeof ke_hs);
    br_secure_zero(prk, sizeof prk);
    return ret;
}

/* ---- probe session frames ------------------------------------------------- */

static uint16_t rec_keepalive(const br_probe_record_t *r)
{
    if (r->cfg_active < 2u && r->cfg[r->cfg_active].config_id != 0u) {
        return r->cfg[r->cfg_active].keepalive_ms;
    }
    return (uint16_t)BR_KEEPALIVE_DEFAULT_MS;
}

static const br_mode_t *rec_cfg(const br_probe_record_t *r, uint8_t config_id)
{
    for (size_t i = 0; i < 2u; i++) {
        if (config_id != 0u && r->cfg[i].config_id == config_id) {
            return &r->cfg[i];
        }
    }
    return NULL;
}

static br_err_t prb_send_session(br_probe_record_t *r, br_sess_env_t *env, uint8_t type,
                                 const uint8_t *pt, size_t len)
{
    uint16_t seq = 0;
    uint32_t roc = 0;
    br_err_t rc = br_tx_index_next(&r->tx, &seq, &roc);
    if (rc != BR_OK) {
        return rc;
    }
    sess_tx_t t = { type, r->src_id, r->session_id, seq, false, roc, BR_DIR_FROM_PROBE, r->ke_p2s, 0u };
    r->last_tx_ms = env->now_ms;
    return sess_send(env, &t, pt, len, false);
}

static void prb_send_ack(br_probe_t *p, br_probe_record_t *r, br_sess_env_t *env)
{
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_ACK;
    if (r->stream != BR_NO_INDEX && r->stream < BR_RX_STREAMS) {
        br_arq_rx_t *rx = &p->streams[r->stream];
        (void)br_arq_rx_ack_fields(rx, &m.u.ack.cum_seq, &m.u.ack.bitmap);
        (void)br_arq_rx_ack_sent(rx);
    } else {
        m.u.ack.cum_seq = r->rx.s_l;
        m.u.ack.bitmap = 0u;
    }
    uint8_t pl[BR_LEN_ACK];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    (void)prb_send_session(r, env, (uint8_t)BR_TYPE_ACK, pl, n);
}

typedef struct {
    br_probe_t        *p;
    br_sess_env_t     *env;
    br_probe_record_t *r;
    uint16_t           cur_seq;
    uint32_t           cur_roc;
} prb_ctx_t;

static void prb_deliver_data(prb_ctx_t *cx, uint16_t seq, uint32_t roc, const uint8_t *pl, size_t len)
{
    br_probe_record_t *r = cx->r;
    if (!rec_bound(r) || len < BR_DATA_HDR_LEN) {
        return;
    }
    const br_mode_t *cfg = rec_cfg(r, pl[0]);
    br_data_hdr_t dh;
    if (cfg == NULL || br_data_hdr_decode(pl, len, cfg, &dh) != BR_OK) {
        return;
    }
    br_samples_meta_t meta;
    memset(&meta, 0, sizeof meta);
    meta.session = prb_handle(cx->p, r);
    meta.src_id = r->src_id;
    meta.session_id = r->session_id;
    meta.hops = r->hops;
    meta.seq = seq;
    meta.roc = roc;
    meta.hdr = dh;
    meta.utc_us = 0u;
    const br_app_callbacks_t *a = appcb(cx->env);
    if (a != NULL && a->on_samples != NULL) {
        a->on_samples(a->user, &meta, cfg, pl + BR_DATA_HDR_LEN, len - BR_DATA_HDR_LEN);
    }
}

static uint32_t rec_roc_for(const br_probe_record_t *r, uint16_t seq)
{
    uint32_t roc = (uint32_t)(r->rx.highest >> 16);
    if (seq > r->rx.s_l && roc > 0u) {
        roc--; /* drained seqs are at or below the highest index */
    }
    return roc;
}

static void prb_arq_deliver(void *user, uint16_t seq, const uint8_t *payload, uint8_t len)
{
    prb_ctx_t *cx = (prb_ctx_t *)user;
    prb_deliver_data(cx, seq, rec_roc_for(cx->r, seq), payload, len);
}

static void prb_arq_gap(void *user, uint16_t first, uint16_t count)
{
    prb_ctx_t *cx = (prb_ctx_t *)user;
    br_stats_inc(cx->env->stats, BR_STAT_GAPS);
    cb_gap(cx->env, prb_handle(cx->p, cx->r), first, count);
}

/*
 * SPEC-NOTES N46: the record's DATA floor (BR_PRB_DATA_BASE, a 16-bit seq) as
 * a 48-bit index: the floor is never above highest + 1 and never more than
 * 2^16 below it (a session cannot carry 65536 control frames between the
 * floor-raising MODE and the first DATA before SESSION_TIMEOUT closes it;
 * even then the replay window below bounds the seed).
 */
static uint64_t rec_data_base_index(const br_probe_record_t *r)
{
    uint64_t hi1 = r->rx.any != 0u ? r->rx.highest + 1u : 0u;
    uint64_t b = (hi1 & ~(uint64_t)0xFFFFu) | BR_PRB_DATA_BASE(r);
    if (b > hi1) {
        b = b >= 0x10000u ? b - 0x10000u : 0u;
    }
    return b;
}

/*
 * 4.1.12: a session with arq 1 or fec_m > 0 takes a stream at its first DATA.
 * The receive state starts from what the replay window already accepted
 * (MODE, PING ... since BIND_ACK; N23: index 0 first), so seqs consumed
 * before the stream existed are neither reported missing nor re-delivered.
 * SPEC-NOTES N46: holes below the DATA floor were control frames (already
 * reported through on_gap when the floor rose) and are not waited for.
 */
static void stream_seed(br_arq_rx_t *a, const br_probe_record_t *r, uint32_t now)
{
    const br_rx_index_t *ri = &r->rx;
    if (ri->any == 0u) {
        (void)br_arq_rx_init(a, 0u, now);
        return;
    }
    uint64_t hi = ri->highest;
    uint64_t lo = hi >= (BR_REPLAY_WINDOW - 1u) ? hi - (BR_REPLAY_WINDOW - 1u) : 0u;
    uint64_t first = hi + 1u;
    for (uint64_t i = lo; i <= hi; i++) {
        if (((ri->seen >> (hi - i)) & 1u) == 0u) {
            first = i;
            break;
        }
    }
    uint64_t base = rec_data_base_index(r);
    if (first < base) {
        first = base; /* N46: at most hi + 1 */
    }
    (void)br_arq_rx_init(a, (uint16_t)(first & 0xFFFFu), now); /* cum_seq = first - 1 */
    for (uint64_t j = first + 1u; j <= hi && j - first < BR_ACK_BITMAP_BITS; j++) {
        if (((ri->seen >> (hi - j)) & 1u) != 0u) {
            a->above |= 1u << (uint32_t)(j - first - 1u);
        }
    }
}

static void prb_take_stream(br_probe_t *p, br_probe_record_t *r, uint8_t config_id, uint32_t now)
{
    const br_mode_t *cfg = rec_cfg(r, config_id);
    if (r->stream != BR_NO_INDEX || cfg == NULL || (cfg->arq == 0u && cfg->fec_m == 0u)) {
        return;
    }
    int si = prb_free_stream(p);
    if (si < 0) {
        return; /* none left (4.1.12 gap, see report): delivered in arrival order without ARQ */
    }
    r->stream = (uint8_t)si;
    p->stream_owner[si] = (uint8_t)(r - p->rec);
    stream_seed(&p->streams[si], r, now);
}

/*
 * SPEC-NOTES N46: a MODE at index k whose config_id is the only config this
 * record holds (the session's first config, new or re-acked) proves that no
 * seq below k is DATA: the sender sends DATA only in STREAMING (4.1), which
 * it enters on the MODE_ACK of that config, and it stops resending the MODE
 * once it has that MODE_ACK (6.1), so every MODE of the first config was
 * sent before any DATA. The holes below k are lost control frames (MODE
 * retries, 3.5: each takes a new seq; or a PING). They are given up at
 * once: reported through on_gap (informational, counted in `gaps`) and the
 * DATA floor rises to k + 1 so the stream seeded at the first DATA does not
 * wait REORDER_MS for them. Holes below a MODE of any later config may be
 * DATA of the previous config still in flight (6.1: DATA keeps the old
 * config_id until MODE_ACK) and keep the section 7 wait (N35).
 */
static void prb_mode_raise_floor(prb_ctx_t *cx, uint8_t cid)
{
    br_probe_record_t *r = cx->r;
    for (size_t i = 0; i < 2u; i++) {
        if (r->cfg[i].config_id != 0u && r->cfg[i].config_id != cid) {
            return; /* another config is live: a hole below may be its DATA */
        }
    }
    uint64_t k = ((uint64_t)cx->cur_roc << 16) | cx->cur_seq;
    uint64_t base = rec_data_base_index(r);
    if (k < base) {
        return; /* an older copy than one already applied: nothing new below it */
    }
    if (r->stream != BR_NO_INDEX && r->stream < BR_RX_STREAMS) {
        br_arq_rx_give_up_below(&cx->p->streams[r->stream], cx->cur_seq, cx->env->now_ms, prb_arq_deliver,
                                prb_arq_gap, cx);
    } else {
        /* no stream yet: the holes are the unseen indices of the replay window in [base, k) */
        uint64_t hi = r->rx.highest; /* >= k: the MODE is committed */
        uint64_t lo = base;
        if (hi >= (BR_REPLAY_WINDOW - 1u) && lo < hi - (BR_REPLAY_WINDOW - 1u)) {
            lo = hi - (BR_REPLAY_WINDOW - 1u); /* older indices are unknown, not reported */
        }
        uint16_t first = 0;
        uint16_t count = 0;
        for (uint64_t i = lo; i < k; i++) {
            bool seen = ((r->rx.seen >> (hi - i)) & 1u) != 0u;
            if (!seen) {
                if (count == 0u) {
                    first = (uint16_t)(i & 0xFFFFu);
                }
                count++;
            } else if (count != 0u) {
                prb_arq_gap(cx, first, count);
                count = 0u;
            }
        }
        if (count != 0u) {
            prb_arq_gap(cx, first, count);
        }
    }
    if (rec_bound(r)) {
        BR_PRB_DATA_BASE(r) = (uint16_t)(cx->cur_seq + 1u);
    }
}

/* Non-mutating ARQ classification (br_arq_rx_on_frame() rules). */
static br_arq_rx_result_t arq_classify(const br_arq_rx_t *rx, uint16_t seq, bool is_data)
{
    uint16_t d = (uint16_t)(seq - rx->cum_seq);
    if (d == 0u || d >= 0x8000u || (d <= BR_ACK_BITMAP_BITS && ((rx->above >> (d - 1u)) & 1u) != 0u)) {
        return BR_ARQ_RX_DUP;
    }
    if (d > BR_ACK_BITMAP_BITS) {
        return BR_ARQ_RX_TOO_FAR;
    }
    if (d > 1u && is_data) {
        bool free_slot = false;
        for (size_t i = 0; i < BR_REORDER_SLOTS; i++) {
            free_slot = free_slot || rx->slot[i].used == 0u;
        }
        if (!free_slot) {
            return BR_ARQ_RX_TOO_FAR;
        }
    }
    return d == 1u ? BR_ARQ_RX_IN_ORDER : BR_ARQ_RX_BUFFERED;
}

static void prb_handle_mode(prb_ctx_t *cx, const uint8_t *pl, size_t n)
{
    br_probe_t *p = cx->p;
    br_probe_record_t *r = cx->r;
    br_sess_env_t *env = cx->env;
    br_mode_t md;
    uint8_t st = BR_MODE_ACK_BAD_ARG;
    br_err_t rc = br_mode_decode(pl, n, r->max_payload, env->caps, &md, &st);
    uint8_t cid = n >= 1u ? pl[0] : 0u;
    if (rc == BR_OK && st == BR_MODE_ACK_OK) {
        if (rec_cfg(r, md.config_id) == NULL) {
            /* new config: keep the last two (6.1) */
            uint8_t slot = (r->cfg_active == 0u) ? 1u : 0u;
            r->cfg[slot] = md;
            r->cfg_active = slot;
            br_session_t hd = prb_handle(p, r);
            if (r->state == BR_PRB_BOUND) {
                r->state = BR_PRB_STREAMING;
                cb_state(env, hd, BR_PRB_BOUND, BR_PRB_STREAMING);
            }
            const br_app_callbacks_t *a = appcb(env);
            if (a != NULL && a->on_mode != NULL && rec_bound(r)) {
                a->on_mode(a->user, hd, &r->cfg[slot]);
            }
            if (!rec_bound(r)) {
                return;
            }
        }
        /* a known config_id is re-acked without side effects */
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_MODE_ACK;
    m.u.mode_ack.config_id = cid;
    m.u.mode_ack.status = (rc == BR_OK) ? BR_MODE_ACK_OK : st;
    uint8_t out[BR_LEN_MODE_ACK];
    size_t w = 0;
    (void)br_msg_encode(&m, out, sizeof out, &w);
    (void)prb_send_session(r, env, (uint8_t)BR_TYPE_MODE_ACK, out, w);
    prb_mode_raise_floor(cx, cid); /* N46: holes below a first-config MODE are control gaps */
}

static br_err_t prb_rx_session(br_probe_t *p, br_sess_env_t *env, const br_rx_frame_t *f,
                               br_stat_id_t *drop_out)
{
    const br_hdr_t *h = &f->view->hdr;
    br_probe_record_t *r = (h->session_id != 0u) ? prb_find_session(p, h->src_id, h->session_id) : NULL;
    if (r == NULL || h->dst_id != env->self_id) {
        /* 4.1.13: unknown (src_id, session_id): dropped and counted (N27). The
         * bench CLOSE(2) reply is not sent: without the session keys it cannot
         * be authenticated, so the sender would drop it (see report). */
        set_drop(drop_out, BR_STAT_UNKNOWN_SESSION);
        return BR_OK;
    }
    uint32_t roc = 0;
    bool fresh = false;
    if (br_rx_index_check(&r->rx, h->seq, &roc, &fresh) != BR_OK) {
        set_drop(drop_out, BR_STAT_REPLAY_DROPPED);
        return BR_OK;
    }
    uint8_t plain[BR_PTBUF];
    size_t n = 0;
    if (sess_open(env, f, r->ke_s2p, BR_DIR_TO_PROBE, roc, 0u, plain, sizeof plain, &n) != BR_OK) {
        set_drop(drop_out, BR_STAT_AUTH_FAIL);
        return BR_OK;
    }
    bool is_data = (h->type == (uint8_t)BR_TYPE_DATA);
    bool ack_req = (h->flags & BR_FLAG_ACK_REQ) != 0u;
    if (is_data && fresh && n >= 1u) {
        prb_take_stream(p, r, plain[0], env->now_ms);
    }
    br_arq_rx_t *rx = (r->stream != BR_NO_INDEX && r->stream < BR_RX_STREAMS) ? &p->streams[r->stream] : NULL;
    br_arq_rx_result_t cls = BR_ARQ_RX_IN_ORDER;
    if (rx != NULL) {
        cls = arq_classify(rx, h->seq, is_data);
    }
    if (!fresh || cls == BR_ARQ_RX_DUP) {
        if (rx != NULL && cls == BR_ARQ_RX_DUP) {
            /* 8.4: a retransmission is dropped by the ARQ before the replay window */
            if (ack_req) {
                rx->ack_req_pending = 1u;
                r->last_rx_ms = env->now_ms;
                prb_send_ack(p, r, env);
            }
            return BR_OK;
        }
        set_drop(drop_out, BR_STAT_REPLAY_DROPPED);
        return BR_OK;
    }
    if (cls == BR_ARQ_RX_TOO_FAR) {
        return BR_OK; /* not committed: the sender's retransmission is accepted later */
    }
    /* per-type rows before the commit decide what is delivered */
    bool bad = false;
    if (is_data) {
        const br_mode_t *cfg = (n >= 1u) ? rec_cfg(r, plain[0]) : NULL;
        br_data_hdr_t dh;
        bad = cfg == NULL || br_data_hdr_decode(plain, n, cfg, &dh) != BR_OK;
    } else if (h->type == (uint8_t)BR_TYPE_PING) {
        bad = n != BR_LEN_PING;
    } else if (h->type == (uint8_t)BR_TYPE_CLOSE) {
        bad = n != BR_LEN_CLOSE;
    } else if (h->type == (uint8_t)BR_TYPE_PARITY) {
        bad = true; /* 3.6 PARITY row: idx < m == fec_m fails with fec_m 0 (no group FEC in phase 1b) */
    } else if (h->type != (uint8_t)BR_TYPE_MODE) {
        bad = true;
    }
    (void)br_rx_index_commit(&r->rx, h->seq, roc);
    r->last_rx_ms = env->now_ms;
    r->hops = f->hops;
    prb_ctx_t cx = { p, env, r, h->seq, roc };
    br_arq_rx_result_t res = BR_ARQ_RX_IN_ORDER;
    if (rx != NULL) {
        bool buffer_data = is_data && !bad;
        (void)br_arq_rx_on_frame(rx, h->seq, buffer_data, buffer_data ? plain : NULL,
                                 buffer_data ? (uint8_t)n : 0u, ack_req, env->now_ms, &res);
    }
    if (bad) {
        set_drop(drop_out, BR_STAT_BAD_FRAME);
    } else {
        switch (h->type) {
        case BR_TYPE_DATA:
            if (rx == NULL || res == BR_ARQ_RX_IN_ORDER) {
                prb_deliver_data(&cx, h->seq, roc, plain, n);
            }
            break;
        case BR_TYPE_MODE:
            prb_handle_mode(&cx, plain, n);
            break;
        case BR_TYPE_PING: {
            br_msg_t m;
            memset(&m, 0, sizeof m);
            m.type = BR_TYPE_PONG;
            m.u.pong.t_echo_us = br_rd_le32(plain);
            m.u.pong.t_local_us = env->now_ms * 1000u;
            uint8_t out[BR_LEN_PONG];
            size_t w = 0;
            (void)br_msg_encode(&m, out, sizeof out, &w);
            (void)prb_send_session(r, env, (uint8_t)BR_TYPE_PONG, out, w);
            break;
        }
        case BR_TYPE_CLOSE:
            prb_close_rec(p, env, r, plain[0]);
            return BR_OK;
        default:
            break;
        }
    }
    if (!rec_bound(r)) {
        return BR_OK; /* closed from a callback */
    }
    if (rx != NULL) {
        (void)br_arq_rx_drain(rx, env->now_ms, br_reorder_ms(&r->rtt), prb_arq_deliver, prb_arq_gap, &cx);
        if (!rec_bound(r)) {
            return BR_OK;
        }
        bool ack_due = false;
        (void)br_arq_rx_ack_due(rx, env->now_ms, r->last_tx_ms, rec_keepalive(r), &ack_due);
        if (ack_due) {
            prb_send_ack(p, r, env);
        }
    } else if (ack_req) {
        prb_send_ack(p, r, env);
    }
    return BR_OK;
}

br_err_t br_probe_rx(br_probe_t *p, br_sess_env_t *env, const br_rx_frame_t *f,
                     br_stat_id_t *drop_out)
{
    if (p == NULL || env == NULL || f == NULL || f->view == NULL || f->buf == NULL) {
        return BR_ERR_ARG;
    }
    set_drop(drop_out, BR_STAT_NONE);
    switch (f->view->hdr.type) {
    case BR_TYPE_SEEK:
        return prb_rx_seek(p, env, f, drop_out);
    case BR_TYPE_BIND:
        return prb_rx_bind(p, env, f, drop_out);
    case BR_TYPE_MODE:
    case BR_TYPE_DATA:
    case BR_TYPE_PARITY:
    case BR_TYPE_PING:
    case BR_TYPE_CLOSE:
        return prb_rx_session(p, env, f, drop_out);
    default:
        set_drop(drop_out, BR_STAT_BAD_FRAME);
        return BR_OK;
    }
}

br_err_t br_probe_tick(br_probe_t *p, br_sess_env_t *env, uint32_t *next_deadline_out)
{
    if (p == NULL || env == NULL || next_deadline_out == NULL) {
        return BR_ERR_ARG;
    }
    uint32_t now = env->now_ms;
    uint32_t next = now + BR_SESS_FAR_MS;
    /* offers: delayed HELLO (4.1.2), BIND_TIMEOUT expiry (4.1.7) */
    for (size_t i = 0; i < BR_PROBE_OFFERS_MAX; i++) {
        br_offer_t *o = &p->offers[i];
        if (o->src_id == 0u) {
            continue;
        }
        if (o->hello_sent == 0u && due(now, o->hello_due_ms)) {
            br_probe_record_t *same = prb_find_src(p, o->src_id);
            uint8_t st = prb_full(p, same, o->sender_caps) ? BR_HELLO_STATUS_FULL : BR_HELLO_STATUS_OK;
            uint32_t hc = 0;
            br_err_t rc = prb_send_hello(env, o->src_id, o->seek_e2e, o->seek_payload, o->nonce_p,
                                         o->path_mtu, o->cost, st, &hc, o->hello_plain);
            if (rc != BR_OK || st != BR_HELLO_STATUS_OK) {
                memset(o, 0, sizeof *o);
                continue;
            }
            o->hello_ctr = hc;
            o->hello_sent = 1u;
            o->expiry_ms = now + br_bind_timeout_ms(o->hops);
        }
        if (o->hello_sent != 0u && due(now, o->expiry_ms)) {
            memset(o, 0, sizeof *o); /* back to LISTENING for this sender (4.1.7) */
            continue;
        }
        next_min(now, &next, o->hello_sent != 0u ? o->expiry_ms : o->hello_due_ms);
    }
    /* records: reorder expiry, ACK cadence, SESSION_TIMEOUT (4.2, 7) */
    for (size_t i = 0; i < BR_RX_RECORDS; i++) {
        br_probe_record_t *r = &p->rec[i];
        if (!rec_bound(r)) {
            continue;
        }
        uint16_t ka = rec_keepalive(r);
        uint32_t to = br_session_timeout_ms(ka, &r->rtt);
        if (due(now, r->last_rx_ms + to)) {
            prb_close_rec(p, env, r, BR_CLOSE_TIMEOUT); /* frees the record and its stream */
            continue;
        }
        next_min(now, &next, r->last_rx_ms + to);
        if (r->stream == BR_NO_INDEX || r->stream >= BR_RX_STREAMS) {
            continue;
        }
        br_arq_rx_t *rx = &p->streams[r->stream];
        prb_ctx_t cx = { p, env, r, 0u, 0u };
        uint32_t rms = br_reorder_ms(&r->rtt);
        (void)br_arq_rx_drain(rx, now, rms, prb_arq_deliver, prb_arq_gap, &cx);
        if (!rec_bound(r)) {
            continue;
        }
        bool ack_due = false;
        (void)br_arq_rx_ack_due(rx, now, r->last_tx_ms, ka, &ack_due);
        if (ack_due) {
            prb_send_ack(p, r, env);
        }
        if (rx->above != 0u) {
            next_min(now, &next, rx->hole_since_ms + rms);
        }
        if (rx->since_ack > 0u) {
            next_min(now, &next, r->last_tx_ms + ka);
        }
    }
    *next_deadline_out = next;
    return BR_OK;
}

br_err_t br_probe_close(br_probe_t *p, br_sess_env_t *env, uint8_t idx, uint8_t reason)
{
    if (p == NULL || env == NULL || idx >= BR_RX_RECORDS) {
        return BR_ERR_ARG;
    }
    br_probe_record_t *r = &p->rec[idx];
    if (!rec_bound(r)) {
        return BR_ERR_STATE;
    }
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_CLOSE;
    m.u.close.reason = reason;
    uint8_t pl[BR_LEN_CLOSE];
    size_t n = 0;
    (void)br_msg_encode(&m, pl, sizeof pl, &n);
    (void)prb_send_session(r, env, (uint8_t)BR_TYPE_CLOSE, pl, n);
    prb_close_rec(p, env, r, reason);
    return BR_OK;
}
