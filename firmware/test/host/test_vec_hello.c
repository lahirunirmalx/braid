// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_vec_hello.c - A.9 HELLO bytes from the code against BRV_A9_HELLO_*
 * (SPEC-NOTES N32: HELLO carries the SEEK copy's path_cost as received).
 *
 * Layer A: the A.9 field values through br_msg_encode(), the session key
 * schedule (K_site -> PRK -> T0 -> Ke_hello), br_ccm_encrypt(), br_hop_tag()
 * and br_frame_seal_crc() must give BRV_A9_HELLO_PAYLOAD and the full 61-byte
 * BRV_A9_HELLO_FRAME.
 *
 * Layer B: a real br_node_t probe (0x0042, group 0xFF01, A.6 test K_site,
 * epoch 1, preseq 0x00010007, txseq 3) receives the A.8 hop-2 SEEK copy
 * (relay 0x0099, path_cost 1, 2 links) and emits its HELLO. The live frame
 * must match BRV_A9_HELLO_HEADER and the clear pre_ctr byte for byte, and the
 * decrypted secret must match BRV_A9_HELLO_SECRET except three fields the
 * stack cannot be made to produce:
 *   - nonce_p (secret offsets 8..11): drawn through the node's 4.1.14 nonce
 *     hash (SHA-256 of RNG output, counters, unit ID, time), so the vector's
 *     0x0BADF00D cannot be injected; checked equal to the offer's nonce_p;
 *   - rssi (secret offset 16): -128 until carriers report RSSI per offer
 *     (SPEC-NOTES N41); the vector has -61;
 *   - fw_build (secret offsets 20..23): br_node_config_t has no fw_build, the
 *     node sends 0; the vector has 2.
 * path_cost (secret offset 18) must be 1, the field as received (N32); the
 * pre-N32 code sent 2 (field + link cost). Then the three masked fields are
 * set to the vector values, the frame is re-sealed with the same primitives
 * the node uses, and the result must equal BRV_A9_HELLO_FRAME in full: every
 * other byte (header, per-hop fields, hop_seq, clear pre_ctr, seek_ctr,
 * nonce_s, caps, max_frame, status, cost, minor) comes from the live stack.
 *
 * Layer C: a cheaper direct copy (A.8 hop 1, path_cost 0) arriving inside the
 * window moves the offer to the direct link (br_probe_offer_copy) and the
 * HELLO then reports path_cost 0, again the field as received.
 *
 * Platform: virtual clock and a constant RNG (0d f0 ad 0b repeated), so the
 * run is deterministic.
 */
#include "braid/br_crc16.h"
#include "braid/br_crypto.h"
#include "braid/br_frame.h"
#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_session.h"
#include "test_util.h"
#include "vectors_generated.h"

#define HELLO_LEN       BRV_A9_HELLO_FRAME_LEN /* 61 */
#define SECRET_NONCE_P   8u
#define SECRET_RSSI     16u
#define SECRET_COST     18u
#define SECRET_FW       20u

/* ------------------------------------------------------------------------- */
/* Platform and transport doubles                                             */
/* ------------------------------------------------------------------------- */

static uint64_t g_now_us = 1000000u;

static uint64_t t_now(void *user)
{
    (void)user;
    return g_now_us;
}

static br_err_t t_random(void *user, uint8_t *buf, size_t len)
{
    static const uint8_t pat[4] = {0x0d, 0xf0, 0xad, 0x0b};
    (void)user;
    for (size_t i = 0; i < len; i++) {
        buf[i] = pat[i % 4u];
    }
    return BR_OK;
}

static void t_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    (void)user;
    (void)level;
    (void)tag;
    (void)msg;
}

typedef struct {
    uint8_t  frame[BR_MAX_FRAME_MESH];
    uint16_t len;
    uint8_t  addr[6];
    bool     unicast;
} tx_rec_t;

#define TX_MAX 8u
static tx_rec_t g_tx[TX_MAX];
static unsigned g_ntx;

static br_err_t t_send(void *user, const uint8_t *addr, const uint8_t *frame, uint16_t len)
{
    (void)user;
    if (g_ntx < TX_MAX && len <= BR_MAX_FRAME_MESH) {
        tx_rec_t *r = &g_tx[g_ntx];
        memcpy(r->frame, frame, len);
        r->len = len;
        r->unicast = addr != NULL;
        if (addr != NULL) {
            memcpy(r->addr, addr, 6);
        }
    }
    g_ntx++;
    return BR_OK;
}

static const uint8_t MAC_R[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x99};
static const uint8_t MAC_S[6] = {0x02, 0x00, 0x00, 0x00, 0x12, 0x34};

static br_node_t g_node;

static bool probe_init(void)
{
    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = 0x0042;
    c.role = BR_ROLE_LEAF; /* no 9f rebroadcast: the HELLO takes txseq 3 */
    c.node_count = 3;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = 0x003Bu; /* HIGH | LOW | AUTH | FEC | RELAY, as in A.9 */
    c.auth = true;
    c.cold_boot = false;
    c.groups[0] = 0xFF01; /* A.8 SEEK dst_id */
    c.n_groups = 1;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE;
    c.net_key_len = BRV_A6_K_SITE_LEN;
    c.n_transports = 1;
    c.transports[0].name = "test";
    c.transports[0].link_class = BR_LINK_PACKET;
    c.transports[0].max_frame = BR_MAX_FRAME_MESH;
    c.transports[0].rs_nsym = 0;
    c.transports[0].can_broadcast = true;
    c.transports[0].mac_retry = true;
    c.transports[0].link_cost = 1;
    c.transports[0].addr_len = 6;
    c.transports[0].send = t_send;
    c.txseq_start = 3;
    c.preseq_start = 0x00010007u;
    memset(&g_node, 0, sizeof g_node);
    g_ntx = 0;
    br_err_t rc = br_node_init(&g_node, sizeof g_node, &c);
    CHECK_ERR(rc, BR_OK);
    return rc == BR_OK;
}

static void probe_rx(const uint8_t *frame, size_t len, const uint8_t mac[6], int8_t rssi)
{
    br_rx_meta_t m;
    memset(&m, 0, sizeof m);
    memcpy(m.addr, mac, 6);
    m.addr_len = 6;
    m.rssi = rssi;
    br_rx_verdict_t v;
    CHECK_ERR(br_node_rx(&g_node, frame, len, 0, &m, &v), BR_OK);
    CHECK(v.action == BR_RXV_DELIVER || v.action == BR_RXV_DELIVER_FLOOD);
}

static void probe_run_ms(uint32_t ms)
{
    uint64_t end = g_now_us + (uint64_t)ms * 1000u;
    while (g_now_us < end) {
        g_now_us += 1000u;
        uint64_t next = 0;
        CHECK_ERR(br_node_tick(&g_node, g_now_us, &next), BR_OK);
    }
}

/* Index of the single HELLO in g_tx, or -1. */
static int find_hello(void)
{
    int idx = -1;
    unsigned n = g_ntx < TX_MAX ? g_ntx : TX_MAX;
    for (unsigned i = 0; i < n; i++) {
        if (g_tx[i].len > 1u && g_tx[i].frame[1] == BR_TYPE_HELLO) {
            CHECK_MSG(idx < 0, "more than one HELLO sent");
            idx = (int)i;
        }
    }
    return idx;
}

/* ------------------------------------------------------------------------- */
/* Sealing helper: header + clear || secret -> full frame (same steps as the  */
/* node: CCM under Ke_hello, hop_tag under K_hop(1), CRC)                     */
/* ------------------------------------------------------------------------- */

static br_crypto_t C;

static void seal_hello(const uint8_t hdr[BR_HDR_LEN], const uint8_t clear[4], const uint8_t secret[24],
                       uint8_t out[HELLO_LEN])
{
    memcpy(out, hdr, BR_HDR_LEN);
    memcpy(out + BR_HDR_LEN, clear, 4);
    uint32_t pre = br_rd_le32(clear);
    uint8_t nonce[BR_CCM_NONCE_LEN];
    CHECK_ERR(br_ccm_nonce(BR_DIR_FROM_PROBE, br_rd_le16(hdr + 2), br_rd_le16(hdr + 4), 0, pre >> 16,
                           br_rd_le16(hdr + BR_OFF_SEQ), nonce),
              BR_OK);
    uint8_t aad[BR_AAD_MAX_LEN];
    size_t al = 0;
    CHECK_ERR(br_ccm_aad(out, BR_HDR_LEN + 4u, pre >> 16, 4, aad, sizeof aad, &al), BR_OK);
    CHECK_ERR(br_ccm_encrypt(&C, BRV_A9_KE_HELLO, nonce, aad, al, secret, 24, out + BR_HDR_LEN + 4u,
                             out + BR_HDR_LEN + 28u),
              BR_OK);
    CHECK_ERR(br_hop_tag(&C, BRV_A6_K_HOP_1, out, BR_HDR_LEN + 28u + BR_AUTH_TAG_LEN,
                         out + BR_HDR_LEN + 28u + BR_AUTH_TAG_LEN),
              BR_OK);
    size_t total = 0;
    CHECK_ERR(br_frame_seal_crc(out, HELLO_LEN - BR_CRC_LEN, HELLO_LEN, &total), BR_OK);
    CHECK_EQ_U32(total, HELLO_LEN);
}

/* Decrypt a live HELLO; returns false if the tag does not verify. */
static bool open_hello(const uint8_t *f, size_t len, uint8_t secret[24])
{
    CHECK_EQ_U32(len, HELLO_LEN);
    if (len != HELLO_LEN) {
        return false;
    }
    uint32_t pre = br_rd_le32(f + BR_HDR_LEN);
    uint8_t nonce[BR_CCM_NONCE_LEN];
    CHECK_ERR(br_ccm_nonce(BR_DIR_FROM_PROBE, br_rd_le16(f + 2), br_rd_le16(f + 4), 0, pre >> 16,
                           br_rd_le16(f + BR_OFF_SEQ), nonce),
              BR_OK);
    uint8_t aad[BR_AAD_MAX_LEN];
    size_t al = 0;
    CHECK_ERR(br_ccm_aad(f, len, pre >> 16, 4, aad, sizeof aad, &al), BR_OK);
    br_err_t rc = br_ccm_decrypt(&C, BRV_A9_KE_HELLO, nonce, aad, al, f + BR_HDR_LEN + 4u, 24,
                                 f + BR_HDR_LEN + 28u, secret);
    CHECK_ERR(rc, BR_OK);
    CHECK_ERR(br_hop_tag_verify(&C, BRV_A6_K_HOP_1, f, BR_HDR_LEN + 28u + BR_AUTH_TAG_LEN,
                                f + BR_HDR_LEN + 28u + BR_AUTH_TAG_LEN),
              BR_OK);
    uint16_t crc = 0;
    CHECK_ERR(br_crc16(f, len - BR_CRC_LEN, &crc), BR_OK);
    CHECK_EQ_U32(crc, br_rd_le16(f + len - BR_CRC_LEN));
    return rc == BR_OK;
}

/* ------------------------------------------------------------------------- */
/* Layer A                                                                    */
/* ------------------------------------------------------------------------- */

static void test_layer_a_codec(void)
{
    tu_ctx("A: br_msg_encode + key schedule + seal");
    br_msg_t m;
    memset(&m, 0, sizeof m);
    m.type = BR_TYPE_HELLO;
    m.u.hello.pre_ctr = 0x00010007u;
    m.u.hello.seek_ctr = 0x00010001u;
    m.u.hello.nonce_s = 0xA1B2C3D4u;
    m.u.hello.nonce_p = 0x0BADF00Du;
    m.u.hello.caps = 0x003Bu;
    m.u.hello.max_frame = 250u;
    m.u.hello.rssi = -61;
    m.u.hello.status = BR_HELLO_STATUS_OK;
    m.u.hello.path_cost = 1u;
    m.u.hello.proto_minor = 0u;
    m.u.hello.fw_build = 2u;
    uint8_t pl[BR_LEN_HELLO];
    size_t n = 0;
    CHECK_ERR(br_msg_encode(&m, pl, sizeof pl, &n), BR_OK);
    CHECK_EQ_U32(n, BR_LEN_HELLO);
    CHECK_MEM(BRV_A9_HELLO_CLEAR, pl, 4);
    CHECK_MEM(BRV_A9_HELLO_SECRET, pl + 4, 24);

    /* Ke_hello the way prb_send_hello() derives it */
    br_keyring_t kr;
    CHECK_ERR(br_keyring_init_bench(&C, &kr, BRV_A6_K_SITE, BRV_A6_K_SITE_LEN, 1), BR_OK);
    uint8_t prk[BR_KEY_LEN], t0[BR_KEY_LEN], ke[BR_AES_KEY_LEN];
    CHECK_ERR(br_ks_pair_prk(&C, &kr, 0x1234, 0x0042, prk), BR_OK);
    CHECK_MEM(BRV_A6_PRK, prk, 32);
    uint8_t seek_e2e[BR_E2E_HDR_LEN];
    memcpy(seek_e2e, BRV_A8_SEEK_HOP2_FRAME, 6);
    seek_e2e[6] = BRV_A8_SEEK_HOP2_FRAME[BR_OFF_SESSION_ID_SEEK];
    memcpy(seek_e2e + 7, BRV_A8_SEEK_HOP2_FRAME + BR_OFF_SEQ_SEEK, 2);
    seek_e2e[9] = BRV_A8_SEEK_HOP2_FRAME[BR_OFF_LEN_SEEK];
    CHECK_ERR(br_ks_t0(seek_e2e, BRV_A8_SEEK_HOP2_FRAME + BR_HDR_LEN_SEEK, t0), BR_OK);
    CHECK_MEM(BRV_A9_T0, t0, 32);
    CHECK_ERR(br_ks_hello(&C, prk, 0x1234, 0x0042, t0, ke), BR_OK);
    CHECK_MEM(BRV_A9_KE_HELLO, ke, 16);
    br_keyring_wipe(&kr);

    uint8_t frame[HELLO_LEN];
    seal_hello(BRV_A9_HELLO_HEADER, pl, pl + 4, frame);
    CHECK_MEM(BRV_A9_HELLO_PAYLOAD, frame + BR_HDR_LEN, BRV_A9_HELLO_PAYLOAD_LEN);
    CHECK_MEM(BRV_A9_HELLO_TAG, frame + BR_HDR_LEN + 28u, 8);
    CHECK_MEM(BRV_A9_HELLO_FRAME, frame, BRV_A9_HELLO_FRAME_LEN);
}

/* ------------------------------------------------------------------------- */
/* Layer B                                                                    */
/* ------------------------------------------------------------------------- */

static void test_layer_b_live_probe(void)
{
    tu_ctx("B: live probe HELLO for the A.8 hop-2 SEEK");
    if (!probe_init()) {
        return;
    }
    probe_rx(BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, MAC_R, -61);
    CHECK_EQ_U32(g_ntx, 0u); /* LEAF: no rebroadcast; HELLO is delayed */
    probe_run_ms(BR_HELLO_WINDOW_MS + 10u);
    int i = find_hello();
    CHECK_MSG(i >= 0, "no HELLO sent");
    if (i < 0) {
        br_node_deinit(&g_node);
        return;
    }
    const tx_rec_t *r = &g_tx[i];
    CHECK(r->unicast);
    CHECK_MEM(MAC_R, r->addr, 6); /* reverse route via relay 0x0099 */
    CHECK_EQ_U32(r->len, HELLO_LEN);
    /* header (e2e + per-hop: prev 0x0042, next 0x0099, ttl 4 / hops 0, hop_seq 3, seq 7, len 28) */
    CHECK_MEM(BRV_A9_HELLO_HEADER, r->frame, BR_HDR_LEN);
    CHECK_MEM(BRV_A9_HELLO_CLEAR, r->frame + BR_HDR_LEN, 4);

    uint8_t secret[24];
    if (!open_hello(r->frame, r->len, secret)) {
        br_node_deinit(&g_node);
        return;
    }
    /* N32: path_cost as received (1), not field + link cost (2) */
    CHECK_EQ_U32(secret[SECRET_COST], 1u);
    /* the two fields the stack cannot produce yet (see file header) */
    CHECK_EQ_U32(secret[SECRET_RSSI], 0x80u); /* -128, N41 */
    CHECK_EQ_U32(br_rd_le32(secret + SECRET_FW), 0u);
    CHECK_EQ_U32(g_node.probe.offers[0].src_id, 0x1234u);
    CHECK_EQ_U32(br_rd_le32(secret + SECRET_NONCE_P), g_node.probe.offers[0].nonce_p);
    uint8_t masked_live[24], masked_vec[24];
    memcpy(masked_live, secret, 24);
    memcpy(masked_vec, BRV_A9_HELLO_SECRET, 24);
    memset(masked_live + SECRET_NONCE_P, 0, 4);
    memset(masked_vec + SECRET_NONCE_P, 0, 4);
    masked_live[SECRET_RSSI] = masked_vec[SECRET_RSSI] = 0;
    memset(masked_live + SECRET_FW, 0, 4);
    memset(masked_vec + SECRET_FW, 0, 4);
    CHECK_MEM(masked_vec, masked_live, 24);

    /* set nonce_p / rssi / fw_build to the vector values and re-seal: full frame match */
    memcpy(secret + SECRET_NONCE_P, BRV_A9_HELLO_SECRET + SECRET_NONCE_P, 4);
    secret[SECRET_RSSI] = BRV_A9_HELLO_SECRET[SECRET_RSSI];
    memcpy(secret + SECRET_FW, BRV_A9_HELLO_SECRET + SECRET_FW, 4);
    uint8_t resealed[HELLO_LEN];
    seal_hello(r->frame, r->frame + BR_HDR_LEN, secret, resealed);
    CHECK_MEM(BRV_A9_HELLO_PAYLOAD, resealed + BR_HDR_LEN, BRV_A9_HELLO_PAYLOAD_LEN);
    CHECK_MEM(BRV_A9_HELLO_FRAME, resealed, BRV_A9_HELLO_FRAME_LEN);

    /* the offer keeps the as-received value too */
    CHECK_EQ_U32(g_node.probe.offers[0].cost, 1u);
    CHECK_EQ_U32(g_node.probe.offers[0].hops, 2u);
    br_node_deinit(&g_node);
}

/* ------------------------------------------------------------------------- */
/* Layer C                                                                    */
/* ------------------------------------------------------------------------- */

static void test_layer_c_cheaper_copy(void)
{
    tu_ctx("C: cheaper direct copy inside the window");
    if (!probe_init()) {
        return;
    }
    probe_rx(BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, MAC_R, -61);
    probe_run_ms(5u);
    /* the same SEEK straight from S: path_cost 0 + link 1 = 1 < 1 + 1 */
    br_rx_meta_t m;
    memset(&m, 0, sizeof m);
    memcpy(m.addr, MAC_S, 6);
    m.addr_len = 6;
    m.rssi = -61;
    br_rx_verdict_t v;
    CHECK_ERR(br_node_rx(&g_node, BRV_A8_SEEK_HOP1_FRAME, BRV_A8_SEEK_HOP1_FRAME_LEN, 0, &m, &v), BR_OK);
    CHECK_EQ_U32(g_node.probe.offers[0].cost, 0u);
    CHECK_EQ_U32(g_node.probe.offers[0].hops, 1u);
    CHECK_EQ_U32(g_node.probe.offers[0].prev_hop, 0x1234u);
    probe_run_ms(BR_HELLO_WINDOW_MS + 10u);
    int i = find_hello();
    CHECK_MSG(i >= 0, "no HELLO sent");
    if (i >= 0) {
        const tx_rec_t *r = &g_tx[i];
        CHECK(r->unicast);
        CHECK_MEM(MAC_S, r->addr, 6);
        CHECK_EQ_U32(br_rd_le16(r->frame + BR_OFF_NEXT_HOP), 0x1234u);
        uint8_t secret[24];
        if (open_hello(r->frame, r->len, secret)) {
            CHECK_EQ_U32(secret[SECRET_COST], 0u);
        }
    }
    br_node_deinit(&g_node);
}

int main(void)
{
    const br_platform_t plat = {t_now, t_random, t_log, NULL};
    CHECK_ERR(br_platform_set(&plat), BR_OK);
    CHECK_ERR(br_crypto_init(&C), BR_OK);
    test_layer_a_codec();
    test_layer_b_live_probe();
    test_layer_c_cheaper_copy();
    br_crypto_free(&C);
    return tu_summary("test_vec_hello");
}
