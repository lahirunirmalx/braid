// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_frame.c - frame header codec, frame encoder and the stateless receive
 * validator (spec 3, 3.5, 3.6; SPEC-NOTES N1-N6, N8, N12; Appendix A.2-A.15).
 *
 * The expected reject reason for every case is stated here from the spec text
 * and is also cross-checked against the independent reference validator in
 * test_util.h (tu_ref_validate) so a typo in an expectation cannot go unseen.
 */
#include "braid/br_frame.h"
#include "test_util.h"
#include "test_vectab.h"

/* ------------------------------------------------------------------------- */
/* helpers                                                                    */
/* ------------------------------------------------------------------------- */

#define BUFSZ 420

static const tu_link_t LK_PKT = {250, 0};
static const tu_link_t LK_UART = {250, 8};
static const tu_link_t LK_IR = {80, 6};

/** Validate and compare rc + reason with the expectation. */
static void expect_rej(const char *file, int line, const uint8_t *buf, size_t len, tu_link_t lk,
                       bool endpoint, br_reject_t expect)
{
    br_link_params_t lp = {lk.max_frame, lk.rs_nsym};
    uint8_t *d = tu_dup(buf, len);
    br_reject_t r = (br_reject_t)99;
    br_frame_view_t view;
    memset(&view, 0, sizeof view);
    br_err_t rc = br_frame_validate(d, len, &lp, endpoint, &view, &r);
    br_err_t want_rc = (expect == BR_REJ_NONE) ? BR_OK : BR_ERR_REJECT;
    tu_checks += 2;
    if (rc != want_rc || r != expect) {
        if (tu_begin_fail(file, line)) {
            fprintf(stderr, "validate: rc %s reason %s, expected rc %s reason %s (len %zu, link %u/%u, %s)\n",
                    tu_err_name((int)rc), tu_rej_name((int)r), tu_err_name((int)want_rc), tu_rej_name((int)expect),
                    len, lk.max_frame, lk.rs_nsym, endpoint ? "endpoint" : "forwarder");
        }
    }
    /* the independent oracle must agree with the stated expectation */
    tu_checks++;
    br_reject_t oracle = tu_map_reason(tu_ref_validate(buf, len, &lk, endpoint));
    if (oracle != expect) {
        if (tu_begin_fail(file, line)) {
            fprintf(stderr, "TEST BUG: reference validator says %s, test expects %s\n", tu_rej_name((int)oracle),
                    tu_rej_name((int)expect));
        }
    }
    free(d);
}
#define EXPECT(buf, len, lk, ep, reason) expect_rej(__FILE__, __LINE__, (buf), (len), (lk), (ep), (reason))

static tu_ref_hdr_t hdr_for(uint8_t type, uint8_t flags)
{
    tu_ref_hdr_t h;
    tu_ref_default_hdr(&h, type);
    h.flags = flags;
    if (type == 0x01) {
        h.session_id = 0;
        h.seq = 1;
        h.dst = 0xFF01;
        h.next = 0xFFFF;
        h.path_mtu = 242;
    }
    return h;
}

/** Build a frame with an 0x5A-filled payload. */
static size_t build(uint8_t *out, uint8_t type, uint8_t flags, size_t plen, unsigned nsym)
{
    tu_ref_hdr_t h = hdr_for(type, flags);
    uint8_t pl[256];
    memset(pl, 0x5A, sizeof pl);
    return tu_ref_build(&h, pl, plen, NULL, nsym, out);
}

enum { F_TTL, F_HOPS, F_PREV, F_SRC, F_NEXT, F_DST, F_MTU, F_COST, F_VER };

/** Overwrite one header field in place and re-seal CRC + RS parity. */
static void mut(uint8_t *b, size_t len, unsigned nsym, int field, uint32_t v)
{
    switch (field) {
    case F_TTL: b[10] = (uint8_t)((b[10] & 0x0Fu) | ((v & 0x0Fu) << 4)); break;
    case F_HOPS: b[10] = (uint8_t)((b[10] & 0xF0u) | (v & 0x0Fu)); break;
    case F_PREV: tu_put16(b + 6, (uint16_t)v); break;
    case F_SRC: tu_put16(b + 2, (uint16_t)v); break;
    case F_NEXT: tu_put16(b + 8, (uint16_t)v); break;
    case F_DST: tu_put16(b + 4, (uint16_t)v); break;
    case F_MTU: tu_put16(b + 15, (uint16_t)v); break;
    case F_COST: b[17] = (uint8_t)v; break;
    case F_VER: b[0] = (uint8_t)((b[0] & 0x0Fu) | ((v & 0x0Fu) << 4)); break;
    default: break;
    }
    tu_ref_seal(b, len, nsym);
}

/* ------------------------------------------------------------------------- */
/* LE helpers, header codec                                                   */
/* ------------------------------------------------------------------------- */

static void test_le_helpers(void)
{
    tu_ctx("LE helpers");
    uint8_t b[16];
    for (unsigned i = 0; i < 16; i++) {
        b[i] = (uint8_t)(0x10u + i);
    }
    for (unsigned off = 0; off < 9; off++) { /* every alignment */
        CHECK_EQ_U32(br_rd_le16(b + off), (uint32_t)(b[off] | (b[off + 1] << 8)));
        CHECK_EQ_U32(br_rd_le32(b + off), tu_get32(b + off));
    }
    uint8_t w[12] = {0};
    br_wr_le16(w + 1, 0xBEEF);
    CHECK_EQ_U32(w[1], 0xEFu);
    CHECK_EQ_U32(w[2], 0xBEu);
    CHECK_EQ_U32(w[0], 0u);
    CHECK_EQ_U32(w[3], 0u);
    br_wr_le32(w + 3, 0x01020304u);
    CHECK_EQ_U32(w[3], 4u);
    CHECK_EQ_U32(w[4], 3u);
    CHECK_EQ_U32(w[5], 2u);
    CHECK_EQ_U32(w[6], 1u);
    CHECK_EQ_U32(w[7], 0u);
}

static void test_hdr_len(void)
{
    tu_ctx("hdr_len_for_type");
    for (unsigned t = 0; t < 256; t++) {
        CHECK_EQ_U32(br_hdr_len_for_type((uint8_t)t), t == 0x01u ? 22u : 19u); /* N12 */
    }
    CHECK_EQ_U32(BR_HDR_LEN, 19u);
    CHECK_EQ_U32(BR_HDR_LEN_SEEK, 22u);
    CHECK_EQ_U32(BR_FIXED_OVERHEAD, 21u);
}

static void test_a2_fields(void)
{
    tu_ctx("A.2 SEEK header fields");
    br_hdr_t h;
    size_t hl = 0;
    CHECK_ERR(br_hdr_decode(BRV_A2_FRAME, BRV_A2_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(hl, 22u);
    CHECK_EQ_U32(h.version, 1u);
    CHECK_EQ_U32(h.flags, 0u);
    CHECK_EQ_U32(h.type, BR_TYPE_SEEK);
    CHECK_EQ_U32(h.src_id, 0x1234u);
    CHECK_EQ_U32(h.dst_id, 0xFF01u);
    CHECK_EQ_U32(h.prev_hop, 0x1234u);
    CHECK_EQ_U32(h.next_hop, 0xFFFFu);
    CHECK_EQ_U32(h.ttl, 4u);
    CHECK_EQ_U32(h.hops, 0u);
    CHECK_EQ_U32(h.hop_seq, 1u);
    CHECK_EQ_U32(h.path_mtu, 250u);
    CHECK_EQ_U32(h.path_cost, 0u);
    CHECK_EQ_U32(h.session_id, 0u);
    CHECK_EQ_U32(h.seq, 1u);
    CHECK_EQ_U32(h.len, 18u);

    tu_ctx("A.8 SEEK hop 2 fields");
    CHECK_ERR(br_hdr_decode(BRV_A8_SEEK_HOP2_FRAME, BRV_A8_SEEK_HOP2_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(h.flags, BR_FLAG_AUTH);
    CHECK_EQ_U32(h.prev_hop, 0x0099u);
    CHECK_EQ_U32(h.ttl, 3u);
    CHECK_EQ_U32(h.hops, 1u);
    CHECK_EQ_U32(h.hop_seq, 0x00010130u);
    CHECK_EQ_U32(h.path_mtu, 250u);
    CHECK_EQ_U32(h.path_cost, 1u);

    tu_ctx("A.7 DATA header fields");
    CHECK_ERR(br_hdr_decode(BRV_A7_FRAME, BRV_A7_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(hl, 19u);
    CHECK_EQ_U32(h.type, BR_TYPE_DATA);
    CHECK_EQ_U32(h.src_id, 0x1234u);
    CHECK_EQ_U32(h.dst_id, 0x0042u);
    CHECK_EQ_U32(h.prev_hop, 0x1234u); /* a direct link is a one-hop route */
    CHECK_EQ_U32(h.next_hop, 0x0042u);
    CHECK_EQ_U32(h.hop_seq, 9u);
    CHECK_EQ_U32(h.session_id, 7u);
    CHECK_EQ_U32(h.seq, 5u);
    CHECK_EQ_U32(h.len, 11u);
    CHECK_EQ_U32(h.path_mtu, 0u); /* only SEEK carries these */
    CHECK_EQ_U32(h.path_cost, 0u);

    tu_ctx("A.10 DATA hop_seq");
    CHECK_ERR(br_hdr_decode(BRV_A10_DATA_ROC1_FRAME, BRV_A10_DATA_ROC1_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(h.hop_seq, 0x2345u);
    tu_ctx("A.8 DATA hop 2 fields");
    CHECK_ERR(br_hdr_decode(BRV_A8_DATA_HOP2_FRAME, BRV_A8_DATA_HOP2_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(h.hop_seq, 0x00010131u);
    CHECK_EQ_U32(h.ttl, 3u);
    CHECK_EQ_U32(h.hops, 1u);
    CHECK_EQ_U32(h.prev_hop, 0x0099u);
    CHECK_EQ_U32(h.next_hop, 0x0042u);
    tu_ctx("A.11 RESUME fields");
    CHECK_ERR(br_hdr_decode(BRV_A11_RESUME_FRAME, BRV_A11_RESUME_FRAME_LEN, &h, &hl), BR_OK);
    CHECK_EQ_U32(h.type, BR_TYPE_RESUME);
    CHECK_EQ_U32(h.next_hop, 0xFFFFu);
    CHECK_EQ_U32(h.hop_seq, 0x4000u);
    CHECK_EQ_U32(h.seq, 0x0042u);
    CHECK_EQ_U32(h.len, 5u);
}

static void test_hdr_codec_args(void)
{
    tu_ctx("hdr codec args");
    br_hdr_t h;
    size_t hl = 0;
    uint8_t buf[32];
    memset(buf, 0, sizeof buf);
    buf[0] = 0x12;
    buf[1] = 0x10;
    CHECK_ERR(br_hdr_decode(NULL, 19, &h, &hl), BR_ERR_ARG);
    CHECK_ERR(br_hdr_decode(buf, 19, NULL, &hl), BR_ERR_ARG);
    CHECK_ERR(br_hdr_decode(buf, 19, &h, NULL), BR_ERR_ARG);
    CHECK_ERR(br_hdr_decode(buf, 0, &h, &hl), BR_ERR_DECODE);
    CHECK_ERR(br_hdr_decode(buf, 1, &h, &hl), BR_ERR_DECODE);
    CHECK_ERR(br_hdr_decode(buf, 2, &h, &hl), BR_ERR_DECODE);
    CHECK_ERR(br_hdr_decode(buf, 18, &h, &hl), BR_ERR_DECODE);
    CHECK_ERR(br_hdr_decode(buf, 19, &h, &hl), BR_OK);
    CHECK_EQ_U32(hl, 19u);
    buf[1] = 0x01; /* SEEK needs 22 */
    CHECK_ERR(br_hdr_decode(buf, 21, &h, &hl), BR_ERR_DECODE);
    CHECK_ERR(br_hdr_decode(buf, 22, &h, &hl), BR_OK);
    CHECK_EQ_U32(hl, 22u);
    /* unknown types use the 19-byte header; reserved flag bits are preserved */
    buf[0] = 0xFF;
    buf[1] = 0xEE;
    CHECK_ERR(br_hdr_decode(buf, 19, &h, &hl), BR_OK);
    CHECK_EQ_U32(hl, 19u);
    CHECK_EQ_U32(h.version, 0x0Fu);
    CHECK_EQ_U32(h.flags, 0x0Fu);
    CHECK_EQ_U32(h.type, 0xEEu);

    /* encode */
    br_hdr_t e;
    memset(&e, 0, sizeof e);
    e.version = 1;
    e.type = BR_TYPE_DATA;
    e.src_id = 0x1234;
    e.dst_id = 0x42;
    e.path_mtu = 0x4321; /* must be ignored for non-SEEK */
    e.path_cost = 77;
    e.session_id = 3;
    e.seq = 0xABCD;
    e.ttl = 15;
    e.hops = 15;
    e.flags = 15;
    uint8_t out[32];
    memset(out, 0xEE, sizeof out);
    size_t wr = 0;
    CHECK_ERR(br_hdr_encode(&e, out, sizeof out, &wr), BR_OK);
    CHECK_EQ_U32(wr, 19u);
    CHECK_EQ_U32(out[0], 0x1Fu); /* reserved bits written as given */
    CHECK_EQ_U32(out[10], 0xFFu);
    CHECK_EQ_U32(out[15], 3u);
    CHECK_EQ_U32(out[16], 0xCDu);
    CHECK_EQ_U32(out[17], 0xABu);
    CHECK_EQ_U32(out[19], 0xEEu); /* nothing beyond 19 touched */
    CHECK_ERR(br_hdr_decode(out, 19, &h, &hl), BR_OK);
    CHECK_EQ_U32(h.path_mtu, 0u);
    CHECK_EQ_U32(h.path_cost, 0u);
    CHECK_ERR(br_hdr_encode(&e, out, 18, &wr), BR_ERR_TOO_BIG);
    CHECK_ERR(br_hdr_encode(&e, out, 19, &wr), BR_OK);
    CHECK_ERR(br_hdr_encode(NULL, out, sizeof out, &wr), BR_ERR_ARG);
    CHECK_ERR(br_hdr_encode(&e, NULL, sizeof out, &wr), BR_ERR_ARG);
    CHECK_ERR(br_hdr_encode(&e, out, sizeof out, NULL), BR_ERR_ARG);
    br_hdr_t bad = e;
    bad.version = 16; CHECK_ERR(br_hdr_encode(&bad, out, sizeof out, &wr), BR_ERR_ARG);
    bad = e; bad.flags = 16; CHECK_ERR(br_hdr_encode(&bad, out, sizeof out, &wr), BR_ERR_ARG);
    bad = e; bad.ttl = 16; CHECK_ERR(br_hdr_encode(&bad, out, sizeof out, &wr), BR_ERR_ARG);
    bad = e; bad.hops = 16; CHECK_ERR(br_hdr_encode(&bad, out, sizeof out, &wr), BR_ERR_ARG);
    bad = e; bad.version = 0; bad.ttl = 0; bad.hops = 0; bad.flags = 0;
    CHECK_ERR(br_hdr_encode(&bad, out, sizeof out, &wr), BR_OK);

    /* SEEK */
    e.type = BR_TYPE_SEEK;
    e.path_mtu = 0x4321;
    e.path_cost = 77;
    e.session_id = 0;
    e.seq = 0x1357;
    CHECK_ERR(br_hdr_encode(&e, out, 21, &wr), BR_ERR_TOO_BIG);
    CHECK_ERR(br_hdr_encode(&e, out, 22, &wr), BR_OK);
    CHECK_EQ_U32(wr, 22u);
    CHECK_EQ_U32(out[15], 0x21u);
    CHECK_EQ_U32(out[16], 0x43u);
    CHECK_EQ_U32(out[17], 77u);
    CHECK_EQ_U32(out[18], 0u);
    CHECK_EQ_U32(out[19], 0x57u);
    CHECK_EQ_U32(out[20], 0x13u);
}

static void test_vector_roundtrips(void)
{
    uint8_t wire[BUFSZ];
    for (size_t i = 0; i < TU_N_FRAME_VECS; i++) {
        const tu_frame_vec_t *v = &TU_FRAME_VECS[i];
        tu_ctx(v->name);
        tu_ref_hdr_t ref;
        tu_ref_parse(v->frame, &ref);

        /* header decode agrees with the spec-offset oracle */
        br_hdr_t h;
        size_t hl = 0;
        CHECK_ERR(br_hdr_decode(v->frame, v->len, &h, &hl), BR_OK);
        CHECK_EQ_U32(hl, ref.hdr_len);
        CHECK_EQ_U32(h.version, ref.version);
        CHECK_EQ_U32(h.flags, ref.flags);
        CHECK_EQ_U32(h.type, ref.type);
        CHECK_EQ_U32(h.src_id, ref.src);
        CHECK_EQ_U32(h.dst_id, ref.dst);
        CHECK_EQ_U32(h.prev_hop, ref.prev);
        CHECK_EQ_U32(h.next_hop, ref.next);
        CHECK_EQ_U32(h.ttl, ref.ttl);
        CHECK_EQ_U32(h.hops, ref.hops);
        CHECK_EQ_U32(h.hop_seq, ref.hop_seq);
        CHECK_EQ_U32(h.path_mtu, ref.path_mtu);
        CHECK_EQ_U32(h.path_cost, ref.path_cost);
        CHECK_EQ_U32(h.session_id, ref.session_id);
        CHECK_EQ_U32(h.seq, ref.seq);
        CHECK_EQ_U32(h.len, ref.len);
        CHECK_EQ_U32(h.version, BR_PROTO_VERSION);

        /* header encode reproduces the header bytes; exact-size cap works, one short fails */
        uint8_t hb[32];
        size_t wr = 0;
        memset(hb, 0xEE, sizeof hb);
        CHECK_ERR(br_hdr_encode(&h, hb, hl, &wr), BR_OK);
        CHECK_EQ_U32(wr, hl);
        CHECK_MEM(v->frame, hb, hl);
        CHECK_ERR(br_hdr_encode(&h, hb, hl - 1u, &wr), BR_ERR_TOO_BIG);
        /* header decode with exactly hdr_len bytes works; one fewer fails */
        CHECK_ERR(br_hdr_decode(v->frame, hl, &h, &wr), BR_OK);
        CHECK_ERR(br_hdr_decode(v->frame, hl - 1u, &h, &wr), BR_ERR_DECODE);
        CHECK_ERR(br_hdr_decode(v->frame, hl, &h, &wr), BR_OK);

        /* whole-frame encode reproduces the vector byte for byte (incl. CRC) */
        bool auth = (ref.flags & BR_FLAG_AUTH) != 0;
        size_t plen = ref.len;
        const uint8_t *payload = v->frame + hl;
        const uint8_t *atag = auth ? v->frame + hl + plen : NULL;
        const uint8_t *htag = auth ? v->frame + hl + plen + 8u : NULL;
        uint8_t out[BUFSZ];
        size_t out_len = 0;
        memset(out, 0xEE, sizeof out);
        h.len = 0xEE; /* ignored by the encoder */
        CHECK_ERR(br_frame_encode(&h, payload, plen, atag, htag, out, sizeof out, &out_len), BR_OK);
        CHECK_EQ_U32(out_len, v->len);
        CHECK_MEM(v->frame, out, v->len);
        CHECK_EQ_U32(out[v->len], 0xEEu);
        CHECK_ERR(br_frame_encode(&h, payload, plen, atag, htag, out, v->len, &out_len), BR_OK); /* exact cap */
        CHECK_ERR(br_frame_encode(&h, payload, plen, atag, htag, out, v->len - 1u, &out_len), BR_ERR_TOO_BIG);

        /* seal_crc over the body gives the same trailer */
        uint8_t body[BUFSZ];
        memcpy(body, v->frame, v->len - 2u);
        body[v->len - 2u] = 0xEE;
        body[v->len - 1u] = 0xEE;
        CHECK_ERR(br_frame_seal_crc(body, v->len - 2u, v->len, &out_len), BR_OK);
        CHECK_EQ_U32(out_len, v->len);
        CHECK_MEM(v->frame, body, v->len);
        CHECK_ERR(br_frame_seal_crc(body, v->len - 2u, v->len - 1u, &out_len), BR_ERR_TOO_BIG);

        /* validator accepts, as endpoint and forwarder, with a complete view */
        size_t wl = tu_vec_wire(v, wire);
        tu_link_t lk = {v->max_frame, v->rs_nsym};
        EXPECT(wire, wl, lk, true, BR_REJ_NONE);
        EXPECT(wire, wl, lk, false, BR_REJ_NONE);
        {
            br_link_params_t lp = {v->max_frame, v->rs_nsym};
            br_frame_view_t view;
            br_reject_t r = (br_reject_t)99;
            uint8_t *d = tu_dup(wire, wl);
            memset(&view, 0xEE, sizeof view);
            CHECK_ERR(br_frame_validate(d, wl, &lp, true, &view, &r), BR_OK);
            CHECK_EQ_U32(r, BR_REJ_NONE);
            CHECK_EQ_U32(view.hdr_len, hl);
            CHECK_EQ_U32(view.payload_off, hl);
            CHECK_EQ_U32(view.payload_len, plen);
            CHECK(view.has_auth == auth);
            if (auth) {
                CHECK_EQ_U32(view.auth_tag_off, hl + plen);
                CHECK_EQ_U32(view.hop_tag_off, hl + plen + 8u);
            }
            CHECK_EQ_U32(view.crc_off, v->len - 2u);
            CHECK_EQ_U32(view.crc, v->crc);
            CHECK_EQ_U32(view.rs_off, v->len);
            CHECK_EQ_U32(view.rs_nsym, v->rs_nsym);
            CHECK_EQ_U32(view.total_len, wl);
            CHECK_EQ_U32(view.hdr.src_id, ref.src);
            CHECK_EQ_U32(view.hdr.hop_seq, ref.hop_seq);
            CHECK_EQ_U32(view.hdr.type, ref.type);
            /* NULL view is allowed */
            CHECK_ERR(br_frame_validate(d, wl, &lp, true, NULL, &r), BR_OK);
            free(d);
        }

        /* per-type payload length rule accepts the real frame */
        br_reject_t rr = (br_reject_t)99;
        CHECK_ERR(br_frame_check_type_len(ref.type, ref.len, &rr), BR_OK);
        CHECK_EQ_U32(rr, BR_REJ_NONE);

        /* set_hop_fields with the frame's own per-hop values is the identity on the whole frame */
        {
            br_hop_fields_t hf = {ref.prev, ref.next, ref.ttl, ref.hops, ref.hop_seq, ref.path_mtu, ref.path_cost};
            uint8_t cp[BUFSZ];
            memcpy(cp, v->frame, v->len);
            CHECK_ERR(br_frame_set_hop_fields(cp, v->len, &hf), BR_OK);
            CHECK_MEM(v->frame, cp, v->len);
            /* a forwarder rewrite: change per-hop fields only, end-to-end bytes stay */
            hf.prev_hop = 0x0777;
            hf.next_hop = 0x0888;
            hf.ttl = 2;
            hf.hops = 5;
            hf.hop_seq = 0xDEADBEEFu;
            hf.path_mtu = 0x1111;
            hf.path_cost = 9;
            CHECK_ERR(br_frame_set_hop_fields(cp, v->len, &hf), BR_OK);
            tu_ref_hdr_t nh = ref;
            nh.prev = 0x0777;
            nh.next = 0x0888;
            nh.ttl = 2;
            nh.hops = 5;
            nh.hop_seq = 0xDEADBEEFu;
            if (ref.type == 0x01) {
                nh.path_mtu = 0x1111;
                nh.path_cost = 9;
            }
            uint8_t expect[BUFSZ];
            memcpy(expect, v->frame, v->len);
            (void)tu_ref_write_hdr(&nh, ref.len, expect);
            CHECK_MEM(expect, cp, v->len);
            /* then re-seal the CRC like a forwarder and the validator accepts it again (hop_tag aside) */
            CHECK_ERR(br_frame_seal_crc(cp, v->len - 2u, v->len, &out_len), BR_OK);
            CHECK_EQ_U32(tu_get16(cp + v->len - 2u), tu_ref_crc16(cp, v->len - 2u));
        }
    }
}

static void test_hop_fields_errors(void)
{
    tu_ctx("set_hop_fields errors");
    uint8_t f[BUFSZ];
    memcpy(f, BRV_A7_FRAME, BRV_A7_FRAME_LEN);
    br_hop_fields_t hf = {0x0011, 0x0022, 3, 2, 77, 0, 0};
    CHECK_ERR(br_frame_set_hop_fields(NULL, 44, &hf), BR_ERR_ARG);
    CHECK_ERR(br_frame_set_hop_fields(f, 44, NULL), BR_ERR_ARG);
    br_hop_fields_t b = hf;
    b.ttl = 16; CHECK_ERR(br_frame_set_hop_fields(f, 44, &b), BR_ERR_ARG);
    b = hf; b.hops = 16; CHECK_ERR(br_frame_set_hop_fields(f, 44, &b), BR_ERR_ARG);
    CHECK_ERR(br_frame_set_hop_fields(f, 18, &hf), BR_ERR_DECODE);
    CHECK_ERR(br_frame_set_hop_fields(f, 19, &hf), BR_OK);
    /* non-SEEK: bytes 15..17 are session_id / seq and must not be treated as path_mtu / path_cost */
    memcpy(f, BRV_A7_FRAME, BRV_A7_FRAME_LEN);
    hf.path_mtu = 0xFFFF;
    hf.path_cost = 0xFF;
    CHECK_ERR(br_frame_set_hop_fields(f, 44, &hf), BR_OK);
    CHECK_EQ_U32(f[15], 7u);
    CHECK_EQ_U32(f[16], 5u);
    CHECK_EQ_U32(f[17], 0u);
    CHECK_EQ_U32(tu_get16(f + 6), 0x0011u);
    CHECK_EQ_U32(tu_get16(f + 8), 0x0022u);
    CHECK_EQ_U32(f[10], 0x32u);
    CHECK_EQ_U32(tu_get32(f + 11), 77u);
    /* SEEK needs 22 bytes */
    memcpy(f, BRV_A2_FRAME, BRV_A2_FRAME_LEN);
    CHECK_ERR(br_frame_set_hop_fields(f, 21, &hf), BR_ERR_DECODE);
    CHECK_ERR(br_frame_set_hop_fields(f, 22, &hf), BR_OK);
    CHECK_EQ_U32(tu_get16(f + 15), 0xFFFFu);
    CHECK_EQ_U32(f[17], 0xFFu);
    /* seal_crc args */
    size_t ol = 0;
    CHECK_ERR(br_frame_seal_crc(NULL, 10, 12, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_seal_crc(f, 10, 12, NULL), BR_ERR_ARG);
    CHECK_ERR(br_frame_seal_crc(f, 10, 11, &ol), BR_ERR_TOO_BIG);
    CHECK_ERR(br_frame_seal_crc(f, 10, 12, &ol), BR_OK);
    CHECK_EQ_U32(ol, 12u);
}

/* ------------------------------------------------------------------------- */
/* frame encode limits                                                        */
/* ------------------------------------------------------------------------- */

static void test_frame_encode_rules(void)
{
    tu_ctx("frame_encode rules");
    br_hdr_t h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    h.type = BR_TYPE_DATA;
    h.src_id = 0x1234;
    h.dst_id = 0x42;
    h.prev_hop = 0x1234;
    h.next_hop = 0x42;
    h.ttl = 4;
    h.session_id = 7;
    h.seq = 5;
    uint8_t pay[300];
    memset(pay, 0x33, sizeof pay);
    uint8_t out[BUFSZ];
    size_t ol = 0;
    uint8_t at[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t ht[4] = {9, 10, 11, 12};

    /* no AUTH: caps 229 */
    CHECK_ERR(br_frame_encode(&h, pay, 229, NULL, NULL, out, sizeof out, &ol), BR_OK);
    CHECK_EQ_U32(ol, 250u);
    CHECK_EQ_U32(out[18], 229u);
    CHECK_ERR(br_frame_encode(&h, pay, 230, NULL, NULL, out, sizeof out, &ol), BR_ERR_TOO_BIG);
    CHECK_ERR(br_frame_encode(&h, pay, 300, NULL, NULL, out, sizeof out, &ol), BR_ERR_TOO_BIG);
    CHECK_ERR(br_frame_encode(&h, NULL, 0, NULL, NULL, out, sizeof out, &ol), BR_OK);
    CHECK_EQ_U32(ol, 21u);
    CHECK_EQ_U32(out[18], 0u);
    CHECK_ERR(br_frame_encode(&h, NULL, 1, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    /* AUTH: caps 217 */
    h.flags = BR_FLAG_AUTH;
    CHECK_ERR(br_frame_encode(&h, pay, 217, at, ht, out, sizeof out, &ol), BR_OK);
    CHECK_EQ_U32(ol, 250u);
    CHECK_MEM(at, out + 19 + 217, 8);
    CHECK_MEM(ht, out + 19 + 217 + 8, 4);
    CHECK_ERR(br_frame_encode(&h, pay, 218, at, ht, out, sizeof out, &ol), BR_ERR_TOO_BIG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, ht, out, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, at, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    /* tags without FLAG_AUTH are an error */
    h.flags = 0;
    CHECK_ERR(br_frame_encode(&h, pay, 5, at, ht, out, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, at, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, ht, out, sizeof out, &ol), BR_ERR_ARG);
    /* null args and nibble limits */
    CHECK_ERR(br_frame_encode(NULL, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, NULL, NULL, sizeof out, &ol), BR_ERR_ARG);
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, NULL, out, sizeof out, NULL), BR_ERR_ARG);
    br_hdr_t b = h;
    b.version = 16; CHECK_ERR(br_frame_encode(&b, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    b = h; b.flags = 16; CHECK_ERR(br_frame_encode(&b, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    b = h; b.ttl = 16; CHECK_ERR(br_frame_encode(&b, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    b = h; b.hops = 16; CHECK_ERR(br_frame_encode(&b, pay, 5, NULL, NULL, out, sizeof out, &ol), BR_ERR_ARG);
    /* capacity */
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, NULL, out, 25, &ol), BR_ERR_TOO_BIG); /* needs 26 */
    CHECK_ERR(br_frame_encode(&h, pay, 5, NULL, NULL, out, 26, &ol), BR_OK);
    CHECK_EQ_U32(ol, 26u);
    /* the CRC is little-endian over everything before it */
    CHECK_EQ_U32(tu_get16(out + 24), tu_ref_crc16(out, 24));
    /* SEEK: 22-byte header, path fields present */
    b = h;
    b.type = BR_TYPE_SEEK;
    b.path_mtu = 250;
    b.path_cost = 3;
    CHECK_ERR(br_frame_encode(&b, pay, 18, NULL, NULL, out, sizeof out, &ol), BR_OK);
    CHECK_EQ_U32(ol, 42u);
    CHECK_EQ_U32(tu_get16(out + 15), 250u);
    CHECK_EQ_U32(out[17], 3u);
    CHECK_EQ_U32(out[21], 18u);
}

/* ------------------------------------------------------------------------- */
/* Validator rows (3.6)                                                       */
/* ------------------------------------------------------------------------- */

static void test_validator_args(void)
{
    tu_ctx("validate args");
    uint8_t f[BUFSZ];
    size_t n = build(f, 0x10, 0, 11, 0);
    br_link_params_t lp = {250, 0};
    br_reject_t r = (br_reject_t)99;
    CHECK_ERR(br_frame_validate(NULL, n, &lp, true, NULL, &r), BR_ERR_ARG);
    CHECK_ERR(br_frame_validate(f, n, NULL, true, NULL, &r), BR_ERR_ARG);
    CHECK_ERR(br_frame_validate(f, n, &lp, true, NULL, NULL), BR_ERR_ARG);
    br_link_params_t bad = {8, 8}; /* rs_nsym must be < max_frame */
    CHECK_ERR(br_frame_validate(f, n, &bad, true, NULL, &r), BR_ERR_ARG);
    bad.max_frame = 9;
    bad.rs_nsym = 8;
    r = (br_reject_t)99;
    CHECK(br_frame_validate(f, n, &bad, true, NULL, &r) != BR_ERR_ARG); /* 8 < 9 is consistent */
    r = (br_reject_t)99;
    CHECK_ERR(br_frame_validate(f, n, &lp, true, NULL, &r), BR_OK);
    CHECK_EQ_U32(r, BR_REJ_NONE);
}

static void test_len_rows(void)
{
    tu_ctx("Length row");
    uint8_t f[BUFSZ], g[BUFSZ];
    size_t n;

    /* too short: below header(type) + CRC + rs_nsym, also len < 2 */
    n = build(f, 0x10, 0, 11, 0);
    EXPECT(f, 0, LK_PKT, true, BR_REJ_LEN_SHORT);
    EXPECT(f, 1, LK_PKT, true, BR_REJ_LEN_SHORT);
    EXPECT(f, 2, LK_PKT, true, BR_REJ_LEN_SHORT);
    EXPECT(f, 20, LK_PKT, true, BR_REJ_LEN_SHORT); /* needs 19 + 2 */
    n = build(g, 0x10, 0, 0, 0);
    CHECK_EQ_U32(n, 21u);
    EXPECT(g, n, LK_PKT, true, BR_REJ_NONE);        /* the shortest legal frame */
    n = build(f, 0x01, 0, 18, 0);
    EXPECT(f, 23, LK_PKT, true, BR_REJ_LEN_SHORT); /* SEEK header is 22: needs 24 */
    n = build(g, 0x01, 0, 0, 0);
    CHECK_EQ_U32(n, 24u);
    EXPECT(g, 24, LK_PKT, true, BR_REJ_NONE); /* length is consistent; the per-type 18-byte rule is a later row */
    n = build(f, 0x10, 0, 0, 8);
    CHECK_EQ_U32(n, 29u);
    EXPECT(f, 28, LK_UART, true, BR_REJ_LEN_SHORT); /* 19 + 2 + 8 = 29 */
    EXPECT(f, 29, LK_UART, true, BR_REJ_NONE);
    n = build(f, 0x10, 0, 0, 6);
    CHECK_EQ_U32(n, 27u);
    EXPECT(f, 26, LK_IR, true, BR_REJ_LEN_SHORT);
    EXPECT(f, 27, LK_IR, true, BR_REJ_NONE);

    /* mismatch (CRC valid): len field off by one in either direction, extra byte, AUTH toggled */
    n = build(f, 0x10, 0, 11, 0);
    memcpy(g, f, n);
    g[18] = 12;
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_LEN_MISMATCH);
    memcpy(g, f, n);
    g[18] = 10;
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_LEN_MISMATCH);
    memcpy(g, f, n);
    g[n - 2] = 0x77; /* one extra payload byte before the CRC, len field unchanged */
    tu_ref_seal(g, n + 1u, 0);
    EXPECT(g, n + 1u, LK_PKT, true, BR_REJ_LEN_MISMATCH);
    memcpy(g, f, n);
    g[0] = (uint8_t)(g[0] | BR_FLAG_AUTH); /* claims 12 tag bytes that are not there */
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_LEN_MISMATCH);
    n = build(f, 0x10, BR_FLAG_AUTH, 11, 0);
    memcpy(g, f, n);
    g[0] = (uint8_t)(g[0] & ~BR_FLAG_AUTH);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_LEN_MISMATCH);
    /* the same on a RAW link: the formula includes rs_nsym (N4) */
    n = build(f, 0x10, BR_FLAG_AUTH, 11, 8);
    CHECK_EQ_U32(n, 19u + 11u + 12u + 2u + 8u);
    EXPECT(f, n, LK_UART, true, BR_REJ_NONE);
    memcpy(g, f, n);
    g[18] = 12;
    tu_ref_seal(g, n, 8);
    EXPECT(g, n, LK_UART, true, BR_REJ_LEN_MISMATCH);

    /* payload cap: 229 / 217 minus rs_nsym; boundary accepted, one more rejected.
       (A link with max_frame 400 keeps the max_frame check out of the way.) */
    static const tu_link_t big_pkt = {400, 0}, big_uart = {400, 8}, big_ir = {400, 6};
    n = build(f, 0x10, 0, 229, 0);
    EXPECT(f, n, LK_PKT, true, BR_REJ_NONE);
    n = build(f, 0x10, 0, 230, 0);
    EXPECT(f, n, big_pkt, true, BR_REJ_LEN_PAYLOAD);
    n = build(f, 0x10, BR_FLAG_AUTH, 217, 0);
    EXPECT(f, n, LK_PKT, true, BR_REJ_NONE);
    n = build(f, 0x10, BR_FLAG_AUTH, 218, 0);
    EXPECT(f, n, big_pkt, true, BR_REJ_LEN_PAYLOAD);
    n = build(f, 0x10, 0, 221, 8);
    EXPECT(f, n, LK_UART, true, BR_REJ_NONE);
    n = build(f, 0x10, 0, 222, 8);
    EXPECT(f, n, big_uart, true, BR_REJ_LEN_PAYLOAD);
    n = build(f, 0x10, BR_FLAG_AUTH, 209, 8);
    EXPECT(f, n, LK_UART, true, BR_REJ_NONE);
    n = build(f, 0x10, BR_FLAG_AUTH, 210, 8);
    EXPECT(f, n, big_uart, true, BR_REJ_LEN_PAYLOAD);
    n = build(f, 0x10, 0, 224, 6);
    EXPECT(f, n, big_ir, true, BR_REJ_LEN_PAYLOAD);
    n = build(f, 0x10, 0, 255, 0);
    EXPECT(f, n, big_pkt, true, BR_REJ_LEN_PAYLOAD);

    /* N6: BR_REJ_LEN_MAX_FRAME is a valid named reject: frame longer than the link's max_frame */
    n = build(f, 0x10, 0, 230, 0);
    CHECK_EQ_U32(n, 251u);
    EXPECT(f, n, LK_PKT, true, BR_REJ_LEN_MAX_FRAME);
    EXPECT(f, n, LK_PKT, false, BR_REJ_LEN_MAX_FRAME);
    n = build(f, 0x10, 0, 61, 6); /* 19 + 61 + 2 + 6 = 88 > 80 */
    CHECK_EQ_U32(n, 88u);
    EXPECT(f, n, LK_IR, true, BR_REJ_LEN_MAX_FRAME);
    n = build(f, 0x10, 0, 53, 6); /* exactly 80 */
    CHECK_EQ_U32(n, 80u);
    EXPECT(f, n, LK_IR, true, BR_REJ_NONE);
    n = build(f, 0x10, 0, 54, 6); /* 81 */
    EXPECT(f, n, LK_IR, true, BR_REJ_LEN_MAX_FRAME);
    /* ... which wins over a mismatching len field and over the payload cap (checked first), but not over CRC (N5) */
    n = build(f, 0x10, 0, 230, 0);
    memcpy(g, f, n);
    g[18] = 10;
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_LEN_MAX_FRAME);
    memcpy(g, f, n);
    g[n - 1] ^= 0x01;
    EXPECT(g, n, LK_PKT, true, BR_REJ_CRC);
}

static void test_crc_row(void)
{
    tu_ctx("CRC row (N5)");
    uint8_t f[BUFSZ], g[BUFSZ];
    size_t n = build(f, 0x10, BR_FLAG_AUTH, 11, 0);
    EXPECT(f, n, LK_PKT, true, BR_REJ_NONE);
    for (size_t pos = 0; pos < n; pos++) { /* a single bit flip anywhere is a CRC failure and nothing else */
        memcpy(g, f, n);
        g[pos] ^= 0x10;
        EXPECT(g, n, LK_PKT, true, BR_REJ_CRC);
    }
    /* N5: CRC is checked before the Length row, so a corrupted len field counts as crc_fail, not bad_frame */
    memcpy(g, f, n);
    g[18] ^= 0x01;
    EXPECT(g, n, LK_PKT, true, BR_REJ_CRC);
    /* ... and before the Header rows */
    memcpy(g, f, n);
    g[10] = 0xFF;
    EXPECT(g, n, LK_PKT, true, BR_REJ_CRC);
    /* an extra trailing byte moves the CRC position: CRC failure */
    memcpy(g, f, n);
    g[n] = 0x00;
    EXPECT(g, n + 1u, LK_PKT, true, BR_REJ_CRC);
    /* minimum length comes first: below it the reason is LEN_SHORT even if the CRC would be wrong */
    EXPECT(f, 5, LK_PKT, true, BR_REJ_LEN_SHORT);
    /* RAW link: CRC sits before the parity */
    n = build(f, 0x10, 0, 11, 8);
    EXPECT(f, n, LK_UART, true, BR_REJ_NONE);
    memcpy(g, f, n);
    g[n - 8 - 1] ^= 0x01; /* a CRC byte */
    EXPECT(g, n, LK_UART, true, BR_REJ_CRC);
    memcpy(g, f, n);
    g[3] ^= 0x40; /* RS parity is not this layer's job: a payload flip with intact CRC trailer is CRC failure */
    EXPECT(g, n, LK_UART, true, BR_REJ_CRC);
    memcpy(g, f, n);
    g[n - 1] ^= 0x55; /* parity bytes are not validated here (RS decode happened earlier) */
    EXPECT(g, n, LK_UART, true, BR_REJ_NONE);
}

static void test_header_rows(void)
{
    tu_ctx("Header row");
    uint8_t f[BUFSZ], g[BUFSZ];
    size_t n = build(f, 0x10, BR_FLAG_AUTH, 11, 0);
    EXPECT(f, n, LK_PKT, true, BR_REJ_NONE);

#define MUT_EXPECT(field, value, reason)                                                                \
    do {                                                                                                \
        memcpy(g, f, n);                                                                                \
        mut(g, n, 0, (field), (value));                                                                 \
        EXPECT(g, n, LK_PKT, true, (reason));                                                           \
    } while (0)

    /* ttl <= MAX_HOPS (8) */
    MUT_EXPECT(F_TTL, 0, BR_REJ_NONE);
    MUT_EXPECT(F_TTL, 8, BR_REJ_NONE);
    MUT_EXPECT(F_TTL, 9, BR_REJ_TTL);
    MUT_EXPECT(F_TTL, 15, BR_REJ_TTL);
    /* hops < MAX_HOPS */
    MUT_EXPECT(F_HOPS, 7, BR_REJ_NONE);
    MUT_EXPECT(F_HOPS, 8, BR_REJ_HOPS);
    MUT_EXPECT(F_HOPS, 15, BR_REJ_HOPS);
    /* both wrong: ttl is checked first */
    memcpy(g, f, n);
    g[10] = 0x98;
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_TTL);

    /* prev_hop / src_id: unit IDs or manager IDs (N1: 0x0001..0x000F inclusive) */
    static const struct { uint16_t id; bool ok; } ids[] = {
        {0x0000, false}, {0x0001, true}, {0x0002, true}, {0x0003, true}, {0x000F, true}, {0x0010, true},
        {0x1234, true},  {0xFEFF, true}, {0xFF00, false}, {0xFF01, false}, {0xFFFE, false}, {0xFFFF, false}};
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        MUT_EXPECT(F_PREV, ids[i].id, ids[i].ok ? BR_REJ_NONE : BR_REJ_PREV_HOP);
        MUT_EXPECT(F_SRC, ids[i].id, ids[i].ok ? BR_REJ_NONE : BR_REJ_SRC_ID);
    }
    /* order: prev_hop before src_id before next_hop before dst_id */
    memcpy(g, f, n);
    tu_put16(g + 6, 0);
    tu_put16(g + 2, 0);
    tu_put16(g + 8, 0);
    tu_put16(g + 4, 0);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_PREV_HOP);
    tu_put16(g + 6, 0x1234);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_SRC_ID);
    tu_put16(g + 2, 0x1234);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_NEXT_HOP);
    tu_put16(g + 8, 0xFFFF);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_DST_ID);
    tu_put16(g + 4, 0xFFFF);
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_NONE);

    /* next_hop: unit ID, manager ID (N2: direct link to the gateway has next_hop = dst_id = 0x0001), or 0xFFFF */
    static const struct { uint16_t id; bool ok; } nh[] = {
        {0x0000, false}, {0x0001, true}, {0x0002, true}, {0x000F, true}, {0x0010, true}, {0xFEFF, true},
        {0xFF00, false}, {0xFF05, false}, {0xFFFE, false}, {0xFFFF, true}};
    for (size_t i = 0; i < sizeof nh / sizeof nh[0]; i++) {
        MUT_EXPECT(F_NEXT, nh[i].id, nh[i].ok ? BR_REJ_NONE : BR_REJ_NEXT_HOP);
    }
    /* dst_id != 0: unit, manager, group, flood all fine */
    MUT_EXPECT(F_DST, 0x0000, BR_REJ_DST_ID);
    MUT_EXPECT(F_DST, 0x0001, BR_REJ_NONE);
    MUT_EXPECT(F_DST, 0x0010, BR_REJ_NONE);
    MUT_EXPECT(F_DST, 0xFF05, BR_REJ_NONE);
    MUT_EXPECT(F_DST, 0xFFFF, BR_REJ_NONE);
    MUT_EXPECT(F_DST, 0xFFFE, BR_REJ_NONE);
    /* N1/N2 concrete case: a direct frame to the gateway */
    {
        tu_ref_hdr_t h = hdr_for(0x10, BR_FLAG_AUTH);
        h.dst = 0x0001;
        h.next = 0x0001;
        uint8_t pl[11] = {0};
        size_t m = tu_ref_build(&h, pl, 11, NULL, 0, g);
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
        h.src = 0x0002; /* provisioning station as origin */
        h.prev = 0x0003; /* recovery holder as previous hop */
        m = tu_ref_build(&h, pl, 11, NULL, 0, g);
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
    }
    /* the Header row applies at forwarders too, and to SEEK frames (22-byte header) */
    {
        size_t m = build(g, 0x01, 0, 18, 0);
        EXPECT(g, m, LK_PKT, false, BR_REJ_NONE);
        mut(g, m, 0, F_TTL, 9);
        EXPECT(g, m, LK_PKT, false, BR_REJ_TTL);
        m = build(g, 0x01, 0, 18, 0);
        mut(g, m, 0, F_PREV, 0xFF00);
        EXPECT(g, m, LK_PKT, false, BR_REJ_PREV_HOP);
    }
    /* reserved flag bits 2, 3 are ignored; unknown types are not rejected here */
    {
        size_t m = build(g, 0x10, 0x0C, 11, 0);
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
        m = build(g, 0x10, 0x0F, 11, 0); /* ACK_REQ | AUTH | reserved: AUTH makes 12 bytes of tags expected */
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
        static const uint8_t types[] = {0x00, 0x08, 0x13, 0x22, 0x42, 0x7F, 0xFF};
        for (size_t i = 0; i < sizeof types; i++) {
            tu_ref_hdr_t h = hdr_for(types[i], 0);
            uint8_t pl[7] = {0};
            m = tu_ref_build(&h, pl, 7, NULL, 0, g);
            EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
        }
    }
#undef MUT_EXPECT
}

static void test_seek_rows(void)
{
    tu_ctx("SEEK hop fields row");
    uint8_t f[BUFSZ], g[BUFSZ];
    size_t n = build(f, 0x01, 0, 18, 0);
    CHECK_EQ_U32(n, 42u);
    EXPECT(f, n, LK_PKT, true, BR_REJ_NONE);
#define SEEK_EXPECT(lk, field, value, reason, nsym_)                                                    \
    do {                                                                                                \
        size_t m_ = build(g, 0x01, 0, 18, (nsym_));                                                     \
        mut(g, m_, (nsym_), (field), (value));                                                          \
        EXPECT(g, m_, (lk), true, (reason));                                                            \
    } while (0)
    /* MIN_PATH_MTU 48 <= path_mtu <= max_frame - rs_nsym */
    SEEK_EXPECT(LK_PKT, F_MTU, 47, BR_REJ_PATH_MTU, 0);
    SEEK_EXPECT(LK_PKT, F_MTU, 0, BR_REJ_PATH_MTU, 0);
    SEEK_EXPECT(LK_PKT, F_MTU, 48, BR_REJ_NONE, 0);
    SEEK_EXPECT(LK_PKT, F_MTU, 250, BR_REJ_NONE, 0);
    SEEK_EXPECT(LK_PKT, F_MTU, 251, BR_REJ_PATH_MTU, 0);
    SEEK_EXPECT(LK_PKT, F_MTU, 0xFFFF, BR_REJ_PATH_MTU, 0);
    SEEK_EXPECT(LK_UART, F_MTU, 242, BR_REJ_NONE, 8); /* A.3: 250 - 8 */
    SEEK_EXPECT(LK_UART, F_MTU, 243, BR_REJ_PATH_MTU, 8);
    SEEK_EXPECT(LK_UART, F_MTU, 250, BR_REJ_PATH_MTU, 8);
    SEEK_EXPECT(LK_IR, F_MTU, 74, BR_REJ_NONE, 6); /* A.15: 80 - 6 */
    SEEK_EXPECT(LK_IR, F_MTU, 75, BR_REJ_PATH_MTU, 6);
    SEEK_EXPECT(LK_IR, F_MTU, 48, BR_REJ_NONE, 6);
    SEEK_EXPECT(LK_IR, F_MTU, 47, BR_REJ_PATH_MTU, 6);
    /* path_cost <= 250 */
    SEEK_EXPECT(LK_PKT, F_COST, 0, BR_REJ_NONE, 0);
    SEEK_EXPECT(LK_PKT, F_COST, 250, BR_REJ_NONE, 0);
    SEEK_EXPECT(LK_PKT, F_COST, 251, BR_REJ_PATH_COST, 0);
    SEEK_EXPECT(LK_PKT, F_COST, 255, BR_REJ_PATH_COST, 0);
    /* both wrong: path_mtu first; Header row comes before both */
    memcpy(g, f, n);
    tu_put16(g + 15, 10);
    g[17] = 255;
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_PATH_MTU);
    g[10] = 0xF0; /* ttl 15 */
    tu_ref_seal(g, n, 0);
    EXPECT(g, n, LK_PKT, true, BR_REJ_TTL);
    /* the row applies at forwarders as well */
    memcpy(g, f, n);
    mut(g, n, 0, F_MTU, 40);
    EXPECT(g, n, LK_PKT, false, BR_REJ_PATH_MTU);
    /* it does not apply to other types: bytes 15..17 of a DATA frame are session_id / seq */
    {
        tu_ref_hdr_t h = hdr_for(0x10, 0);
        h.session_id = 0;
        h.seq = 0;
        uint8_t pl[7] = {0};
        size_t m = tu_ref_build(&h, pl, 7, NULL, 0, g);
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
        h.session_id = 0xFF;
        h.seq = 0xFFFF;
        m = tu_ref_build(&h, pl, 7, NULL, 0, g);
        EXPECT(g, m, LK_PKT, true, BR_REJ_NONE);
    }
#undef SEEK_EXPECT
}

static void test_version_row(void)
{
    tu_ctx("Version row (N3)");
    uint8_t f[BUFSZ], g[BUFSZ];
    size_t n = build(f, 0x10, BR_FLAG_AUTH, 11, 0);
    for (unsigned v = 0; v < 16; v++) {
        memcpy(g, f, n);
        mut(g, n, 0, F_VER, v);
        /* endpoints accept only version 1 (N3: version 0 is not N-1); forwarders accept any */
        EXPECT(g, n, LK_PKT, true, v == 1u ? BR_REJ_NONE : BR_REJ_VERSION);
        EXPECT(g, n, LK_PKT, false, BR_REJ_NONE);
    }
    CHECK_EQ_U32(BR_PROTO_VERSION, 1u);
    CHECK_EQ_U32(BR_PROTO_VERSION_MIN, 1u);
    /* SEEK (frozen prefix) behaves the same, and Version is the last of the stateless rows */
    size_t m = build(g, 0x01, 0, 18, 0);
    mut(g, m, 0, F_VER, 2);
    EXPECT(g, m, LK_PKT, true, BR_REJ_VERSION);
    EXPECT(g, m, LK_PKT, false, BR_REJ_NONE);
    mut(g, m, 0, F_MTU, 10);
    EXPECT(g, m, LK_PKT, true, BR_REJ_PATH_MTU);
    m = build(g, 0x10, 0, 11, 0);
    mut(g, m, 0, F_VER, 0);
    mut(g, m, 0, F_DST, 0);
    EXPECT(g, m, LK_PKT, true, BR_REJ_DST_ID);
    /* a version-2 frame with a different (unknown) layout would still be forwardable: only prefix rules apply */
    m = build(g, 0x77, 0, 20, 0);
    mut(g, m, 0, F_VER, 3);
    EXPECT(g, m, LK_PKT, false, BR_REJ_NONE);
    EXPECT(g, m, LK_PKT, true, BR_REJ_VERSION);
}

static void test_counters(void)
{
    tu_ctx("reject -> counter");
    static const struct { br_reject_t r; br_counter_t c; } map[] = {
        {BR_REJ_NONE, BR_CNT_NONE},
        {BR_REJ_LEN_SHORT, BR_CNT_BAD_FRAME},
        {BR_REJ_LEN_MISMATCH, BR_CNT_BAD_FRAME},
        {BR_REJ_LEN_PAYLOAD, BR_CNT_BAD_FRAME},
        {BR_REJ_LEN_MAX_FRAME, BR_CNT_BAD_FRAME},
        {BR_REJ_CRC, BR_CNT_CRC_FAIL},
        {BR_REJ_TTL, BR_CNT_BAD_FRAME},
        {BR_REJ_HOPS, BR_CNT_BAD_FRAME},
        {BR_REJ_PREV_HOP, BR_CNT_BAD_FRAME},
        {BR_REJ_SRC_ID, BR_CNT_BAD_FRAME},
        {BR_REJ_NEXT_HOP, BR_CNT_BAD_FRAME},
        {BR_REJ_DST_ID, BR_CNT_BAD_FRAME},
        {BR_REJ_PATH_MTU, BR_CNT_BAD_FRAME},
        {BR_REJ_PATH_COST, BR_CNT_BAD_FRAME},
        {BR_REJ_VERSION, BR_CNT_BAD_VERSION},
        {BR_REJ_HOP_TAG, BR_CNT_HOP_TAG_FAIL},
        {BR_REJ_HOP_REPLAY, BR_CNT_HOP_REPLAY},
        {BR_REJ_AUTH, BR_CNT_AUTH_FAIL},
        {BR_REJ_PRE_CTR_SEQ, BR_CNT_BAD_FRAME},
        {BR_REJ_TYPE_LEN, BR_CNT_BAD_FRAME},
        {BR_REJ_REPLAY, BR_CNT_REPLAY_DROPPED},
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        br_counter_t c = (br_counter_t)99;
        CHECK_ERR(br_reject_counter(map[i].r, &c), BR_OK);
        CHECK_EQ_U32(c, map[i].c);
    }
    br_counter_t c;
    CHECK_ERR(br_reject_counter(BR_REJ_CRC, NULL), BR_ERR_ARG);
    CHECK_ERR(br_reject_counter((br_reject_t)(BR_REJ_REPLAY + 1), &c), BR_ERR_ARG);
    CHECK_ERR(br_reject_counter((br_reject_t)-1, &c), BR_ERR_ARG);
    CHECK_ERR(br_reject_counter((br_reject_t)1000, &c), BR_ERR_ARG);
}

static void test_hop_seq(void)
{
    tu_ctx("hop_seq freshness (3.5)");
    br_reject_t r;
    /* no link-table entry: everything accepted (known limitation, 8.4) */
    static const uint32_t any[] = {0, 1, 0x7FFFFFFFu, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof any / sizeof any[0]; i++) {
        r = (br_reject_t)99;
        CHECK_ERR(br_hop_seq_check(false, 12345, any[i], &r), BR_OK);
        CHECK_EQ_U32(r, BR_REJ_NONE);
    }
    struct { uint32_t last, rx; bool ok; } t[] = {
        {100, 101, true},
        {100, 100, false},
        {100, 99, false},
        {100, 0, false},
        {0, 1, true},
        {0, 65536, true},          /* exactly HOP_MAX_JUMP ahead */
        {0, 65537, false},         /* one beyond */
        {100, 100 + 65536, true},
        {100, 100 + 65537, false},
        {0xFFFFFFF0u, 5, false},   /* plain unsigned compare: no wrap */
        {0xFFFFFFFEu, 0xFFFFFFFFu, true},
        {0xFFFFFFFFu, 0xFFFFFFFFu, false},
        {0xFFFFFFFFu, 0, false},
        {0x00010130u, 0x00010131u, true},
        {0x00010131u, 0x00010130u, false},
        {0x7FFFFFFFu, 0x80000000u, true},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        r = (br_reject_t)99;
        br_err_t rc = br_hop_seq_check(true, t[i].last, t[i].rx, &r);
        CHECK_ERR(rc, t[i].ok ? BR_OK : BR_ERR_REJECT);
        CHECK_EQ_U32(r, t[i].ok ? BR_REJ_NONE : BR_REJ_HOP_REPLAY);
    }
    CHECK_ERR(br_hop_seq_check(true, 1, 2, NULL), BR_ERR_ARG);
    /* random vs the rule */
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x409u);
    for (unsigned it = 0; it < 20000; it++) {
        uint32_t last = (uint32_t)tu_rng_next(&rng);
        uint32_t rx;
        switch (it % 4) {
        case 0: rx = (uint32_t)tu_rng_next(&rng); break;
        case 1: rx = last + tu_rng_below(&rng, 70000); break;
        case 2: rx = last - tu_rng_below(&rng, 70000); break;
        default: rx = last + 65536u + tu_rng_below(&rng, 3) - 1u; break;
        }
        bool ok = rx > last && (rx - last) <= 65536u;
        r = (br_reject_t)99;
        CHECK_ERR(br_hop_seq_check(true, last, rx, &r), ok ? BR_OK : BR_ERR_REJECT);
        CHECK_EQ_U32(r, ok ? BR_REJ_NONE : BR_REJ_HOP_REPLAY);
    }
}

static void test_type_len(void)
{
    tu_ctx("type/len rows");
    static const struct { uint8_t type; size_t len; } exact[] = {
        {BR_TYPE_SEEK, 18}, {BR_TYPE_HELLO, 28}, {BR_TYPE_BIND, 17}, {BR_TYPE_BIND_ACK, 12}, {BR_TYPE_BIND_NAK, 9},
        {BR_TYPE_MODE_ACK, 2}, {BR_TYPE_ACK, 6}, {BR_TYPE_RESUME_ACK, 6}, {BR_TYPE_PING, 4}, {BR_TYPE_PONG, 8},
        {BR_TYPE_CLOSE, 3}, {BR_TYPE_RESUME, 5}};
    br_reject_t r;
    for (size_t i = 0; i < sizeof exact / sizeof exact[0]; i++) {
        for (size_t len = 0; len <= 255; len++) {
            r = (br_reject_t)99;
            br_err_t rc = br_frame_check_type_len(exact[i].type, len, &r);
            bool ok = (len == exact[i].len);
            CHECK_ERR(rc, ok ? BR_OK : BR_ERR_REJECT);
            CHECK_EQ_U32(r, ok ? BR_REJ_NONE : BR_REJ_TYPE_LEN);
        }
    }
    static const struct { uint8_t type; size_t min; } minimum[] = {
        {BR_TYPE_MGMT_REQ, 22}, {BR_TYPE_MGMT_RESP, 33}, {BR_TYPE_MODE, 13}, {BR_TYPE_DATA, 7}, {BR_TYPE_PARITY, 8}};
    for (size_t i = 0; i < sizeof minimum / sizeof minimum[0]; i++) {
        for (size_t len = 0; len <= 255; len++) {
            r = (br_reject_t)99;
            br_err_t rc = br_frame_check_type_len(minimum[i].type, len, &r);
            bool ok = (len >= minimum[i].min);
            CHECK_ERR(rc, ok ? BR_OK : BR_ERR_REJECT);
            CHECK_EQ_U32(r, ok ? BR_REJ_NONE : BR_REJ_TYPE_LEN);
        }
    }
    /* unknown types: OK for any length */
    static const uint8_t unk[] = {0x00, 0x08, 0x13, 0x22, 0x33, 0x42, 0x7F, 0xFF};
    for (size_t i = 0; i < sizeof unk; i++) {
        for (size_t len = 0; len <= 255; len += 17) {
            r = (br_reject_t)99;
            CHECK_ERR(br_frame_check_type_len(unk[i], len, &r), BR_OK);
            CHECK_EQ_U32(r, BR_REJ_NONE);
        }
    }
    CHECK_ERR(br_frame_check_type_len(BR_TYPE_DATA, 7, NULL), BR_ERR_ARG);
    CHECK_EQ_U32(BR_LEN_SEEK, 18u);
    CHECK_EQ_U32(BR_LEN_HELLO, 28u);
    CHECK_EQ_U32(BR_LEN_MGMT_REQ_FIXED, 22u);
    CHECK_EQ_U32(BR_LEN_MGMT_RESP_FIXED, 33u);
    CHECK_EQ_U32(BR_LEN_MODE_FIXED, 13u);
    CHECK_EQ_U32(BR_LEN_DATA_FIXED, 7u);
}

static void test_clear_len_and_pre_ctr(void)
{
    tu_ctx("clear_len");
    size_t c;
    /* SEEK and RESUME: the whole payload is clear */
    CHECK_ERR(br_frame_clear_len(BR_TYPE_SEEK, 0, 18, &c), BR_OK);
    CHECK_EQ_U32(c, 18u);
    CHECK_ERR(br_frame_clear_len(BR_TYPE_RESUME, 7, 5, &c), BR_OK);
    CHECK_EQ_U32(c, 5u);
    /* session_id 0 frames: 4 bytes of pre_ctr */
    static const uint8_t pre[] = {BR_TYPE_HELLO, BR_TYPE_BIND, BR_TYPE_BIND_ACK, BR_TYPE_BIND_NAK, BR_TYPE_MGMT_REQ,
                                  BR_TYPE_MGMT_RESP};
    for (size_t i = 0; i < sizeof pre; i++) {
        c = 99;
        CHECK_ERR(br_frame_clear_len(pre[i], 0, 28, &c), BR_OK);
        CHECK_EQ_U32(c, 4u);
        c = 99;
        CHECK_ERR(br_frame_clear_len(pre[i], 0, 4, &c), BR_OK);
        CHECK_EQ_U32(c, 4u);
        CHECK_ERR(br_frame_clear_len(pre[i], 0, 3, &c), BR_ERR_DECODE);
        CHECK_ERR(br_frame_clear_len(pre[i], 0, 0, &c), BR_ERR_DECODE);
    }
    /* session frames: nothing in clear */
    static const uint8_t ses[] = {BR_TYPE_DATA, BR_TYPE_PARITY, BR_TYPE_ACK, BR_TYPE_PING, BR_TYPE_PONG, BR_TYPE_CLOSE,
                                  BR_TYPE_MODE, BR_TYPE_MODE_ACK, BR_TYPE_RESUME_ACK};
    for (size_t i = 0; i < sizeof ses; i++) {
        c = 99;
        CHECK_ERR(br_frame_clear_len(ses[i], 7, 20, &c), BR_OK);
        CHECK_EQ_U32(c, 0u);
    }
    CHECK_ERR(br_frame_clear_len(BR_TYPE_DATA, 7, 20, NULL), BR_ERR_ARG);

    tu_ctx("pre_ctr (3.5, 3.6 CCM row)");
    uint8_t wire[BUFSZ];
    struct { const tu_frame_vec_t *v; uint32_t pre_ctr; } cases[] = {
        {&TU_FRAME_VECS[0], 1u},                 /* A.2 SEEK */
        {&TU_FRAME_VECS[3], 0x00010001u},        /* A.8 SEEK hop 1 */
        {&TU_FRAME_VECS[4], 0x00010001u},        /* A.8 SEEK hop 2 */
        {&TU_FRAME_VECS[8], 0x00010007u},        /* A.9 HELLO */
        {&TU_FRAME_VECS[9], 0x00010002u},        /* A.9 BIND */
        {&TU_FRAME_VECS[11], 0x00010003u},       /* A.11 RESUME: seq is the session seq, not pre_ctr */
        {&TU_FRAME_VECS[12], 0x00010008u},       /* A.12 MGMT_REQ */
        {&TU_FRAME_VECS[13], 0x00020005u},       /* A.12 MGMT_RESP */
        {&TU_FRAME_VECS[14], 0x11u},             /* A.15 IR SEEK */
        {&TU_FRAME_VECS[15], 5u},                /* A.15 IR HELLO */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const tu_frame_vec_t *v = cases[i].v;
        tu_ctx(v->name);
        size_t wl = tu_vec_wire(v, wire);
        br_link_params_t lp = {v->max_frame, v->rs_nsym};
        br_frame_view_t view;
        br_reject_t r = (br_reject_t)99;
        uint8_t *d = tu_dup(wire, wl);
        CHECK_ERR(br_frame_validate(d, wl, &lp, true, &view, &r), BR_OK);
        uint32_t pc = 0;
        r = (br_reject_t)99;
        CHECK_ERR(br_frame_pre_ctr(d, &view, &pc, &r), BR_OK);
        CHECK_EQ_U32(r, BR_REJ_NONE);
        CHECK_EQ_U32(pc, cases[i].pre_ctr);
        CHECK_ERR(br_frame_pre_ctr(NULL, &view, &pc, &r), BR_ERR_ARG);
        CHECK_ERR(br_frame_pre_ctr(d, NULL, &pc, &r), BR_ERR_ARG);
        CHECK_ERR(br_frame_pre_ctr(d, &view, NULL, &r), BR_ERR_ARG);
        CHECK_ERR(br_frame_pre_ctr(d, &view, &pc, NULL), BR_ERR_ARG);
        free(d);
        /* session_id 0 frames: header seq must equal the low 16 bits of pre_ctr */
        if (view.hdr.session_id == 0) {
            uint8_t g[BUFSZ];
            memcpy(g, wire, wl);
            size_t seq_off = (v->frame[1] == 0x01) ? 19u : 16u;
            g[seq_off] ^= 0x01;
            tu_ref_seal(g, wl, v->rs_nsym);
            uint8_t *d2 = tu_dup(g, wl);
            CHECK_ERR(br_frame_validate(d2, wl, &lp, true, &view, &r), BR_OK);
            r = (br_reject_t)99;
            CHECK_ERR(br_frame_pre_ctr(d2, &view, &pc, &r), BR_ERR_REJECT);
            CHECK_EQ_U32(r, BR_REJ_PRE_CTR_SEQ);
            free(d2);
        }
    }
    tu_ctx("pre_ctr errors");
    {
        /* HELLO with a 3-byte payload: no room for pre_ctr */
        uint8_t g[BUFSZ];
        tu_ref_hdr_t h = hdr_for(BR_TYPE_HELLO, BR_FLAG_AUTH);
        h.session_id = 0;
        uint8_t pl[3] = {1, 2, 3};
        size_t m = tu_ref_build(&h, pl, 3, NULL, 0, g);
        br_link_params_t lp = {250, 0};
        br_frame_view_t view;
        br_reject_t r = (br_reject_t)99;
        uint8_t *d = tu_dup(g, m);
        CHECK_ERR(br_frame_validate(d, m, &lp, true, &view, &r), BR_OK);
        uint32_t pc = 0;
        CHECK_ERR(br_frame_pre_ctr(d, &view, &pc, &r), BR_ERR_REJECT);
        CHECK_EQ_U32(r, BR_REJ_TYPE_LEN);
        free(d);
        /* DATA (session frame other than RESUME): no pre_ctr -> argument error */
        m = build(g, 0x10, BR_FLAG_AUTH, 11, 0);
        d = tu_dup(g, m);
        CHECK_ERR(br_frame_validate(d, m, &lp, true, &view, &r), BR_OK);
        CHECK_ERR(br_frame_pre_ctr(d, &view, &pc, &r), BR_ERR_ARG);
        free(d);
    }
}

static void test_seq_roc(void)
{
    tu_ctx("seq16 newer (RFC 1982)");
    bool nw;
    CHECK_ERR(br_seq16_newer(1, 0, &nw), BR_OK);
    CHECK(nw);
    CHECK_ERR(br_seq16_newer(0, 1, &nw), BR_OK);
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(5, 5, &nw), BR_OK);
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(0, 0xFFFF, &nw), BR_OK); /* wrap */
    CHECK(nw);
    CHECK_ERR(br_seq16_newer(0xFFFF, 0, &nw), BR_OK);
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(0x8000, 0, &nw), BR_OK); /* difference exactly 2^15: undefined, reported NOT newer */
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(0, 0x8000, &nw), BR_OK);
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(0x7FFF, 0, &nw), BR_OK);
    CHECK(nw);
    CHECK_ERR(br_seq16_newer(0x8001, 0, &nw), BR_OK);
    CHECK(!nw);
    CHECK_ERR(br_seq16_newer(1, 2, NULL), BR_ERR_ARG);
    tu_rng_t rng;
    tu_rng_seed(&rng, 0x5E91u);
    for (unsigned it = 0; it < 20000; it++) {
        uint16_t a = (uint16_t)tu_rng_below(&rng, 65536), b = (uint16_t)tu_rng_below(&rng, 65536);
        if (it % 3 == 0) {
            b = (uint16_t)(a - (uint16_t)tu_rng_below(&rng, 70000)); /* near and around the half-range */
        }
        CHECK_ERR(br_seq16_newer(a, b, &nw), BR_OK);
        CHECK(nw == tu_ref_seq16_newer(a, b));
    }
    for (unsigned d = 0; d < 65536; d += 257) { /* exhaustive-ish sweep of differences */
        CHECK_ERR(br_seq16_newer((uint16_t)(0x1234 + d), 0x1234, &nw), BR_OK);
        CHECK(nw == (d != 0 && d < 0x8000u));
    }

    tu_ctx("ROC estimate (A.10)");
    for (unsigned i = 0; i < BRV_A10_ROC_CASE_COUNT; i++) {
        uint32_t out = 0xDEAD;
        CHECK_ERR(br_roc_estimate(BRV_A10_ROC_CASES[i].seq, BRV_A10_ROC_CASES[i].highest, BRV_A10_ROC_CASES[i].roc, &out),
                  BR_OK);
        CHECK_EQ_U32(out, BRV_A10_ROC_CASES[i].expected);
    }
    /* N8: roc - 1 with roc == 0 -> REJECT; roc + 1 with roc == UINT32_MAX -> TOO_BIG */
    uint32_t out = 0xDEAD;
    CHECK_ERR(br_roc_estimate(0xFFF0, 0x0005, 0, &out), BR_ERR_REJECT);
    CHECK_ERR(br_roc_estimate(0x0005, 0xFFF0, UINT32_MAX, &out), BR_ERR_TOO_BIG);
    CHECK_ERR(br_roc_estimate(0x0005, 0xFFF0, UINT32_MAX - 1u, &out), BR_OK);
    CHECK_EQ_U32(out, UINT32_MAX);
    CHECK_ERR(br_roc_estimate(0xFFF0, 0x0005, 1, &out), BR_OK);
    CHECK_EQ_U32(out, 0u);
    CHECK_ERR(br_roc_estimate(0xFFF0, 0x0005, UINT32_MAX, &out), BR_OK);
    CHECK_EQ_U32(out, UINT32_MAX - 1u);
    CHECK_ERR(br_roc_estimate(1, 2, 3, NULL), BR_ERR_ARG);
    /* boundaries of the three branches */
    CHECK_ERR(br_roc_estimate(0x8000, 0x0000, 5, &out), BR_OK); /* diff exactly 32768 -> roc (not > 32768) */
    CHECK_EQ_U32(out, 5u);
    CHECK_ERR(br_roc_estimate(0x8001, 0x0000, 5, &out), BR_OK);
    CHECK_EQ_U32(out, 4u);
    CHECK_ERR(br_roc_estimate(0x0000, 0x8000, 5, &out), BR_OK); /* s_l - 32768 == 0, not > seq */
    CHECK_EQ_U32(out, 5u);
    CHECK_ERR(br_roc_estimate(0x0000, 0x8001, 5, &out), BR_OK);
    CHECK_EQ_U32(out, 6u);
    tu_rng_seed(&rng, 0x20C0u);
    for (unsigned it = 0; it < 30000; it++) {
        uint16_t seq = (uint16_t)tu_rng_below(&rng, 65536), sl = (uint16_t)tu_rng_below(&rng, 65536);
        uint32_t roc = (it % 7 == 0) ? 0u : (it % 11 == 0) ? UINT32_MAX : (uint32_t)tu_rng_below(&rng, 100000);
        uint32_t want = 0, got = 0xDEAD;
        int wrc = tu_ref_roc(seq, sl, roc, &want);
        br_err_t rc = br_roc_estimate(seq, sl, roc, &got);
        CHECK_ERR(rc, wrc);
        if (wrc == BR_OK) {
            CHECK_EQ_U32(got, want);
        }
    }
}

static void test_a15_sizes(void)
{
    tu_ctx("A.15 frame budget");
    static const struct { uint8_t type; size_t plen; uint32_t expect; const char *name; } sz[] = {
        {BR_TYPE_SEEK, 18, BRV_A15_SIZE_SEEK, "SEEK"},
        {BR_TYPE_HELLO, 28, BRV_A15_SIZE_HELLO, "HELLO"},
        {BR_TYPE_BIND, 17, BRV_A15_SIZE_BIND, "BIND"},
        {BR_TYPE_BIND_ACK, 12, BRV_A15_SIZE_BIND_ACK, "BIND_ACK"},
        {BR_TYPE_BIND_NAK, 9, BRV_A15_SIZE_BIND_NAK, "BIND_NAK"},
        {BR_TYPE_RESUME, 5, BRV_A15_SIZE_RESUME, "RESUME"},
        {BR_TYPE_RESUME_ACK, 6, BRV_A15_SIZE_RESUME_ACK, "RESUME_ACK"},
        {BR_TYPE_MGMT_REQ, BR_LEN_MGMT_REQ_FIXED, BRV_A15_SIZE_MGMT_REQ_FIXED, "MGMT_REQ fixed"},
        {BR_TYPE_MGMT_RESP, BR_LEN_MGMT_RESP_FIXED + 3u, BRV_A15_SIZE_MGMT_RESP_FIXED_PLUS_CMD_TLV,
         "MGMT_RESP fixed + cmd TLV (type, len, 1 byte)"},
    };
    CHECK_EQ_U32(BRV_A15_IR_PATH, 74u);
    CHECK_EQ_U32(BRV_A15_IR_PATH, BR_MAX_FRAME_IR - BR_RS_NSYM_IR);
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        tu_ctx(sz[i].name);
        br_hdr_t h;
        memset(&h, 0, sizeof h);
        h.version = 1;
        h.flags = BR_FLAG_AUTH;
        h.type = sz[i].type;
        h.src_id = 0x20;
        h.dst_id = 0x21;
        h.prev_hop = 0x20;
        h.next_hop = 0x21;
        h.ttl = 1;
        h.hop_seq = 0x100;
        h.path_mtu = 74;
        uint8_t pay[64] = {0};
        uint8_t at[8] = {0}, ht[4] = {0};
        uint8_t out[128];
        size_t ol = 0;
        CHECK_ERR(br_frame_encode(&h, pay, sz[i].plen, at, ht, out, sizeof out, &ol), BR_OK);
        CHECK_EQ_U32(ol, sz[i].expect);
        CHECK(ol <= BRV_A15_IR_PATH);
        /* with the 6 RS parity bytes the whole frame fits the 80-byte IR carrier and the validator takes it */
        uint8_t wire[128];
        size_t wl = tu_ref_build(&(tu_ref_hdr_t){.version = 1, .flags = BR_FLAG_AUTH, .type = sz[i].type, .src = 0x20,
                                                 .dst = 0x21, .prev = 0x20, .next = 0x21, .ttl = 1, .hops = 0,
                                                 .hop_seq = 0x100, .path_mtu = 74, .path_cost = 0, .session_id = 0,
                                                 .seq = 0, .len = 0, .hdr_len = 0},
                                 pay, sz[i].plen, NULL, 6, wire);
        CHECK_EQ_U32(wl, sz[i].expect + 6u);
        CHECK(wl <= 80u);
        EXPECT(wire, wl, LK_IR, true, BR_REJ_NONE);
    }
    CHECK_EQ_U32(BRV_A15_SEEK_ON_AIR_LEN, BRV_A15_SEEK_FRAME_LEN + BRV_A15_SEEK_RS_PARITY_LEN);
    CHECK_EQ_U32(BRV_A15_HELLO_ON_AIR_LEN, BRV_A15_HELLO_FRAME_LEN + BRV_A15_HELLO_RS_PARITY_LEN);
}

/* A frame built by the vectors' own recipe must be rejected one rule at a time starting from a vector. */
static void test_vector_breaks(void)
{
    uint8_t wire[BUFSZ], g[BUFSZ];
    for (size_t i = 0; i < TU_N_FRAME_VECS; i++) {
        const tu_frame_vec_t *v = &TU_FRAME_VECS[i];
        tu_ctx(v->name);
        size_t wl = tu_vec_wire(v, wire);
        tu_link_t lk = {v->max_frame, v->rs_nsym};
        bool seek = v->frame[1] == 0x01;
        /* header row failures */
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_TTL, 9);
        EXPECT(g, wl, lk, true, BR_REJ_TTL);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_HOPS, 8);
        EXPECT(g, wl, lk, true, BR_REJ_HOPS);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_PREV, 0);
        EXPECT(g, wl, lk, true, BR_REJ_PREV_HOP);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_SRC, 0xFF10);
        EXPECT(g, wl, lk, true, BR_REJ_SRC_ID);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_NEXT, 0xFF10);
        EXPECT(g, wl, lk, true, BR_REJ_NEXT_HOP);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_DST, 0);
        EXPECT(g, wl, lk, true, BR_REJ_DST_ID);
        memcpy(g, wire, wl);
        mut(g, wl, v->rs_nsym, F_VER, 2);
        EXPECT(g, wl, lk, true, BR_REJ_VERSION);
        EXPECT(g, wl, lk, false, BR_REJ_NONE); /* forwarders accept any version */
        if (seek) {
            memcpy(g, wire, wl);
            mut(g, wl, v->rs_nsym, F_MTU, 47);
            EXPECT(g, wl, lk, true, BR_REJ_PATH_MTU);
            memcpy(g, wire, wl);
            mut(g, wl, v->rs_nsym, F_MTU, (uint32_t)(v->max_frame - v->rs_nsym + 1u));
            EXPECT(g, wl, lk, true, BR_REJ_PATH_MTU);
            memcpy(g, wire, wl);
            mut(g, wl, v->rs_nsym, F_COST, 251);
            EXPECT(g, wl, lk, true, BR_REJ_PATH_COST);
        }
        /* crc */
        memcpy(g, wire, wl);
        g[v->len - 2u] ^= 0x01;
        EXPECT(g, wl, lk, true, BR_REJ_CRC);
        /* length mismatch with a valid CRC */
        memcpy(g, wire, wl);
        g[seek ? 21 : 18] ^= 0x01;
        tu_ref_seal(g, wl, v->rs_nsym);
        EXPECT(g, wl, lk, true, BR_REJ_LEN_MISMATCH);
        /* short */
        EXPECT(wire, (seek ? 22u : 19u) + 1u + v->rs_nsym, lk, true, BR_REJ_LEN_SHORT);
    }
}

int main(void)
{
    test_le_helpers();
    test_hdr_len();
    test_a2_fields();
    test_hdr_codec_args();
    test_vector_roundtrips();
    test_hop_fields_errors();
    test_frame_encode_rules();
    test_validator_args();
    test_len_rows();
    test_crc_row();
    test_header_rows();
    test_seek_rows();
    test_version_row();
    test_counters();
    test_hop_seq();
    test_type_len();
    test_clear_len_and_pre_ctr();
    test_seq_roc();
    test_a15_sizes();
    test_vector_breaks();
    return tu_summary("test_frame");
}
