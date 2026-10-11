// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_fuzz_validator.c - deterministic fuzzing of the receive validator and
 * the decoders (spec 3.6; Appendix A frames as seeds).
 *
 *   ./test_fuzz_validator [iterations [seed]]
 *
 * Default iteration count is BR_FUZZ_ITERS (1,000,000); override at compile
 * time with -DBR_FUZZ_ITERS=n or at run time with argv[1].
 *
 * Per iteration:
 *   - the frame goes to br_frame_validate() on a random link as endpoint and as
 *     forwarder; the result must be accept or a named stateless reject
 *     (never anything else), must equal the independent reference validator in
 *     test_util.h, and an accepted frame must re-encode to the same bytes;
 *   - the same bytes go through the header decoder, set_hop_fields, type/len and
 *     clear_len/pre_ctr helpers, COBS, RS, FEC header/block decoders and the
 *     counter helpers, each on an exact-size heap copy so ASan sees any overread.
 * Run clean under -DBR_SANITIZE=ON.
 */
#include <errno.h>

#include "braid/br_cobs.h"
#include "braid/br_fec.h"
#include "braid/br_frame.h"
#include "braid/br_rs.h"
#include "test_util.h"
#include "test_vectab.h"

#ifndef BR_FUZZ_ITERS
#define BR_FUZZ_ITERS 1000000ull
#endif

#define BUFCAP 640

static const tu_link_t LINKS[] = {{250, 0}, {250, 8}, {80, 6}, {400, 0}, {400, 8}, {255, 0}, {80, 0}, {250, 6}};
#define N_LINKS (sizeof LINKS / sizeof LINKS[0])

static unsigned long hist[BR_REJ_REPLAY + 1];
static unsigned long accepted_ep, accepted_fwd;
static unsigned long mismatch_vs_oracle;

static tu_rng_t rng;

static uint16_t pick_id(void)
{
    static const uint16_t interesting[] = {0x0000, 0x0001, 0x0002, 0x0003, 0x000F, 0x0010, 0x0042, 0x1234, 0xFEFF,
                                           0xFF00, 0xFF01, 0xFFFE, 0xFFFF, 0x0099};
    if (tu_rng_below(&rng, 10) < 7) {
        return interesting[tu_rng_below(&rng, sizeof interesting / sizeof interesting[0])];
    }
    return (uint16_t)tu_rng_below(&rng, 65536);
}

static uint8_t pick_type(void)
{
    static const uint8_t known[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x20, 0x21, 0x30, 0x31,
                                    0x32, 0x40, 0x41};
    if (tu_rng_below(&rng, 10) < 8) {
        return known[tu_rng_below(&rng, sizeof known)];
    }
    return tu_rng_u8(&rng);
}

/** Build a structured random frame; returns its length. */
static size_t gen_structured(uint8_t *out, tu_link_t lk)
{
    tu_ref_hdr_t h;
    tu_ref_default_hdr(&h, pick_type());
    h.version = (uint8_t)(tu_rng_below(&rng, 10) < 7 ? 1u : tu_rng_below(&rng, 16));
    h.flags = (uint8_t)(tu_rng_below(&rng, 2) ? (0x02u | (tu_rng_below(&rng, 4) << 2) | tu_rng_below(&rng, 2)) : tu_rng_below(&rng, 16));
    h.src = pick_id();
    h.dst = pick_id();
    h.prev = pick_id();
    h.next = pick_id();
    h.ttl = (uint8_t)(tu_rng_below(&rng, 10) < 7 ? tu_rng_below(&rng, 9) : tu_rng_below(&rng, 16));
    h.hops = (uint8_t)(tu_rng_below(&rng, 10) < 7 ? tu_rng_below(&rng, 8) : tu_rng_below(&rng, 16));
    h.hop_seq = (uint32_t)tu_rng_next(&rng);
    static const uint16_t mtus[] = {0, 47, 48, 49, 74, 75, 80, 242, 243, 250, 251, 0xFFFF};
    h.path_mtu = tu_rng_below(&rng, 3) ? mtus[tu_rng_below(&rng, sizeof mtus / sizeof mtus[0])] : (uint16_t)tu_rng_below(&rng, 65536);
    static const uint8_t costs[] = {0, 1, 249, 250, 251, 255};
    h.path_cost = tu_rng_below(&rng, 3) ? costs[tu_rng_below(&rng, sizeof costs)] : tu_rng_u8(&rng);
    h.session_id = tu_rng_u8(&rng);
    h.seq = (uint16_t)tu_rng_below(&rng, 65536);
    bool auth = (h.flags & 0x02u) != 0;
    size_t cap = (auth ? 217u : 229u) - lk.rs_nsym;
    size_t plen;
    switch (tu_rng_below(&rng, 6)) {
    case 0: plen = cap; break;
    case 1: plen = cap + 1u; break;
    case 2: plen = (size_t)tu_rng_below(&rng, 256); break;
    case 3: plen = (size_t)lk.max_frame > 40u ? (size_t)lk.max_frame - 40u + tu_rng_below(&rng, 3) : 0u; break;
    default: plen = tu_rng_below(&rng, 60); break;
    }
    if (plen > 255) {
        plen = 255;
    }
    uint8_t pl[256];
    tu_rng_fill(&rng, pl, sizeof pl);
    size_t n = tu_ref_build(&h, pl, plen, NULL, lk.rs_nsym, out);
    if (tu_rng_below(&rng, 5) == 0) { /* inconsistent len field, valid CRC */
        size_t lo = (h.type == 0x01) ? 21u : 18u;
        out[lo] = (uint8_t)(out[lo] + (uint8_t)(1u + tu_rng_below(&rng, 3)) * (tu_rng_below(&rng, 2) ? 1u : 255u));
        tu_ref_seal(out, n, lk.rs_nsym);
    }
    return n;
}

/** Mutate buf[0..len) in place / by resizing; returns the new length (< BUFCAP - 8). */
static size_t mutate(uint8_t *b, size_t len)
{
    unsigned k = 1u + tu_rng_below(&rng, 6);
    for (unsigned i = 0; i < k; i++) {
        switch (tu_rng_below(&rng, 8)) {
        case 0: /* replace a byte */
            if (len) b[tu_rng_below(&rng, (uint32_t)len)] = tu_rng_u8(&rng);
            break;
        case 1: /* flip a bit */
            if (len) b[tu_rng_below(&rng, (uint32_t)len)] ^= (uint8_t)(1u << tu_rng_below(&rng, 8));
            break;
        case 2: /* truncate */
            if (len) len = tu_rng_below(&rng, (uint32_t)len + 1u);
            break;
        case 3: /* extend */
            if (len + 8 < BUFCAP) {
                size_t add = 1u + tu_rng_below(&rng, 6);
                tu_rng_fill(&rng, b + len, add);
                len += add;
            }
            break;
        case 4: /* delete a byte */
            if (len) {
                size_t at = tu_rng_below(&rng, (uint32_t)len);
                memmove(b + at, b + at + 1u, len - at - 1u);
                len--;
            }
            break;
        case 5: /* insert a byte */
            if (len + 8 < BUFCAP) {
                size_t at = tu_rng_below(&rng, (uint32_t)len + 1u);
                memmove(b + at + 1u, b + at, len - at);
                b[at] = tu_rng_u8(&rng);
                len++;
            }
            break;
        case 6: /* set a header byte to an edge value */
            if (len) b[tu_rng_below(&rng, len < 22 ? (uint32_t)len : 22u)] = (tu_rng_below(&rng, 2) ? 0x00u : 0xFFu);
            break;
        default: /* swap two bytes */
            if (len > 1) {
                size_t a = tu_rng_below(&rng, (uint32_t)len), c = tu_rng_below(&rng, (uint32_t)len);
                uint8_t t = b[a];
                b[a] = b[c];
                b[c] = t;
            }
            break;
        }
    }
    return len;
}

static void check_validator(const uint8_t *src, size_t len, tu_link_t lk)
{
    br_link_params_t lp = {lk.max_frame, lk.rs_nsym};
    for (int ep = 0; ep < 2; ep++) {
        uint8_t *d = tu_dup(src, len);
        br_frame_view_t view;
        memset(&view, 0, sizeof view);
        br_reject_t r = (br_reject_t)99;
        br_err_t rc = br_frame_validate(d, len, &lp, ep == 1, &view, &r);
        CHECK(rc == BR_OK || rc == BR_ERR_REJECT);
        CHECK((int)r >= (int)BR_REJ_NONE && (int)r <= (int)BR_REJ_VERSION); /* stateless rows only */
        CHECK((rc == BR_OK) == (r == BR_REJ_NONE));
        if ((int)r >= 0 && (int)r <= (int)BR_REJ_REPLAY) {
            hist[r]++;
            br_counter_t c = (br_counter_t)99;
            CHECK_ERR(br_reject_counter(r, &c), BR_OK);
            CHECK((r == BR_REJ_NONE) == (c == BR_CNT_NONE));
        }
        /* independent reference */
        br_reject_t want = tu_map_reason(tu_ref_validate(src, len, &lk, ep == 1));
        if (r != want) {
            mismatch_vs_oracle++;
        }
        CHECK(r == want);
        if (rc == BR_OK) {
            if (ep) accepted_ep++; else accepted_fwd++;
            /* view invariants */
            tu_ref_hdr_t h;
            tu_ref_parse(src, &h);
            CHECK(view.hdr_len == h.hdr_len);
            CHECK(view.payload_off == h.hdr_len);
            CHECK(view.payload_len == h.len);
            CHECK(view.has_auth == ((h.flags & 2u) != 0));
            CHECK(view.rs_nsym == lk.rs_nsym);
            CHECK(view.total_len == len);
            CHECK(view.crc_off + 2u + lk.rs_nsym == len);
            CHECK(view.rs_off == view.crc_off + 2u);
            CHECK(view.crc_off == h.hdr_len + h.len + (view.has_auth ? 12u : 0u));
            CHECK(view.crc == tu_get16(src + view.crc_off));
            if (view.has_auth) {
                CHECK(view.auth_tag_off == h.hdr_len + h.len);
                CHECK(view.hop_tag_off == view.auth_tag_off + 8u);
            }
            /* accepted frames re-encode to the same bytes */
            br_hdr_t hd;
            size_t hl = 0;
            CHECK_ERR(br_hdr_decode(src, len, &hd, &hl), BR_OK);
            uint8_t out[BUFCAP];
            size_t ol = 0;
            const uint8_t *atag = view.has_auth ? src + view.auth_tag_off : NULL;
            const uint8_t *htag = view.has_auth ? src + view.hop_tag_off : NULL;
            memset(out, 0xEE, sizeof out);
            br_err_t erc = br_frame_encode(&hd, src + view.payload_off, view.payload_len, atag, htag, out, sizeof out, &ol);
            CHECK_ERR(erc, BR_OK);
            if (erc == BR_OK) {
                CHECK(ol == view.crc_off + 2u);
                CHECK_MEM(src, out, ol);
            }
            uint8_t hb[32];
            size_t hw = 0;
            if (br_hdr_encode(&hd, hb, sizeof hb, &hw) == BR_OK) {
                CHECK(hw == hl);
                CHECK_MEM(src, hb, hl);
            } else {
                CHECK_MSG(false, "br_hdr_encode failed on a decoded header");
            }
            /* per-type helpers on the validated frame */
            br_reject_t tr = (br_reject_t)99;
            br_err_t trc = br_frame_check_type_len(hd.type, hd.len, &tr);
            CHECK(trc == BR_OK || trc == BR_ERR_REJECT);
            CHECK((trc == BR_OK) == (tr == BR_REJ_NONE));
            CHECK(tr == BR_REJ_NONE || tr == BR_REJ_TYPE_LEN);
            size_t cl = 12345;
            br_err_t crc2 = br_frame_clear_len(hd.type, hd.session_id, hd.len, &cl);
            CHECK(crc2 == BR_OK || crc2 == BR_ERR_DECODE);
            if (crc2 == BR_OK) {
                CHECK(cl <= hd.len);
            }
            uint32_t pc = 0;
            br_reject_t pr = (br_reject_t)99;
            br_err_t prc = br_frame_pre_ctr(d, &view, &pc, &pr);
            CHECK(prc == BR_OK || prc == BR_ERR_REJECT || prc == BR_ERR_ARG);
            if (prc == BR_ERR_REJECT) {
                CHECK(pr == BR_REJ_PRE_CTR_SEQ || pr == BR_REJ_TYPE_LEN);
            } else if (prc == BR_OK) {
                CHECK(pr == BR_REJ_NONE);
                CHECK(hd.len >= 4u);
                CHECK(pc == tu_get32(src + view.payload_off));
                if (hd.session_id == 0) {
                    CHECK((uint16_t)(pc & 0xFFFFu) == hd.seq);
                }
            }
        }
        free(d);
    }
}

static void check_decoders(const uint8_t *src, size_t len, unsigned it)
{
    /* header decode on whatever bytes arrived */
    {
        uint8_t *d = tu_dup(src, len);
        br_hdr_t hd;
        size_t hl = 99;
        br_err_t rc = br_hdr_decode(d, len, &hd, &hl);
        bool should = len >= 2 && len >= (src[1] == 0x01 ? 22u : 19u);
        CHECK((rc == BR_OK) == should);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE);
        if (rc == BR_OK) {
            tu_ref_hdr_t h;
            tu_ref_parse(src, &h);
            CHECK(hl == h.hdr_len);
            CHECK(hd.version == h.version && hd.flags == h.flags && hd.type == h.type);
            CHECK(hd.src_id == h.src && hd.dst_id == h.dst && hd.prev_hop == h.prev && hd.next_hop == h.next);
            CHECK(hd.ttl == h.ttl && hd.hops == h.hops && hd.hop_seq == h.hop_seq);
            CHECK(hd.session_id == h.session_id && hd.seq == h.seq && hd.len == h.len);
            CHECK(hd.path_mtu == h.path_mtu && hd.path_cost == h.path_cost);
            /* round trip of the header bytes */
            uint8_t hb[32];
            size_t hw = 0;
            CHECK_ERR(br_hdr_encode(&hd, hb, sizeof hb, &hw), BR_OK);
            CHECK(hw == hl);
            CHECK_MEM(src, hb, hl);
            /* rewriting the per-hop fields with random valid values */
            br_hop_fields_t hf;
            hf.prev_hop = pick_id();
            hf.next_hop = pick_id();
            hf.ttl = (uint8_t)tu_rng_below(&rng, 16);
            hf.hops = (uint8_t)tu_rng_below(&rng, 16);
            hf.hop_seq = (uint32_t)tu_rng_next(&rng);
            hf.path_mtu = (uint16_t)tu_rng_below(&rng, 65536);
            hf.path_cost = tu_rng_u8(&rng);
            CHECK_ERR(br_frame_set_hop_fields(d, len, &hf), BR_OK);
            tu_ref_hdr_t h2;
            tu_ref_parse(d, &h2);
            CHECK(h2.prev == hf.prev_hop && h2.next == hf.next_hop && h2.ttl == hf.ttl && h2.hops == hf.hops);
            CHECK(h2.hop_seq == hf.hop_seq);
            CHECK(h2.src == h.src && h2.dst == h.dst && h2.type == h.type && h2.session_id == h.session_id);
            CHECK(h2.seq == h.seq && h2.len == h.len && h2.version == h.version && h2.flags == h.flags);
            if (h.type == 0x01) {
                CHECK(h2.path_mtu == hf.path_mtu && h2.path_cost == hf.path_cost);
            } else {
                CHECK(h2.path_mtu == 0 && h2.path_cost == 0);
            }
            CHECK(memcmp(d + hl, src + hl, len - hl) == 0); /* nothing beyond the header touched */
        } else {
            br_hop_fields_t hf = {1, 2, 3, 4, 5, 6, 7};
            br_err_t rc2 = br_frame_set_hop_fields(d, len, &hf);
            CHECK(rc2 == BR_ERR_DECODE);
        }
        free(d);
    }
    /* type/len for every type byte present, payload length from the header field */
    if (len >= 19) {
        br_reject_t tr = (br_reject_t)99;
        br_err_t rc = br_frame_check_type_len(src[1], src[len >= 22 && src[1] == 0x01 ? 21 : 18], &tr);
        CHECK(rc == BR_OK || rc == BR_ERR_REJECT);
        CHECK((rc == BR_OK) == (tr == BR_REJ_NONE));
        size_t cl = 0;
        rc = br_frame_clear_len(src[1], src[15], src[18], &cl);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE);
    }
    /* counters and numeric helpers */
    {
        uint16_t a = (uint16_t)tu_rng_below(&rng, 65536), b = (uint16_t)tu_rng_below(&rng, 65536);
        bool nw = false;
        CHECK_ERR(br_seq16_newer(a, b, &nw), BR_OK);
        CHECK(nw == tu_ref_seq16_newer(a, b));
        uint32_t roc = (it & 31u) == 0 ? 0u : (it & 31u) == 1 ? UINT32_MAX : (uint32_t)tu_rng_next(&rng);
        uint32_t out = 0, want = 0;
        int wrc = tu_ref_roc(a, b, roc, &want);
        br_err_t rc = br_roc_estimate(a, b, roc, &out);
        CHECK_ERR(rc, wrc);
        if (wrc == BR_OK) {
            CHECK(out == want);
        }
        uint32_t last = (uint32_t)tu_rng_next(&rng);
        uint32_t rx = (it & 1u) ? last + tu_rng_below(&rng, 70000) : (uint32_t)tu_rng_next(&rng);
        br_reject_t r = (br_reject_t)99;
        bool have = (it & 7u) != 0;
        bool ok = !have || (rx > last && rx - last <= 65536u);
        CHECK_ERR(br_hop_seq_check(have, last, rx, &r), ok ? BR_OK : BR_ERR_REJECT);
        CHECK(r == (ok ? BR_REJ_NONE : BR_REJ_HOP_REPLAY));
    }
    /* COBS: decode arbitrary bytes into an exact-size buffer; encode/decode round trip */
    if ((it & 3u) == 0 && len >= 1) {
        uint8_t *s = tu_dup(src, len);
        uint8_t *dst = tu_alloc(len);
        size_t dn = 0;
        br_err_t rc = br_cobs_decode(s, len, dst, len, &dn);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE || rc == BR_ERR_ARG || rc == BR_ERR_TOO_BIG);
        if (rc == BR_OK) {
            CHECK(dn <= len);
        }
        free(dst);
        free(s);
        size_t cap = BR_COBS_MAX_ENCODED(len);
        uint8_t *enc = tu_alloc(cap);
        size_t en = 0;
        uint8_t *srcd = tu_dup(src, len);
        CHECK_ERR(br_cobs_encode(srcd, len, enc, cap, &en), BR_OK);
        if (en >= 2 && en <= cap) {
            uint8_t *back = tu_alloc(len);
            size_t bn = 0;
            CHECK_ERR(br_cobs_decode(enc, en, back, len, &bn), BR_OK);
            CHECK(bn == len);
            CHECK_MEM(src, back, len);
            free(back);
        }
        free(srcd);
        free(enc);
    }
    /* Reed-Solomon: random codeword decode, and encode / damage / decode */
    if ((it & 15u) == 0 && len >= 3) {
        unsigned nsym = 1u + tu_rng_below(&rng, (uint32_t)(len - 1u < BR_RS_MAX_NSYM ? len - 1u : BR_RS_MAX_NSYM));
        size_t cl = len > 255 ? 255 : len;
        if (cl > nsym) {
            uint8_t *w = tu_dup(src, cl);
            uint8_t *orig = tu_dup(src, cl);
            br_err_t rc = br_rs_decode(w, cl, (uint8_t)nsym, NULL, 0, NULL);
            CHECK(rc == BR_OK || rc == BR_ERR_UNCORRECTABLE);
            if (rc == BR_OK) {
                uint8_t par[BR_RS_MAX_NSYM];
                tu_ref_rs_encode(w, cl - nsym, nsym, par);
                CHECK_MEM(par, w + cl - nsym, nsym);
            } else {
                CHECK_MEM(orig, w, cl);
            }
            free(w);
            free(orig);
        }
        size_t ml = len;
        if (ml + nsym > 255) {
            ml = 255 - nsym;
        }
        uint8_t par[BR_RS_MAX_NSYM];
        uint8_t *m = tu_dup(src, ml);
        if (br_rs_encode(m, ml, (uint8_t)nsym, par) == BR_OK) {
            uint8_t ref[BR_RS_MAX_NSYM];
            tu_ref_rs_encode(m, ml, nsym, ref);
            CHECK_MEM(ref, par, nsym);
            uint8_t *cw = tu_alloc(ml + nsym);
            memcpy(cw, m, ml);
            memcpy(cw + ml, par, nsym);
            uint8_t *orig = tu_dup(cw, ml + nsym);
            unsigned e = tu_rng_below(&rng, nsym / 2u + 1u);
            for (unsigned i = 0; i < e; i++) { /* distinct positions */
                size_t at;
                bool dup;
                do {
                    at = tu_rng_below(&rng, (uint32_t)(ml + nsym));
                    dup = false;
                    for (size_t j = 0; j < ml + nsym; j++) {
                        if (cw[j] != orig[j] && j == at) {
                            dup = true;
                        }
                    }
                } while (dup);
                cw[at] ^= (uint8_t)(1u + tu_rng_below(&rng, 255));
            }
            CHECK_ERR(br_rs_decode(cw, ml + nsym, (uint8_t)nsym, NULL, 0, NULL), BR_OK);
            CHECK_MEM(orig, cw, ml + nsym);
            free(cw);
            free(orig);
        } else {
            CHECK_MSG(false, "br_rs_encode failed on valid arguments");
        }
        free(m);
    }
    /* FEC PARITY header and block decoders on arbitrary bytes */
    if ((it & 7u) == 1u) {
        uint8_t *s = tu_dup(src, len);
        br_fec_parity_hdr_t ph;
        br_err_t rc = br_fec_parity_hdr_decode(s, len, &ph);
        CHECK(rc == BR_OK || rc == BR_ERR_DECODE);
        CHECK((rc == BR_OK) == (len >= 8 && tu_get16(src + 5) == len - 8u));
        if (rc == BR_OK) {
            CHECK(ph.first_seq == tu_get16(src) && ph.k == src[2] && ph.m == src[3] && ph.idx == src[4]);
            CHECK(ph.block_len == tu_get16(src + 5) && ph.reserved == src[7]);
            uint8_t hb[8];
            br_err_t erc = br_fec_parity_hdr_encode(&ph, hb, sizeof hb);
            bool valid = ph.k >= 1 && ph.k <= 16 && ph.m >= 1 && ph.m <= 4 && ph.idx < ph.m && ph.block_len >= 1 &&
                         ph.block_len <= BR_FEC_MAX_BLOCK_LEN;
            CHECK((erc == BR_OK) == valid);
            if (erc == BR_OK) {
                CHECK_MEM(src, hb, 8);
            }
        }
        const uint8_t *pp = NULL;
        uint8_t pn = 0;
        if (len >= 1 && len <= BR_FEC_MAX_BLOCK_LEN) {
            br_err_t brc = br_fec_payload_from_block(s, (uint16_t)len, &pp, &pn);
            CHECK(brc == BR_OK || brc == BR_ERR_DECODE);
            if (brc == BR_OK) {
                CHECK(pp == s + 1 && (size_t)pn + 1u <= len);
            }
        } else if (len > BR_FEC_MAX_BLOCK_LEN) {
            CHECK_ERR(br_fec_payload_from_block(s, (uint16_t)len, &pp, &pn), BR_ERR_ARG);
        }
        free(s);
    }
}

int main(int argc, char **argv)
{
    unsigned long long iters = BR_FUZZ_ITERS;
    unsigned long long seed = 0xF0225EEDull;
    if (argc > 1) {
        char *end = NULL;
        errno = 0;
        unsigned long long v = strtoull(argv[1], &end, 0);
        if (errno != 0 || end == argv[1] || *end != '\0') {
            fprintf(stderr, "usage: %s [iterations [seed]]\n", argv[0]);
            return 2;
        }
        iters = v;
    }
    if (argc > 2) {
        seed = strtoull(argv[2], NULL, 0);
    }
    tu_rng_seed(&rng, seed);
    printf("test_fuzz_validator: %llu iterations, seed 0x%llx\n", iters, seed);

    uint8_t buf[BUFCAP];
    for (unsigned long long n = 0; n < iters; n++) {
        unsigned it = (unsigned)n;
        tu_link_t lk = LINKS[tu_rng_below(&rng, N_LINKS)];
        size_t len = 0;
        switch (it % 8u) {
        case 0: /* random bytes, short bias */
            len = (tu_rng_below(&rng, 4) == 0) ? tu_rng_below(&rng, 300) : tu_rng_below(&rng, 48);
            tu_rng_fill(&rng, buf, len);
            if (len > 0 && tu_rng_below(&rng, 2)) {
                buf[0] = (uint8_t)(0x12u | (tu_rng_below(&rng, 4) == 0 ? 0xE0u : 0u)); /* plausible ver_flags */
            }
            break;
        case 1:
        case 4:
        case 7: { /* mutated Appendix A frame, link usually its own */
            const tu_frame_vec_t *v = &TU_FRAME_VECS[tu_rng_below(&rng, TU_N_FRAME_VECS)];
            len = tu_vec_wire(v, buf);
            if (tu_rng_below(&rng, 10) < 7) {
                lk.max_frame = v->max_frame;
                lk.rs_nsym = v->rs_nsym;
            }
            if (it % 8u == 4u) { /* header-only damage then fix CRC so deeper rows run */
                unsigned k = 1u + tu_rng_below(&rng, 3);
                for (unsigned i = 0; i < k; i++) {
                    buf[tu_rng_below(&rng, 22)] = tu_rng_u8(&rng);
                }
                if (len >= (size_t)lk.rs_nsym + 2u) {
                    tu_ref_seal(buf, len, lk.rs_nsym);
                }
            } else {
                len = mutate(buf, len);
                if (len >= (size_t)lk.rs_nsym + 2u && tu_rng_below(&rng, 2)) {
                    tu_ref_seal(buf, len, lk.rs_nsym);
                }
            }
            break;
        }
        case 2:
        case 6: /* structured random header */
            len = gen_structured(buf, lk);
            break;
        case 3: /* the pristine vector, optionally with one flipped bit (CRC must catch it) */
        {
            const tu_frame_vec_t *v = &TU_FRAME_VECS[tu_rng_below(&rng, TU_N_FRAME_VECS)];
            len = tu_vec_wire(v, buf);
            lk.max_frame = v->max_frame;
            lk.rs_nsym = v->rs_nsym;
            if (tu_rng_below(&rng, 2)) {
                buf[tu_rng_below(&rng, (uint32_t)(v->len))] ^= (uint8_t)(1u << tu_rng_below(&rng, 8));
            }
            break;
        }
        default: /* random bytes with a valid CRC (and parity) */
            len = (size_t)lk.rs_nsym + 2u + (size_t)tu_rng_below(&rng, 250);
            if (len > 255) {
                len = 255;
            }
            tu_rng_fill(&rng, buf, len);
            buf[0] = (uint8_t)((buf[0] & 0x0Fu) | (tu_rng_below(&rng, 4) ? 0x10u : (buf[0] & 0xF0u)));
            tu_ref_seal(buf, len, lk.rs_nsym);
            break;
        }
        check_validator(buf, len, lk);
        check_decoders(buf, len, it);
    }

    /* coverage report and sanity */
    static const char *names[] = {"NONE", "LEN_SHORT", "LEN_MISMATCH", "LEN_PAYLOAD", "LEN_MAX_FRAME", "CRC", "TTL",
                                  "HOPS", "PREV_HOP", "SRC_ID", "NEXT_HOP", "DST_ID", "PATH_MTU", "PATH_COST", "VERSION"};
    printf("outcomes (endpoint + forwarder calls):");
    for (unsigned i = 0; i <= (unsigned)BR_REJ_VERSION; i++) {
        printf(" %s=%lu", names[i], hist[i]);
    }
    printf("\naccepted: endpoint %lu, forwarder %lu; differences from reference validator: %lu\n", accepted_ep,
           accepted_fwd, mismatch_vs_oracle);
    if (iters >= 100000ull) {
        for (unsigned i = 0; i <= (unsigned)BR_REJ_VERSION; i++) {
            CHECK_MSG(hist[i] > 0, names[i]); /* every stateless outcome must have been exercised */
        }
    }
    return tu_summary("test_fuzz_validator");
}
