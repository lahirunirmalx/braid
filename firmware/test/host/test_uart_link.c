// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_uart_link.c - host test of the UART transport adapter
 * (components/app_node/src/uart_link.c; spec 1.2 UART row, 3.2, 11.3,
 * 11.11, C.2; SPEC-NOTES N22, N42, N43).
 *
 * The adapter is portable C; this test compiles the real source file into
 * the executable (as test_console.c does with node_console.c). The byte
 * pipe below the adapter is a fake HAL (a capture buffer, or a pipe between
 * two adapters).
 *
 * Part 1  COBS stream reassembly against the fake HAL: arbitrary chunk
 *         boundaries, back-to-back frames, frames full of 0x00, garbage
 *         before a delimiter, oversize frames, loss reports, send errors.
 * Part 2  Spec vectors through the adapter: A.3 (UART SEEK, RS(8) + COBS:
 *         the adapter's wire output must equal BRV_A3_COBS_WIRE byte for
 *         byte) and A.15 (RS blocks of 60 and 67 bytes = *_ON_AIR_LEN).
 * Part 3  Bench allowlist on a RAW link (N43): the prev_hop check runs on an
 *         RS-corrected copy; uncorrectable frames go to the node (rs_fail).
 * Part 4  Two real br_node instances joined by two adapters and a byte pipe
 *         (sender 0x0101 <-> probe 0x0103 direct, bench key, AUTH on):
 *         SEEK -> HELLO -> BIND -> MODE -> STREAMING -> presses acked,
 *         clean; with <= rs_nsym / 2 corrupted bytes in EVERY RS block
 *         (RS corrects all of them); with > rs_nsym / 2 corrupted bytes in
 *         every third block (dropped and counted, ARQ recovers); with
 *         wire-level flips / deletions / insertions (COBS resync, session
 *         survives); and with an allowlist that excludes the peer.
 */
#include "braid/br_cobs.h"
#include "braid/br_node.h"
#include "braid/br_platform.h"
#include "braid/br_rs.h"
#include "braid/br_sample.h"
#include "braid/br_session.h"
#include "test_util.h"
#include "vectors_generated.h"

#include "../../components/app_node/src/uart_link.c"

/* ========================================================================= */
/* Fake HAL: capture buffer and frame sink                                    */
/* ========================================================================= */

typedef struct {
    uint8_t  buf[16384];
    size_t   len;
    bool     refuse;
    unsigned writes;
} cap_t;

static bool cap_write(void *ctx, const uint8_t *d, size_t n)
{
    cap_t *c = (cap_t *)ctx;
    if (c->refuse || c->len + n > sizeof c->buf) {
        return false;
    }
    memcpy(c->buf + c->len, d, n);
    c->len += n;
    c->writes++;
    return true;
}

#define SINK_MAX 64u

typedef struct {
    uint8_t  data[SINK_MAX][UART_LINK_MAX_FRAME];
    size_t   len[SINK_MAX];
    unsigned n;
} sink_t;

static void sink_frame(void *ctx, const uint8_t *f, size_t n)
{
    sink_t *s = (sink_t *)ctx;
    CHECK(n >= 1u && n <= UART_LINK_MAX_FRAME);
    if (s->n < SINK_MAX && n <= UART_LINK_MAX_FRAME) {
        memcpy(s->data[s->n], f, n);
        s->len[s->n] = n;
    }
    s->n++;
}

static cap_t CAP;
static sink_t SINK;
static uart_link_t L;

static void fresh(void)
{
    memset(&CAP, 0, sizeof CAP);
    memset(&SINK, 0, sizeof SINK);
    CHECK(uart_link_init(&L, cap_write, &CAP, sink_frame, &SINK));
}

static void feed_chunked(uart_link_t *l, const uint8_t *d, size_t n, size_t chunk)
{
    for (size_t i = 0; i < n; i += chunk) {
        size_t k = n - i < chunk ? n - i : chunk;
        uart_link_feed(l, d + i, k);
    }
}

static void feed_random(uart_link_t *l, const uint8_t *d, size_t n, tu_rng_t *r, uint32_t max_chunk)
{
    size_t i = 0;
    while (i < n) {
        size_t k = 1u + tu_rng_below(r, max_chunk);
        if (k > n - i) {
            k = n - i;
        }
        uart_link_feed(l, d + i, k);
        i += k;
    }
}

static uart_link_stats_t stats(const uart_link_t *l)
{
    uart_link_stats_t s;
    memset(&s, 0xA5, sizeof s);
    uart_link_get_stats(l, &s);
    return s;
}

/* ========================================================================= */
/* Part 1: reassembly                                                         */
/* ========================================================================= */

static void test_transport_fields(void)
{
    tu_ctx("transport fields (1.2 UART row)");
    fresh();
    br_transport_t tr;
    memset(&tr, 0, sizeof tr);
    tr.allowlist.enabled = true;
    tr.allowlist.n = 1;
    tr.allowlist.ids[0] = 0x0102;
    uart_link_fill_transport(&L, &tr);
    CHECK(strcmp(tr.name, "uart") == 0);
    CHECK(tr.link_class == BR_LINK_RAW);
    CHECK_EQ_U32(tr.max_frame, 250u);
    CHECK_EQ_U32(tr.rs_nsym, 8u);
    CHECK(!tr.can_broadcast);
    CHECK(!tr.mac_retry);
    CHECK(!tr.edge_only);
    CHECK_EQ_U32(tr.link_cost, 1u);
    CHECK_EQ_U32(tr.addr_len, 0u);
    CHECK(tr.send == uart_link_send);
    CHECK(tr.user == &L);
    CHECK(tr.allowlist.enabled && tr.allowlist.n == 1u && tr.allowlist.ids[0] == 0x0102u); /* untouched */
    CHECK_EQ_U32(UART_LINK_WIRE_MAX, 252u);
    CHECK_EQ_U32(UART_LINK_ENC_MAX, 251u);
    uart_link_fill_transport(&L, NULL); /* tolerated */
    CHECK(!uart_link_init(NULL, cap_write, &CAP, sink_frame, &SINK));
    CHECK(!uart_link_init(&L, NULL, &CAP, sink_frame, &SINK));
    CHECK(!uart_link_init(&L, cap_write, &CAP, NULL, &SINK));
}

static void test_start_and_idle_delimiters(void)
{
    tu_ctx("start delimiter, idle delimiters");
    fresh();
    CHECK(uart_link_start(&L));
    CHECK_EQ_U32(CAP.len, 1u);
    CHECK_EQ_U32(CAP.buf[0], 0x00u);
    CHECK(!uart_link_start(NULL));
    static const uint8_t idle[] = {0x00, 0x00, 0x00};
    uart_link_feed(&L, idle, sizeof idle);
    uart_link_stats_t s = stats(&L);
    CHECK_EQ_U32(SINK.n, 0u);
    CHECK_EQ_U32(s.cobs_err, 0u);
    CHECK_EQ_U32(s.oversize, 0u);
    CHECK_EQ_U32(s.resyncs, 0u);
    CHECK_EQ_U32(s.rx_bytes, 3u);
    uart_link_feed(&L, NULL, 5); /* tolerated */
    uart_link_feed(NULL, idle, 1);
}

/* Six frames covering the COBS corner cases; returns the count. */
#define NF 6u
static uint8_t F[NF][UART_LINK_MAX_FRAME];
static size_t FL[NF];

static void build_frames(tu_rng_t *r)
{
    /* 0: 250 x 0x00 */
    memset(F[0], 0, 250);
    FL[0] = 250;
    /* 1: a single byte */
    F[1][0] = 0x7F;
    FL[1] = 1;
    /* 2: 250 non-zero bytes (largest COBS block: 251 bytes + delimiter) */
    for (size_t i = 0; i < 250; i++) {
        F[2][i] = (uint8_t)(1u + tu_rng_below(r, 255));
    }
    FL[2] = 250;
    /* 3: alternating 0x00 / 0xAA */
    for (size_t i = 0; i < 100; i++) {
        F[3][i] = (i & 1u) ? 0xAAu : 0x00u;
    }
    FL[3] = 100;
    /* 4: random bytes with zeros */
    tu_rng_fill(r, F[4], 200);
    F[4][0] = 0;
    F[4][199] = 0;
    FL[4] = 200;
    /* 5: a single 0x00 */
    F[5][0] = 0x00;
    FL[5] = 1;
}

static size_t encode_all(uint8_t *wire)
{
    size_t total = 0;
    for (unsigned k = 0; k < NF; k++) {
        size_t before = CAP.len;
        CHECK_ERR(uart_link_send(&L, NULL, F[k], (uint16_t)FL[k]), BR_OK);
        /* independent oracle (test_util.h, eager = N15 convention) */
        uint8_t ref[UART_LINK_WIRE_MAX + 4];
        size_t rl = tu_ref_cobs_encode(F[k], FL[k], ref, true);
        CHECK_EQ_U32(CAP.len - before, rl);
        if (CAP.len - before == rl) {
            CHECK_MEM(ref, CAP.buf + before, rl);
        }
        CHECK(CAP.len - before <= UART_LINK_WIRE_MAX);
        for (size_t i = before; i + 1u < CAP.len; i++) {
            CHECK(CAP.buf[i] != 0x00u); /* only the delimiter is zero */
        }
        CHECK_EQ_U32(CAP.buf[CAP.len - 1u], 0x00u);
    }
    memcpy(wire, CAP.buf, CAP.len);
    total = CAP.len;
    return total;
}

static void expect_all_frames(const char *what)
{
    tu_ctx(what);
    CHECK_EQ_U32(SINK.n, NF);
    for (unsigned k = 0; k < NF && k < SINK.n; k++) {
        CHECK_EQ_U32(SINK.len[k], FL[k]);
        if (SINK.len[k] == FL[k]) {
            CHECK_MEM(F[k], SINK.data[k], FL[k]);
        }
    }
    uart_link_stats_t s = stats(&L);
    CHECK_EQ_U32(s.cobs_err, 0u);
    CHECK_EQ_U32(s.oversize, 0u);
    CHECK_EQ_U32(s.resyncs, 0u);
    CHECK_EQ_U32(s.rx_frames, NF);
}

static void test_chunk_boundaries(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0xC0B5u);
    build_frames(&r);
    static uint8_t wire[NF * UART_LINK_WIRE_MAX];

    tu_ctx("encode six frames");
    fresh();
    size_t n = encode_all(wire);
    uart_link_stats_t s = stats(&L);
    CHECK_EQ_U32(s.tx_frames, NF);
    CHECK_EQ_U32(s.tx_bytes, (uint32_t)n);

    /* every fixed chunk size 1..n: back-to-back frames split everywhere */
    unsigned bad = 0;
    for (size_t chunk = 1; chunk <= n; chunk++) {
        memset(&SINK, 0, sizeof SINK);
        memset(&L.st, 0, sizeof L.st);
        L.acc_len = 0;
        L.discarding = false;
        feed_chunked(&L, wire, n, chunk);
        if (SINK.n != NF || L.st.cobs_err != 0u) {
            bad++;
        }
        for (unsigned k = 0; k < NF && k < SINK.n; k++) {
            if (SINK.len[k] != FL[k] || memcmp(F[k], SINK.data[k], FL[k]) != 0) {
                bad++;
            }
        }
    }
    tu_ctx("fixed chunk sizes 1..n");
    CHECK_EQ_U32(bad, 0u);

    /* random chunking, many seeds */
    for (uint64_t seed = 1; seed <= 200; seed++) {
        tu_rng_t cr;
        tu_rng_seed(&cr, seed);
        memset(&SINK, 0, sizeof SINK);
        memset(&L.st, 0, sizeof L.st);
        feed_random(&L, wire, n, &cr, 1u + (uint32_t)(seed % 64u));
        if (SINK.n != NF) {
            bad++;
        }
        for (unsigned k = 0; k < NF && k < SINK.n; k++) {
            if (SINK.len[k] != FL[k] || memcmp(F[k], SINK.data[k], FL[k]) != 0) {
                bad++;
            }
        }
    }
    tu_ctx("random chunking, 200 seeds");
    CHECK_EQ_U32(bad, 0u);

    /* one call with everything */
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_feed(&L, wire, n);
    expect_all_frames("single feed of the whole stream");
}

static void test_garbage_before_delimiter(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0x6A5Bu);
    build_frames(&r);
    static uint8_t wire[NF * UART_LINK_WIRE_MAX];
    fresh();
    size_t n = encode_all(wire);

    tu_ctx("invalid COBS garbage, then a delimiter");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    static const uint8_t junk[] = {0x09, 0x11, 0x22, 0x00}; /* code 9 needs 8 bytes, has 2 */
    uart_link_feed(&L, junk, sizeof junk);
    CHECK_EQ_U32(L.st.cobs_err, 1u);
    CHECK_EQ_U32(SINK.n, 0u);
    feed_chunked(&L, wire, n, 5);
    CHECK_EQ_U32(SINK.n, NF);
    CHECK_EQ_U32(L.st.cobs_err, 1u);

    tu_ctx("valid-looking garbage is delivered as a block (the node drops it by RS / CRC)");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    static const uint8_t junk2[] = {0x03, 0x41, 0x42, 0x00};
    uart_link_feed(&L, junk2, sizeof junk2);
    CHECK_EQ_U32(SINK.n, 1u);
    CHECK_EQ_U32(SINK.len[0], 2u);
    CHECK_EQ_U32(L.st.cobs_err, 0u);

    tu_ctx("a lone code byte 0x01 (empty block) is not a frame");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    static const uint8_t junk3[] = {0x01, 0x00};
    uart_link_feed(&L, junk3, sizeof junk3);
    CHECK_EQ_U32(SINK.n, 0u);
    CHECK_EQ_U32(L.st.cobs_err, 1u);

    tu_ctx("random garbage before a delimiter, 100 rounds");
    unsigned lost = 0;
    for (uint64_t seed = 1; seed <= 100; seed++) {
        tu_rng_t gr;
        tu_rng_seed(&gr, seed * 7919u);
        uint8_t g[64];
        size_t gl = 1u + tu_rng_below(&gr, sizeof g);
        for (size_t i = 0; i < gl; i++) {
            g[i] = (uint8_t)(1u + tu_rng_below(&gr, 255));
        }
        memset(&SINK, 0, sizeof SINK);
        L.acc_len = 0;
        L.discarding = false;
        uart_link_feed(&L, g, gl);
        static const uint8_t z = 0x00;
        uart_link_feed(&L, &z, 1);
        unsigned junk_frames = SINK.n;
        feed_random(&L, wire, n, &gr, 40);
        if (SINK.n != junk_frames + NF) {
            lost++;
        }
        for (unsigned k = 0; k < NF && junk_frames + k < SINK.n && junk_frames + k < SINK_MAX; k++) {
            if (SINK.len[junk_frames + k] != FL[k] || memcmp(F[k], SINK.data[junk_frames + k], FL[k]) != 0) {
                lost++;
            }
        }
    }
    CHECK_EQ_U32(lost, 0u);
}

static void test_oversize(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0x0B16u);
    build_frames(&r);
    static uint8_t wire[NF * UART_LINK_WIRE_MAX];
    fresh();
    size_t n = encode_all(wire);
    uint8_t big[2000];
    for (size_t i = 0; i < sizeof big; i++) {
        big[i] = (uint8_t)(1u + tu_rng_below(&r, 255));
    }
    static const uint8_t z = 0x00;

    tu_ctx("251 encoded bytes are accepted (largest legal block)");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_feed(&L, wire + 0, 0); /* no-op */
    {
        /* frame 2 is 250 non-zero bytes: wire 0xFB + 250 + 0x00 */
        size_t off = 0;
        for (unsigned k = 0; k < 2; k++) {
            uint8_t ref[UART_LINK_WIRE_MAX + 4];
            off += tu_ref_cobs_encode(F[k], FL[k], ref, true);
        }
        CHECK_EQ_U32(wire[off], 0xFBu);
        uart_link_feed(&L, wire + off, 252);
        CHECK_EQ_U32(SINK.n, 1u);
        CHECK_EQ_U32(L.st.oversize, 0u);
    }

    tu_ctx("252 bytes without a delimiter: oversize, resync on the next 0x00");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_feed(&L, big, 252);
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.resyncs, 0u);
    uart_link_feed(&L, big, 100); /* still discarding: no second oversize */
    CHECK_EQ_U32(L.st.oversize, 1u);
    uart_link_feed(&L, &z, 1);
    CHECK_EQ_U32(L.st.resyncs, 1u);
    CHECK_EQ_U32(SINK.n, 0u);
    CHECK_EQ_U32(L.st.cobs_err, 0u);
    feed_chunked(&L, wire, n, 17);
    CHECK_EQ_U32(SINK.n, NF);

    tu_ctx("2000 bytes of noise inside a stream");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    feed_chunked(&L, big, sizeof big, 33);
    uart_link_feed(&L, &z, 1);
    feed_chunked(&L, wire, n, 33);
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.resyncs, 1u);
    CHECK_EQ_U32(SINK.n, NF);
    for (unsigned k = 0; k < NF && k < SINK.n; k++) {
        CHECK_EQ_U32(SINK.len[k], FL[k]);
    }

    tu_ctx("oversize run that ends a frame early swallows only that frame");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_feed(&L, big, 300);       /* no delimiter: the next frame's bytes are hunted over */
    feed_chunked(&L, wire, n, 64);     /* frame 0 ends at its delimiter: resync, frames 1..5 arrive */
    CHECK_EQ_U32(L.st.oversize, 1u);
    CHECK_EQ_U32(L.st.resyncs, 1u);
    CHECK_EQ_U32(SINK.n, NF - 1u);
}

static void test_rx_lost(void)
{
    tu_rng_t r;
    tu_rng_seed(&r, 0x1057u);
    build_frames(&r);
    static uint8_t wire[NF * UART_LINK_WIRE_MAX];
    fresh();
    size_t n = encode_all(wire);
    uint8_t ref[UART_LINK_WIRE_MAX + 4];
    size_t w0 = tu_ref_cobs_encode(F[0], FL[0], ref, true);

    tu_ctx("loss report mid-frame drops the partial frame");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_feed(&L, wire, w0 / 2u);
    uart_link_rx_lost(&L);
    CHECK_EQ_U32(L.st.rx_lost, 1u);
    uart_link_feed(&L, wire + w0 / 2u, n - w0 / 2u);
    CHECK_EQ_U32(L.st.resyncs, 1u);
    CHECK_EQ_U32(L.st.cobs_err, 0u);
    CHECK_EQ_U32(SINK.n, NF - 1u);
    for (unsigned k = 1; k < NF && k - 1u < SINK.n; k++) {
        CHECK_EQ_U32(SINK.len[k - 1u], FL[k]);
    }

    tu_ctx("loss report between frames costs nothing");
    memset(&SINK, 0, sizeof SINK);
    memset(&L.st, 0, sizeof L.st);
    uart_link_rx_lost(&L);
    uart_link_feed(&L, wire, n);
    CHECK_EQ_U32(L.st.rx_lost, 1u);
    CHECK_EQ_U32(L.st.resyncs, 0u);
    CHECK_EQ_U32(SINK.n, NF);
    uart_link_rx_lost(NULL); /* tolerated */
}

static void test_send_errors(void)
{
    uint8_t f[UART_LINK_MAX_FRAME + 1];
    memset(f, 0x5A, sizeof f);

    tu_ctx("send argument errors");
    fresh();
    CHECK_ERR(uart_link_send(NULL, NULL, f, 10), BR_ERR_ARG);
    CHECK_ERR(uart_link_send(&L, NULL, NULL, 10), BR_ERR_ARG);
    CHECK_ERR(uart_link_send(&L, NULL, f, 0), BR_ERR_ARG);
    CHECK_ERR(uart_link_send(&L, NULL, f, (uint16_t)sizeof f), BR_ERR_TOO_BIG);
    CHECK_EQ_U32(L.st.tx_bad_len, 3u);
    CHECK_EQ_U32(CAP.len, 0u);
    CHECK_EQ_U32(L.tx_ok_pending, 0u);

    tu_ctx("addr is ignored (point to point)");
    static const uint8_t addr[6] = {1, 2, 3, 4, 5, 6};
    CHECK_ERR(uart_link_send(&L, addr, f, 250), BR_OK);
    CHECK_ERR(uart_link_send(&L, NULL, f, 250), BR_OK);
    CHECK_EQ_U32(CAP.len, 2u * 252u);
    CHECK_MEM(CAP.buf, CAP.buf + 252, 252);
    CHECK_EQ_U32(L.tx_ok_pending, 2u);

    tu_ctx("byte pipe full: frame refused, counted, not reported as delivered");
    CAP.refuse = true;
    CHECK_ERR(uart_link_send(&L, NULL, f, 40), BR_ERR_QUEUE_FULL);
    CHECK_EQ_U32(L.st.tx_refused, 1u);
    CHECK_EQ_U32(L.st.tx_frames, 2u);
    CHECK_EQ_U32(L.tx_ok_pending, 2u);
    CHECK_EQ_U32(uart_link_report_tx_status(&L, NULL, 0), 0u);
    CHECK_EQ_U32(uart_link_report_tx_status(NULL, NULL, 0), 0u);
}

/* ========================================================================= */
/* Part 2: spec vectors                                                       */
/* ========================================================================= */

static void roundtrip_block(const char *what, const uint8_t *blk, size_t len)
{
    tu_ctx(what);
    fresh();
    CHECK_ERR(uart_link_send(&L, NULL, blk, (uint16_t)len), BR_OK);
    for (size_t chunk = 1; chunk <= CAP.len; chunk += 6) {
        memset(&SINK, 0, sizeof SINK);
        feed_chunked(&L, CAP.buf, CAP.len, chunk);
        CHECK_EQ_U32(SINK.n, 1u);
        CHECK_EQ_U32(SINK.len[0], len);
        if (SINK.n == 1u && SINK.len[0] == len) {
            CHECK_MEM(blk, SINK.data[0], len);
        }
    }
    CHECK_EQ_U32(L.st.cobs_err, 0u);
}

static void test_a3(void)
{
    tu_ctx("A.3 block = frame || RS(8) parity");
    CHECK_EQ_U32(BRV_A3_COBS_INPUT_LEN, BRV_A3_FRAME_LEN + BRV_A3_RS_PARITY_LEN);
    CHECK_MEM(BRV_A3_FRAME, BRV_A3_COBS_INPUT, BRV_A3_FRAME_LEN);
    CHECK_MEM(BRV_A3_RS_PARITY, BRV_A3_COBS_INPUT + BRV_A3_FRAME_LEN, BRV_A3_RS_PARITY_LEN);
    CHECK_EQ_U32(br_rd_le16(BRV_A3_FRAME + BR_OFF_PATH_MTU), 242u); /* 11.3: 250 - 8 */

    tu_ctx("A.3 adapter wire output == BRV_A3_COBS_WIRE");
    fresh();
    CHECK_ERR(uart_link_send(&L, NULL, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN), BR_OK);
    CHECK_EQ_U32(CAP.len, BRV_A3_COBS_WIRE_LEN);
    CHECK_MEM(BRV_A3_COBS_WIRE, CAP.buf, BRV_A3_COBS_WIRE_LEN);

    tu_ctx("A.3 wire in 1 / 7 / 13 / 52-byte chunks -> the RS block");
    static const size_t chunks[] = {1, 7, 13, 52};
    for (size_t i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
        fresh();
        feed_chunked(&L, BRV_A3_COBS_WIRE, BRV_A3_COBS_WIRE_LEN, chunks[i]);
        CHECK_EQ_U32(SINK.n, 1u);
        CHECK_EQ_U32(SINK.len[0], BRV_A3_COBS_INPUT_LEN);
        CHECK_MEM(BRV_A3_COBS_INPUT, SINK.data[0], BRV_A3_COBS_INPUT_LEN);
    }
    roundtrip_block("A.3 round trip", BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN);
}

static void test_a15(void)
{
    uint8_t blk[BR_MAX_FRAME_MESH];
    uint8_t chk[BR_MAX_FRAME_MESH];
    uint8_t fixed = 0;

    tu_ctx("A.15 SEEK on-air block");
    CHECK_EQ_U32(BRV_A15_SEEK_FRAME_LEN + BRV_A15_SEEK_RS_PARITY_LEN, BRV_A15_SEEK_ON_AIR_LEN);
    memcpy(blk, BRV_A15_SEEK_FRAME, BRV_A15_SEEK_FRAME_LEN);
    memcpy(blk + BRV_A15_SEEK_FRAME_LEN, BRV_A15_SEEK_RS_PARITY, BRV_A15_SEEK_RS_PARITY_LEN);
    memcpy(chk, blk, BRV_A15_SEEK_ON_AIR_LEN);
    CHECK_ERR(br_rs_decode(chk, BRV_A15_SEEK_ON_AIR_LEN, BRV_A15_SEEK_RS_NSYM, NULL, 0, &fixed), BR_OK);
    CHECK_EQ_U32(fixed, 0u);
    roundtrip_block("A.15 SEEK round trip (60 bytes)", blk, BRV_A15_SEEK_ON_AIR_LEN);

    tu_ctx("A.15 HELLO on-air block");
    CHECK_EQ_U32(BRV_A15_HELLO_FRAME_LEN + BRV_A15_HELLO_RS_PARITY_LEN, BRV_A15_HELLO_ON_AIR_LEN);
    memcpy(blk, BRV_A15_HELLO_FRAME, BRV_A15_HELLO_FRAME_LEN);
    memcpy(blk + BRV_A15_HELLO_FRAME_LEN, BRV_A15_HELLO_RS_PARITY, BRV_A15_HELLO_RS_PARITY_LEN);
    memcpy(chk, blk, BRV_A15_HELLO_ON_AIR_LEN);
    CHECK_ERR(br_rs_decode(chk, BRV_A15_HELLO_ON_AIR_LEN, BRV_A15_HELLO_RS_NSYM, NULL, 0, &fixed), BR_OK);
    roundtrip_block("A.15 HELLO round trip (67 bytes)", blk, BRV_A15_HELLO_ON_AIR_LEN);

    tu_ctx("A.15 blocks carry 0x00 bytes (COBS must restore them)");
    unsigned zeros = 0;
    for (size_t i = 0; i < BRV_A15_HELLO_ON_AIR_LEN; i++) {
        zeros += blk[i] == 0u ? 1u : 0u;
    }
    CHECK(zeros > 0u);
}

/* ========================================================================= */
/* Platform for parts 3 and 4                                                 */
/* ========================================================================= */

static uint64_t g_now_us = 1000000u;
static tu_rng_t g_plat_rng;

static uint64_t t_now(void *user)
{
    (void)user;
    return g_now_us;
}

static br_err_t t_random(void *user, uint8_t *buf, size_t len)
{
    (void)user;
    tu_rng_fill(&g_plat_rng, buf, len);
    return BR_OK;
}

static void t_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    (void)user;
    (void)level;
    (void)tag;
    (void)msg;
}

static br_stats_t node_stats(const br_node_t *n)
{
    br_stats_t s;
    memset(&s, 0, sizeof s);
    CHECK_ERR(br_node_get_stats(n, &s), BR_OK);
    return s;
}

/* ========================================================================= */
/* Part 3: allowlist on a RAW link (N43)                                      */
/* ========================================================================= */

static br_node_t g_lone;

static void lone_init(uint16_t allow_id)
{
    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = 0x0103;
    c.role = BR_ROLE_NODE;
    c.node_count = 2;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY;
    c.auth = true;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE;
    c.net_key_len = BRV_A6_K_SITE_LEN;
    c.n_transports = 1;
    uart_link_fill_transport(&L, &c.transports[0]);
    c.transports[0].allowlist.enabled = allow_id != 0u;
    c.transports[0].allowlist.n = allow_id != 0u ? 1u : 0u;
    c.transports[0].allowlist.ids[0] = allow_id;
    c.txseq_start = 1;
    c.preseq_start = 1;
    memset(&g_lone, 0, sizeof g_lone);
    CHECK_ERR(br_node_init(&g_lone, sizeof g_lone, &c), BR_OK);
}

static void test_allowlist_raw(void)
{
    uint8_t blk[BRV_A3_COBS_INPUT_LEN];
    const uint16_t prev = br_rd_le16(BRV_A3_FRAME + BR_OFF_PREV_HOP); /* 0x1234 */
    br_stats_t s;

    tu_ctx("A.3 prev_hop");
    CHECK_EQ_U32(prev, 0x1234u);

    tu_ctx("allowlist lists the sender: admitted");
    fresh();
    lone_init(prev);
    const br_transport_t *tr = &g_lone.cfg.transports[0];
    CHECK(uart_link_deliver(&L, &g_lone, 0, tr, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, NULL));
    s = node_stats(&g_lone);
    CHECK_EQ_U32(s.f.rx_frames, 1u);
    CHECK_EQ_U32(L.st.allowlist_drop, 0u);

    tu_ctx("prev_hop bytes corrupted (<= 4 errors): RS-corrected copy admits it, the node corrects");
    memcpy(blk, BRV_A3_COBS_INPUT, sizeof blk);
    blk[BR_OFF_PREV_HOP] ^= 0x55u;
    blk[BR_OFF_PREV_HOP + 1u] ^= 0x0Fu;
    blk[30] ^= 0x80u;
    blk[45] ^= 0x01u;
    br_rx_verdict_t v;
    memset(&v, 0, sizeof v);
    CHECK(uart_link_deliver(&L, &g_lone, 0, tr, blk, sizeof blk, &v));
    s = node_stats(&g_lone);
    CHECK_EQ_U32(s.f.rx_frames, 2u);
    CHECK_EQ_U32(s.f.rs_corrected, 1u);
    CHECK_EQ_U32(s.f.rs_fail, 0u);
    CHECK_EQ_U32(L.st.allowlist_drop, 0u);
    CHECK_EQ_U32(blk[BR_OFF_PREV_HOP], BRV_A3_COBS_INPUT[BR_OFF_PREV_HOP] ^ 0x55u); /* input untouched */
    br_node_deinit(&g_lone);

    tu_ctx("allowlist without the sender: dropped before the node, counted in the adapter");
    fresh();
    lone_init(0x0101);
    tr = &g_lone.cfg.transports[0];
    CHECK(!uart_link_deliver(&L, &g_lone, 0, tr, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, NULL));
    CHECK(!uart_link_deliver(&L, &g_lone, 0, tr, blk, sizeof blk, NULL)); /* corrected copy is 0x1234 too */
    s = node_stats(&g_lone);
    CHECK_EQ_U32(s.f.rx_frames, 0u);
    CHECK_EQ_U32(L.st.allowlist_drop, 2u);

    tu_ctx("uncorrectable block: passed on unchecked, the node counts rs_fail");
    memcpy(blk, BRV_A3_COBS_INPUT, sizeof blk);
    for (size_t i = 0; i < 9; i++) {
        blk[2u + 5u * i] ^= (uint8_t)(0x11u * (i + 1u));
    }
    uint8_t probe_copy[sizeof blk];
    uint8_t fixed = 0;
    memcpy(probe_copy, blk, sizeof blk);
    bool uncorrectable = br_rs_decode(probe_copy, sizeof blk, 8, NULL, 0, &fixed) != BR_OK;
    CHECK(uncorrectable);
    if (uncorrectable) {
        CHECK(uart_link_deliver(&L, &g_lone, 0, tr, blk, sizeof blk, NULL));
        s = node_stats(&g_lone);
        CHECK_EQ_U32(s.f.rx_frames, 1u);
        CHECK_EQ_U32(s.f.rs_fail, 1u);
        CHECK_EQ_U32(L.st.allowlist_drop, 2u);
    }

    tu_ctx("NULL transport admits; bad arguments refused");
    CHECK(uart_link_deliver(&L, &g_lone, 0, NULL, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, NULL));
    CHECK(!uart_link_deliver(&L, NULL, 0, tr, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, NULL));
    CHECK(!uart_link_deliver(&L, &g_lone, 0, tr, NULL, 10, NULL));
    CHECK(!uart_link_deliver(NULL, &g_lone, 0, tr, BRV_A3_COBS_INPUT, BRV_A3_COBS_INPUT_LEN, NULL));
    br_node_deinit(&g_lone);
}

/* ========================================================================= */
/* Part 4: two nodes, two adapters, one byte pipe                             */
/* ========================================================================= */

/*
 * Damage models. CORR_RS_OK is applied from the first frame (handshake
 * included: RS repairs everything). CORR_BEYOND and CORR_WIRE lose frames,
 * so they are armed only once the session is STREAMING. The lost-first-MODE
 * stall this guard originally worked around is fixed in the core
 * (SPEC-NOTES N46, "DATA floor"; test_scen_mode_loss.c covers it); the guard
 * is kept only so that handshake loss (SEEK / HELLO / BIND retries, their
 * own timers) stays out of what the damage models measure: ARQ recovery of
 * DATA / ACK on a RAW link.
 */
typedef enum {
    CORR_NONE = 0,
    CORR_RS_OK,       /* every RS block: exactly rs_nsym / 2 = 4 bytes flipped */
    CORR_BEYOND,      /* every third RS block per direction: 5..8 bytes flipped */
    CORR_WIRE         /* 1 block in 4 on average: 1..3 wire-byte flips (code bytes and delimiters
                         included), deletions or insertions */
} corr_t;

typedef struct {
    uint8_t buf[1u << 16];
    size_t  rd;
    size_t  wr;
} pipe_t;

typedef struct ep ep_t;
struct ep {
    const char    *name;
    br_node_t      node;
    uart_link_t    link;
    br_transport_t tr;          /* copy of the configured transport (allowlist for deliver) */
    pipe_t        *out;
    ep_t          *peer;
    corr_t         corr;
    bool           armed;        /* damage enabled */
    unsigned       armed_blocks; /* blocks written while armed */
    tu_rng_t       rng;
    /* write-side observations */
    unsigned       blocks_written;
    unsigned       seeks_written;
    uint16_t       first_seek_path_mtu;
    unsigned       corrupted;    /* blocks given damage */
    unsigned       beyond;       /* blocks given > rs_nsym / 2 errors */
    bool           hit_prev_hop; /* an RS_OK block had bytes 6..7 flipped */
    /* application observations */
    br_session_t   sess;
    bool           streaming;
    unsigned       acked;
    unsigned       ones;
    unsigned       zeros;
    unsigned       samples;
    unsigned       gaps;
    unsigned       gap_seqs;     /* sender: DATA seqs given up (ARQ retries exhausted) */
    unsigned       closed;
    bool           bound;
};

static pipe_t PAB; /* A -> B */
static pipe_t PBA; /* B -> A */
static ep_t EA;
static ep_t EB;

static bool pipe_put(pipe_t *p, const uint8_t *d, size_t n)
{
    if (p->rd > 0u && p->rd == p->wr) {
        p->rd = 0;
        p->wr = 0;
    }
    if (p->wr + n > sizeof p->buf) {
        memmove(p->buf, p->buf + p->rd, p->wr - p->rd);
        p->wr -= p->rd;
        p->rd = 0;
    }
    if (p->wr + n > sizeof p->buf) {
        return false;
    }
    memcpy(p->buf + p->wr, d, n);
    p->wr += n;
    return true;
}

/* Flip k distinct positions of blk[0..len) (value changes, may become 0). */
static void flip_distinct(ep_t *e, uint8_t *blk, size_t len, unsigned k, bool want_prev_hop)
{
    bool used[UART_LINK_MAX_FRAME];
    memset(used, 0, sizeof used);
    unsigned done = 0;
    if (want_prev_hop && len > BR_OFF_PREV_HOP + 1u && k >= 2u) {
        blk[BR_OFF_PREV_HOP] ^= (uint8_t)(1u + tu_rng_below(&e->rng, 255));
        blk[BR_OFF_PREV_HOP + 1u] ^= (uint8_t)(1u + tu_rng_below(&e->rng, 255));
        used[BR_OFF_PREV_HOP] = true;
        used[BR_OFF_PREV_HOP + 1u] = true;
        done = 2;
        e->hit_prev_hop = true;
    }
    while (done < k && done < len) {
        size_t pos = tu_rng_below(&e->rng, (uint32_t)len);
        if (used[pos]) {
            continue;
        }
        used[pos] = true;
        blk[pos] ^= (uint8_t)(1u + tu_rng_below(&e->rng, 255));
        done++;
    }
}

/* The fake HAL write: one call per adapter frame (COBS block + 0x00). */
static bool ep_write(void *ctx, const uint8_t *d, size_t n)
{
    ep_t *e = (ep_t *)ctx;
    if (n == 1u && d[0] == 0x00u) {
        return pipe_put(e->out, d, n); /* start delimiter */
    }
    uint8_t blk[UART_LINK_MAX_FRAME];
    size_t bl = 0;
    CHECK_ERR(br_cobs_decode(d, n, blk, sizeof blk, &bl), BR_OK);
    CHECK(bl > UART_LINK_RS_NSYM && bl <= UART_LINK_MAX_FRAME);
    e->blocks_written++;
    if (bl > 1u && blk[BR_OFF_TYPE] == BR_TYPE_SEEK) {
        if (e->seeks_written == 0u && bl > BR_OFF_PATH_MTU + 1u) {
            e->first_seek_path_mtu = br_rd_le16(blk + BR_OFF_PATH_MTU);
        }
        e->seeks_written++;
    }
    uint8_t wire[UART_LINK_WIRE_MAX + 8];
    size_t wl = 0;
    if (e->armed) {
        e->armed_blocks++;
    }
    switch (e->armed ? e->corr : CORR_NONE) {
    case CORR_RS_OK:
        flip_distinct(e, blk, bl, UART_LINK_RS_NSYM / 2u, (e->armed_blocks % 4u) == 1u);
        e->corrupted++;
        wl = tu_ref_cobs_encode(blk, bl, wire, true);
        break;
    case CORR_BEYOND:
        if (e->armed_blocks % 3u == 0u) {
            flip_distinct(e, blk, bl, UART_LINK_RS_NSYM / 2u + 1u + tu_rng_below(&e->rng, 4), false);
            e->corrupted++;
            e->beyond++;
        }
        wl = tu_ref_cobs_encode(blk, bl, wire, true);
        break;
    case CORR_WIRE:
        memcpy(wire, d, n);
        wl = n;
        if (tu_rng_below(&e->rng, 4) == 0u) {
            unsigned edits = 1u + tu_rng_below(&e->rng, 3);
            for (unsigned i = 0; i < edits && wl > 2u; i++) {
                size_t pos = tu_rng_below(&e->rng, (uint32_t)wl);
                uint32_t what = tu_rng_below(&e->rng, 3);
                if (what == 0u) {
                    wire[pos] ^= (uint8_t)(1u + tu_rng_below(&e->rng, 255)); /* flip */
                } else if (what == 1u) {
                    memmove(wire + pos, wire + pos + 1u, wl - pos - 1u); /* delete */
                    wl--;
                } else if (wl < sizeof wire) {
                    memmove(wire + pos + 1u, wire + pos, wl - pos); /* insert */
                    wire[pos] = tu_rng_u8(&e->rng);
                    wl++;
                }
            }
            e->corrupted++;
        }
        break;
    case CORR_NONE:
    default:
        memcpy(wire, d, n);
        wl = n;
        break;
    }
    return pipe_put(e->out, wire, wl);
}

static void ep_frame(void *ctx, const uint8_t *f, size_t n)
{
    ep_t *e = (ep_t *)ctx;
    (void)uart_link_deliver(&e->link, &e->node, 0, &e->tr, f, n, NULL);
}

/* ---- app callbacks -------------------------------------------------------- */

static void cb_acked(void *user, br_session_t s, uint16_t seq)
{
    (void)s;
    (void)seq;
    ((ep_t *)user)->acked++;
}

static void cb_state(void *user, br_session_t s, uint8_t old_state, uint8_t new_state)
{
    ep_t *e = (ep_t *)user;
    (void)old_state;
    if ((s & BR_SESSION_PROBE) == 0u && new_state == BR_SND_STREAMING) {
        e->streaming = true;
    }
}

static void cb_bound(void *user, br_session_t s, uint16_t peer)
{
    (void)s;
    (void)peer;
    ((ep_t *)user)->bound = true;
}

static void cb_samples(void *user, const br_samples_meta_t *meta, const br_mode_t *mode, const uint8_t *samples,
                       size_t samples_len)
{
    ep_t *e = (ep_t *)user;
    size_t sz = 0;
    CHECK_ERR(br_sample_size(mode, &sz), BR_OK);
    CHECK_EQ_U32(meta->src_id, 0x0101u);
    CHECK_EQ_U32(meta->hops, 1u);
    for (uint8_t i = 0; i < meta->hdr.n_samples && sz > 0u; i++) {
        size_t off = (size_t)i * sz;
        if (off + sz > samples_len) {
            break;
        }
        br_value_t vals[BR_MAX_CHANNELS];
        if (br_sample_decode(mode, samples + off, sz, vals) == BR_OK) {
            e->samples++;
            if ((vals[0].lines & 1u) != 0u) {
                e->ones++;
            } else {
                e->zeros++;
            }
        }
    }
}

static void cb_gap(void *user, br_session_t s, uint16_t first, uint16_t count)
{
    ep_t *e = (ep_t *)user;
    (void)first;
    e->gaps++;
    if ((s & BR_SESSION_PROBE) == 0u) {
        e->gap_seqs += count;
    }
}

static void cb_closed(void *user, br_session_t s, uint8_t reason)
{
    (void)s;
    (void)reason;
    ((ep_t *)user)->closed++;
}

/* ---- set-up and stepping -------------------------------------------------- */

static void ep_init(ep_t *e, const char *name, uint16_t unit, bool probe, pipe_t *out, ep_t *peer, corr_t corr,
                    uint16_t allow_id, uint64_t seed)
{
    memset(e, 0, sizeof *e);
    e->name = name;
    e->out = out;
    e->peer = peer;
    e->corr = corr;
    e->armed = corr == CORR_RS_OK;
    e->sess = BR_SESSION_NONE;
    tu_rng_seed(&e->rng, seed);
    CHECK(uart_link_init(&e->link, ep_write, e, ep_frame, e));

    br_node_config_t c;
    memset(&c, 0, sizeof c);
    c.unit_id = unit;
    c.role = BR_ROLE_NODE;
    c.node_count = 2;
    c.seek_ttl = BR_SEEK_TTL_DEFAULT;
    c.caps = BR_CAP_HIGH | BR_CAP_LOW | BR_CAP_ARQ | BR_CAP_AUTH | BR_CAP_RELAY; /* node_app kCapsBase */
    if (probe) {
        c.caps = (uint16_t)(c.caps | BR_CAP_MULTI);
        c.groups[0] = 0xFF10;
        c.n_groups = 1;
    }
    c.auth = true;
    c.cold_boot = false;
    c.key_epoch = 1;
    c.net_key = BRV_A6_K_SITE; /* the bench key of node_app (bytes 0x00..0x1F) */
    c.net_key_len = BRV_A6_K_SITE_LEN;
    uart_link_fill_transport(&e->link, &c.transports[0]);
    c.transports[0].allowlist.enabled = allow_id != 0u;
    c.transports[0].allowlist.n = allow_id != 0u ? 1u : 0u;
    c.transports[0].allowlist.ids[0] = allow_id;
    e->tr = c.transports[0];
    c.n_transports = 1;
    c.app.user = e;
    c.app.on_bound = cb_bound;
    c.app.on_samples = cb_samples;
    c.app.on_gap = cb_gap;
    c.app.on_acked = cb_acked;
    c.app.on_closed = cb_closed;
    c.app.on_state = cb_state;
    c.txseq_start = 1;
    c.preseq_start = 1;
    CHECK_ERR(br_node_init(&e->node, sizeof e->node, &c), BR_OK);
}

/* Bytes per millisecond per direction at 921600 baud, 8N1. */
#define WIRE_BYTES_PER_MS 92u

static void deliver(pipe_t *p, ep_t *dst, uint32_t budget)
{
    while (budget > 0u && p->rd < p->wr) {
        size_t k = 1u + tu_rng_below(&dst->rng, 40);
        if (k > budget) {
            k = budget;
        }
        if (k > p->wr - p->rd) {
            k = p->wr - p->rd;
        }
        size_t at = p->rd;
        p->rd += k;
        budget -= (uint32_t)k;
        uart_link_feed(&dst->link, p->buf + at, k); /* may append to the other pipe only */
        (void)uart_link_report_tx_status(&dst->link, &dst->node, 0);
    }
}

static void step_ms(void)
{
    uint64_t nd = 0;
    g_now_us += 1000u;
    CHECK_ERR(br_node_tick(&EA.node, g_now_us, &nd), BR_OK);
    (void)uart_link_report_tx_status(&EA.link, &EA.node, 0);
    CHECK_ERR(br_node_tick(&EB.node, g_now_us, &nd), BR_OK);
    (void)uart_link_report_tx_status(&EB.link, &EB.node, 0);
    deliver(&PAB, &EB, WIRE_BYTES_PER_MS);
    deliver(&PBA, &EA, WIRE_BYTES_PER_MS);
}

static bool run_until(bool (*cond)(void), uint32_t max_ms)
{
    for (uint32_t i = 0; i < max_ms; i++) {
        if (cond()) {
            return true;
        }
        step_ms();
    }
    return cond();
}

static unsigned g_want_acked;
static bool cond_streaming(void) { return EA.streaming; }
/* every DATA sent so far is either acknowledged or given up and reported */
static bool cond_acked(void) { return EA.acked + EA.gap_seqs >= g_want_acked; }
static bool cond_pipes_empty(void) { return PAB.rd == PAB.wr && PBA.rd == PBA.wr; }

static uint64_t g_t0_us;

static void start_pair(corr_t corr, uint16_t a_allow, uint16_t b_allow, uint64_t seed)
{
    g_t0_us = g_now_us;
    memset(&PAB, 0, sizeof PAB);
    memset(&PBA, 0, sizeof PBA);
    tu_rng_seed(&g_plat_rng, seed ^ 0xA5A5A5A5u);
    ep_init(&EA, "A", 0x0101, false, &PAB, &EB, corr, a_allow, seed * 3u + 1u);
    ep_init(&EB, "B", 0x0103, true, &PBA, &EA, corr, b_allow, seed * 5u + 2u);
    CHECK(uart_link_start(&EA.link));
    CHECK(uart_link_start(&EB.link));
    CHECK_ERR(br_node_seek(&EA.node, 0xFF10, &EA.sess), BR_OK);
    br_mode_t m; /* node_app demo MODE */
    memset(&m, 0, sizeof m);
    m.config_id = 1;
    m.mode = BR_MODE_HIGH;
    m.ch_count = 1;
    m.period = 1;
    m.flags = BR_MODE_FLAG_PERIOD_MS;
    m.fec_k = 8;
    m.fec_m = 0;
    m.arq = 1;
    m.keepalive_ms = BR_KEEPALIVE_DEFAULT_MS;
    m.ch[0].kind = BR_CH_KIND_DIGITAL;
    m.ch[0].fmt = 1;
    CHECK_ERR(br_node_set_mode(&EA.node, EA.sess, &m), BR_OK);
}

/* One press = value 1 then value 0, both ACK_REQ (node_app sender_press). */
static bool press(unsigned i)
{
    br_value_t v;
    v.lines = 1;
    br_err_t r1 = br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true);
    v.lines = 0;
    br_err_t r0 = br_node_send_sample(&EA.node, EA.sess, &v, 1, (uint32_t)g_now_us, 0, true);
    CHECK_ERR(r1, BR_OK);
    CHECK_ERR(r0, BR_OK);
    g_want_acked = 2u * (i + 1u);
    return run_until(cond_acked, 30000);
}

static void finish_pair(void)
{
    (void)run_until(cond_pipes_empty, 2000);
    br_node_deinit(&EA.node);
    br_node_deinit(&EB.node);
}

#define PRESSES 20u

typedef struct {
    br_stats_t a;
    br_stats_t b;
} pair_stats_t;

/*
 * strict: every press delivered and acknowledged. Not strict (heavy wire
 * damage): ARQ may give a DATA seq up after ARQ_MAX_RETRIES (4 losses of the
 * same frame in a row); then every DATA must be accounted for (acked or
 * reported through on_gap) and the session must still be STREAMING.
 */
static pair_stats_t run_session(const char *what, corr_t corr, uint16_t a_allow, uint16_t b_allow, uint64_t seed,
                                bool strict)
{
    pair_stats_t ps;
    tu_ctx(what);
    start_pair(corr, a_allow, b_allow, seed);
    bool up = run_until(cond_streaming, 60000);
    CHECK_MSG(up, "sender never reached STREAMING");
    CHECK(EB.bound);
    EA.armed = corr != CORR_NONE;
    EB.armed = corr != CORR_NONE;
    unsigned ok = 0;
    for (unsigned i = 0; up && i < PRESSES; i++) {
        if (press(i)) {
            ok++;
        }
        for (unsigned k = 0; k < 50u; k++) {
            step_ms();
        }
    }
    for (unsigned k = 0; k < 2000u; k++) {
        step_ms(); /* > REORDER_MS (500 ms): the probe releases anything held behind a given-up seq */
    }
    CHECK_EQ_U32(ok, PRESSES);
    CHECK_EQ_U32(EA.acked + EA.gap_seqs, 2u * PRESSES);
    if (strict) {
        CHECK_EQ_U32(EA.acked, 2u * PRESSES);
        CHECK_EQ_U32(EA.gap_seqs, 0u);
        CHECK_EQ_U32(EB.ones, PRESSES);
        CHECK_EQ_U32(EB.zeros, PRESSES);
    } else {
        CHECK(EB.ones + EB.zeros + EA.gap_seqs >= 2u * PRESSES);
        CHECK(EA.acked >= PRESSES); /* most of it got through */
    }
    uint8_t st = 0;
    CHECK_ERR(br_node_session_state(&EA.node, EA.sess, &st), BR_OK);
    CHECK_EQ_U32(st, BR_SND_STREAMING);
    CHECK_EQ_U32(EA.closed, 0u);
    CHECK_EQ_U32(EB.closed, 0u);
    (void)run_until(cond_pipes_empty, 2000);
    ps.a = node_stats(&EA.node);
    ps.b = node_stats(&EB.node);

    /* every frame the pipe accepted was reported delivered */
    CHECK_EQ_U32(EA.link.st.tx_status, EA.link.st.tx_frames);
    CHECK_EQ_U32(EB.link.st.tx_status, EB.link.st.tx_frames);
    CHECK_EQ_U32(EA.link.st.tx_refused, 0u);
    CHECK_EQ_U32(EB.link.st.tx_refused, 0u);
    /* 11.3: the SEEK leaves over the UART with path_mtu 250 - 8 */
    CHECK_EQ_U32(EA.first_seek_path_mtu, 242u);
    /* 11.11: the probe never floods back over the point-to-point arrival link */
    CHECK_EQ_U32(EB.seeks_written, 0u);
    /* 11.6 is off on UART: no link deletions */
    CHECK_EQ_U32(ps.a.f.link_fail_drops, 0u);
    printf("  %-52s t=%5.1fs blocks A->B %3u B->A %3u damaged %3u/%3u rs_fixed %3u/%3u rs_fail %u/%u "
           "crc %u/%u cobs %u/%u resync %u/%u oversize %u/%u allowlist %u/%u retx %u gave_up %u\n",
           what, (double)(g_now_us - g_t0_us) / 1e6, EA.blocks_written, EB.blocks_written, EA.corrupted,
           EB.corrupted, (unsigned)ps.b.f.rs_corrected, (unsigned)ps.a.f.rs_corrected, (unsigned)ps.b.f.rs_fail,
           (unsigned)ps.a.f.rs_fail, (unsigned)ps.b.f.crc_fail, (unsigned)ps.a.f.crc_fail,
           (unsigned)EB.link.st.cobs_err, (unsigned)EA.link.st.cobs_err, (unsigned)EB.link.st.resyncs,
           (unsigned)EA.link.st.resyncs, (unsigned)EB.link.st.oversize, (unsigned)EA.link.st.oversize,
           (unsigned)EB.link.st.allowlist_drop, (unsigned)EA.link.st.allowlist_drop, (unsigned)ps.a.f.arq_retx,
           EA.gap_seqs);
    return ps;
}

static void test_loopback_clean(void)
{
    pair_stats_t ps = run_session("loopback clean", CORR_NONE, 0, 0, 11, true);
    CHECK_EQ_U32(ps.a.f.rs_corrected + ps.b.f.rs_corrected, 0u);
    CHECK_EQ_U32(ps.a.f.rs_fail + ps.b.f.rs_fail, 0u);
    CHECK_EQ_U32(ps.a.f.crc_fail + ps.b.f.crc_fail, 0u);
    CHECK_EQ_U32(ps.a.f.arq_retx, 0u);
    CHECK_EQ_U32(EA.link.st.cobs_err + EB.link.st.cobs_err, 0u);
    CHECK_EQ_U32(EA.link.st.rx_frames, EB.link.st.tx_frames);
    CHECK_EQ_U32(EB.link.st.rx_frames, EA.link.st.tx_frames);
    CHECK_EQ_U32(ps.a.f.rx_frames, EA.link.st.rx_frames);
    CHECK_EQ_U32(ps.b.f.rx_frames, EB.link.st.rx_frames);
    CHECK_EQ_U32(EA.gaps + EB.gaps, 0u);
    finish_pair();
}

#define SEEDS 8u

static void test_loopback_rs_corrects(uint64_t seed)
{
    /* allowlist on both ends; some blocks have prev_hop (bytes 6..7) hit */
    pair_stats_t ps = run_session("loopback, 4 bytes flipped in every RS block", CORR_RS_OK, 0x0103, 0x0101, seed,
                                  true);
    CHECK(EA.hit_prev_hop && EB.hit_prev_hop);
    CHECK_EQ_U32(ps.b.f.rs_corrected, EA.corrupted);
    CHECK_EQ_U32(ps.a.f.rs_corrected, EB.corrupted);
    CHECK(EA.corrupted > 10u && EB.corrupted > 10u);
    CHECK_EQ_U32(ps.a.f.rs_fail + ps.b.f.rs_fail, 0u);
    CHECK_EQ_U32(ps.a.f.crc_fail + ps.b.f.crc_fail, 0u);
    CHECK_EQ_U32(EA.link.st.allowlist_drop + EB.link.st.allowlist_drop, 0u);
    CHECK_EQ_U32(ps.a.f.arq_retx, 0u);
    CHECK_EQ_U32(EA.gaps + EB.gaps, 0u);
    finish_pair();
}

static void test_loopback_beyond(uint64_t seed)
{
    pair_stats_t ps = run_session("loopback, 5..8 bytes flipped in every third RS block", CORR_BEYOND, 0x0103,
                                  0x0101, seed, true);
    CHECK(EA.beyond > 5u && EB.beyond > 5u);
    /* each damaged block is dropped exactly once: RS gives up, or mis-corrects and
     * the CRC (or, for the bench check, the corrected prev_hop) rejects it */
    CHECK_EQ_U32(ps.b.f.rs_fail + ps.b.f.crc_fail + EB.link.st.allowlist_drop, EA.beyond);
    CHECK_EQ_U32(ps.a.f.rs_fail + ps.a.f.crc_fail + EA.link.st.allowlist_drop, EB.beyond);
    CHECK(ps.a.f.rs_fail + ps.b.f.rs_fail > 0u);
    CHECK(ps.a.f.arq_retx > 0u); /* the session survived through ARQ */
    finish_pair();
}

static void test_loopback_wire_noise(uint64_t seed)
{
    pair_stats_t ps =
        run_session("loopback, wire-level flips / deletions / insertions", CORR_WIRE, 0, 0, seed, false);
    CHECK(EA.corrupted + EB.corrupted > 2u);
    uint32_t framing = EA.link.st.cobs_err + EB.link.st.cobs_err + EA.link.st.resyncs + EB.link.st.resyncs +
                       EA.link.st.oversize + EB.link.st.oversize;
    uint32_t node_drops = ps.a.f.rs_fail + ps.b.f.rs_fail + ps.a.f.crc_fail + ps.b.f.crc_fail +
                          ps.a.f.rs_corrected + ps.b.f.rs_corrected + ps.a.f.bad_frame + ps.b.f.bad_frame;
    CHECK(framing + node_drops > 0u);
    finish_pair();
}

static void test_loopback_allowlist_excludes(void)
{
    tu_ctx("loopback, probe allowlist excludes the sender");
    start_pair(CORR_NONE, 0x0103, 0x0102, 77);
    bool up = run_until(cond_streaming, 10000);
    CHECK(!up);
    CHECK(!EB.bound);
    br_stats_t b = node_stats(&EB.node);
    CHECK_EQ_U32(b.f.rx_frames, 0u); /* the core saw nothing (N22) */
    CHECK(EB.link.st.allowlist_drop > 0u);
    CHECK_EQ_U32(EB.link.st.allowlist_drop, EB.link.st.rx_frames);
    finish_pair();
}

int main(void)
{
    const br_platform_t plat = {t_now, t_random, t_log, NULL};
    tu_rng_seed(&g_plat_rng, 1);
    CHECK_ERR(br_platform_set(&plat), BR_OK);

    test_transport_fields();
    test_start_and_idle_delimiters();
    test_chunk_boundaries();
    test_garbage_before_delimiter();
    test_oversize();
    test_rx_lost();
    test_send_errors();
    test_a3();
    test_a15();
    test_allowlist_raw();
    test_loopback_clean();
    for (uint64_t seed = 0; seed < SEEDS; seed++) {
        test_loopback_rs_corrects(23u + seed);
    }
    for (uint64_t seed = 0; seed < SEEDS; seed++) {
        test_loopback_beyond(37u + seed);
    }
    for (uint64_t seed = 0; seed < SEEDS; seed++) {
        test_loopback_wire_noise(51u + seed);
    }
    test_loopback_allowlist_excludes();
    return tu_summary("test_uart_link");
}
