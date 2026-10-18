// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_console_robust.c - host test of the gateway robustness fixes:
 *   - NVS blob keys decoded and validated one by one
 *     (node_cfg_load_blobs, SPEC-NOTES N70): a corrupt optional blob falls
 *     back to its default and the rest of the configuration still loads; a
 *     corrupt REQUIRED key (ssid / pass with the station on, udp_peers with
 *     udp=on mcast=off) is refused with a reason naming the NVS key, and a
 *     corrupt pass is never taken as an open AP;
 *   - raw SSID bytes kept for the driver, sanitised only when printed;
 *   - the station reconnect schedule of hal_udp.h (N69): sequence, cap,
 *     jitter bounds, reset, saturation;
 *   - the no-quote error rule (N72): tokens that are not key=value of a
 *     known key are never echoed, and passphrase values never appear in an
 *     error text;
 *   - node_wipe (N71).
 *
 * The other test_console*.c files are frozen; this file only adds. Like
 * them it compiles the real source file into the executable.
 */
#include "test_util.h"

#include "../../components/app_hal/include/hal_udp.h"
#include "../../examples/demo-3board/components/app_node/src/node_console.c"

static node_cmd_t C;

static bool parse(const char *line)
{
    return node_cmd_parse(line, NODE_CHIP_ESP32, &C);
}

/* ---- helpers for the blob loader ----------------------------------------- */

static node_kv_blob_t present(const void *data, size_t len)
{
    node_kv_blob_t b;
    b.state = NODE_KV_PRESENT;
    b.data = (const uint8_t *)data;
    b.len = len;
    return b;
}

static node_kv_blob_t absent(void)
{
    node_kv_blob_t b = {NODE_KV_ABSENT, NULL, 0};
    return b;
}

static node_kv_blob_t unreadable(void)
{
    node_kv_blob_t b = {NODE_KV_UNREADABLE, NULL, 0};
    return b;
}

static const uint8_t NBR_OK[] = {0x01, 0x01, 0x02, 0x01};            /* 0x0101, 0x0102 */
static const uint8_t PEERS_OK[] = {192, 168, 1, 20, 0x9F, 0x78};     /* 192.168.1.20:40824 */
static const char SSID_OK[] = "lab";
static const char PASS_OK[] = "Secret123";
static const char NTP_OK[] = "time.example.org";

/* The u32 part of a single-chip gateway as cfg_load() leaves it before the blobs. */
static void gateway_u32(node_cfg_t *c)
{
    node_cfg_defaults(c);
    c->role = NODE_ROLE_PROBE;
    c->uid = 0x0010u;
    c->grp = 0xFF10u;
    c->espnow = 0u;
    c->nrf = 1u;
    c->wifi = 1u;
}

/* All five blobs valid. */
static node_cfg_blobs_t good_blobs(void)
{
    node_cfg_blobs_t b;
    b.nbr = present(NBR_OK, sizeof NBR_OK);
    b.peers = present(PEERS_OK, sizeof PEERS_OK);
    b.ssid = present(SSID_OK, strlen(SSID_OK));
    b.pass = present(PASS_OK, strlen(PASS_OK));
    b.ntp = present(NTP_OK, strlen(NTP_OK));
    return b;
}

/* What good_blobs() decodes to on top of gateway_u32(). */
static void gateway_expected(node_cfg_t *c)
{
    gateway_u32(c);
    c->n_nbr = 2u;
    c->nbr[0] = 0x0101u;
    c->nbr[1] = 0x0102u;
    c->n_peers = 1u;
    c->peers[0].ip = HAL_UDP_IP4(192, 168, 1, 20);
    c->peers[0].port = 40824u;
    memset(c->ssid, 0, sizeof c->ssid);
    memcpy(c->ssid, SSID_OK, strlen(SSID_OK));
    memset(c->pass, 0, sizeof c->pass);
    memcpy(c->pass, PASS_OK, strlen(PASS_OK));
    memset(c->ntp, 0, sizeof c->ntp);
    memcpy(c->ntp, NTP_OK, strlen(NTP_OK));
}

static bool cfg_equal(const node_cfg_t *a, const node_cfg_t *b)
{
    return memcmp(a, b, sizeof *a) == 0;
}

static void test_all_good(void)
{
    tu_ctx("all blobs valid");
    node_cfg_t c, exp;
    gateway_u32(&c);
    gateway_expected(&exp);
    node_cfg_blobs_t b = good_blobs();
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), 0u);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK(cfg_equal(&c, &exp));
    const char *why = NULL;
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);

    tu_ctx("all blobs absent: defaults, nothing falls back, nothing flagged");
    node_cfg_defaults(&c);
    node_cfg_defaults(&exp);
    node_cfg_blobs_t none = {absent(), absent(), absent(), absent(), absent()};
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &none), 0u);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK(cfg_equal(&c, &exp));
}

static void test_corrupt_ntp(void)
{
    tu_ctx("corrupt ntp blob (non-printable byte): default, rest loads, boot not blocked");
    static const char bad[] = {'p', 'o', 'o', 'l', 0x01, '.', 'n', 't', 'p'};
    node_cfg_t c, exp;
    gateway_u32(&c);
    gateway_expected(&exp);
    memset(exp.ntp, 0, sizeof exp.ntp);
    memcpy(exp.ntp, NODE_DEFAULT_NTP, sizeof NODE_DEFAULT_NTP);
    node_cfg_blobs_t b = good_blobs();
    b.ntp = present(bad, sizeof bad);
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), NODE_F_NTP);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK(strcmp(c.ntp, "pool.ntp.org") == 0);
    CHECK(cfg_equal(&c, &exp));
    const char *why = NULL;
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);
    CHECK(strcmp(node_cfg_nvs_key(NODE_F_NTP), "ntp") == 0);

    /* the app's warning line, built from the key name */
    char line[64];
    node_fmt_t f;
    node_fmt_init(&f, line, sizeof line);
    node_fmt_str(&f, "BRCFG ");
    node_fmt_str(&f, node_cfg_nvs_key(NODE_F_NTP));
    node_fmt_str(&f, " invalid in NVS, using default");
    CHECK(strcmp(line, "BRCFG ntp invalid in NVS, using default") == 0);

    static const char *const bad_hosts[] = {"pool..ntp.org", "-pool.ntp.org", "pool.ntp.org.", "pool ntp", "a_b"};
    for (size_t i = 0; i < sizeof bad_hosts / sizeof bad_hosts[0]; i++) {
        tu_ctx(bad_hosts[i]);
        gateway_u32(&c);
        b = good_blobs();
        b.ntp = present(bad_hosts[i], strlen(bad_hosts[i]));
        CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), NODE_F_NTP);
        CHECK(cfg_equal(&c, &exp));
    }
    tu_ctx("ntp blob longer than the read buffer (unreadable): default");
    gateway_u32(&c);
    b = good_blobs();
    b.ntp = unreadable();
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), NODE_F_NTP);
    CHECK(cfg_equal(&c, &exp));
    tu_ctx("ntp blob of 64 bytes (over NODE_NTP_MAX): default, no overrun");
    char long_ntp[NODE_NTP_MAX + 1];
    memset(long_ntp, 'a', sizeof long_ntp);
    gateway_u32(&c);
    b = good_blobs();
    b.ntp = present(long_ntp, sizeof long_ntp);
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), NODE_F_NTP);
    CHECK(cfg_equal(&c, &exp));
}

/* One optional blob replaced by `bad`; expect only `bit` to fall back. */
static void expect_fallback(const char *ctx, node_cfg_t *u32_cfg, node_cfg_blobs_t *b, uint32_t bit,
                            const node_cfg_t *exp)
{
    tu_ctx(ctx);
    node_cfg_t c = *u32_cfg;
    CHECK_EQ_U32(node_cfg_load_blobs(&c, b), bit);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK(cfg_equal(&c, exp));
}

static void test_optional_fallbacks(void)
{
    node_cfg_t u, exp;
    node_cfg_blobs_t b;

    /* nbr -> none (allowlist off) */
    gateway_u32(&u);
    gateway_expected(&exp);
    exp.n_nbr = 0u;
    memset(exp.nbr, 0, sizeof exp.nbr);
    static const uint8_t nbr_odd[] = {0x01, 0x01, 0x02};
    static const uint8_t nbr_mgr[] = {0x01, 0x00};                    /* 0x0001: a manager ID */
    static const uint8_t nbr_dup[] = {0x01, 0x01, 0x01, 0x01};
    static const uint8_t nbr_self[] = {0x10, 0x00};                   /* the node's own uid */
    static const uint8_t nbr_grp[] = {0x10, 0xFF};                    /* a group ID */
    b = good_blobs();
    b.nbr = present(nbr_odd, sizeof nbr_odd);
    expect_fallback("nbr odd length", &u, &b, NODE_F_NBR, &exp);
    b.nbr = present(nbr_mgr, sizeof nbr_mgr);
    expect_fallback("nbr manager ID", &u, &b, NODE_F_NBR, &exp);
    b.nbr = present(nbr_dup, sizeof nbr_dup);
    expect_fallback("nbr duplicate", &u, &b, NODE_F_NBR, &exp);
    b.nbr = present(nbr_self, sizeof nbr_self);
    expect_fallback("nbr own uid", &u, &b, NODE_F_NBR, &exp);
    b.nbr = present(nbr_grp, sizeof nbr_grp);
    expect_fallback("nbr group ID", &u, &b, NODE_F_NBR, &exp);
    b.nbr = unreadable();
    expect_fallback("nbr longer than 8 entries (unreadable)", &u, &b, NODE_F_NBR, &exp);
    uint8_t nbr18[18];
    for (size_t i = 0; i < 9u; i++) {
        nbr18[2u * i] = (uint8_t)(0x20u + i);
        nbr18[2u * i + 1u] = 0x01u;
    }
    b.nbr = present(nbr18, sizeof nbr18);
    expect_fallback("nbr 9 entries", &u, &b, NODE_F_NBR, &exp);

    /* udp_peers -> none (optional here: udp off) */
    gateway_expected(&exp);
    exp.n_peers = 0u;
    memset(exp.peers, 0, sizeof exp.peers);
    static const uint8_t peers_len7[] = {192, 168, 1, 20, 0x9F, 0x78, 0};
    static const uint8_t peers_lo[] = {127, 0, 0, 1, 0x9F, 0x78};
    static const uint8_t peers_mc[] = {239, 255, 40, 88, 0x9F, 0x78};
    static const uint8_t peers_port0[] = {192, 168, 1, 20, 0, 0};
    b = good_blobs();
    b.peers = present(peers_len7, sizeof peers_len7);
    expect_fallback("peers length 7", &u, &b, NODE_F_PEERS, &exp);
    b.peers = present(peers_lo, sizeof peers_lo);
    expect_fallback("peers loopback", &u, &b, NODE_F_PEERS, &exp);
    b.peers = present(peers_mc, sizeof peers_mc);
    expect_fallback("peers multicast", &u, &b, NODE_F_PEERS, &exp);
    b.peers = present(peers_port0, sizeof peers_port0);
    expect_fallback("peers port 0", &u, &b, NODE_F_PEERS, &exp);
    b.peers = unreadable();
    expect_fallback("peers unreadable", &u, &b, NODE_F_PEERS, &exp);

    /* ssid and pass are optional while the station is off */
    gateway_u32(&u);
    u.wifi = 0u;
    gateway_expected(&exp);
    exp.wifi = 0u;
    memset(exp.ssid, 0, sizeof exp.ssid);
    static const char ssid_ctl[] = {'l', 0x01, 'b'};
    b = good_blobs();
    b.ssid = present(ssid_ctl, sizeof ssid_ctl);
    expect_fallback("ssid control byte, wifi off", &u, &b, NODE_F_SSID, &exp);
    char ssid33[33];
    memset(ssid33, 's', sizeof ssid33);
    b.ssid = present(ssid33, sizeof ssid33);
    expect_fallback("ssid 33 bytes, wifi off", &u, &b, NODE_F_SSID, &exp);

    gateway_expected(&exp);
    exp.wifi = 0u;
    memset(exp.pass, 0, sizeof exp.pass);
    b = good_blobs();
    b.pass = present("short", 5u);
    expect_fallback("pass 5 bytes, wifi off", &u, &b, NODE_F_PASS, &exp);

    tu_ctx("two corrupt optional blobs at once: both fall back, the rest loads");
    gateway_u32(&u);
    gateway_expected(&exp);
    exp.n_nbr = 0u;
    memset(exp.nbr, 0, sizeof exp.nbr);
    memset(exp.ntp, 0, sizeof exp.ntp);
    memcpy(exp.ntp, NODE_DEFAULT_NTP, sizeof NODE_DEFAULT_NTP);
    b = good_blobs();
    b.nbr = present(nbr_odd, sizeof nbr_odd);
    b.ntp = present("\x7f", 1u);
    node_cfg_t c = u;
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), NODE_F_NBR | NODE_F_NTP);
    CHECK(cfg_equal(&c, &exp));
    const char *why = NULL;
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);
}

static void expect_required(const char *ctx, const node_cfg_t *u, const node_cfg_blobs_t *b, uint32_t bit,
                            const char *needle, const char *secret)
{
    tu_ctx(ctx);
    node_cfg_t c = *u;
    CHECK_EQ_U32(node_cfg_load_blobs(&c, b), 0u);
    CHECK_EQ_U32(c.nvs_bad, bit);
    const char *why = NULL;
    CHECK(!node_cfg_ready(&c, NODE_CHIP_ESP32, &why));
    CHECK_MSG(why != NULL && strstr(why, needle) != NULL, why != NULL ? why : "(null)");
    if (secret != NULL && why != NULL) {
        CHECK(strstr(why, secret) == NULL);
    }
}

static void test_required_keys(void)
{
    node_cfg_t u;
    node_cfg_blobs_t b;
    gateway_u32(&u); /* wifi on: ssid and pass required */

    static const char ssid_ctl[] = {'l', 0x01, 'b'};
    b = good_blobs();
    b.ssid = present(ssid_ctl, sizeof ssid_ctl);
    expect_required("ssid control byte, wifi on", &u, &b, NODE_F_SSID, "NVS key ssid invalid", NULL);
    b.ssid = unreadable();
    expect_required("ssid unreadable, wifi on", &u, &b, NODE_F_SSID, "NVS key ssid invalid", NULL);

    tu_ctx("ssid invalid: the other blobs still load");
    node_cfg_t c = u;
    b = good_blobs();
    b.ssid = present(ssid_ctl, sizeof ssid_ctl);
    (void)node_cfg_load_blobs(&c, &b);
    CHECK(c.ssid[0] == '\0');
    CHECK(strcmp(c.pass, PASS_OK) == 0);
    CHECK(strcmp(c.ntp, NTP_OK) == 0);
    CHECK_EQ_U32(c.n_nbr, 2u);
    CHECK_EQ_U32(c.n_peers, 1u);

    b = good_blobs();
    b.pass = present("Zq9xW", 5u);
    expect_required("pass 5 bytes, wifi on: refused, not an open AP", &u, &b, NODE_F_PASS, "NVS key pass invalid",
                    "Zq9xW");
    static const char pass_ctl[] = {'S', 'e', 'c', 'r', 'e', 't', 0x0A, '9', '9'};
    b.pass = present(pass_ctl, sizeof pass_ctl);
    expect_required("pass with a control byte, wifi on", &u, &b, NODE_F_PASS, "NVS key pass invalid", "Secret");
    b.pass = unreadable();
    expect_required("pass unreadable, wifi on", &u, &b, NODE_F_PASS, "NVS key pass invalid", NULL);
    tu_ctx("pass invalid: the field is empty but flagged (never an open AP)");
    c = u;
    b = good_blobs();
    b.pass = present("Zq9xW", 5u);
    (void)node_cfg_load_blobs(&c, &b);
    CHECK(c.pass[0] == '\0');
    CHECK((c.nvs_bad & NODE_F_PASS) != 0u);

    tu_ctx("legacy udp=1 (wifi implied) makes ssid required");
    node_cfg_t lu;
    node_cfg_defaults(&lu);
    lu.role = NODE_ROLE_NODE;
    lu.uid = 0x0103u; /* not in NBR_OK */
    lu.espnow = 0u;
    lu.udp = 1u;
    node_cfg_legacy_wifi(&lu, false);
    b = good_blobs();
    b.ssid = present(ssid_ctl, sizeof ssid_ctl);
    expect_required("legacy udp=1, ssid corrupt", &lu, &b, NODE_F_SSID, "ssid", NULL);

    tu_ctx("udp=on mcast=off: udp_peers required");
    node_cfg_t pu = lu;
    pu.mcast = 0u;
    static const uint8_t peers_lo[] = {127, 0, 0, 1, 0x9F, 0x78};
    b = good_blobs();
    b.peers = present(peers_lo, sizeof peers_lo);
    expect_required("peers corrupt with mcast=off", &pu, &b, NODE_F_PEERS, "NVS key udp_peers invalid", NULL);

    tu_ctx("br set of the flagged key clears it; another key does not");
    c = u;
    b = good_blobs();
    b.pass = present("Zq9xW", 5u);
    (void)node_cfg_load_blobs(&c, &b);
    char err[NODE_ERR_MAX];
    CHECK(parse("br set chan=3"));
    CHECK_MSG(node_cfg_apply(&c, &C, err, sizeof err), err);
    CHECK((c.nvs_bad & NODE_F_PASS) != 0u);
    const char *why = NULL;
    CHECK(!node_cfg_ready(&c, NODE_CHIP_ESP32, &why));
    CHECK(parse("br set pass=NewSecret1"));
    CHECK_MSG(node_cfg_apply(&c, &C, err, sizeof err), err);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);

    c = u;
    b = good_blobs();
    b.ssid = present(ssid_ctl, sizeof ssid_ctl);
    (void)node_cfg_load_blobs(&c, &b);
    CHECK(parse("br set ssid=lab2"));
    CHECK_MSG(node_cfg_apply(&c, &C, err, sizeof err), err);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);

    tu_ctx("wifi turned off: a flagged ssid no longer blocks");
    c = u;
    (void)node_cfg_load_blobs(&c, &b);
    CHECK(parse("br set wifi=off"));
    CHECK_MSG(node_cfg_apply(&c, &C, err, sizeof err), err);
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);
}

static void test_raw_ssid(void)
{
    tu_ctx("UTF-8 ssid bytes kept raw, printed sanitised");
    static const char cafe[] = {'c', 'a', 'f', (char)0xC3, (char)0xA9};
    node_cfg_t c;
    gateway_u32(&c);
    node_cfg_blobs_t b = good_blobs();
    b.ssid = present(cafe, sizeof cafe);
    CHECK_EQ_U32(node_cfg_load_blobs(&c, &b), 0u);
    CHECK_EQ_U32(c.nvs_bad, 0u);
    CHECK(memcmp(c.ssid, cafe, sizeof cafe) == 0 && c.ssid[sizeof cafe] == '\0');
    char show[NODE_SHOW_MAX];
    node_cfg_format(&c, show, sizeof show);
    CHECK_MSG(strstr(show, " ssid=caf?? ") != NULL, show);
    for (size_t i = 0; show[i] != '\0'; i++) {
        CHECK((unsigned char)show[i] >= 0x20u && (unsigned char)show[i] < 0x7Fu);
    }
    char line[40];
    node_fmt_t f;
    node_fmt_init(&f, line, sizeof line);
    node_fmt_ssid(&f, c.ssid);
    CHECK(strcmp(line, "caf??") == 0);
    const char *why = NULL;
    CHECK_MSG(node_cfg_ready(&c, NODE_CHIP_ESP32, &why), why);
}

/* ---- backoff schedule (hal_udp.h) ----------------------------------------- */

static void test_backoff(void)
{
    static const uint32_t base[] = {1000u, 2000u, 4000u, 8000u, 16000u, 32000u, 60000u, 60000u, 60000u, 60000u};
    hal_udp_wifi_backoff_t b;
    hal_udp_wifi_backoff_reset(&b);

    tu_ctx("base sequence 1 2 4 8 16 32 60 60 ... s (rnd = span gives the base)");
    for (uint32_t i = 0; i < sizeof base / sizeof base[0]; i++) {
        CHECK_EQ_U32(hal_udp_wifi_backoff_base_ms(i + 1u), base[i]);
        const uint32_t span = base[i] / 5u;
        CHECK_EQ_U32(hal_udp_wifi_backoff_next(&b, span), base[i]);
        CHECK_EQ_U32(b.attempts, i + 1u);
    }
    CHECK_EQ_U32(hal_udp_wifi_backoff_base_ms(0u), 1000u);
    CHECK_EQ_U32(hal_udp_wifi_backoff_base_ms(1000u), 60000u);

    tu_ctx("jitter bounds: base - 20 % .. base + 20 %, both ends reachable");
    for (uint32_t n = 1; n <= 12u; n++) {
        const uint32_t bs = hal_udp_wifi_backoff_base_ms(n);
        const uint32_t lo = bs - bs / 5u;
        const uint32_t hi = bs + bs / 5u;
        hal_udp_wifi_backoff_t t = {n - 1u};
        CHECK_EQ_U32(hal_udp_wifi_backoff_next(&t, 0u), lo);
        t.attempts = n - 1u;
        CHECK_EQ_U32(hal_udp_wifi_backoff_next(&t, 2u * (bs / 5u)), hi);
        uint32_t x = 0x12345678u;
        for (int k = 0; k < 2000; k++) {
            x = x * 1664525u + 1013904223u; /* LCG */
            t.attempts = n - 1u;
            const uint32_t d = hal_udp_wifi_backoff_next(&t, x);
            CHECK(d >= lo && d <= hi);
        }
        t.attempts = n - 1u;
        const uint32_t dmax = hal_udp_wifi_backoff_next(&t, 0xFFFFFFFFu);
        CHECK(dmax >= lo && dmax <= hi);
    }

    tu_ctx("cap: never above 60 s base / 72 s with jitter, never below 0.8 s");
    hal_udp_wifi_backoff_reset(&b);
    for (int k = 0; k < 200; k++) {
        const uint32_t d = hal_udp_wifi_backoff_next(&b, (uint32_t)k * 2654435761u);
        CHECK(d >= 800u && d <= 72000u);
    }

    tu_ctx("reset: the next delay is 1 s +/- 20 % again");
    hal_udp_wifi_backoff_reset(&b);
    CHECK_EQ_U32(b.attempts, 0u);
    CHECK_EQ_U32(hal_udp_wifi_backoff_next(&b, 200u), 1000u);
    CHECK_EQ_U32(hal_udp_wifi_backoff_next(&b, 400u), 2000u);

    tu_ctx("saturation: attempts never wraps to 0 (no burst after 2^32 failures)");
    b.attempts = 0xFFFFFFFEu;
    CHECK_EQ_U32(hal_udp_wifi_backoff_next(&b, 12000u), 60000u);
    CHECK_EQ_U32(b.attempts, 0xFFFFFFFFu);
    CHECK_EQ_U32(hal_udp_wifi_backoff_next(&b, 12000u), 60000u);
    CHECK_EQ_U32(b.attempts, 0xFFFFFFFFu);
}

/* ---- no-quote rule and passphrase values in error texts -------------------- */

static void expect_hidden(const char *line, const char *needle, const char *secret)
{
    tu_ctx(line);
    CHECK(!parse(line));
    CHECK(C.kind == NODE_CMD_ERROR);
    CHECK_MSG(strstr(C.err, needle) != NULL, C.err);
    CHECK_MSG(strstr(C.err, secret) == NULL, C.err);
}

static void test_no_quote(void)
{
    /* a passphrase typed without pass= (no "pass" on the line): never quoted */
    expect_hidden("br set Hunter2Secret", "expected key=value", "Hunter2Secret");
    expect_hidden("br set Hunter2Secret", "13 characters", "Hunter2");
    expect_hidden("Hunter2Secret", "unknown command", "Hunter2Secret");
    expect_hidden("br Hunter2Secret", "unknown verb", "Hunter2Secret");
    expect_hidden("br show Hunter2Secret", "unexpected", "Hunter2Secret");
    expect_hidden("br set =Hunter2Secret", "expected key=value", "Hunter2Secret");
    expect_hidden("br set ssid=lab Hunter2Secret", "expected key=value", "Hunter2Secret");

    /* pass= values never appear, whatever the error */
    expect_hidden("br set pass=Zq9xW", "8..63", "Zq9xW");
    expect_hidden("br set pass=Zq9xWv8uTs7rQp6oNm5lKj4iHg3fEd2cBa1zYx0wVu9tSr8qPo7nMl6kJi5hGf4eDc3bA2zy",
                  "longer than 63", "Zq9xWv8");
    expect_hidden("br set pass=Secret123 pass=Secret456", "given twice", "Secret");
    expect_hidden("br set pass=Secret123 pass=Secret456", "given twice", "Secret456");

    /* upper case: PASS= is the pass key, the no-echo rule still applies */
    tu_ctx("BR SET PASS=Secret123 is accepted");
    CHECK(parse("BR SET PASS=Secret123"));
    CHECK(C.kind == NODE_CMD_SET);
    CHECK((C.fields & NODE_F_PASS) != 0u);
    CHECK(C.no_echo != 0u);
    expect_hidden("br set PASS=Zq9xW", "8..63", "Zq9xW");
    expect_hidden("BR SET PASS=Secret123 udp=maybe", "udp", "maybe");
    expect_hidden("BR SET PASS=Secret123 udp=maybe", "udp", "Secret123");
    expect_hidden("br set Pass=Secret123 Pass=Other4567", "given twice", "Other4567");

    /* a known key's bad value on a line without "pass" is still quoted (unchanged behaviour) */
    tu_ctx("br set udp=maybe quotes the value");
    CHECK(!parse("br set udp=maybe"));
    CHECK_MSG(strstr(C.err, "'maybe'") != NULL, C.err);
}

static void test_wipe(void)
{
    tu_ctx("node_wipe zeroes every byte; NULL / 0 are no-ops");
    char buf[NODE_PASS_MAX + 1];
    memset(buf, 'x', sizeof buf);
    node_wipe(buf, sizeof buf);
    for (size_t i = 0; i < sizeof buf; i++) {
        CHECK(buf[i] == 0);
    }
    node_wipe(NULL, 10u);
    memset(buf, 'y', sizeof buf);
    node_wipe(buf, 0u);
    CHECK(buf[0] == 'y');

    tu_ctx("node_cfg_apply leaves the passphrase only in the target cfg");
    node_cfg_t c;
    gateway_expected(&c);
    char err[NODE_ERR_MAX];
    CHECK(parse("br set pass=Another99"));
    CHECK_MSG(node_cfg_apply(&c, &C, err, sizeof err), err);
    CHECK(strcmp(c.pass, "Another99") == 0);
    CHECK(strstr(err, "Another99") == NULL);
}

int main(void)
{
    test_all_good();
    test_corrupt_ntp();
    test_optional_fallbacks();
    test_required_keys();
    test_raw_ssid();
    test_backoff();
    test_no_quote();
    test_wipe();
    return tu_summary("test_console_robust");
}
