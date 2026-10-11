// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_console_links.c - host test of the WiFi UDP and nRF24 console keys
 * (espnow= udp= port= mcast= peers= ssid= pass= nrf= nch= nrate= npa=
 * nsck= nmiso= nmosi= ncsn= nce= nirq=) and the transport policies of
 * spec 12.4 in components/app_node/src/node_console.c.
 *
 * Kept separate from test_console.c (phase 1c, frozen) and
 * test_console_uart.c (UART link, frozen) on purpose: those files check
 * that the earlier lines and the `br show` text are unchanged. Like them,
 * this test compiles the real source file into the executable.
 */
#include "test_util.h"

#include "../../components/app_node/src/node_console.c"

static node_cmd_t C;

static bool parse_on(node_chip_t chip, const char *line)
{
    return node_cmd_parse(line, chip, &C);
}

static bool parse(const char *line)
{
    return parse_on(NODE_CHIP_ESP32, line);
}

static void expect_err_on(node_chip_t chip, const char *line, const char *needle)
{
    tu_ctx(line);
    CHECK(!parse_on(chip, line));
    CHECK(C.kind == NODE_CMD_ERROR);
    CHECK_MSG(strstr(C.err, needle) != NULL, C.err);
}

static void expect_err(const char *line, const char *needle)
{
    expect_err_on(NODE_CHIP_ESP32, line, needle);
}

/* apply must fail with needle in err and leave cfg untouched */
static void expect_apply_err(node_cfg_t *cfg, const char *needle)
{
    char err[NODE_ERR_MAX];
    node_cfg_t before = *cfg;
    CHECK(!node_cfg_apply(cfg, &C, err, sizeof err));
    CHECK_MSG(strstr(err, needle) != NULL, err);
    CHECK(memcmp(&before, cfg, sizeof before) == 0);
}

static bool apply(node_cfg_t *cfg)
{
    char err[NODE_ERR_MAX];
    bool ok = node_cfg_apply(cfg, &C, err, sizeof err);
    if (!ok) {
        fprintf(stderr, "  apply: %s\n", err);
    }
    return ok;
}

static void test_defaults(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("defaults");
    node_cfg_defaults(&cfg);
    CHECK_EQ_U32(cfg.espnow, 1u);
    CHECK_EQ_U32(cfg.udp, 0u);
    CHECK_EQ_U32(cfg.port, 40888u);
    CHECK_EQ_U32(cfg.mcast, 1u);
    CHECK_EQ_U32(cfg.n_peers, 0u);
    CHECK(cfg.ssid[0] == '\0');
    CHECK(cfg.pass[0] == '\0');
    CHECK_EQ_U32(cfg.nrf, 0u);
    CHECK_EQ_U32(cfg.nch, 76u);
    CHECK_EQ_U32(cfg.nrate, NODE_NRATE_2M);
    CHECK_EQ_U32(cfg.npa, NODE_NPA_MAX);
    CHECK_EQ_U32(cfg.nsck, 18u);
    CHECK_EQ_U32(cfg.nmiso, 19u);
    CHECK_EQ_U32(cfg.nmosi, 23u);
    CHECK_EQ_U32(cfg.ncsn, 5u);
    CHECK_EQ_U32(cfg.nce, 4u);
    CHECK_EQ_U32(cfg.nirq, NODE_PIN_NONE);
    /* every link off: the phase 1c text, byte for byte */
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=unset id=unset grp=0xFF10 nbr=none led=2 btn=0 chan=1") == 0, out);

    tu_ctx("C.6 nRF24 default pins per chip");
    node_nrf_default_pins(NODE_CHIP_ESP32S3, &cfg);
    CHECK_EQ_U32(cfg.nsck, 12u);
    CHECK_EQ_U32(cfg.nmiso, 13u);
    CHECK_EQ_U32(cfg.nmosi, 11u);
    CHECK_EQ_U32(cfg.ncsn, 10u);
    CHECK_EQ_U32(cfg.nce, 9u);
    CHECK_EQ_U32(cfg.nirq, NODE_PIN_NONE);
    node_nrf_default_pins(NODE_CHIP_ESP32S3, NULL); /* tolerated */

    tu_ctx("default pins pass the pin rules on their chip, IRQ pins included");
    node_cfg_defaults(&cfg);
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, cfg.nsck, NODE_NRF_PIN_SCK, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, cfg.nmiso, NODE_NRF_PIN_MISO, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, cfg.nmosi, NODE_NRF_PIN_MOSI, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, cfg.ncsn, NODE_NRF_PIN_CSN, NULL)); /* GPIO5 strap exception */
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, cfg.nce, NODE_NRF_PIN_CE, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, NODE_PIN_NONE, NODE_NRF_PIN_IRQ, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, 35u, NODE_NRF_PIN_IRQ, NULL)); /* input-only is fine for IRQ */
    node_nrf_default_pins(NODE_CHIP_ESP32S3, &cfg);
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, cfg.nsck, NODE_NRF_PIN_SCK, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, cfg.nmiso, NODE_NRF_PIN_MISO, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, cfg.nmosi, NODE_NRF_PIN_MOSI, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, cfg.ncsn, NODE_NRF_PIN_CSN, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, cfg.nce, NODE_NRF_PIN_CE, NULL));
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32S3, 14u, NODE_NRF_PIN_IRQ, NULL));

    tu_ctx("names");
    CHECK(strcmp(node_nrate_name(NODE_NRATE_250K), "250k") == 0);
    CHECK(strcmp(node_nrate_name(NODE_NRATE_1M), "1m") == 0);
    CHECK(strcmp(node_nrate_name(NODE_NRATE_2M), "2m") == 0);
    CHECK(strcmp(node_nrate_name(9), "?") == 0);
    CHECK(strcmp(node_npa_name(NODE_NPA_MIN), "min") == 0);
    CHECK(strcmp(node_npa_name(NODE_NPA_LOW), "low") == 0);
    CHECK(strcmp(node_npa_name(NODE_NPA_HIGH), "high") == 0);
    CHECK(strcmp(node_npa_name(NODE_NPA_MAX), "max") == 0);
    CHECK(strcmp(node_npa_name(9), "?") == 0);
}

static void test_peer_parse(void)
{
    uint32_t ip = 0;
    uint16_t port = 0;
    char buf[32];
    node_fmt_t f;

    tu_ctx("peer parse");
    CHECK(node_peer_parse("192.168.1.20", &ip, &port));
    CHECK_EQ_U32(ip, 0xC0A80114u);
    CHECK_EQ_U32(port, 40888u);
    CHECK(node_peer_parse("10.0.0.1:5000", &ip, &port));
    CHECK_EQ_U32(ip, 0x0A000001u);
    CHECK_EQ_U32(port, 5000u);
    CHECK(node_peer_parse("223.255.255.255:65535", &ip, &port));
    CHECK_EQ_U32(ip, 0xDFFFFFFFu);
    CHECK_EQ_U32(port, 65535u);
    CHECK(node_peer_parse("1.2.3.4", NULL, NULL));
    tu_ctx("peer parse: unicast host addresses only");
    CHECK(!node_peer_parse("0.0.0.0", &ip, &port));
    CHECK(!node_peer_parse("127.0.0.1", &ip, &port));
    CHECK(!node_peer_parse("224.0.0.1", &ip, &port));
    CHECK(!node_peer_parse("239.255.40.88:40888", &ip, &port));
    CHECK(!node_peer_parse("255.255.255.255", &ip, &port));
    CHECK(node_peer_parse("223.255.255.255", &ip, &port));
    CHECK(node_peer_parse("128.0.0.1", &ip, &port));
    CHECK(!node_peer_parse(NULL, &ip, &port));
    CHECK(!node_peer_parse("", &ip, &port));
    CHECK(!node_peer_parse("1.2.3", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4.5", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.256", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4:", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4:0", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4:65536", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4:40888x", &ip, &port));
    CHECK(!node_peer_parse("1..3.4", &ip, &port));
    CHECK(!node_peer_parse("a.b.c.d", &ip, &port));
    CHECK(!node_peer_parse("1.2.3.4 ", &ip, &port));
    CHECK(!node_peer_parse("0x1.2.3.4", &ip, &port));

    tu_ctx("peer format");
    node_fmt_init(&f, buf, sizeof buf);
    node_fmt_peer(&f, 0xC0A80114u, 40888u);
    CHECK_MSG(strcmp(buf, "192.168.1.20:40888") == 0, buf);
    node_fmt_init(&f, buf, sizeof buf);
    node_fmt_peer(&f, 0u, 1u);
    CHECK_MSG(strcmp(buf, "0.0.0.0:1") == 0, buf);
}

static void test_udp_keys_and_show(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("LAN-side board: udp on, espnow off, multicast");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=probe id=0x0103 grp=0xFF10 espnow=off udp=on ssid=lab pass=secret-1"));
    CHECK(C.kind == NODE_CMD_SET);
    CHECK_EQ_U32(C.fields, NODE_F_ROLE | NODE_F_UID | NODE_F_GRP | NODE_F_ESPNOW | NODE_F_UDP | NODE_F_SSID |
                               NODE_F_PASS);
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(strcmp(cfg.ssid, "lab") == 0);
    CHECK(strcmp(cfg.pass, "secret-1") == 0);
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=probe id=0x0103 grp=0xFF10 nbr=none led=2 btn=0 chan=1 espnow=off udp=on "
                          "port=40888 mcast=on peers=none ssid=lab pass=set") == 0,
              out);
    CHECK(strstr(out, "secret") == NULL); /* the passphrase is never printed */

    tu_ctx("peer list, port, mcast off");
    CHECK(parse("br set port=5000 mcast=off peers=192.168.1.10,192.168.1.11:5001"));
    CHECK_EQ_U32(C.fields, NODE_F_PORT | NODE_F_MCAST | NODE_F_PEERS);
    CHECK_EQ_U32(C.val.n_peers, 2u);
    CHECK_EQ_U32(C.val.peers[0].ip, 0xC0A8010Au);
    CHECK_EQ_U32(C.val.peers[0].port, 40888u);
    CHECK_EQ_U32(C.val.peers[1].ip, 0xC0A8010Bu);
    CHECK_EQ_U32(C.val.peers[1].port, 5001u);
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " udp=on port=5000 mcast=off peers=192.168.1.10:40888,192.168.1.11:5001 ssid=lab "
                          "pass=set") != NULL,
              out);

    tu_ctx("open AP: empty pass is accepted and shown as unset");
    CHECK(parse("br set pass="));
    CHECK_EQ_U32(C.fields, NODE_F_PASS);
    CHECK(C.val.pass[0] == '\0');
    CHECK(apply(&cfg));
    CHECK(cfg.pass[0] == '\0');
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " pass=unset") != NULL, out);
    expect_err("br set ssid=", "empty value"); /* only pass may be empty */

    tu_ctx("udp=off hides the group but keeps the values");
    CHECK(parse("br set udp=off espnow=on"));
    CHECK(apply(&cfg));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=probe id=0x0103 grp=0xFF10 nbr=none led=2 btn=0 chan=1") == 0, out);
    CHECK_EQ_U32(cfg.port, 5000u);
    CHECK_EQ_U32(cfg.n_peers, 2u);
    CHECK(strcmp(cfg.ssid, "lab") == 0);

    tu_ctx("espnow=off alone is shown");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 uart=on espnow=off"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=node id=0x0102 grp=0xFF10 nbr=none led=2 btn=0 chan=1 uart=on utx=17 urx=16 "
                          "ubaud=921600 espnow=off") == 0,
              out);

    tu_ctx("peers=none clears the list");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set peers=10.0.0.1,10.0.0.2"));
    CHECK(apply(&cfg));
    CHECK_EQ_U32(cfg.n_peers, 2u);
    CHECK(parse("br set peers=none"));
    CHECK(apply(&cfg));
    CHECK_EQ_U32(cfg.n_peers, 0u);

    tu_ctx("eight peers, longest spelling, fits the line and the show buffer");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=sender id=0xFEFF grp=0xFFFE "
                "nbr=0x0010,0x0011,0x0012,0x0013,0x0014,0x0015,0x0016,0x0017 led=33 btn=32 chan=13 "
                "uart=on utx=25 urx=26 ubaud=2000000 espnow=off"));
    CHECK(apply(&cfg));
    CHECK(parse("br set udp=on port=65535 mcast=off peers=223.255.255.255:65535,223.255.255.254:65535,223.255.255.253:65535,"
                "223.255.255.252:65535,223.255.255.251:65535,223.255.255.250:65535,223.255.255.249:65535,"
                "223.255.255.248:65535 ssid=abcdefghijklmnopqrstuvwxyz012345 "
                "pass=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0"));
    CHECK_EQ_U32(C.val.n_peers, 8u);
    CHECK_EQ_U32(strlen(C.val.ssid), 32u);
    CHECK_EQ_U32(strlen(C.val.pass), 63u);
    CHECK(apply(&cfg));
    CHECK(parse("br set nrf=on nsck=14 nmiso=35 nmosi=27 ncsn=13 nce=4 nirq=34"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    size_t n = node_cfg_format(&cfg, out, sizeof out);
    CHECK(n + 1u < sizeof out); /* not truncated */
    CHECK_MSG(strstr(out, " peers=223.255.255.255:65535,") != NULL, out);
    CHECK_MSG(strstr(out, ",223.255.255.248:65535 ssid=abcdefghijklmnopqrstuvwxyz012345 pass=set nrf=on") != NULL,
              out);
    CHECK(strstr(out, "0123456789abc") == NULL); /* no passphrase fragment */
}

static void test_udp_values(void)
{
    expect_err("br set udp=maybe", "udp: 'maybe' is not on|off");
    expect_err("br set espnow=1", "espnow: '1' is not on|off");
    expect_err("br set mcast=yes", "mcast: 'yes' is not on|off");
    expect_err("br set port=0", "port: '0' is not a UDP port 1..65535");
    expect_err("br set port=65536", "not a UDP port");
    expect_err("br set port=http", "not a UDP port");
    expect_err("br set peers=1.2.3", "peers: '1.2.3' is not a.b.c.d[:port]");
    expect_err("br set peers=1.2.3.4:0", "is not a.b.c.d[:port]");
    expect_err("br set peers=1.2.3.4,,5.6.7.8", "peers: empty entry in the list");
    expect_err("br set peers=1.2.3.4,1.2.3.4", "peers: duplicate '1.2.3.4'");
    expect_err("br set peers=1.2.3.4:40888,1.2.3.4", "duplicate"); /* same ip:port spelt differently */
    expect_err("br set peers=1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5,1.1.1.6,1.1.1.7,1.1.1.8,1.1.1.9",
               "peers: more than 8 entries");
    expect_err("br set peers=1234567890123456789012345", "is not a.b.c.d[:port]");
    expect_err("br set ssid=abcdefghijklmnopqrstuvwxyz0123456", "ssid: longer than 32 characters");
    tu_ctx("a too-long pass is refused without echoing it");
    CHECK(!parse("br set pass=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"));
    CHECK(C.kind == NODE_CMD_ERROR);
    CHECK_MSG(strstr(C.err, "pass: longer than 63 characters") != NULL, C.err);
    CHECK(strstr(C.err, "abcdef") == NULL);
    tu_ctx("a short WPA2 pass is refused without echoing it");
    CHECK(!parse("br set pass=Secret7"));
    CHECK_MSG(strstr(C.err, "8..63") != NULL, C.err);
    CHECK(strstr(C.err, "Secret7") == NULL);
    CHECK(parse("br set pass=Secret78"));
    tu_ctx("no error text of a line that mentions pass quotes a token");
    CHECK(!parse("br set pass= Secret123"));         /* a space in the passphrase: stray token */
    CHECK_MSG(strstr(C.err, "Secret123") == NULL, C.err);
    CHECK_MSG(strstr(C.err, "<hidden>") != NULL, C.err);
    CHECK(!parse("br set pass:Secret123"));          /* colon instead of = */
    CHECK_MSG(strstr(C.err, "Secret123") == NULL, C.err);
    CHECK(!parse("MyPassword99"));                   /* passphrase pasted alone on a line */
    CHECK_MSG(strstr(C.err, "MyPassword99") == NULL, C.err);
    CHECK(!parse("br set pass=Secret123 udp=maybe")); /* another key's bad value on the same line */
    CHECK_MSG(strstr(C.err, "maybe") == NULL, C.err);
    CHECK(!parse("br set ssid=lab pass=Secret123 nirq=x"));
    CHECK_MSG(strstr(C.err, "'x'") == NULL, C.err);
    CHECK(!parse("br set udp=maybe"));               /* no pass on the line: tokens are quoted as before */
    CHECK_MSG(strstr(C.err, "'maybe'") != NULL, C.err);
    expect_err("br set udp=on udp=off", "given twice");
    expect_err("br set pass=Secret123 pass=Secret456", "given twice");
    expect_err("br set peers=1.2.3.4 peers=none", "given twice");
    expect_err("br set udpx=on", "unknown key");
    expect_err("br set colour=red", "espnow udp port mcast peers ssid pass");
    expect_err("br set colour=red", "nrf nch nrate npa nsck nmiso nmosi ncsn nce nirq");
    expect_err("br set colour=red", "uart utx urx ubaud"); /* the UART test's needle still fits */
}

static void test_transport_policy(void)
{
    node_cfg_t cfg;
    const char *why = NULL;

    tu_ctx("udp=on with espnow=on (default) is refused, 12.4");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=probe id=0x0103 udp=on ssid=lab"));
    expect_apply_err(&cfg, "udp and espnow cannot share a chip");
    CHECK(parse("br set role=probe id=0x0103 udp=on ssid=lab espnow=off"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    tu_ctx("turning espnow back on while udp is on is refused");
    CHECK(parse("br set espnow=on"));
    expect_apply_err(&cfg, "udp and espnow cannot share a chip");
    tu_ctx("udp=off first, then espnow=on, in one line");
    CHECK(parse("br set udp=off espnow=on"));
    CHECK(apply(&cfg));

    tu_ctx("espnow=off with nothing else on");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 espnow=off"));
    expect_apply_err(&cfg, "no transport on");
    CHECK(parse("br set role=node id=0x0102 espnow=off nrf=on"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(parse("br set nrf=off"));
    expect_apply_err(&cfg, "no transport on");
    CHECK(parse("br set nrf=off uart=on"));
    CHECK(apply(&cfg));

    tu_ctx("udp=on needs ssid");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=probe id=0x0103 espnow=off udp=on"));
    expect_apply_err(&cfg, "udp=on needs ssid=");

    tu_ctx("mcast=off needs peers");
    CHECK(parse("br set role=probe id=0x0103 espnow=off udp=on ssid=lab mcast=off"));
    expect_apply_err(&cfg, "mcast=off needs peers=");
    CHECK(parse("br set role=probe id=0x0103 espnow=off udp=on ssid=lab mcast=off peers=10.0.0.1"));
    CHECK(apply(&cfg));
    CHECK(parse("br set peers=none"));
    expect_apply_err(&cfg, "mcast=off needs peers=");
    CHECK(parse("br set peers=none mcast=on"));
    CHECK(apply(&cfg));

    tu_ctx("bridge: espnow + nrf24 on one board is fine; espnow + uart + nrf too");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nrf=on uart=on"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("ready() re-checks the policy on what NVS returned");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_PROBE;
    cfg.uid = 0x0103;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.udp = 1;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "udp and espnow") != NULL);
    cfg.espnow = 0;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ssid") != NULL);
    memcpy(cfg.ssid, "lab", 4);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.mcast = 0;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "peers") != NULL);
    cfg.n_peers = 1;
    cfg.peers[0].ip = 0;
    cfg.peers[0].port = 40888;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "peers entry") != NULL);
    cfg.peers[0].ip = 0x0A000001u;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.port = 0;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "port") != NULL);
    cfg.port = 40888;
    cfg.n_peers = 9;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "peers has more") != NULL);
    cfg.n_peers = 1;
    cfg.udp = 2;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "udp not on/off") != NULL);
    cfg.udp = 1;
    cfg.espnow = 2;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "espnow not on/off") != NULL);
    cfg.espnow = 0;
    cfg.mcast = 2;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "mcast not on/off") != NULL);
    cfg.mcast = 1;
    memset(cfg.ssid, 'a', sizeof cfg.ssid); /* no NUL: a corrupt blob */
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ssid longer") != NULL);
    memcpy(cfg.ssid, "lab", 4);
    memset(cfg.pass, 'b', sizeof cfg.pass);
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "pass longer") != NULL);
    memcpy(cfg.pass, "short", 6);
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "pass shorter") != NULL);
    memcpy(cfg.pass, "longenough", 11);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.pass[0] = '\0';
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    tu_ctx("udp off: its fields are not checked");
    cfg.udp = 0;
    cfg.espnow = 1;
    cfg.port = 0;
    cfg.ssid[0] = '\0';
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
}

static void test_nrf_keys_and_show(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("bridge board: nrf on with defaults");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nrf=on"));
    CHECK_EQ_U32(C.fields, NODE_F_ROLE | NODE_F_UID | NODE_F_NRF);
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=node id=0x0102 grp=0xFF10 nbr=none led=2 btn=0 chan=1 nrf=on nch=76 nrate=2m "
                          "npa=max nsck=18 nmiso=19 nmosi=23 ncsn=5 nce=4 nirq=-1") == 0,
              out);

    tu_ctx("radio settings, case-insensitive");
    CHECK(parse("br set NCH=81 NRATE=250K NPA=Min NIRQ=35"));
    CHECK_EQ_U32(C.fields, NODE_F_NCH | NODE_F_NRATE | NODE_F_NPA | NODE_F_NIRQ);
    CHECK(apply(&cfg));
    CHECK_EQ_U32(cfg.nch, 81u);
    CHECK_EQ_U32(cfg.nrate, NODE_NRATE_250K);
    CHECK_EQ_U32(cfg.npa, NODE_NPA_MIN);
    CHECK_EQ_U32(cfg.nirq, 35u);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " nrf=on nch=81 nrate=250k npa=min nsck=18 nmiso=19 nmosi=23 ncsn=5 nce=4 nirq=35") != NULL,
              out);
    CHECK(parse("br set nrate=1m npa=low"));
    CHECK(apply(&cfg));
    CHECK_EQ_U32(cfg.nrate, NODE_NRATE_1M);
    CHECK_EQ_U32(cfg.npa, NODE_NPA_LOW);
    CHECK(parse("br set nrate=2m npa=high nirq=none"));
    CHECK(apply(&cfg));
    CHECK_EQ_U32(cfg.nrate, NODE_NRATE_2M);
    CHECK_EQ_U32(cfg.npa, NODE_NPA_HIGH);
    CHECK_EQ_U32(cfg.nirq, NODE_PIN_NONE);

    tu_ctx("all six pins on an S3");
    node_cfg_defaults(&cfg);
    node_nrf_default_pins(NODE_CHIP_ESP32S3, &cfg);
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set role=probe id=0x0103 nrf=on nsck=12 nmiso=13 nmosi=11 ncsn=10 nce=9 nirq=14"));
    CHECK_EQ_U32(C.fields, NODE_F_ROLE | NODE_F_UID | NODE_F_NRF | NODE_F_NSCK | NODE_F_NMISO | NODE_F_NMOSI |
                               NODE_F_NCSN | NODE_F_NCE | NODE_F_NIRQ);
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32S3, NULL));
    CHECK_EQ_U32(cfg.nirq, 14u);
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " nsck=12 nmiso=13 nmosi=11 ncsn=10 nce=9 nirq=14") != NULL, out);

    tu_ctx("nrf=off hides the group but keeps the values");
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set nrf=off"));
    CHECK(apply(&cfg));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=probe id=0x0103 grp=0xFF10 nbr=none led=2 btn=0 chan=1") == 0, out);
    CHECK_EQ_U32(cfg.nirq, 14u);
}

static void test_nrf_values(void)
{
    expect_err("br set nrf=1", "nrf: '1' is not on|off");
    expect_err("br set nch=75", "nch: '75' is not a channel 76..83");
    expect_err("br set nch=84", "not a channel 76..83");
    expect_err("br set nch=0x54", "not a channel 76..83"); /* hex is parsed: 0x54 = 84 */
    expect_err("br set nrate=3m", "nrate: '3m' is not 250k|1m|2m");
    expect_err("br set nrate=2", "is not 250k|1m|2m");
    expect_err("br set npa=0", "npa: '0' is not min|low|high|max");
    expect_err("br set npa=medium", "is not min|low|high|max");
    expect_err("br set nsck=x", "nsck: 'x' is not a GPIO number");
    expect_err("br set nirq=-2", "nirq: '-2' is not a GPIO number or -1");
    expect_err("br set nce=255", "nce: '255' is not a GPIO number");
    expect_err("br set nch=76 nch=77", "given twice");
    expect_err("br set nirq=-1 nirq=35", "given twice");
}

static void test_nrf_pin_rules(void)
{
    const char *why = NULL;

    /* ESP32: flash, console, no such GPIO, input-only for outputs, strapping */
    expect_err("br set nsck=6", "SPI flash");
    expect_err("br set nmiso=11", "SPI flash");
    expect_err("br set nmosi=1", "UART0");
    expect_err("br set nirq=3", "UART0");
    expect_err("br set nce=20", "no such GPIO");
    expect_err("br set ncsn=40", "no such GPIO");
    expect_err("br set nsck=34", "input-only");
    expect_err("br set nmosi=36", "input-only");
    expect_err("br set ncsn=39", "input-only");
    expect_err("br set nce=35", "input-only");
    expect_err("br set nsck=0", "strapping");
    expect_err("br set nmosi=2", "strapping");
    expect_err("br set nce=5", "strapping");   /* GPIO5 only as CSN */
    expect_err("br set nsck=5", "strapping");
    expect_err("br set nmiso=12", "strapping");
    expect_err("br set nirq=15", "strapping");
    expect_err("br set ncsn=12", "strapping");

    /* ESP32-S3: flash, PSRAM, USB, console, strapping, input-only 46 */
    expect_err_on(NODE_CHIP_ESP32S3, "br set nsck=27", "SPI flash");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nmiso=35", "PSRAM");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nmosi=19", "USB-JTAG");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nirq=44", "UART0");
    expect_err_on(NODE_CHIP_ESP32S3, "br set ncsn=3", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nce=45", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nsck=46", "input-only"); /* 46 is input-only and strapping */
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set ncsn=5")); /* plain GPIO on the S3 */
    expect_err_on(NODE_CHIP_ESP32S3, "br set nirq=46", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set nce=23", "no such GPIO");

    tu_ctx("accepted pins");
    CHECK(parse("br set ncsn=5"));            /* the C.6 exception */
    CHECK(parse("br set nmiso=35 nirq=39"));  /* input-only inputs */
    CHECK(parse("br set nsck=14 nmosi=27 nce=33 ncsn=32"));
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set nsck=12 nmiso=13 nmosi=11 ncsn=10 nce=9 nirq=14"));
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set nsck=47 nmiso=48 nmosi=21 ncsn=38 nce=39 nirq=40"));

    tu_ctx("why strings");
    CHECK(!node_nrf_pin_ok(NODE_CHIP_ESP32, 5u, NODE_NRF_PIN_CE, &why));
    CHECK(why != NULL && strstr(why, "GPIO0/2/5/12/15") != NULL);
    CHECK(node_nrf_pin_ok(NODE_CHIP_ESP32, 5u, NODE_NRF_PIN_CSN, &why));
    CHECK(why == NULL);
    CHECK(!node_nrf_pin_ok(NODE_CHIP_ESP32S3, 46u, NODE_NRF_PIN_CE, &why));
    CHECK(why != NULL && strstr(why, "input-only") != NULL);
    CHECK(!node_nrf_pin_ok(NODE_CHIP_ESP32, NODE_PIN_NONE, NODE_NRF_PIN_SCK, &why)); /* -1 only for IRQ */
    CHECK(why != NULL);
    tu_ctx("strapping pins are fine for led / btn, not for the radio");
    CHECK(node_pin_ok(NODE_CHIP_ESP32, 12u, true, NULL));
    CHECK(!node_nrf_pin_ok(NODE_CHIP_ESP32, 12u, NODE_NRF_PIN_SCK, NULL));
}

static void test_nrf_cross_fields(void)
{
    node_cfg_t cfg;
    const char *why = NULL;

    tu_ctx("two nRF24 pins the same");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nrf=on nsck=18 nmiso=18"));
    expect_apply_err(&cfg, "two nRF24 pins are the same pin");
    CHECK(parse("br set role=node id=0x0102 nrf=on nirq=4")); /* = nce default */
    expect_apply_err(&cfg, "two nRF24 pins are the same pin");

    tu_ctx("nRF24 pin equal to led / btn");
    CHECK(parse("br set role=node id=0x0102 nrf=on led=4"));
    expect_apply_err(&cfg, "led pin");
    CHECK(parse("br set role=node id=0x0102 nrf=on btn=19"));
    expect_apply_err(&cfg, "btn pin");
    CHECK(parse("br set role=node id=0x0102 led=4")); /* nrf off: no conflict yet */
    CHECK(apply(&cfg));
    CHECK(parse("br set nrf=on"));
    expect_apply_err(&cfg, "led pin");
    CHECK(parse("br set nrf=on led=2"));
    CHECK(apply(&cfg));

    tu_ctx("nRF24 pin equal to a UART link pin, only when uart=on");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nrf=on nce=17"));
    CHECK(apply(&cfg)); /* uart off */
    CHECK(parse("br set uart=on"));
    expect_apply_err(&cfg, "UART link pin");
    CHECK(parse("br set uart=on utx=25 urx=26"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("channels 82 / 83 need 250k or 1m");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nrf=on nch=82"));
    expect_apply_err(&cfg, "nch 82..83 need nrate=250k|1m");
    CHECK(parse("br set role=node id=0x0102 nrf=on nch=83 nrate=1m"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(parse("br set nrate=2m"));
    expect_apply_err(&cfg, "nch 82..83");
    CHECK(parse("br set nrate=2m nch=81"));
    CHECK(apply(&cfg));
    tu_ctx("nrf off: the channel rule does not apply");
    CHECK(parse("br set nrf=off nch=83"));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("a bad token anywhere changes nothing");
    node_cfg_defaults(&cfg);
    CHECK(!parse("br set nrf=on nsck=14 nmosi=12"));
    CHECK(C.kind == NODE_CMD_ERROR);

    tu_ctx("ready() re-checks what NVS returned");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_NODE;
    cfg.uid = 0x0102;
    cfg.nsck = 6; /* nrf off: not used, not checked */
    cfg.nch = 1;
    cfg.nrate = 7;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nrf = 1;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nch") != NULL);
    cfg.nch = 76;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nrate") != NULL);
    cfg.nrate = NODE_NRATE_2M;
    cfg.npa = 4;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "npa") != NULL);
    cfg.npa = NODE_NPA_MAX;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nsck") != NULL);
    cfg.nsck = 18;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nmiso = 34; /* input-only: fine for MISO */
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nmosi = 34;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nmosi") != NULL);
    cfg.nmosi = 23;
    cfg.ncsn = 15;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ncsn") != NULL);
    cfg.ncsn = 5;
    cfg.nce = 2;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nce") != NULL);
    cfg.nce = 4;
    cfg.nirq = 12;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nirq") != NULL);
    cfg.nirq = 35;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nirq = 18; /* = nsck */
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "same pin") != NULL);
    cfg.nirq = NODE_PIN_NONE;
    cfg.nch = 82;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "82..83") != NULL);
    cfg.nrate = NODE_NRATE_250K;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nrf = 3;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "nrf not on/off") != NULL);
    cfg.nrf = 1;
    tu_ctx("the ESP32 default pins are refused on an S3 only where the S3 says so");
    cfg.nsck = 18;
    cfg.nmiso = 19; /* S3: USB-JTAG */
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32S3, &why));
    CHECK(why != NULL && strstr(why, "nmiso") != NULL);
}

int main(void)
{
    test_defaults();
    test_peer_parse();
    test_udp_keys_and_show();
    test_udp_values();
    test_transport_policy();
    test_nrf_keys_and_show();
    test_nrf_values();
    test_nrf_pin_rules();
    test_nrf_cross_fields();
    return tu_summary("test_console_links");
}
