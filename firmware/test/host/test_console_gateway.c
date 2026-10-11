// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_console_gateway.c - host test of the single-chip WiFi + nRF24 gateway
 * support in components/app_node/src/node_console.c:
 *   - the wifi= key (station decoupled from udp=) and its policies:
 *     wifi=on needs espnow=off and ssid=, udp=on needs wifi=on, a line with
 *     udp= and no wifi= keeps the pre-wifi= coupling, wifi alone is not a
 *     transport, nrf=on + wifi=on + espnow=off is allowed;
 *   - the backward-compatibility rule (stored udp=1 without a wifi key reads
 *     as wifi=on);
 *   - the ntp= key (SNTP server) and the no-echo rule on lines with pass=;
 *   - the gateway configuration line of firmware/GATEWAY-NRF24.txt and the
 *     manager-ID refusal (SPEC-NOTES N1: the core runs units only);
 *   - the AP channel / nRF24 channel clearance helper and the BRNRF
 *     coexistence text;
 *   - the ISO-8601 formatter behind the BRNTP line.
 *
 * test_console.c, test_console_uart.c and test_console_links.c are frozen
 * and must stay green unchanged; this file only adds. Like them it compiles
 * the real source file into the executable.
 */
#include "test_util.h"

#include "../../components/app_node/src/node_console.c"

static node_cmd_t C;

static bool parse(const char *line)
{
    return node_cmd_parse(line, NODE_CHIP_ESP32, &C);
}

static void expect_err(const char *line, const char *needle)
{
    tu_ctx(line);
    CHECK(!parse(line));
    CHECK(C.kind == NODE_CMD_ERROR);
    CHECK_MSG(strstr(C.err, needle) != NULL, C.err);
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

/* parse + apply one line that must succeed */
static void set_ok(node_cfg_t *cfg, const char *line)
{
    tu_ctx(line);
    CHECK(parse(line));
    CHECK(apply(cfg));
}

static void test_defaults(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("defaults: station off, ntp pool.ntp.org, nothing new in br show");
    node_cfg_defaults(&cfg);
    CHECK_EQ_U32(cfg.wifi, 0u);
    CHECK(strcmp(cfg.ntp, "pool.ntp.org") == 0);
    CHECK(!node_cfg_wifi_on(&cfg));
    CHECK(!node_cfg_wifi_on(NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=unset id=unset grp=0xFF10 nbr=none led=2 btn=0 chan=1") == 0, out);
}

static void test_wifi_key(void)
{
    tu_ctx("wifi=on|off parses into its own field bit");
    CHECK(parse("br set wifi=on"));
    CHECK_EQ_U32(C.fields, NODE_F_WIFI);
    CHECK_EQ_U32(C.val.wifi, 1u);
    CHECK(parse("br set WIFI=OFF"));
    CHECK_EQ_U32(C.fields, NODE_F_WIFI);
    CHECK_EQ_U32(C.val.wifi, 0u);
    expect_err("br set wifi=1", "wifi: '1' is not on|off");
    expect_err("br set wifi=", "empty value");
    expect_err("br set wifi=on wifi=off", "given twice");
    expect_err("br set colour=red", "nce nirq wifi ntp)");
    /* the frozen needles of the earlier tests still fit the key list */
    expect_err("br set colour=red", "espnow udp port mcast peers ssid pass");
    expect_err("br set colour=red", "nrf nch nrate npa nsck nmiso nmosi ncsn nce nirq");
    expect_err("br set colour=red", "uart utx urx ubaud");
    tu_ctx("the longest unknown key still shows the whole key list");
    CHECK(!parse("br set abcdefghijklmnopqrstuvwxyz0123456789=1"));
    CHECK_MSG(strstr(C.err, "wifi ntp)") != NULL, C.err);
}

static void test_policies(void)
{
    node_cfg_t cfg;

    tu_ctx("wifi=on with espnow=on (default) is refused, 12.4");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=probe id=0x0103 wifi=on ssid=lab nrf=on"));
    expect_apply_err(&cfg, "wifi and espnow cannot share a chip");

    tu_ctx("wifi alone is not a transport");
    CHECK(parse("br set role=probe id=0x0103 wifi=on ssid=lab espnow=off"));
    expect_apply_err(&cfg, "no transport on");

    tu_ctx("wifi=on needs ssid=");
    CHECK(parse("br set role=probe id=0x0103 wifi=on espnow=off nrf=on"));
    expect_apply_err(&cfg, "wifi=on needs ssid=");

    tu_ctx("udp=on with an explicit wifi=off is refused");
    CHECK(parse("br set role=probe id=0x0103 espnow=off udp=on wifi=off ssid=lab"));
    expect_apply_err(&cfg, "udp=on requires wifi=on");

    tu_ctx("nrf=on + wifi=on + espnow=off: the gateway combination");
    set_ok(&cfg, "br set role=probe id=0x0103 nrf=on espnow=off wifi=on ssid=lab");
    CHECK_EQ_U32(cfg.wifi, 1u);
    CHECK_EQ_U32(cfg.udp, 0u);
    CHECK(node_cfg_wifi_on(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("espnow back on while the station is on is refused");
    CHECK(parse("br set espnow=on"));
    expect_apply_err(&cfg, "wifi and espnow cannot share a chip");

    tu_ctx("wifi=off is fine while nrf carries the frames");
    set_ok(&cfg, "br set wifi=off");
    CHECK_EQ_U32(cfg.wifi, 0u);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    set_ok(&cfg, "br set wifi=on");

    tu_ctx("udp=on without wifi= on the line: the station stays on");
    set_ok(&cfg, "br set udp=on");
    CHECK_EQ_U32(cfg.wifi, 1u);
    CHECK_EQ_U32(cfg.udp, 1u);
    tu_ctx("wifi=off while udp is on is refused");
    CHECK(parse("br set wifi=off"));
    expect_apply_err(&cfg, "udp=on requires wifi=on");
    tu_ctx("udp=off wifi=on keeps the station (SNTP) and drops the LAN link");
    set_ok(&cfg, "br set udp=off wifi=on");
    CHECK_EQ_U32(cfg.udp, 0u);
    CHECK_EQ_U32(cfg.wifi, 1u);
    tu_ctx("udp=off alone also turns the station off (pre-wifi= coupling)");
    set_ok(&cfg, "br set udp=on");
    set_ok(&cfg, "br set udp=off");
    CHECK_EQ_U32(cfg.udp, 0u);
    CHECK_EQ_U32(cfg.wifi, 0u);
    tu_ctx("udp=on alone (no wifi= anywhere) turns the station on, as before");
    set_ok(&cfg, "br set udp=on");
    CHECK_EQ_U32(cfg.wifi, 1u);

    tu_ctx("uart + wifi on a LAN-side board is fine");
    node_cfg_defaults(&cfg);
    set_ok(&cfg, "br set role=node id=0x0102 uart=on espnow=off wifi=on ssid=lab");
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("ready() re-checks the wifi rules on what NVS returned");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_PROBE;
    cfg.uid = 0x0103;
    cfg.nrf = 1;
    memcpy(cfg.ssid, "lab", 4);
    const char *why = NULL;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.wifi = 1;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "wifi and espnow") != NULL);
    cfg.espnow = 0;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.nrf = 0;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "no transport on") != NULL);
    cfg.nrf = 1;
    cfg.ssid[0] = '\0';
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "wifi=on needs ssid=") != NULL);
    memcpy(cfg.ssid, "lab", 4);
    cfg.wifi = 2;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "wifi not on/off") != NULL);
    cfg.wifi = 1;
    memcpy(cfg.pass, "short", 6);
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "pass shorter") != NULL);
    memcpy(cfg.pass, "longenough", 11);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    memcpy(cfg.ntp, "bad host", 9);
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ntp not a host name") != NULL);
    memset(cfg.ntp, 'a', sizeof cfg.ntp); /* no NUL: a corrupt blob */
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ntp not a host name") != NULL);
    tu_ctx("station off: ssid, pass and ntp are not checked");
    cfg.wifi = 0;
    cfg.ssid[0] = '\0';
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
}

static void test_backward_compat(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("NVS from before wifi=: udp=1 and no wifi key loads as wifi=on");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_PROBE;
    cfg.uid = 0x0103;
    cfg.espnow = 0;
    cfg.udp = 1;
    memcpy(cfg.ssid, "lab", 4);
    CHECK_EQ_U32(cfg.wifi, 0u);
    CHECK(node_cfg_wifi_on(&cfg)); /* implied even before the loader fixes the field */
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_legacy_wifi(&cfg, false);
    CHECK_EQ_U32(cfg.wifi, 1u);
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=probe id=0x0103 grp=0xFF10 nbr=none led=2 btn=0 chan=1 espnow=off udp=on "
                          "port=40888 mcast=on peers=none ssid=lab pass=unset") == 0,
              out); /* the udp line is unchanged: no wifi= token where udp implies it */

    tu_ctx("a present wifi key is never overridden");
    cfg.wifi = 0;
    node_cfg_legacy_wifi(&cfg, true);
    CHECK_EQ_U32(cfg.wifi, 0u);
    tu_ctx("no wifi key and udp off: station stays off");
    node_cfg_defaults(&cfg);
    node_cfg_legacy_wifi(&cfg, false);
    CHECK_EQ_U32(cfg.wifi, 0u);
    node_cfg_legacy_wifi(NULL, false); /* no crash */

    tu_ctx("an unrelated br set on a legacy configuration keeps the station");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_PROBE;
    cfg.uid = 0x0103;
    cfg.espnow = 0;
    cfg.udp = 1;
    memcpy(cfg.ssid, "lab", 4);
    set_ok(&cfg, "br set nbr=0x0102");
    CHECK_EQ_U32(cfg.wifi, 1u);
    CHECK_EQ_U32(cfg.udp, 1u);
}

static void test_gateway_line(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("the task's literal line with id=0x0001 is refused: manager ID (N1)");
    node_cfg_defaults(&cfg);
    expect_err("br set role=probe id=0x0001 grp=0xFF10 nrf=on espnow=off wifi=on ssid=lab pass=secret-1",
               "unit ID");
    CHECK_MSG(strstr(C.err, "manager IDs (N1)") != NULL, C.err);
    CHECK(strstr(C.err, "secret") == NULL);
    CHECK_MSG(strstr(C.err, "id: '<hidden>'") != NULL, C.err); /* the line mentions pass: no token is quoted */
    expect_err("br set id=0x0001", "'0x0001' is not a unit ID");
    CHECK_MSG(strstr(C.err, "manager IDs (N1)") != NULL, C.err);
    expect_err("br set id=0x000F", "manager IDs (N1)");
    expect_err("br set id=0x0000", "is not a unit ID");
    CHECK_MSG(strstr(C.err, "manager") == NULL, C.err); /* 0 is unassigned, not a manager */

    tu_ctx("documented gateway line (GATEWAY-NRF24.txt), unit ID 0x0010");
    set_ok(&cfg, "br set role=probe id=0x0010 grp=0xFF10 nrf=on espnow=off wifi=on ssid=lab pass=secret-1");
    CHECK_EQ_U32(C.fields, NODE_F_ROLE | NODE_F_UID | NODE_F_GRP | NODE_F_NRF | NODE_F_ESPNOW | NODE_F_WIFI |
                               NODE_F_SSID | NODE_F_PASS);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK_EQ_U32(cfg.uid, 0x0010u);
    CHECK(strcmp(cfg.pass, "secret-1") == 0);
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=probe id=0x0010 grp=0xFF10 nbr=none led=2 btn=0 chan=1 espnow=off wifi=on "
                          "ssid=lab pass=set nrf=on nch=76 nrate=2m npa=max nsck=18 nmiso=19 nmosi=23 ncsn=5 "
                          "nce=4 nirq=-1") == 0,
              out);
    CHECK(strstr(out, "secret") == NULL); /* the passphrase is never printed */

    tu_ctx("same line on an ESP32-S3: S3 nRF24 pins");
    node_cfg_defaults(&cfg);
    node_nrf_default_pins(NODE_CHIP_ESP32S3, &cfg);
    CHECK(node_cmd_parse("br set role=probe id=0x0010 grp=0xFF10 nrf=on espnow=off wifi=on ssid=lab pass=",
                         NODE_CHIP_ESP32S3, &C));
    CHECK(apply(&cfg));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32S3, NULL));

    tu_ctx("an nRF24 sender talking to the gateway (no WiFi, no ESP-NOW)");
    node_cfg_defaults(&cfg);
    set_ok(&cfg, "br set role=sender id=0x0101 grp=0xFF10 nrf=on espnow=off");
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    tu_ctx("an nRF24 relay with IRQ wired and channel 81");
    node_cfg_defaults(&cfg);
    set_ok(&cfg, "br set role=node id=0x0102 grp=0xFF10 nrf=on espnow=off nch=81 nirq=35");
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    tu_ctx("gateway and nodes on nch=83 need a lower rate");
    CHECK(parse("br set nch=83"));
    expect_apply_err(&cfg, "nch 82..83 need nrate=250k|1m");
    set_ok(&cfg, "br set nch=83 nrate=1m");
}

static void test_ntp_key(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];

    tu_ctx("ntp= accepted, shown after pass only when not the default");
    node_cfg_defaults(&cfg);
    set_ok(&cfg, "br set role=probe id=0x0010 nrf=on espnow=off wifi=on ssid=lab ntp=time.google.com");
    CHECK_EQ_U32(C.fields & NODE_F_NTP, NODE_F_NTP);
    CHECK(strcmp(cfg.ntp, "time.google.com") == 0);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " wifi=on ssid=lab pass=unset ntp=time.google.com nrf=on") != NULL, out);
    set_ok(&cfg, "br set ntp=192.168.1.1");
    CHECK(strcmp(cfg.ntp, "192.168.1.1") == 0);
    set_ok(&cfg, "br set ntp=pool.ntp.org");
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, "ntp=") == NULL, out);
    tu_ctx("ntp is shown in the udp group too, and not when the station is off");
    set_ok(&cfg, "br set ntp=ntp1.example-lab.net udp=on");
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, " udp=on port=40888 mcast=on peers=none ssid=lab pass=unset ntp=ntp1.example-lab.net nrf=on") !=
                  NULL,
              out);
    set_ok(&cfg, "br set udp=off");
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strstr(out, "ntp=") == NULL && strstr(out, "ssid=") == NULL, out);

    tu_ctx("63 characters accepted, 64 refused");
    CHECK(parse("br set ntp=a23456789012345678901234567890123456789012345678901234567890123"));
    CHECK_EQ_U32(strlen(C.val.ntp), 63u);
    expect_err("br set ntp=a234567890123456789012345678901234567890123456789012345678901234",
               "is not a host name or IPv4 address");
    expect_err("br set ntp=bad_host", "ntp: 'bad_host' is not a host name");
    expect_err("br set ntp=-lead", "is not a host name");
    expect_err("br set ntp=trail.", "is not a host name");
    expect_err("br set ntp=a..b", "is not a host name");
    expect_err("br set ntp=", "empty value");
    expect_err("br set ntp=a ntp=b", "given twice");

    tu_ctx("no-echo: a line with pass= never quotes the ntp token either");
    CHECK(!parse("br set pass=Secret123 ntp=bad_host"));
    CHECK_MSG(strstr(C.err, "Secret123") == NULL, C.err);
    CHECK_MSG(strstr(C.err, "bad_host") == NULL, C.err);
    CHECK_MSG(strstr(C.err, "<hidden>") != NULL, C.err);
    CHECK(!parse("br set wifi=maybe pass=Secret123"));
    CHECK_MSG(strstr(C.err, "maybe") == NULL && strstr(C.err, "Secret123") == NULL, C.err);

    tu_ctx("longest show line (uart + wifi + 63-char ntp + nrf) is not truncated");
    node_cfg_defaults(&cfg);
    set_ok(&cfg, "br set role=sender id=0xFEFF grp=0xFFFE nbr=0x0010,0x0011,0x0012,0x0013,0x0014,0x0015,0x0016,0x0017 "
                 "led=33 btn=32 chan=13 uart=on utx=25 urx=26 ubaud=2000000 espnow=off");
    set_ok(&cfg, "br set udp=on port=65535 mcast=off peers=223.255.255.255:65535,223.255.255.254:65535,"
                 "223.255.255.253:65535,223.255.255.252:65535,223.255.255.251:65535,223.255.255.250:65535,"
                 "223.255.255.249:65535,223.255.255.248:65535 ssid=abcdefghijklmnopqrstuvwxyz012345");
    set_ok(&cfg, "br set pass=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0 "
                 "ntp=a23456789012345678901234567890123456789012345678901234567890123");
    set_ok(&cfg, "br set nrf=on nsck=14 nmiso=35 nmosi=27 ncsn=13 nce=4 nirq=34 nch=83 nrate=250k");
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    size_t n = node_cfg_format(&cfg, out, sizeof out);
    CHECK(n + 1u < sizeof out);
    CHECK_MSG(strstr(out, "ntp=a23456789012345678901234567890123456789012345678901234567890123 nrf=on") != NULL,
              out);
    CHECK_MSG(strstr(out, " nirq=34") != NULL, out);
    CHECK(strstr(out, "0123456789abc") == NULL); /* no passphrase fragment */
}

typedef struct {
    uint8_t ap;
    uint8_t nch;
    int32_t mhz;
} clr_row_t;

static void test_clearance(void)
{
    /* Wi-Fi band edge = 2407 + 5 x ch + 11 (ch 14: 2484 + 11), nRF = 2400 + nch */
    static const clr_row_t rows[] = {
        {1, 76, 53},  {2, 76, 48},  {3, 76, 43}, {4, 76, 38},  {5, 76, 33},  {6, 76, 28}, {7, 76, 23},
        {8, 76, 18},  {9, 76, 13},  {10, 76, 8}, {11, 76, 3},  {12, 76, -2}, {13, 76, -7}, {14, 76, -3},
        {1, 83, 60},  {6, 83, 35},  {8, 83, 25}, {9, 83, 20},  {10, 83, 15}, {11, 83, 10}, {13, 83, 0},
        {6, 81, 33},  {11, 81, 8},  {13, 81, -2},
        {1, 0, 1},    {1, 1, 0},    {1, 12, -11}, /* below the band, on the lower edge, at the centre */
    };
    tu_ctx("clearance table");
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        int32_t d = 12345;
        CHECK(node_wifi_nrf_clearance_mhz(rows[i].ap, rows[i].nch, &d));
        if (d != rows[i].mhz) {
            fprintf(stderr, "  ap ch %u nch %u: got %d want %d\n", rows[i].ap, rows[i].nch, (int)d, (int)rows[i].mhz);
        }
        CHECK(d == rows[i].mhz);
    }
    tu_ctx("WiFi 1-6 keep >= 28 MHz from every nRF channel 76..83");
    for (uint8_t ap = 1; ap <= 6u; ap++) {
        for (uint8_t nch = NODE_NCH_MIN; nch <= NODE_NCH_MAX; nch++) {
            int32_t d = 0;
            CHECK(node_wifi_nrf_clearance_mhz(ap, nch, &d));
            CHECK(d >= 28);
        }
    }
    tu_ctx("out of range channels");
    int32_t keep = 77;
    CHECK(!node_wifi_nrf_clearance_mhz(0, 76, &keep));
    CHECK(!node_wifi_nrf_clearance_mhz(15, 76, &keep));
    CHECK(!node_wifi_nrf_clearance_mhz(6, 126, &keep));
    CHECK(keep == 77);
    CHECK(node_wifi_nrf_clearance_mhz(6, 76, NULL));
}

static void coexist(uint8_t ap, uint8_t nch, uint8_t nrate, bool warn, const char *expect)
{
    char buf[160];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    tu_ctx(expect);
    CHECK(node_fmt_coexist(&f, ap, nch, nrate) == warn);
    CHECK_MSG(strcmp(buf, expect) == 0, buf);
}

static void test_coexist_text(void)
{
    coexist(1, 76, NODE_NRATE_2M, false, "BRNRF coexist ok: AP ch 1, nRF ch 76, 53 MHz apart");
    coexist(6, 76, NODE_NRATE_2M, false, "BRNRF coexist ok: AP ch 6, nRF ch 76, 28 MHz apart");
    coexist(7, 76, NODE_NRATE_2M, false, "BRNRF coexist ok: AP ch 7, nRF ch 76, 23 MHz apart");
    coexist(9, 83, NODE_NRATE_1M, false, "BRNRF coexist ok: AP ch 9, nRF ch 83, 20 MHz apart");
    /* nch 83 would clear ch 8 / 9: suggested (with the rate it needs at 2 Mbps) */
    coexist(8, 76, NODE_NRATE_2M, true,
            "BRNRF coexist: AP ch 8, nRF ch 76, 18 MHz apart - move the router to ch 1-6 or set nch=83 nrate=1m");
    coexist(9, 81, NODE_NRATE_250K, true,
            "BRNRF coexist: AP ch 9, nRF ch 81, 18 MHz apart - move the router to ch 1-6 or set nch=83");
    /* ch 10..13: nch 83 does not help, only the router move is suggested */
    coexist(11, 76, NODE_NRATE_2M, true, "BRNRF coexist: AP ch 11, nRF ch 76, 3 MHz apart - move the router to ch 1-6");
    coexist(13, 76, NODE_NRATE_2M, true,
            "BRNRF coexist: AP ch 13, nRF ch 76, -7 MHz apart - move the router to ch 1-6");
    coexist(10, 83, NODE_NRATE_1M, true,
            "BRNRF coexist: AP ch 10, nRF ch 83, 15 MHz apart - move the router to ch 1-6");
    coexist(0, 76, NODE_NRATE_2M, false, "BRNRF coexist: AP channel unknown");
}

static void iso(int64_t t, const char *expect)
{
    char buf[32];
    node_fmt_t f;
    node_fmt_init(&f, buf, sizeof buf);
    node_fmt_iso8601(&f, t);
    tu_ctx(expect);
    CHECK_MSG(strcmp(buf, expect) == 0, buf);
}

static void test_iso8601(void)
{
    iso(0, "1970-01-01T00:00:00Z");
    iso(-5, "1970-01-01T00:00:00Z");
    iso(951782400, "2000-02-29T00:00:00Z");
    iso(1700000000, "2023-11-14T22:13:20Z");
    iso(1791462896, "2026-10-08T12:34:56Z");
    iso(2147483647, "2038-01-19T03:14:07Z");
    iso(4107542399LL, "2100-02-28T23:59:59Z");
    iso(4107542400LL, "2100-03-01T00:00:00Z");
    iso(253402300799LL, "9999-12-31T23:59:59Z");
    tu_ctx("short buffer: truncated, NUL-terminated");
    char small[8];
    node_fmt_t f;
    node_fmt_init(&f, small, sizeof small);
    node_fmt_iso8601(&f, 0);
    CHECK(strcmp(small, "1970-01") == 0);
}

int main(void)
{
    test_defaults();
    test_wifi_key();
    test_policies();
    test_backward_compat();
    test_gateway_line();
    test_ntp_key();
    test_clearance();
    test_coexist_text();
    test_iso8601();
    return tu_summary("test_console_gateway");
}
