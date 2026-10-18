// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_console_uart.c - host test of the UART link console keys
 * (uart= utx= urx= ubaud=) in examples/demo-3board/components/app_node/src/node_console.c.
 *
 * Kept separate from test_console.c (phase 1c, frozen) on purpose: that
 * file still checks that the phase 1c lines and the `br show` text are
 * unchanged with the UART link off. Like test_console.c, this test
 * compiles the real source file into the executable.
 */
#include "test_util.h"

#include "../../examples/demo-3board/components/app_node/src/node_console.c"

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

static void test_defaults(void)
{
    node_cfg_t cfg;
    char out[NODE_SHOW_MAX];
    uint8_t tx = 0;
    uint8_t rx = 0;

    tu_ctx("defaults");
    node_cfg_defaults(&cfg);
    CHECK_EQ_U32(cfg.uart, 0u);
    CHECK_EQ_U32(cfg.utx, 17u);
    CHECK_EQ_U32(cfg.urx, 16u);
    CHECK_EQ_U32(cfg.ubaud, 921600u);
    /* uart off: the phase 1c text, byte for byte */
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=unset id=unset grp=0xFF10 nbr=none led=2 btn=0 chan=1") == 0, out);

    tu_ctx("C.6 default pins");
    node_uart_default_pins(NODE_CHIP_ESP32, &tx, &rx);
    CHECK_EQ_U32(tx, 17u);
    CHECK_EQ_U32(rx, 16u);
    node_uart_default_pins(NODE_CHIP_ESP32S3, &tx, &rx);
    CHECK_EQ_U32(tx, 17u);
    CHECK_EQ_U32(rx, 18u);
    node_uart_default_pins(NODE_CHIP_ESP32S3, NULL, NULL); /* tolerated */

    tu_ctx("default pins pass the pin rules");
    CHECK(node_uart_pin_ok(NODE_CHIP_ESP32, 17u, true, NULL));
    CHECK(node_uart_pin_ok(NODE_CHIP_ESP32, 16u, false, NULL));
    CHECK(node_uart_pin_ok(NODE_CHIP_ESP32S3, 17u, true, NULL));
    CHECK(node_uart_pin_ok(NODE_CHIP_ESP32S3, 18u, false, NULL));
}

static void test_enable_and_show(void)
{
    node_cfg_t cfg;
    char err[NODE_ERR_MAX];
    char out[NODE_SHOW_MAX];

    tu_ctx("board A with the UART link");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=sender id=0x0101 nbr=0x0102 uart=on utx=17 urx=16 ubaud=921600"));
    CHECK(C.kind == NODE_CMD_SET);
    CHECK_EQ_U32(C.fields, NODE_F_ROLE | NODE_F_UID | NODE_F_NBR | NODE_F_UART | NODE_F_UTX | NODE_F_URX |
                               NODE_F_UBAUD);
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=sender id=0x0101 grp=0xFF10 nbr=0x0102 led=2 btn=0 chan=1 uart=on utx=17 urx=16 "
                          "ubaud=921600") == 0,
              out);

    tu_ctx("uart=off hides the keys again but keeps them");
    CHECK(parse("br set uart=off"));
    CHECK_EQ_U32(C.fields, NODE_F_UART);
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=sender id=0x0101 grp=0xFF10 nbr=0x0102 led=2 btn=0 chan=1") == 0, out);
    CHECK_EQ_U32(cfg.utx, 17u);
    CHECK_EQ_U32(cfg.ubaud, 921600u);

    tu_ctx("only the baud, case-insensitive key and value, hex number");
    CHECK(parse("br set UART=ON ubaud=0x1C200"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_EQ_U32(cfg.uart, 1u);
    CHECK_EQ_U32(cfg.ubaud, 115200u);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));

    tu_ctx("S3 pins");
    node_cfg_defaults(&cfg);
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set role=probe id=0x0103 uart=on utx=17 urx=18"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32S3, NULL));
    CHECK_EQ_U32(cfg.urx, 18u);

    tu_ctx("longest show line fits NODE_SHOW_MAX");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=sender id=0xFEFF grp=0xFFFE "
                "nbr=0x0010,0x0011,0x0012,0x0013,0x0014,0x0015,0x0016,0x0017 led=33 btn=32 chan=13"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(parse("br set uart=on utx=25 urx=26 ubaud=2000000"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    size_t n = node_cfg_format(&cfg, out, sizeof out);
    CHECK(n + 1u < sizeof out); /* not truncated */
    CHECK_MSG(strstr(out, " uart=on utx=25 urx=26 ubaud=2000000") != NULL, out);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
}

static void test_pin_rules(void)
{
    const char *why = NULL;

    /* ESP32: flash, console, input-only, no pull-up, strapping, no such GPIO */
    expect_err("br set utx=6", "SPI flash");
    expect_err("br set urx=11", "SPI flash");
    expect_err("br set utx=1", "UART0");
    expect_err("br set urx=3", "UART0");
    expect_err("br set utx=34", "input-only");
    expect_err("br set urx=36", "no internal pull-up");
    expect_err("br set urx=12", "strapping");
    expect_err("br set utx=12", "strapping");
    expect_err("br set urx=0", "strapping");
    expect_err("br set utx=2", "strapping");
    expect_err("br set urx=5", "strapping");
    expect_err("br set utx=15", "strapping");
    expect_err("br set utx=20", "no such GPIO");
    expect_err("br set urx=40", "no such GPIO");
    expect_err("br set utx=seventeen", "not a GPIO number");
    expect_err("br set urx=-1", "not a GPIO number");
    expect_err("br set utx=256", "not a GPIO number");

    /* ESP32-S3: flash, PSRAM, USB, console, strapping */
    expect_err_on(NODE_CHIP_ESP32S3, "br set utx=27", "SPI flash");
    expect_err_on(NODE_CHIP_ESP32S3, "br set urx=35", "PSRAM");
    expect_err_on(NODE_CHIP_ESP32S3, "br set utx=19", "USB-JTAG");
    expect_err_on(NODE_CHIP_ESP32S3, "br set urx=44", "UART0");
    expect_err_on(NODE_CHIP_ESP32S3, "br set urx=45", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set utx=46", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set urx=3", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set utx=0", "strapping");
    expect_err_on(NODE_CHIP_ESP32S3, "br set urx=23", "no such GPIO");

    tu_ctx("strapping pins are fine for led / btn, not for the link");
    CHECK(node_pin_ok(NODE_CHIP_ESP32, 12u, true, NULL));
    CHECK(!node_uart_pin_ok(NODE_CHIP_ESP32, 12u, true, &why));
    CHECK(why != NULL && strstr(why, "GPIO0/2/5/12/15") != NULL);
    CHECK(!node_uart_pin_ok(NODE_CHIP_ESP32S3, 45u, false, &why));
    CHECK(why != NULL && strstr(why, "GPIO0/3/45/46") != NULL);

    tu_ctx("accepted pins");
    CHECK(parse("br set utx=25 urx=26"));
    CHECK(parse("br set utx=33 urx=32"));
    CHECK(parse("br set utx=4 urx=13"));
    CHECK(!parse_on(NODE_CHIP_ESP32S3, "br set utx=43")); /* UART0 TX (console) */
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set utx=47 urx=48"));
    CHECK(parse_on(NODE_CHIP_ESP32S3, "br set utx=16 urx=15"));
}

static void test_values_and_cross_fields(void)
{
    node_cfg_t cfg;
    node_cfg_t before;
    char err[NODE_ERR_MAX];
    const char *why = NULL;

    expect_err("br set uart=maybe", "uart: 'maybe' is not on|off");
    expect_err("br set uart=1", "not on|off");
    expect_err("br set uart=", "empty value");
    expect_err("br set ubaud=92160", "ubaud: '92160' is not a supported rate");
    expect_err("br set ubaud=0", "not a supported rate");
    expect_err("br set ubaud=99999999999", "not a supported rate");
    expect_err("br set ubaud=fast", "not a supported rate");
    expect_err("br set uart=on uart=off", "given twice");
    expect_err("br set utx=17 utx=25", "given twice");
    expect_err("br set ubaud=115200 ubaud=115200", "given twice");
    expect_err("br set uartx=on", "unknown key");
    expect_err("br set colour=red", "uart utx urx ubaud");

    tu_ctx("every listed baud rate parses");
    static const uint32_t ok[] = {9600u,   19200u,  38400u,   57600u,   115200u, 230400u,
                                  460800u, 921600u, 1000000u, 1500000u, 2000000u};
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        CHECK(node_baud_ok(ok[i]));
    }
    CHECK(!node_baud_ok(4800u));
    CHECK(!node_baud_ok(3000000u));

    tu_ctx("uart=on with utx == urx");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 uart=on utx=25 urx=25"));
    before = cfg;
    CHECK(!node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_MSG(strstr(err, "utx and urx are the same pin") != NULL, err);
    CHECK(memcmp(&before, &cfg, sizeof cfg) == 0);

    tu_ctx("uart=on with a pin equal to led / btn");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set led=17"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err)); /* uart off: no conflict */
    CHECK(parse("br set uart=on"));
    before = cfg;
    CHECK(!node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_MSG(strstr(err, "led pin") != NULL, err);
    CHECK(memcmp(&before, &cfg, sizeof cfg) == 0);
    CHECK(parse("br set uart=on led=2"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(parse("br set btn=16"));
    before = cfg;
    CHECK(!node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_MSG(strstr(err, "btn pin") != NULL, err);
    CHECK(memcmp(&before, &cfg, sizeof cfg) == 0);

    tu_ctx("a bad token anywhere changes nothing");
    node_cfg_defaults(&cfg);
    CHECK(!parse("br set uart=on utx=25 urx=12"));
    CHECK(C.kind == NODE_CMD_ERROR);

    tu_ctx("ready() re-checks what NVS returned");
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_NODE;
    cfg.uid = 0x0102;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.utx = 12; /* uart off: link pins are not used, not checked */
    cfg.ubaud = 1234;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.uart = 1;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "utx") != NULL);
    cfg.utx = 17;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "ubaud") != NULL);
    cfg.ubaud = 921600;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    cfg.urx = 36;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "urx") != NULL);
    cfg.urx = 17;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "same pin") != NULL);
    cfg.urx = 2; /* the led pin, and a strapping pin: the pin rule fires first */
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.urx = 16;
    cfg.uart = 7;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "on/off") != NULL);
    cfg.uart = 1;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32S3, NULL)); /* GPIO17 / 16 are plain GPIOs on the S3 too */
}

int main(void)
{
    test_defaults();
    test_enable_and_show();
    test_pin_rules();
    test_values_and_cross_fields();
    return tu_summary("test_console_uart");
}
