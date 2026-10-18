// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * test_console.c - host test of the demo console parser and config
 * validation (examples/demo-3board/components/app_node/src/node_console.c, phase 1c).
 *
 * The parser is portable C; this test compiles the real source file into
 * the test executable (no separate host library for app_node).
 */
#include "test_util.h"

#include "../../examples/demo-3board/components/app_node/src/node_console.c"

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

static void test_flash_sheet_lines(void)
{
    node_cfg_t cfg;
    char err[NODE_ERR_MAX];
    char out[NODE_SHOW_MAX];

    tu_ctx("board A");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=sender id=0x0101 grp=0xFF10 nbr=0x0102 led=2 btn=0 chan=1"));
    CHECK(C.kind == NODE_CMD_SET);
    CHECK_EQ_U32(C.fields, 0x7Fu);
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=sender id=0x0101 grp=0xFF10 nbr=0x0102 led=2 btn=0 chan=1") == 0, out);

    tu_ctx("board B");
    node_cfg_defaults(&cfg);
    CHECK(parse("br set role=node id=0x0102 nbr=0x0101,0x0103"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    node_cfg_format(&cfg, out, sizeof out);
    CHECK_MSG(strcmp(out, "role=node id=0x0102 grp=0xFF10 nbr=0x0101,0x0103 led=2 btn=0 chan=1") == 0, out);

    tu_ctx("board C");
    node_cfg_defaults(&cfg);
    CHECK(parse("  br   set role=probe id=0x0103 grp=0xff10 nbr=0x0102 led=2\t"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK_EQ_U32(cfg.role, NODE_ROLE_PROBE);
    CHECK_EQ_U32(cfg.grp, 0xFF10u);
    CHECK_EQ_U32(cfg.n_nbr, 1u);
    CHECK_EQ_U32(cfg.nbr[0], 0x0102u);
}

static void test_subsets_and_merge(void)
{
    node_cfg_t cfg;
    char err[NODE_ERR_MAX];
    tu_ctx("subset merge");
    node_cfg_defaults(&cfg);
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(parse("br set role=relay"));
    CHECK_EQ_U32(C.fields, NODE_F_ROLE);
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    const char *why = NULL;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why)); /* id still unset */
    CHECK(why != NULL && strstr(why, "id") != NULL);
    CHECK(parse("br set uid=258"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_EQ_U32(cfg.uid, 0x0102u);
    CHECK_EQ_U32(cfg.role, NODE_ROLE_NODE);
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    CHECK(parse("br set chan=13 led=4"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_EQ_U32(cfg.chan, 13u);
    CHECK_EQ_U32(cfg.led, 4u);
    CHECK_EQ_U32(cfg.uid, 0x0102u); /* untouched */
    CHECK(parse("br set nbr=0x0101,0x0103"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_EQ_U32(cfg.n_nbr, 2u);
    CHECK(parse("br set nbr=none"));
    CHECK(node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK_EQ_U32(cfg.n_nbr, 0u);

    tu_ctx("cross-field rejects leave cfg unchanged");
    node_cfg_t before = cfg;
    CHECK(parse("br set led=0")); /* btn is 0 */
    CHECK(!node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(strstr(err, "same pin") != NULL);
    CHECK(memcmp(&before, &cfg, sizeof cfg) == 0);
    CHECK(parse("br set nbr=0x0101,0x0102")); /* own id 0x0102 */
    CHECK(!node_cfg_apply(&cfg, &C, err, sizeof err));
    CHECK(strstr(err, "own id") != NULL);
    CHECK(memcmp(&before, &cfg, sizeof cfg) == 0);
}

static void test_other_verbs(void)
{
    tu_ctx("verbs");
    CHECK(parse("br show"));
    CHECK(C.kind == NODE_CMD_SHOW);
    CHECK(parse("BR SHOW"));
    CHECK(C.kind == NODE_CMD_SHOW);
    CHECK(parse("br erase"));
    CHECK(C.kind == NODE_CMD_ERASE);
    CHECK(parse("br reboot"));
    CHECK(C.kind == NODE_CMD_REBOOT);
    CHECK(parse("br stats"));
    CHECK(C.kind == NODE_CMD_STATS);
    CHECK(parse(""));
    CHECK(C.kind == NODE_CMD_NONE);
    CHECK(parse("   \t "));
    CHECK(C.kind == NODE_CMD_NONE);
}

static void test_rejects(void)
{
    expect_err("hello", "unknown command");
    expect_err("br", "missing verb");
    expect_err("br frob", "unknown verb");
    expect_err("br show now", "unexpected");
    expect_err("br set", "at least one");
    expect_err("br set role", "key=value");
    expect_err("br set =1", "key=value");
    expect_err("br set role=", "empty value");
    expect_err("br set colour=red", "unknown key");
    expect_err("br set role=boss", "sender|node|probe");
    expect_err("br set role=probe role=node", "twice");
    expect_err("br set id=0x000F", "unit ID");    /* manager range */
    expect_err("br set id=0xFF10", "unit ID");    /* group */
    expect_err("br set id=0x10000", "unit ID");   /* > 16 bit */
    expect_err("br set id=0x", "unit ID");
    expect_err("br set id=12ab", "unit ID");
    expect_err("br set id=-5", "unit ID");
    expect_err("br set id=99999999999", "unit ID");
    expect_err("br set grp=0x0101", "group ID");
    expect_err("br set grp=0xFFFF", "group ID"); /* flood is not a group */
    expect_err("br set nbr=0x0102,", "empty entry");
    expect_err("br set nbr=,0x0102", "empty entry");
    expect_err("br set nbr=0x0102,0x0102", "duplicate");
    expect_err("br set nbr=0x0102,0xFF10", "unit ID");
    expect_err("br set nbr=1,2,3,4,5,6,7,8,9", "unit ID"); /* 1 is a manager ID */
    expect_err("br set nbr=0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19", "more than 8");
    expect_err("br set chan=0", "1..13");
    expect_err("br set chan=14", "1..13");
    expect_err("br set led=6", "SPI flash");
    expect_err("br set led=1", "UART0");
    expect_err("br set led=34", "input-only");
    expect_err("br set btn=36", "pull-up");
    expect_err("br set led=20", "no such GPIO");
    expect_err("br set led=40", "no such GPIO");
    expect_err("br set led=300", "GPIO number");
    expect_err("br set led=x", "GPIO number");

    tu_ctx("a bad token anywhere rejects the whole line");
    CHECK(!parse("br set role=probe id=0x0103 chan=99"));
    CHECK(C.kind == NODE_CMD_ERROR);

    tu_ctx("line too long");
    char longl[NODE_LINE_MAX + 8];
    memset(longl, 'a', sizeof longl);
    longl[sizeof longl - 1] = '\0';
    CHECK(!parse(longl));
    CHECK(strstr(C.err, "too long") != NULL);
}

static void test_s3_pins(void)
{
    tu_ctx("ESP32-S3 pin rules");
    const char *why = NULL;
    CHECK(node_pin_ok(NODE_CHIP_ESP32S3, 2, true, &why));
    CHECK(node_pin_ok(NODE_CHIP_ESP32S3, 0, false, &why));
    CHECK(node_pin_ok(NODE_CHIP_ESP32S3, 48, true, &why));
    CHECK(!node_pin_ok(NODE_CHIP_ESP32S3, 27, true, &why));
    CHECK(!node_pin_ok(NODE_CHIP_ESP32S3, 43, true, &why));
    CHECK(!node_pin_ok(NODE_CHIP_ESP32S3, 19, true, &why));
    CHECK(!node_pin_ok(NODE_CHIP_ESP32S3, 22, true, &why));
    CHECK(!node_pin_ok(NODE_CHIP_ESP32S3, 49, true, &why));
    CHECK(node_pin_ok(NODE_CHIP_ESP32, 39, false, &why) == false);
    CHECK(node_pin_ok(NODE_CHIP_ESP32, 33, true, &why));
}

static void test_ready_on_raw_storage(void)
{
    tu_ctx("node_cfg_ready on raw (NVS) values");
    node_cfg_t cfg;
    node_cfg_defaults(&cfg);
    cfg.role = NODE_ROLE_PROBE;
    cfg.uid = 0x0103;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
    const char *why = NULL;
    cfg.role = 9;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.role = NODE_ROLE_PROBE;
    cfg.n_nbr = 9;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.n_nbr = 2;
    cfg.nbr[0] = 0x0102;
    cfg.nbr[1] = 0x0102;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    CHECK(why != NULL && strstr(why, "duplicate") != NULL);
    cfg.nbr[1] = 0x0103;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.n_nbr = 1;
    cfg.chan = 0;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.chan = 1;
    cfg.led = 7;
    CHECK(!node_cfg_ready(&cfg, NODE_CHIP_ESP32, &why));
    cfg.led = 2;
    CHECK(node_cfg_ready(&cfg, NODE_CHIP_ESP32, NULL));
}

static void test_formatter(void)
{
    tu_ctx("formatter");
    char b[16];
    node_fmt_t f;
    node_fmt_init(&f, b, sizeof b);
    node_fmt_u32(&f, 0);
    node_fmt_str(&f, " ");
    node_fmt_i32(&f, -128);
    node_fmt_str(&f, " ");
    node_fmt_hex16(&f, 0xFF10);
    CHECK_MSG(strcmp(b, "0 -128 0xFF10") == 0, b);
    node_fmt_init(&f, b, sizeof b);
    node_fmt_u32(&f, 4294967295u);
    CHECK_MSG(strcmp(b, "4294967295") == 0, b);
    node_fmt_i32(&f, INT32_MIN); /* truncated at cap - 1 */
    CHECK_EQ_U32(f.len, 15u);
    CHECK_EQ_U32(strlen(b), 15u);
    node_fmt_init(&f, b, sizeof b);
    node_fmt_hex8(&f, 0xA5);
    CHECK_MSG(strcmp(b, "a5") == 0, b);
}

int main(void)
{
    test_flash_sheet_lines();
    test_subsets_and_merge();
    test_other_verbs();
    test_rejects();
    test_s3_pins();
    test_ready_on_raw_storage();
    test_formatter();
    return tu_summary("test_console");
}
