// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * node_console.c - demo configuration, console parser and a libc-free
 * formatter. Portable C11 (see node_console.h); host-tested by
 * firmware/test/host/test_console.c, test_console_uart.c (UART link keys),
 * test_console_links.c (WiFi UDP / nRF24 keys, transport policy) and
 * test_console_gateway.c (wifi= / ntp=, single-chip nRF24 gateway, AP / nRF24
 * clearance, ISO-8601) and test_console_robust.c (NVS blob fallback, the
 * station backoff schedule of hal_udp.h, the no-quote error rule).
 */
#include "node_console.h"

#include <string.h>

#include "braid/br_types.h"

/* ------------------------------------------------------------------------- */
/* Formatter                                                                  */
/* ------------------------------------------------------------------------- */

void node_fmt_init(node_fmt_t *f, char *buf, size_t cap)
{
    f->buf = buf;
    f->cap = cap;
    f->len = 0;
    if (buf != NULL && cap > 0u) {
        buf[0] = '\0';
    }
}

static void fmt_ch(node_fmt_t *f, char c)
{
    if (f->buf != NULL && f->len + 1u < f->cap) {
        f->buf[f->len] = c;
        f->len++;
        f->buf[f->len] = '\0';
    }
}

void node_fmt_str(node_fmt_t *f, const char *s)
{
    if (s == NULL) {
        return;
    }
    while (*s != '\0') {
        fmt_ch(f, *s);
        s++;
    }
}

void node_fmt_u32(node_fmt_t *f, uint32_t v)
{
    char tmp[10];
    size_t n = 0;
    do {
        tmp[n] = (char)('0' + (char)(v % 10u));
        n++;
        v /= 10u;
    } while (v != 0u && n < sizeof tmp);
    while (n > 0u) {
        n--;
        fmt_ch(f, tmp[n]);
    }
}

void node_fmt_i32(node_fmt_t *f, int32_t v)
{
    if (v < 0) {
        fmt_ch(f, '-');
        node_fmt_u32(f, (uint32_t)0 - (uint32_t)v);
    } else {
        node_fmt_u32(f, (uint32_t)v);
    }
}

static const char HEX[] = "0123456789abcdef";
static const char HEXU[] = "0123456789ABCDEF";

void node_fmt_hex16(node_fmt_t *f, uint16_t v)
{
    node_fmt_str(f, "0x");
    for (int s = 12; s >= 0; s -= 4) {
        fmt_ch(f, HEXU[(v >> (unsigned)s) & 0xFu]);
    }
}

void node_fmt_hex8(node_fmt_t *f, uint8_t v)
{
    fmt_ch(f, HEX[(v >> 4) & 0xFu]);
    fmt_ch(f, HEX[v & 0xFu]);
}

void node_fmt_peer(node_fmt_t *f, uint32_t ip, uint16_t port)
{
    for (int s = 24; s >= 0; s -= 8) {
        node_fmt_u32(f, (ip >> (unsigned)s) & 0xFFu);
        if (s > 0) {
            fmt_ch(f, '.');
        }
    }
    fmt_ch(f, ':');
    node_fmt_u32(f, port);
}

void node_fmt_ssid(node_fmt_t *f, const char *ssid)
{
    for (size_t i = 0; ssid != NULL && i < NODE_SSID_MAX && ssid[i] != '\0'; i++) {
        const unsigned char b = (unsigned char)ssid[i];
        fmt_ch(f, (b >= 0x20u && b < 0x7Fu) ? ssid[i] : '?');
    }
}

void node_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    for (size_t i = 0; p != NULL && i < n; i++) {
        v[i] = 0u;
    }
}

/* v as exactly `width` decimal digits (zero padded; v must fit). */
static void fmt_u32_pad(node_fmt_t *f, uint32_t v, uint32_t width)
{
    uint32_t div = 1u;
    for (uint32_t i = 1u; i < width; i++) {
        div *= 10u;
    }
    while (div > 0u) {
        fmt_ch(f, (char)('0' + (char)((v / div) % 10u)));
        div /= 10u;
    }
}

/*
 * Civil date from days since 1970-01-01 (H. Hinnant's days_from_civil
 * inverse, proleptic Gregorian). Only called with days >= 0.
 */
void node_fmt_iso8601(node_fmt_t *f, int64_t unix_s)
{
    if (unix_s < 0) {
        unix_s = 0;
    }
    const int64_t days = unix_s / 86400;
    const uint32_t sod = (uint32_t)(unix_s % 86400);
    const int64_t z = days + 719468;
    const int64_t era = z / 146097;
    const uint32_t doe = (uint32_t)(z - era * 146097);                              /* 0..146096 */
    const uint32_t yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u; /* 0..399 */
    const uint32_t doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);               /* 0..365 */
    const uint32_t mp = (5u * doy + 2u) / 153u;                                     /* 0..11, March first */
    const uint32_t day = doy - (153u * mp + 2u) / 5u + 1u;
    const uint32_t month = mp < 10u ? mp + 3u : mp - 9u;
    int64_t year = (int64_t)yoe + era * 400;
    if (month <= 2u) {
        year++;
    }
    fmt_u32_pad(f, year > 9999 ? 9999u : (uint32_t)year, 4u);
    fmt_ch(f, '-');
    fmt_u32_pad(f, month, 2u);
    fmt_ch(f, '-');
    fmt_u32_pad(f, day, 2u);
    fmt_ch(f, 'T');
    fmt_u32_pad(f, sod / 3600u, 2u);
    fmt_ch(f, ':');
    fmt_u32_pad(f, (sod / 60u) % 60u, 2u);
    fmt_ch(f, ':');
    fmt_u32_pad(f, sod % 60u, 2u);
    fmt_ch(f, 'Z');
}

/* ------------------------------------------------------------------------- */
/* WiFi AP channel vs nRF24 channel (single-chip gateway, GATEWAY-NRF24.txt)  */
/* ------------------------------------------------------------------------- */

#define WIFI_HALF_BW_MHZ 11 /* 22 MHz occupied band (802.11b/g mask; 20 MHz OFDM is narrower) */

bool node_wifi_nrf_clearance_mhz(uint8_t wifi_ch, uint8_t nrf_ch, int32_t *mhz_out)
{
    if (wifi_ch < 1u || wifi_ch > 14u || nrf_ch > 125u) {
        return false;
    }
    const int32_t centre = wifi_ch == 14u ? 2484 : 2407 + 5 * (int32_t)wifi_ch;
    const int32_t lo = centre - WIFI_HALF_BW_MHZ;
    const int32_t hi = centre + WIFI_HALF_BW_MHZ;
    const int32_t fn = 2400 + (int32_t)nrf_ch;
    int32_t d;
    if (fn > hi) {
        d = fn - hi;
    } else if (fn < lo) {
        d = lo - fn;
    } else {
        d = -((fn - lo) < (hi - fn) ? (fn - lo) : (hi - fn));
    }
    if (mhz_out != NULL) {
        *mhz_out = d;
    }
    return true;
}

bool node_fmt_coexist(node_fmt_t *f, uint8_t ap_ch, uint8_t nch, uint8_t nrate)
{
    int32_t d = 0;
    if (!node_wifi_nrf_clearance_mhz(ap_ch, nch, &d)) {
        node_fmt_str(f, "BRNRF coexist: AP channel unknown");
        return false;
    }
    const bool warn = d < NODE_COEX_MIN_MHZ;
    node_fmt_str(f, warn ? "BRNRF coexist: AP ch " : "BRNRF coexist ok: AP ch ");
    node_fmt_u32(f, ap_ch);
    node_fmt_str(f, ", nRF ch ");
    node_fmt_u32(f, nch);
    node_fmt_str(f, ", ");
    node_fmt_i32(f, d);
    node_fmt_str(f, " MHz apart");
    if (!warn) {
        return false;
    }
    node_fmt_str(f, " - move the router to ch 1-6");
    int32_t d83 = 0;
    if (nch < NODE_NCH_MAX && node_wifi_nrf_clearance_mhz(ap_ch, (uint8_t)NODE_NCH_MAX, &d83) &&
        d83 >= NODE_COEX_MIN_MHZ) {
        node_fmt_str(f, nrate == NODE_NRATE_2M ? " or set nch=83 nrate=1m" : " or set nch=83");
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Configuration                                                              */
/* ------------------------------------------------------------------------- */

void node_cfg_defaults(node_cfg_t *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->role = NODE_ROLE_UNSET;
    cfg->uid = 0;
    cfg->grp = NODE_DEFAULT_GRP;
    cfg->n_nbr = 0;
    cfg->led = NODE_DEFAULT_LED;
    cfg->btn = NODE_DEFAULT_BTN;
    cfg->chan = NODE_DEFAULT_CHAN;
    cfg->uart = 0;
    cfg->utx = NODE_DEFAULT_UTX;
    cfg->urx = NODE_DEFAULT_URX;
    cfg->ubaud = NODE_DEFAULT_UBAUD;
    cfg->espnow = 1u;
    cfg->udp = 0;
    cfg->port = NODE_DEFAULT_PORT;
    cfg->mcast = 1u;
    cfg->n_peers = 0;
    cfg->ssid[0] = '\0';
    cfg->pass[0] = '\0';
    cfg->nrf = 0;
    cfg->nch = NODE_DEFAULT_NCH;
    cfg->nrate = NODE_NRATE_2M;
    cfg->npa = NODE_NPA_MAX;
    node_nrf_default_pins(NODE_CHIP_ESP32, cfg);
    cfg->wifi = 0;
    memcpy(cfg->ntp, NODE_DEFAULT_NTP, sizeof NODE_DEFAULT_NTP);
}

bool node_cfg_wifi_on(const node_cfg_t *cfg)
{
    return cfg != NULL && (cfg->wifi != 0u || cfg->udp != 0u);
}

void node_cfg_legacy_wifi(node_cfg_t *cfg, bool wifi_key_present)
{
    if (cfg != NULL && !wifi_key_present && cfg->udp != 0u) {
        cfg->wifi = 1u;
    }
}

void node_uart_default_pins(node_chip_t chip, uint8_t *tx, uint8_t *rx)
{
    if (tx != NULL) {
        *tx = NODE_DEFAULT_UTX;
    }
    if (rx != NULL) {
        *rx = chip == NODE_CHIP_ESP32S3 ? 18u : NODE_DEFAULT_URX;
    }
}

void node_nrf_default_pins(node_chip_t chip, node_cfg_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    if (chip == NODE_CHIP_ESP32S3) {
        cfg->nsck = 12u;
        cfg->nmiso = 13u;
        cfg->nmosi = 11u;
        cfg->ncsn = 10u;
        cfg->nce = 9u;
    } else {
        cfg->nsck = 18u;
        cfg->nmiso = 19u;
        cfg->nmosi = 23u;
        cfg->ncsn = 5u; /* STRAPPING: GPIO5 must be high at boot; CSN idles high, fine (C.6) */
        cfg->nce = 4u;
    }
    cfg->nirq = NODE_PIN_NONE;
}

static const uint32_t BAUDS[] = {9600u,   19200u,  38400u,  57600u,   115200u,  230400u,
                                 460800u, 921600u, 1000000u, 1500000u, 2000000u};

bool node_baud_ok(uint32_t baud)
{
    for (size_t i = 0; i < sizeof BAUDS / sizeof BAUDS[0]; i++) {
        if (BAUDS[i] == baud) {
            return true;
        }
    }
    return false;
}

const char *node_role_name(uint8_t role)
{
    switch (role) {
    case NODE_ROLE_SENDER: return "sender";
    case NODE_ROLE_NODE:   return "node";
    case NODE_ROLE_PROBE:  return "probe";
    default:               return "unset";
    }
}

const char *node_nrate_name(uint8_t rate)
{
    switch (rate) {
    case NODE_NRATE_250K: return "250k";
    case NODE_NRATE_1M:   return "1m";
    case NODE_NRATE_2M:   return "2m";
    default:              return "?";
    }
}

const char *node_npa_name(uint8_t pa)
{
    switch (pa) {
    case NODE_NPA_MIN:  return "min";
    case NODE_NPA_LOW:  return "low";
    case NODE_NPA_HIGH: return "high";
    case NODE_NPA_MAX:  return "max";
    default:            return "?";
    }
}

/*
 * ESP32 (WROOM-32/32E): GPIO 0..39 exist except 20, 24, 28..31. 6..11 are the
 * SPI flash, 1 / 3 are UART0 (this console). 34..39 are input-only and have
 * no internal pull-up.
 * ESP32-S3 (WROOM-1 N8): GPIO 0..21 and 26..48. 26..32 are the SPI flash,
 * 33..37 the octal PSRAM on R8 modules (refused for portability), 19 / 20
 * USB-JTAG, 43 / 44 UART0 (console).
 */
static const char *pin_base_why(node_chip_t chip, uint8_t pin)
{
    if (chip == NODE_CHIP_ESP32) {
        if (pin > 39u || pin == 20u || pin == 24u || (pin >= 28u && pin <= 31u)) {
            return "no such GPIO on ESP32";
        }
        if (pin >= 6u && pin <= 11u) {
            return "GPIO6..11 are the SPI flash";
        }
        if (pin == 1u || pin == 3u) {
            return "GPIO1/3 are UART0 (console)";
        }
        return NULL;
    }
    if (pin > 48u || (pin >= 22u && pin <= 25u)) {
        return "no such GPIO on ESP32-S3";
    }
    if (pin >= 26u && pin <= 32u) {
        return "GPIO26..32 are the SPI flash";
    }
    if (pin >= 33u && pin <= 37u) {
        return "GPIO33..37 are octal PSRAM on R8 modules";
    }
    if (pin == 19u || pin == 20u) {
        return "GPIO19/20 are USB-JTAG";
    }
    if (pin == 43u || pin == 44u) {
        return "GPIO43/44 are UART0 (console)";
    }
    return NULL;
}

static bool is_input_only(node_chip_t chip, uint8_t pin)
{
    return chip == NODE_CHIP_ESP32 ? pin >= 34u : pin == 46u;
}

bool node_pin_ok(node_chip_t chip, uint8_t pin, bool output, const char **why)
{
    const char *r = pin_base_why(chip, pin);
    if (r == NULL && chip == NODE_CHIP_ESP32 && pin >= 34u) {
        r = output ? "GPIO34..39 are input-only" : "GPIO34..39 have no internal pull-up";
    }
    if (why != NULL) {
        *why = r;
    }
    return r == NULL;
}

/*
 * Strapping pins (sampled at reset): ESP32 GPIO0 (boot mode), 2 (download
 * mode), 5 (SDIO timing), 12 (MTDI: high selects 1.8 V flash and the
 * 3.3 V module fails to boot), 15 (MTDO: boot log, SDIO timing); ESP32-S3
 * GPIO0 (boot mode), 3 (JTAG source), 45 (VDD_SPI voltage), 46 (boot mode,
 * input only). A UART RX line is held high by the peer's idle TX through
 * our reset, so none of them may carry the link.
 */
static bool is_strapping(node_chip_t chip, uint8_t pin)
{
    if (chip == NODE_CHIP_ESP32) {
        return pin == 0u || pin == 2u || pin == 5u || pin == 12u || pin == 15u;
    }
    return pin == 0u || pin == 3u || pin == 45u || pin == 46u;
}

static const char *strapping_why(node_chip_t chip)
{
    return chip == NODE_CHIP_ESP32 ? "strapping pin (ESP32 GPIO0/2/5/12/15)" : "strapping pin (ESP32-S3 GPIO0/3/45/46)";
}

bool node_uart_pin_ok(node_chip_t chip, uint8_t pin, bool tx, const char **why)
{
    if (!node_pin_ok(chip, pin, tx, why)) {
        return false;
    }
    if (is_strapping(chip, pin)) {
        if (why != NULL) {
            *why = strapping_why(chip);
        }
        return false;
    }
    return true;
}

/*
 * nRF24 pins, the console side of port_nrf24.cpp's policy: outputs (SCK,
 * MOSI, CSN, CE) may not be input-only; MISO and IRQ are driven by the
 * module (push-pull), so input-only pins are fine for them (C.6 IRQ default
 * GPIO35). Strapping pins are refused for every signal except CSN on ESP32
 * GPIO5 (C.6 default; CSN idles high, which is what the strap wants).
 */
bool node_nrf_pin_ok(node_chip_t chip, uint8_t pin, node_nrf_pin_t role, const char **why)
{
    const char *r = NULL;
    const bool output = role == NODE_NRF_PIN_SCK || role == NODE_NRF_PIN_MOSI || role == NODE_NRF_PIN_CSN ||
                        role == NODE_NRF_PIN_CE;
    if (pin == NODE_PIN_NONE && role == NODE_NRF_PIN_IRQ) {
        r = NULL;
    } else if (pin_base_why(chip, pin) != NULL) {
        r = pin_base_why(chip, pin);
    } else if (output && is_input_only(chip, pin)) {
        r = chip == NODE_CHIP_ESP32 ? "GPIO34..39 are input-only" : "GPIO46 is input-only";
    } else if (is_strapping(chip, pin) && !(chip == NODE_CHIP_ESP32 && pin == 5u && role == NODE_NRF_PIN_CSN)) {
        r = strapping_why(chip);
    }
    if (why != NULL) {
        *why = r;
    }
    return r == NULL;
}

/* uart=on cross-field rule; NULL when fine. */
static const char *uart_pins_conflict(const node_cfg_t *c)
{
    if (c->utx == c->urx) {
        return "utx and urx are the same pin";
    }
    if (c->utx == c->led || c->urx == c->led) {
        return "a UART link pin is the led pin";
    }
    if (c->utx == c->btn || c->urx == c->btn) {
        return "a UART link pin is the btn pin";
    }
    return NULL;
}

/* nrf=on cross-field rules (pins and channel); NULL when fine. */
static const char *nrf_conflict(const node_cfg_t *c)
{
    const uint8_t pins[6] = {c->nsck, c->nmiso, c->nmosi, c->ncsn, c->nce, c->nirq};
    for (size_t i = 0; i < 6u; i++) {
        if (pins[i] == NODE_PIN_NONE) {
            continue; /* nirq=-1 */
        }
        for (size_t j = 0; j < i; j++) {
            if (pins[j] == pins[i]) {
                return "two nRF24 pins are the same pin";
            }
        }
        if (pins[i] == c->led) {
            return "an nRF24 pin is the led pin";
        }
        if (pins[i] == c->btn) {
            return "an nRF24 pin is the btn pin";
        }
        if (c->uart != 0u && (pins[i] == c->utx || pins[i] == c->urx)) {
            return "an nRF24 pin is a UART link pin";
        }
    }
    if (c->nch > NODE_NCH_MAX_2M && c->nrate == NODE_NRATE_2M) {
        return "nch 82..83 need nrate=250k|1m (2 Mbps spills past 2483.5 MHz)";
    }
    return NULL;
}

/*
 * Transport policy (spec 12.4); NULL when fine. The WiFi station is on with
 * wifi=1 or udp=1 (node_cfg_wifi_on: a pre-wifi= configuration has udp=1,
 * wifi=0). udp keeps its own texts so the earlier messages stay unchanged.
 */
static const char *transport_conflict(const node_cfg_t *c)
{
    const bool sta = node_cfg_wifi_on(c);
    if (c->udp != 0u && c->espnow != 0u) {
        return "udp and espnow cannot share a chip (12.4): br set espnow=off";
    }
    if (sta && c->espnow != 0u) {
        return "wifi and espnow cannot share a chip (12.4: a station follows the AP channel): br set espnow=off";
    }
    if (c->espnow == 0u && c->uart == 0u && c->udp == 0u && c->nrf == 0u) {
        return "no transport on: espnow=off needs uart, udp or nrf on";
    }
    if (c->udp != 0u && c->ssid[0] == '\0') {
        return "udp=on needs ssid=";
    }
    if (sta && c->ssid[0] == '\0') {
        return "wifi=on needs ssid=";
    }
    if (c->udp != 0u && c->mcast == 0u && c->n_peers == 0u) {
        return "mcast=off needs peers=";
    }
    return NULL;
}

/*
 * ntp= value: a DNS name or dotted IPv4, 1..NODE_NTP_MAX characters of
 * A-Z a-z 0-9 '.' '-', no leading / trailing '.' or '-', no "..".
 */
static bool ntp_host_ok(const char *s, size_t n)
{
    if (n == 0u || n > NODE_NTP_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!alnum && c != '.' && c != '-') {
            return false;
        }
        if ((c == '.' || c == '-') && (i == 0u || i + 1u == n)) {
            return false;
        }
        if (c == '.' && s[i + 1u] == '.') {
            return false;
        }
    }
    return true;
}

static bool chan_ok(uint32_t c)
{
    return c >= 1u && c <= 13u;
}

static bool nch_ok(uint32_t c)
{
    return c >= NODE_NCH_MIN && c <= NODE_NCH_MAX;
}

static size_t str_len_max(const char *s, size_t cap)
{
    size_t n = 0;
    while (n < cap && s[n] != '\0') {
        n++;
    }
    return n;
}

/* A unicast host address, the node_peer_parse() rule. */
static bool peer_ip_ok(uint32_t ip)
{
    return !(ip == 0u || (ip >> 24) == 127u || (ip >> 28) == 0xEu || ip == 0xFFFFFFFFu);
}

const char *node_cfg_nvs_key(uint32_t field_bit)
{
    switch (field_bit) {
    case NODE_F_NBR:
        return "nbr";
    case NODE_F_PEERS:
        return "udp_peers";
    case NODE_F_SSID:
        return "ssid";
    case NODE_F_PASS:
        return "pass";
    case NODE_F_NTP:
        return "ntp";
    default:
        return "?";
    }
}

/* min..max bytes, no control byte (< 0x20, 0x7F); 0x80..0xFF only when high_ok. */
static bool blob_text_ok(const node_kv_blob_t *k, size_t min, size_t max, bool high_ok)
{
    if (k->len < min || k->len > max || k->data == NULL) {
        return false;
    }
    for (size_t i = 0; i < k->len; i++) {
        const uint8_t b = k->data[i];
        if (b < 0x20u || b == 0x7Fu || (b > 0x7Fu && !high_ok)) {
            return false;
        }
    }
    return true;
}

static bool blob_nbr_ok(const node_kv_blob_t *k, uint16_t uid)
{
    if (k->data == NULL || k->len == 0u || k->len % 2u != 0u || k->len > NODE_NBR_MAX * 2u) {
        return false;
    }
    const size_t n = k->len / 2u;
    for (size_t i = 0; i < n; i++) {
        const uint16_t id = (uint16_t)(k->data[2u * i] | (k->data[2u * i + 1u] << 8));
        if (!br_id_is_unit(id) || id == uid) {
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            if ((uint16_t)(k->data[2u * j] | (k->data[2u * j + 1u] << 8)) == id) {
                return false;
            }
        }
    }
    return true;
}

static void peer_unpack(const uint8_t *b, uint32_t *ip, uint16_t *port)
{
    *ip = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    *port = (uint16_t)(((uint16_t)b[4] << 8) | (uint16_t)b[5]);
}

static bool blob_peers_ok(const node_kv_blob_t *k)
{
    if (k->data == NULL || k->len == 0u || k->len % 6u != 0u || k->len > NODE_PEERS_MAX * 6u) {
        return false;
    }
    for (size_t i = 0; i < k->len / 6u; i++) {
        uint32_t ip = 0;
        uint16_t port = 0;
        peer_unpack(k->data + 6u * i, &ip, &port);
        if (!peer_ip_ok(ip) || port == 0u) {
            return false;
        }
    }
    return true;
}

/* true: absent (default stays) or present and valid (decode it); false: invalid. */
static bool blob_valid(const node_kv_blob_t *k, bool ok_if_present)
{
    if (k->state == NODE_KV_ABSENT) {
        return true;
    }
    return k->state == NODE_KV_PRESENT && ok_if_present;
}

uint32_t node_cfg_load_blobs(node_cfg_t *cfg, const node_cfg_blobs_t *b)
{
    uint32_t fallback = 0;
    if (cfg == NULL || b == NULL) {
        return 0;
    }
    const bool sta = node_cfg_wifi_on(cfg);
    cfg->nvs_bad = 0;

    cfg->n_nbr = 0;
    if (!blob_valid(&b->nbr, b->nbr.state == NODE_KV_PRESENT && blob_nbr_ok(&b->nbr, cfg->uid))) {
        fallback |= NODE_F_NBR;
    } else if (b->nbr.state == NODE_KV_PRESENT) {
        cfg->n_nbr = (uint8_t)(b->nbr.len / 2u);
        for (uint8_t i = 0; i < cfg->n_nbr; i++) {
            cfg->nbr[i] = (uint16_t)(b->nbr.data[2u * i] | (b->nbr.data[2u * i + 1u] << 8));
        }
    }

    cfg->n_peers = 0;
    if (!blob_valid(&b->peers, b->peers.state == NODE_KV_PRESENT && blob_peers_ok(&b->peers))) {
        if (cfg->udp != 0u && cfg->mcast == 0u) {
            cfg->nvs_bad |= NODE_F_PEERS;
        } else {
            fallback |= NODE_F_PEERS;
        }
    } else if (b->peers.state == NODE_KV_PRESENT) {
        cfg->n_peers = (uint8_t)(b->peers.len / 6u);
        for (uint8_t i = 0; i < cfg->n_peers; i++) {
            peer_unpack(b->peers.data + 6u * i, &cfg->peers[i].ip, &cfg->peers[i].port);
        }
    }

    memset(cfg->ssid, 0, sizeof cfg->ssid);
    if (!blob_valid(&b->ssid, b->ssid.state == NODE_KV_PRESENT && blob_text_ok(&b->ssid, 1u, NODE_SSID_MAX, true))) {
        if (sta) {
            cfg->nvs_bad |= NODE_F_SSID;
        } else {
            fallback |= NODE_F_SSID;
        }
    } else if (b->ssid.state == NODE_KV_PRESENT) {
        memcpy(cfg->ssid, b->ssid.data, b->ssid.len); /* raw bytes: the driver needs the real SSID */
    }

    node_wipe(cfg->pass, sizeof cfg->pass);
    if (!blob_valid(&b->pass,
                    b->pass.state == NODE_KV_PRESENT && blob_text_ok(&b->pass, NODE_PASS_MIN, NODE_PASS_MAX, false))) {
        if (sta) {
            cfg->nvs_bad |= NODE_F_PASS; /* never an open AP by accident */
        } else {
            fallback |= NODE_F_PASS;
        }
    } else if (b->pass.state == NODE_KV_PRESENT) {
        memcpy(cfg->pass, b->pass.data, b->pass.len);
    }

    memset(cfg->ntp, 0, sizeof cfg->ntp);
    memcpy(cfg->ntp, NODE_DEFAULT_NTP, sizeof NODE_DEFAULT_NTP);
    if (!blob_valid(&b->ntp, b->ntp.state == NODE_KV_PRESENT && b->ntp.len <= NODE_NTP_MAX &&
                                 ntp_host_ok((const char *)b->ntp.data, b->ntp.len))) {
        fallback |= NODE_F_NTP;
    } else if (b->ntp.state == NODE_KV_PRESENT) {
        memset(cfg->ntp, 0, sizeof cfg->ntp);
        memcpy(cfg->ntp, b->ntp.data, b->ntp.len);
    }
    return fallback;
}

bool node_cfg_ready(const node_cfg_t *cfg, node_chip_t chip, const char **why)
{
    const char *r = NULL;
    const char *pin_why = NULL;
    if (cfg == NULL) {
        r = "no configuration";
    } else if ((cfg->nvs_bad & NODE_F_SSID) != 0u && node_cfg_wifi_on(cfg)) {
        r = "NVS key ssid invalid (needs 1..32 bytes, no control characters): br set ssid=<ssid>";
    } else if ((cfg->nvs_bad & NODE_F_PASS) != 0u && node_cfg_wifi_on(cfg)) {
        r = "NVS key pass invalid (needs 8..63 printable characters; not taken as an open AP): "
            "br set pass=<passphrase>, or pass= alone for an open AP";
    } else if ((cfg->nvs_bad & NODE_F_PEERS) != 0u && cfg->udp != 0u && cfg->mcast == 0u) {
        r = "NVS key udp_peers invalid (needs 1..8 unicast a.b.c.d[:port]): br set peers=<list>";
    } else if (cfg->role != NODE_ROLE_SENDER && cfg->role != NODE_ROLE_NODE && cfg->role != NODE_ROLE_PROBE) {
        r = "role unset";
    } else if (!br_id_is_unit(cfg->uid)) {
        r = "id unset or not a unit ID (0x0010..0xFEFF)";
    } else if (!br_id_is_group(cfg->grp)) {
        r = "grp not a group ID (0xFF00..0xFFFE)";
    } else if (cfg->n_nbr > NODE_NBR_MAX) {
        r = "nbr has more than 8 entries";
    } else if (!chan_ok(cfg->chan)) {
        r = "chan not 1..13";
    } else if (!node_pin_ok(chip, cfg->led, true, &pin_why)) {
        r = "led pin not usable";
    } else if (!node_pin_ok(chip, cfg->btn, false, &pin_why)) {
        r = "btn pin not usable";
    } else if (cfg->led == cfg->btn) {
        r = "led and btn are the same pin";
    } else if (cfg->uart > 1u) {
        r = "uart not on/off";
    } else if (cfg->uart != 0u && !node_uart_pin_ok(chip, cfg->utx, true, &pin_why)) {
        r = "utx pin not usable";
    } else if (cfg->uart != 0u && !node_uart_pin_ok(chip, cfg->urx, false, &pin_why)) {
        r = "urx pin not usable";
    } else if (cfg->uart != 0u && !node_baud_ok(cfg->ubaud)) {
        r = "ubaud not a supported rate";
    } else if (cfg->uart != 0u && uart_pins_conflict(cfg) != NULL) {
        r = uart_pins_conflict(cfg);
    } else if (cfg->espnow > 1u) {
        r = "espnow not on/off";
    } else if (cfg->udp > 1u) {
        r = "udp not on/off";
    } else if (cfg->mcast > 1u) {
        r = "mcast not on/off";
    } else if (cfg->nrf > 1u) {
        r = "nrf not on/off";
    } else if (cfg->wifi > 1u) {
        r = "wifi not on/off";
    } else if (cfg->udp != 0u && cfg->port == 0u) {
        r = "port not 1..65535";
    } else if (cfg->n_peers > NODE_PEERS_MAX) {
        r = "peers has more than 8 entries";
    } else if (str_len_max(cfg->ssid, sizeof cfg->ssid) > NODE_SSID_MAX) {
        r = "ssid longer than 32 characters";
    } else if (str_len_max(cfg->pass, sizeof cfg->pass) > NODE_PASS_MAX) {
        r = "pass longer than 63 characters";
    } else if (node_cfg_wifi_on(cfg) && cfg->pass[0] != '\0' &&
               str_len_max(cfg->pass, sizeof cfg->pass) < NODE_PASS_MIN) {
        r = "pass shorter than 8 characters (WPA2)";
    } else if (node_cfg_wifi_on(cfg) && !ntp_host_ok(cfg->ntp, str_len_max(cfg->ntp, sizeof cfg->ntp))) {
        r = "ntp not a host name (1..63 of A-Z a-z 0-9 . -)";
    } else if (cfg->nrf != 0u && !nch_ok(cfg->nch)) {
        r = "nch not 76..83";
    } else if (cfg->nrf != 0u && cfg->nrate > NODE_NRATE_2M) {
        r = "nrate not 250k|1m|2m";
    } else if (cfg->nrf != 0u && cfg->npa > NODE_NPA_MAX) {
        r = "npa not min|low|high|max";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->nsck, NODE_NRF_PIN_SCK, &pin_why)) {
        r = "nsck pin not usable";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->nmiso, NODE_NRF_PIN_MISO, &pin_why)) {
        r = "nmiso pin not usable";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->nmosi, NODE_NRF_PIN_MOSI, &pin_why)) {
        r = "nmosi pin not usable";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->ncsn, NODE_NRF_PIN_CSN, &pin_why)) {
        r = "ncsn pin not usable";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->nce, NODE_NRF_PIN_CE, &pin_why)) {
        r = "nce pin not usable";
    } else if (cfg->nrf != 0u && !node_nrf_pin_ok(chip, cfg->nirq, NODE_NRF_PIN_IRQ, &pin_why)) {
        r = "nirq pin not usable";
    } else if (cfg->nrf != 0u && nrf_conflict(cfg) != NULL) {
        r = nrf_conflict(cfg);
    } else if (transport_conflict(cfg) != NULL) {
        r = transport_conflict(cfg);
    } else {
        for (uint8_t i = 0; i < cfg->n_nbr && r == NULL; i++) {
            if (!br_id_is_unit(cfg->nbr[i])) {
                r = "nbr entry not a unit ID";
            } else if (cfg->nbr[i] == cfg->uid) {
                r = "nbr contains the node's own id";
            }
            for (uint8_t j = 0; j < i && r == NULL; j++) {
                if (cfg->nbr[j] == cfg->nbr[i]) {
                    r = "nbr has a duplicate";
                }
            }
        }
        for (uint8_t i = 0; i < cfg->n_peers && r == NULL; i++) {
            if (cfg->peers[i].ip == 0u || cfg->peers[i].port == 0u) {
                r = "peers entry not an ip:port";
            }
        }
    }
    if (why != NULL) {
        *why = r;
    }
    return r == NULL;
}

size_t node_cfg_format(const node_cfg_t *cfg, char *buf, size_t cap)
{
    node_fmt_t f;
    node_fmt_init(&f, buf, cap);
    node_fmt_str(&f, "role=");
    node_fmt_str(&f, node_role_name(cfg->role));
    node_fmt_str(&f, " id=");
    if (cfg->uid == 0u) {
        node_fmt_str(&f, "unset");
    } else {
        node_fmt_hex16(&f, cfg->uid);
    }
    node_fmt_str(&f, " grp=");
    node_fmt_hex16(&f, cfg->grp);
    node_fmt_str(&f, " nbr=");
    if (cfg->n_nbr == 0u) {
        node_fmt_str(&f, "none");
    }
    for (uint8_t i = 0; i < cfg->n_nbr && i < NODE_NBR_MAX; i++) {
        if (i > 0u) {
            node_fmt_str(&f, ",");
        }
        node_fmt_hex16(&f, cfg->nbr[i]);
    }
    node_fmt_str(&f, " led=");
    node_fmt_u32(&f, cfg->led);
    node_fmt_str(&f, " btn=");
    node_fmt_u32(&f, cfg->btn);
    node_fmt_str(&f, " chan=");
    node_fmt_u32(&f, cfg->chan);
    if (cfg->uart != 0u) {
        node_fmt_str(&f, " uart=on utx=");
        node_fmt_u32(&f, cfg->utx);
        node_fmt_str(&f, " urx=");
        node_fmt_u32(&f, cfg->urx);
        node_fmt_str(&f, " ubaud=");
        node_fmt_u32(&f, cfg->ubaud);
    }
    if (cfg->espnow == 0u) {
        node_fmt_str(&f, " espnow=off");
    }
    if (cfg->udp != 0u) {
        node_fmt_str(&f, " udp=on port=");
        node_fmt_u32(&f, cfg->port);
        node_fmt_str(&f, cfg->mcast != 0u ? " mcast=on peers=" : " mcast=off peers=");
        if (cfg->n_peers == 0u) {
            node_fmt_str(&f, "none");
        }
        for (uint8_t i = 0; i < cfg->n_peers && i < NODE_PEERS_MAX; i++) {
            if (i > 0u) {
                node_fmt_str(&f, ",");
            }
            node_fmt_peer(&f, cfg->peers[i].ip, cfg->peers[i].port);
        }
    } else if (cfg->wifi != 0u) {
        node_fmt_str(&f, " wifi=on");
    }
    if (node_cfg_wifi_on(cfg)) {
        node_fmt_str(&f, " ssid=");
        if (cfg->ssid[0] != '\0') {
            node_fmt_ssid(&f, cfg->ssid); /* raw bytes stay in cfg; the log gets ASCII */
        } else {
            node_fmt_str(&f, "unset");
        }
        node_fmt_str(&f, cfg->pass[0] != '\0' ? " pass=set" : " pass=unset"); /* never the passphrase */
        if (strncmp(cfg->ntp, NODE_DEFAULT_NTP, sizeof cfg->ntp) != 0) {
            node_fmt_str(&f, " ntp=");
            node_fmt_str(&f, cfg->ntp);
        }
    }
    if (cfg->nrf != 0u) {
        node_fmt_str(&f, " nrf=on nch=");
        node_fmt_u32(&f, cfg->nch);
        node_fmt_str(&f, " nrate=");
        node_fmt_str(&f, node_nrate_name(cfg->nrate));
        node_fmt_str(&f, " npa=");
        node_fmt_str(&f, node_npa_name(cfg->npa));
        node_fmt_str(&f, " nsck=");
        node_fmt_u32(&f, cfg->nsck);
        node_fmt_str(&f, " nmiso=");
        node_fmt_u32(&f, cfg->nmiso);
        node_fmt_str(&f, " nmosi=");
        node_fmt_u32(&f, cfg->nmosi);
        node_fmt_str(&f, " ncsn=");
        node_fmt_u32(&f, cfg->ncsn);
        node_fmt_str(&f, " nce=");
        node_fmt_u32(&f, cfg->nce);
        node_fmt_str(&f, " nirq=");
        if (cfg->nirq == NODE_PIN_NONE) {
            node_fmt_str(&f, "-1");
        } else {
            node_fmt_u32(&f, cfg->nirq);
        }
    }
    return f.len;
}

/* ------------------------------------------------------------------------- */
/* Parser                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *p;                /**< start (not NUL-terminated) */
    size_t      n;
} tok_t;

static bool is_space(char c)
{
    return c == ' ' || c == '\t';
}

static char lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive token == literal. */
static bool tok_is(tok_t t, const char *lit)
{
    size_t n = strlen(lit);
    if (t.n != n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (lower(t.p[i]) != lit[i]) {
            return false;
        }
    }
    return true;
}

static bool next_tok(const char **s, tok_t *t)
{
    const char *p = *s;
    while (*p != '\0' && is_space(*p)) {
        p++;
    }
    if (*p == '\0') {
        *s = p;
        return false;
    }
    t->p = p;
    while (*p != '\0' && !is_space(*p)) {
        p++;
    }
    t->n = (size_t)(p - t->p);
    *s = p;
    return true;
}

/* Decimal or 0x hex, no sign, no trailing garbage, value <= max. */
static bool parse_num(tok_t t, uint32_t max, uint32_t *out)
{
    if (t.n == 0u) {
        return false;
    }
    uint32_t base = 10u;
    size_t i = 0;
    if (t.n > 2u && t.p[0] == '0' && (t.p[1] == 'x' || t.p[1] == 'X')) {
        base = 16u;
        i = 2;
    }
    uint32_t v = 0;
    for (; i < t.n; i++) {
        char c = lower(t.p[i]);
        uint32_t d;
        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (base == 16u && c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a') + 10u;
        } else {
            return false;
        }
        if (v > (max - d) / base) {
            return false; /* above max (also catches overflow) */
        }
        v = v * base + d;
    }
    *out = v;
    return true;
}

/* Plain decimal 0..max from a NUL-terminated run of digits (dotted-quad parts, port). */
static bool parse_dec(const char *s, size_t n, uint32_t max, uint32_t *out)
{
    if (n == 0u || n > 5u) {
        return false;
    }
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10u + (uint32_t)(s[i] - '0');
        if (v > max) {
            return false;
        }
    }
    *out = v;
    return true;
}

bool node_peer_parse(const char *s, uint32_t *ip_out, uint16_t *port_out)
{
    if (s == NULL) {
        return false;
    }
    uint32_t ip = 0;
    size_t i = 0;
    for (int part = 0; part < 4; part++) {
        size_t j = i;
        while (s[j] != '\0' && s[j] != '.' && s[j] != ':') {
            j++;
        }
        uint32_t v = 0;
        if (!parse_dec(s + i, j - i, 255u, &v)) {
            return false;
        }
        ip = (ip << 8) | v;
        if (part < 3) {
            if (s[j] != '.') {
                return false;
            }
            i = j + 1u;
        } else {
            i = j;
        }
    }
    if (!peer_ip_ok(ip)) {
        return false; /* not a unicast host address */
    }
    uint32_t port = NODE_DEFAULT_PORT;
    if (s[i] == ':') {
        size_t j = i + 1u;
        while (s[j] != '\0') {
            j++;
        }
        if (!parse_dec(s + i + 1u, j - i - 1u, 65535u, &port) || port == 0u) {
            return false;
        }
    } else if (s[i] != '\0') {
        return false;
    }
    if (ip_out != NULL) {
        *ip_out = ip;
    }
    if (port_out != NULL) {
        *port_out = (uint16_t)port;
    }
    return true;
}

/*
 * Quote up to 24 characters of a key or of a value of a known key in an
 * error text. When the line mentions "pass" (any case) nothing is quoted (a
 * passphrase typed with a space or a colon must not appear in the log
 * either). Tokens that are not key=value of a known key (unknown command or
 * verb, a token without '=', extra tokens after a verb) never reach this
 * function: set_err_len() reports their length only, so a passphrase typed
 * without pass= is not echoed either (SPEC-NOTES N72).
 */
static void echo_tok(node_fmt_t *f, const node_cmd_t *c, tok_t t)
{
    if (t.n == 0u) {
        return;
    }
    if (c->no_echo != 0u) {
        node_fmt_str(f, "<hidden>");
        return;
    }
    for (size_t i = 0; i < t.n && i < 24u; i++) {
        char s[2] = {t.p[i], '\0'};
        node_fmt_str(f, s);
    }
    if (t.n > 24u) {
        node_fmt_str(f, "...");
    }
}

static void set_err(node_cmd_t *c, const char *a, tok_t t, const char *b)
{
    node_fmt_t f;
    node_fmt_init(&f, c->err, sizeof c->err);
    node_fmt_str(&f, a);
    echo_tok(&f, c, t);
    node_fmt_str(&f, b);
    c->kind = NODE_CMD_ERROR;
}

static void set_err_s(node_cmd_t *c, const char *a)
{
    tok_t none = {"", 0};
    set_err(c, a, none, "");
}

/* a + "<hidden> (<n> characters)" + b: the token itself is never quoted (N72). */
static void set_err_len(node_cmd_t *c, const char *a, tok_t t, const char *b)
{
    node_fmt_t f;
    node_fmt_init(&f, c->err, sizeof c->err);
    node_fmt_str(&f, a);
    node_fmt_str(&f, "<hidden> (");
    node_fmt_u32(&f, (uint32_t)t.n);
    node_fmt_str(&f, t.n == 1u ? " character)" : " characters)");
    node_fmt_str(&f, b);
    c->kind = NODE_CMD_ERROR;
}

static bool parse_nbr(tok_t v, node_cmd_t *c)
{
    if (tok_is(v, "none")) {
        c->val.n_nbr = 0;
        return true;
    }
    size_t i = 0;
    uint8_t n = 0;
    while (i <= v.n) {
        size_t j = i;
        while (j < v.n && v.p[j] != ',') {
            j++;
        }
        tok_t item = {v.p + i, j - i};
        uint32_t id = 0;
        if (item.n == 0u) {
            set_err_s(c, "nbr: empty entry in the list");
            return false;
        }
        if (!parse_num(item, 0xFFFFu, &id) || !br_id_is_unit((uint16_t)id)) {
            set_err(c, "nbr: '", item, "' is not a unit ID (0x0010..0xFEFF)");
            return false;
        }
        if (n >= NODE_NBR_MAX) {
            set_err_s(c, "nbr: more than 8 entries");
            return false;
        }
        for (uint8_t k = 0; k < n; k++) {
            if (c->val.nbr[k] == (uint16_t)id) {
                set_err(c, "nbr: duplicate '", item, "'");
                return false;
            }
        }
        c->val.nbr[n] = (uint16_t)id;
        n++;
        i = j + 1u;
    }
    c->val.n_nbr = n;
    return true;
}

static bool parse_peers(tok_t v, node_cmd_t *c)
{
    if (tok_is(v, "none")) {
        c->val.n_peers = 0;
        return true;
    }
    size_t i = 0;
    uint8_t n = 0;
    while (i <= v.n) {
        size_t j = i;
        while (j < v.n && v.p[j] != ',') {
            j++;
        }
        tok_t item = {v.p + i, j - i};
        if (item.n == 0u) {
            set_err_s(c, "peers: empty entry in the list");
            return false;
        }
        char tmp[24];
        uint32_t ip = 0;
        uint16_t port = 0;
        if (item.n >= sizeof tmp) {
            set_err(c, "peers: '", item, "' is not a.b.c.d[:port]");
            return false;
        }
        memcpy(tmp, item.p, item.n);
        tmp[item.n] = '\0';
        if (!node_peer_parse(tmp, &ip, &port)) {
            set_err(c, "peers: '", item, "' is not a.b.c.d[:port]");
            return false;
        }
        if (n >= NODE_PEERS_MAX) {
            set_err_s(c, "peers: more than 8 entries");
            return false;
        }
        for (uint8_t k = 0; k < n; k++) {
            if (c->val.peers[k].ip == ip && c->val.peers[k].port == port) {
                set_err(c, "peers: duplicate '", item, "'");
                return false;
            }
        }
        c->val.peers[n].ip = ip;
        c->val.peers[n].port = port;
        n++;
        i = j + 1u;
    }
    c->val.n_peers = n;
    return true;
}

/* on|off into *out; false with the error set otherwise. */
static bool parse_onoff(tok_t v, const char *key, node_cmd_t *c, uint8_t *out)
{
    if (tok_is(v, "on")) {
        *out = 1u;
        return true;
    }
    if (tok_is(v, "off")) {
        *out = 0u;
        return true;
    }
    node_fmt_t f;
    node_fmt_init(&f, c->err, sizeof c->err);
    node_fmt_str(&f, key);
    node_fmt_str(&f, ": '");
    echo_tok(&f, c, v);
    node_fmt_str(&f, "' is not on|off");
    c->kind = NODE_CMD_ERROR;
    return false;
}

static void append_why(node_cmd_t *c, const char *why)
{
    node_fmt_t f;
    node_fmt_init(&f, c->err + strlen(c->err), sizeof c->err - strlen(c->err));
    node_fmt_str(&f, why);
}

typedef struct {
    const char    *key;
    uint32_t       bit;
    node_nrf_pin_t role;
} nrf_pin_key_t;

static const nrf_pin_key_t NRF_PIN_KEYS[] = {
    {"nsck", NODE_F_NSCK, NODE_NRF_PIN_SCK},  {"nmiso", NODE_F_NMISO, NODE_NRF_PIN_MISO},
    {"nmosi", NODE_F_NMOSI, NODE_NRF_PIN_MOSI}, {"ncsn", NODE_F_NCSN, NODE_NRF_PIN_CSN},
    {"nce", NODE_F_NCE, NODE_NRF_PIN_CE},     {"nirq", NODE_F_NIRQ, NODE_NRF_PIN_IRQ},
};

static uint8_t *nrf_pin_slot(node_cfg_t *v, node_nrf_pin_t role)
{
    switch (role) {
    case NODE_NRF_PIN_SCK:  return &v->nsck;
    case NODE_NRF_PIN_MISO: return &v->nmiso;
    case NODE_NRF_PIN_MOSI: return &v->nmosi;
    case NODE_NRF_PIN_CSN:  return &v->ncsn;
    case NODE_NRF_PIN_CE:   return &v->nce;
    case NODE_NRF_PIN_IRQ:
    default:                return &v->nirq;
    }
}

static bool parse_nrf_pin(tok_t v, const nrf_pin_key_t *pk, node_chip_t chip, node_cmd_t *c)
{
    uint32_t n = 0;
    const char *why = NULL;
    if (pk->role == NODE_NRF_PIN_IRQ && (tok_is(v, "-1") || tok_is(v, "none"))) {
        c->val.nirq = NODE_PIN_NONE;
        return true;
    }
    if (!parse_num(v, 254u, &n)) {
        /* "<key>: '<value>' is not a GPIO number[ or -1]" (the key is the literal table entry) */
        node_fmt_t f;
        node_fmt_init(&f, c->err, sizeof c->err);
        node_fmt_str(&f, pk->key);
        node_fmt_str(&f, ": '");
        echo_tok(&f, c, v);
        node_fmt_str(&f, pk->role == NODE_NRF_PIN_IRQ ? "' is not a GPIO number or -1" : "' is not a GPIO number");
        c->kind = NODE_CMD_ERROR;
        return false;
    }
    if (!node_nrf_pin_ok(chip, (uint8_t)n, pk->role, &why)) {
        node_fmt_t f;
        node_fmt_init(&f, c->err, sizeof c->err);
        node_fmt_str(&f, pk->key);
        node_fmt_str(&f, ": GPIO");
        node_fmt_u32(&f, n);
        node_fmt_str(&f, " refused: ");
        node_fmt_str(&f, why);
        c->kind = NODE_CMD_ERROR;
        return false;
    }
    *nrf_pin_slot(&c->val, pk->role) = (uint8_t)n;
    return true;
}

static bool parse_kv(tok_t t, node_chip_t chip, node_cmd_t *c)
{
    size_t eq = 0;
    while (eq < t.n && t.p[eq] != '=') {
        eq++;
    }
    if (eq == 0u || eq >= t.n) {
        set_err_len(c, "expected key=value, got ", t, "");
        return false;
    }
    tok_t k = {t.p, eq};
    tok_t v = {t.p + eq + 1u, t.n - eq - 1u};
    if (v.n == 0u && !tok_is(k, "pass")) { /* pass= (empty) means an open AP */
        set_err(c, "empty value for '", k, "'");
        return false;
    }
    uint32_t bit;
    const nrf_pin_key_t *pk = NULL;
    if (tok_is(k, "role")) {
        bit = NODE_F_ROLE;
    } else if (tok_is(k, "id") || tok_is(k, "uid")) {
        bit = NODE_F_UID;
    } else if (tok_is(k, "grp")) {
        bit = NODE_F_GRP;
    } else if (tok_is(k, "nbr")) {
        bit = NODE_F_NBR;
    } else if (tok_is(k, "led")) {
        bit = NODE_F_LED;
    } else if (tok_is(k, "btn")) {
        bit = NODE_F_BTN;
    } else if (tok_is(k, "chan")) {
        bit = NODE_F_CHAN;
    } else if (tok_is(k, "uart")) {
        bit = NODE_F_UART;
    } else if (tok_is(k, "utx")) {
        bit = NODE_F_UTX;
    } else if (tok_is(k, "urx")) {
        bit = NODE_F_URX;
    } else if (tok_is(k, "ubaud")) {
        bit = NODE_F_UBAUD;
    } else if (tok_is(k, "espnow")) {
        bit = NODE_F_ESPNOW;
    } else if (tok_is(k, "udp")) {
        bit = NODE_F_UDP;
    } else if (tok_is(k, "port")) {
        bit = NODE_F_PORT;
    } else if (tok_is(k, "mcast")) {
        bit = NODE_F_MCAST;
    } else if (tok_is(k, "peers")) {
        bit = NODE_F_PEERS;
    } else if (tok_is(k, "ssid")) {
        bit = NODE_F_SSID;
    } else if (tok_is(k, "pass")) {
        bit = NODE_F_PASS;
    } else if (tok_is(k, "nrf")) {
        bit = NODE_F_NRF;
    } else if (tok_is(k, "nch")) {
        bit = NODE_F_NCH;
    } else if (tok_is(k, "nrate")) {
        bit = NODE_F_NRATE;
    } else if (tok_is(k, "npa")) {
        bit = NODE_F_NPA;
    } else if (tok_is(k, "wifi")) {
        bit = NODE_F_WIFI;
    } else if (tok_is(k, "ntp")) {
        bit = NODE_F_NTP;
    } else {
        bit = 0;
        for (size_t i = 0; i < sizeof NRF_PIN_KEYS / sizeof NRF_PIN_KEYS[0]; i++) {
            if (tok_is(k, NRF_PIN_KEYS[i].key)) {
                pk = &NRF_PIN_KEYS[i];
                bit = pk->bit;
            }
        }
        if (bit == 0u) {
            set_err(c, "unknown key '", k,
                    "' (role id grp nbr led btn chan uart utx urx ubaud espnow udp port mcast peers ssid pass "
                    "nrf nch nrate npa nsck nmiso nmosi ncsn nce nirq wifi ntp)");
            return false;
        }
    }
    if ((c->fields & bit) != 0u) {
        set_err(c, "key '", k, "' given twice");
        return false;
    }
    c->fields |= bit;
    uint32_t n = 0;
    const char *why = NULL;
    if (pk != NULL) {
        return parse_nrf_pin(v, pk, chip, c);
    }
    switch (bit) {
    case NODE_F_ROLE:
        if (tok_is(v, "sender")) {
            c->val.role = NODE_ROLE_SENDER;
        } else if (tok_is(v, "node") || tok_is(v, "relay")) {
            c->val.role = NODE_ROLE_NODE;
        } else if (tok_is(v, "probe")) {
            c->val.role = NODE_ROLE_PROBE;
        } else {
            set_err(c, "role: '", v, "' is not sender|node|probe");
            return false;
        }
        return true;
    case NODE_F_UID:
        if (!parse_num(v, 0xFFFFu, &n) || !br_id_is_unit((uint16_t)n)) {
            set_err(c, "id: '", v, "' is not a unit ID (0x0010..0xFEFF)");
            if (n <= 0xFFFFu && br_id_is_manager((uint16_t)n)) {
                append_why(c, "; 0x0001..0x000F are manager IDs (N1): the core runs units only, "
                              "a gateway uses a unit ID");
            }
            return false;
        }
        c->val.uid = (uint16_t)n;
        return true;
    case NODE_F_GRP:
        if (!parse_num(v, 0xFFFFu, &n) || !br_id_is_group((uint16_t)n)) {
            set_err(c, "grp: '", v, "' is not a group ID (0xFF00..0xFFFE)");
            return false;
        }
        c->val.grp = (uint16_t)n;
        return true;
    case NODE_F_NBR:
        return parse_nbr(v, c);
    case NODE_F_LED:
    case NODE_F_BTN:
        if (!parse_num(v, 255u, &n)) {
            set_err(c, bit == NODE_F_LED ? "led: '" : "btn: '", v, "' is not a GPIO number");
            return false;
        }
        if (!node_pin_ok(chip, (uint8_t)n, bit == NODE_F_LED, &why)) {
            set_err(c, bit == NODE_F_LED ? "led: GPIO" : "btn: GPIO", v, " refused: ");
            append_why(c, why);
            return false;
        }
        if (bit == NODE_F_LED) {
            c->val.led = (uint8_t)n;
        } else {
            c->val.btn = (uint8_t)n;
        }
        return true;
    case NODE_F_UART:
        return parse_onoff(v, "uart", c, &c->val.uart);
    case NODE_F_ESPNOW:
        return parse_onoff(v, "espnow", c, &c->val.espnow);
    case NODE_F_UDP:
        return parse_onoff(v, "udp", c, &c->val.udp);
    case NODE_F_MCAST:
        return parse_onoff(v, "mcast", c, &c->val.mcast);
    case NODE_F_NRF:
        return parse_onoff(v, "nrf", c, &c->val.nrf);
    case NODE_F_WIFI:
        return parse_onoff(v, "wifi", c, &c->val.wifi);
    case NODE_F_NTP:
        if (!ntp_host_ok(v.p, v.n)) {
            set_err(c, "ntp: '", v, "' is not a host name or IPv4 address (1..63 of A-Z a-z 0-9 . -)");
            return false;
        }
        memcpy(c->val.ntp, v.p, v.n);
        c->val.ntp[v.n] = '\0';
        return true;
    case NODE_F_UTX:
    case NODE_F_URX:
        if (!parse_num(v, 255u, &n)) {
            set_err(c, bit == NODE_F_UTX ? "utx: '" : "urx: '", v, "' is not a GPIO number");
            return false;
        }
        if (!node_uart_pin_ok(chip, (uint8_t)n, bit == NODE_F_UTX, &why)) {
            set_err(c, bit == NODE_F_UTX ? "utx: GPIO" : "urx: GPIO", v, " refused: ");
            append_why(c, why);
            return false;
        }
        if (bit == NODE_F_UTX) {
            c->val.utx = (uint8_t)n;
        } else {
            c->val.urx = (uint8_t)n;
        }
        return true;
    case NODE_F_UBAUD:
        if (!parse_num(v, 0xFFFFFFFFu, &n) || !node_baud_ok(n)) {
            set_err(c, "ubaud: '", v, "' is not a supported rate (115200, 921600, ...)");
            return false;
        }
        c->val.ubaud = n;
        return true;
    case NODE_F_PORT:
        if (!parse_num(v, 65535u, &n) || n == 0u) {
            set_err(c, "port: '", v, "' is not a UDP port 1..65535");
            return false;
        }
        c->val.port = (uint16_t)n;
        return true;
    case NODE_F_PEERS:
        return parse_peers(v, c);
    case NODE_F_SSID:
        if (v.n > NODE_SSID_MAX) {
            set_err_s(c, "ssid: longer than 32 characters");
            return false;
        }
        memcpy(c->val.ssid, v.p, v.n);
        c->val.ssid[v.n] = '\0';
        return true;
    case NODE_F_PASS:
        /* never echo the value, not even a refused one */
        if (v.n > NODE_PASS_MAX) {
            set_err_s(c, "pass: longer than 63 characters");
            return false;
        }
        if (v.n > 0u && v.n < NODE_PASS_MIN) {
            set_err_s(c, "pass: a WPA2 passphrase has 8..63 characters (pass= alone = open AP)");
            return false;
        }
        memcpy(c->val.pass, v.p, v.n);
        c->val.pass[v.n] = '\0';
        return true;
    case NODE_F_NCH:
        if (!parse_num(v, 255u, &n) || !nch_ok(n)) {
            set_err(c, "nch: '", v, "' is not a channel 76..83");
            return false;
        }
        c->val.nch = (uint8_t)n;
        return true;
    case NODE_F_NRATE:
        if (tok_is(v, "250k")) {
            c->val.nrate = NODE_NRATE_250K;
        } else if (tok_is(v, "1m")) {
            c->val.nrate = NODE_NRATE_1M;
        } else if (tok_is(v, "2m")) {
            c->val.nrate = NODE_NRATE_2M;
        } else {
            set_err(c, "nrate: '", v, "' is not 250k|1m|2m");
            return false;
        }
        return true;
    case NODE_F_NPA:
        if (tok_is(v, "min")) {
            c->val.npa = NODE_NPA_MIN;
        } else if (tok_is(v, "low")) {
            c->val.npa = NODE_NPA_LOW;
        } else if (tok_is(v, "high")) {
            c->val.npa = NODE_NPA_HIGH;
        } else if (tok_is(v, "max")) {
            c->val.npa = NODE_NPA_MAX;
        } else {
            set_err(c, "npa: '", v, "' is not min|low|high|max");
            return false;
        }
        return true;
    case NODE_F_CHAN:
    default:
        if (!parse_num(v, 255u, &n) || !chan_ok(n)) {
            set_err(c, "chan: '", v, "' is not a channel 1..13");
            return false;
        }
        c->val.chan = (uint8_t)n;
        return true;
    }
}

bool node_cmd_parse(const char *line, node_chip_t chip, node_cmd_t *out)
{
    memset(out, 0, sizeof *out);
    if (line == NULL) {
        out->kind = NODE_CMD_NONE;
        return true;
    }
    if (strlen(line) > NODE_LINE_MAX) {
        set_err_s(out, "line too long");
        return false;
    }
    for (const char *q = line; q[0] != '\0' && q[1] != '\0' && q[2] != '\0' && q[3] != '\0'; q++) {
        if (lower(q[0]) == 'p' && lower(q[1]) == 'a' && lower(q[2]) == 's' && lower(q[3]) == 's') {
            out->no_echo = 1u; /* a passphrase may be anywhere on this line: quote nothing */
            break;
        }
    }
    const char *s = line;
    tok_t t;
    if (!next_tok(&s, &t)) {
        out->kind = NODE_CMD_NONE;
        return true;
    }
    if (!tok_is(t, "br")) {
        set_err_len(out, "unknown command ", t, "; try: br set|show|erase|reboot|stats");
        return false;
    }
    tok_t verb;
    if (!next_tok(&s, &verb)) {
        set_err_s(out, "missing verb; try: br set|show|erase|reboot|stats");
        return false;
    }
    if (tok_is(verb, "set")) {
        out->kind = NODE_CMD_SET;
        bool any = false;
        while (next_tok(&s, &t)) {
            any = true;
            if (!parse_kv(t, chip, out)) {
                return false;
            }
        }
        if (!any) {
            set_err_s(out, "br set needs at least one key=value");
            return false;
        }
        return true;
    }
    node_cmd_kind_t k;
    if (tok_is(verb, "show")) {
        k = NODE_CMD_SHOW;
    } else if (tok_is(verb, "erase")) {
        k = NODE_CMD_ERASE;
    } else if (tok_is(verb, "reboot")) {
        k = NODE_CMD_REBOOT;
    } else if (tok_is(verb, "stats")) {
        k = NODE_CMD_STATS;
    } else {
        set_err_len(out, "unknown verb ", verb, "; try: br set|show|erase|reboot|stats");
        return false;
    }
    if (next_tok(&s, &t)) {
        set_err_len(out, "unexpected ", t, " after the command");
        return false;
    }
    out->kind = k;
    return true;
}

static bool cfg_merge(node_cfg_t *np, const node_cmd_t *cmd, node_fmt_t *fp)
{
    if ((cmd->fields & NODE_F_ROLE) != 0u) {
        np->role = cmd->val.role;
    }
    if ((cmd->fields & NODE_F_UID) != 0u) {
        np->uid = cmd->val.uid;
    }
    if ((cmd->fields & NODE_F_GRP) != 0u) {
        np->grp = cmd->val.grp;
    }
    if ((cmd->fields & NODE_F_NBR) != 0u) {
        np->n_nbr = cmd->val.n_nbr;
        memcpy(np->nbr, cmd->val.nbr, sizeof np->nbr);
    }
    if ((cmd->fields & NODE_F_LED) != 0u) {
        np->led = cmd->val.led;
    }
    if ((cmd->fields & NODE_F_BTN) != 0u) {
        np->btn = cmd->val.btn;
    }
    if ((cmd->fields & NODE_F_CHAN) != 0u) {
        np->chan = cmd->val.chan;
    }
    if ((cmd->fields & NODE_F_UART) != 0u) {
        np->uart = cmd->val.uart;
    }
    if ((cmd->fields & NODE_F_UTX) != 0u) {
        np->utx = cmd->val.utx;
    }
    if ((cmd->fields & NODE_F_URX) != 0u) {
        np->urx = cmd->val.urx;
    }
    if ((cmd->fields & NODE_F_UBAUD) != 0u) {
        np->ubaud = cmd->val.ubaud;
    }
    if ((cmd->fields & NODE_F_ESPNOW) != 0u) {
        np->espnow = cmd->val.espnow;
    }
    if ((cmd->fields & NODE_F_UDP) != 0u) {
        np->udp = cmd->val.udp;
    }
    if ((cmd->fields & NODE_F_PORT) != 0u) {
        np->port = cmd->val.port;
    }
    if ((cmd->fields & NODE_F_MCAST) != 0u) {
        np->mcast = cmd->val.mcast;
    }
    if ((cmd->fields & NODE_F_PEERS) != 0u) {
        np->n_peers = cmd->val.n_peers;
        memcpy(np->peers, cmd->val.peers, sizeof np->peers);
    }
    if ((cmd->fields & NODE_F_SSID) != 0u) {
        memcpy(np->ssid, cmd->val.ssid, sizeof np->ssid);
    }
    if ((cmd->fields & NODE_F_PASS) != 0u) {
        memcpy(np->pass, cmd->val.pass, sizeof np->pass);
    }
    if ((cmd->fields & NODE_F_NRF) != 0u) {
        np->nrf = cmd->val.nrf;
    }
    if ((cmd->fields & NODE_F_NCH) != 0u) {
        np->nch = cmd->val.nch;
    }
    if ((cmd->fields & NODE_F_NRATE) != 0u) {
        np->nrate = cmd->val.nrate;
    }
    if ((cmd->fields & NODE_F_NPA) != 0u) {
        np->npa = cmd->val.npa;
    }
    if ((cmd->fields & NODE_F_NSCK) != 0u) {
        np->nsck = cmd->val.nsck;
    }
    if ((cmd->fields & NODE_F_NMISO) != 0u) {
        np->nmiso = cmd->val.nmiso;
    }
    if ((cmd->fields & NODE_F_NMOSI) != 0u) {
        np->nmosi = cmd->val.nmosi;
    }
    if ((cmd->fields & NODE_F_NCSN) != 0u) {
        np->ncsn = cmd->val.ncsn;
    }
    if ((cmd->fields & NODE_F_NCE) != 0u) {
        np->nce = cmd->val.nce;
    }
    if ((cmd->fields & NODE_F_NIRQ) != 0u) {
        np->nirq = cmd->val.nirq;
    }
    if ((cmd->fields & NODE_F_NTP) != 0u) {
        memcpy(np->ntp, cmd->val.ntp, sizeof np->ntp);
    }
    /* wifi= is authoritative; a line with udp= and no wifi= sets wifi to the
     * same value (the pre-wifi= behaviour); otherwise a stored pre-wifi=
     * configuration (udp=1, wifi=0) keeps its implied station. */
    if ((cmd->fields & NODE_F_WIFI) != 0u) {
        np->wifi = cmd->val.wifi;
    } else if ((cmd->fields & NODE_F_UDP) != 0u) {
        np->wifi = cmd->val.udp;
    } else if (np->udp != 0u) {
        np->wifi = 1u;
    }
    if (np->udp != 0u && np->wifi == 0u) {
        node_fmt_str(fp, "udp=on requires wifi=on (the UDP link rides on the station): br set udp=off wifi=off");
        return false;
    }
    if (np->led == np->btn) {
        node_fmt_str(fp, "led and btn are the same pin");
        return false;
    }
    if (np->uart != 0u && uart_pins_conflict(np) != NULL) {
        node_fmt_str(fp, uart_pins_conflict(np));
        return false;
    }
    if (np->nrf != 0u && nrf_conflict(np) != NULL) {
        node_fmt_str(fp, nrf_conflict(np));
        return false;
    }
    if (transport_conflict(np) != NULL) {
        node_fmt_str(fp, transport_conflict(np));
        return false;
    }
    for (uint8_t i = 0; i < np->n_nbr; i++) {
        if (np->uid != 0u && np->nbr[i] == np->uid) {
            node_fmt_str(fp, "nbr contains the node's own id");
            return false;
        }
    }
    /* a key set by this line replaces an invalid stored value */
    np->nvs_bad &= ~(cmd->fields & (NODE_F_SSID | NODE_F_PASS | NODE_F_PEERS));
    return true;
}

bool node_cfg_apply(node_cfg_t *cfg, const node_cmd_t *cmd, char *err, size_t err_cap)
{
    node_fmt_t f;
    node_fmt_init(&f, err, err_cap);
    if (cfg == NULL || cmd == NULL || cmd->kind != NODE_CMD_SET) {
        node_fmt_str(&f, "not a br set command");
        return false;
    }
    node_cfg_t n = *cfg;
    const bool ok = cfg_merge(&n, cmd, &f);
    if (ok) {
        *cfg = n;
    }
    node_wipe(&n, sizeof n); /* the working copy holds the passphrase (N71) */
    return ok;
}
