// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * node_console.h - demo node configuration and the serial console command
 * parser (phase 1c). Portable C11: no ESP-IDF, FreeRTOS or libc formatted I/O, so
 * the same file is unit-tested on the host (firmware/test/host/test_console.c
 * includes node_console.c directly; test_console_uart.c covers the UART link
 * keys, test_console_links.c the WiFi UDP / nRF24 keys and the transport
 * policies, test_console_gateway.c the wifi= / ntp= keys, the single-chip
 * nRF24 gateway line, the AP / nRF24 clearance and the ISO-8601 formatter).
 *
 * Command reference (one command per line, CR and/or LF terminated):
 *
 *   br set <key>=<value> [<key>=<value> ...]   any subset of keys, merged
 *       role=sender|node|probe       (relay is accepted as an alias of node)
 *       id=0x0101                    unit ID 0x0010..0xFEFF (uid= also accepted)
 *       grp=0xFF10                   group ID 0xFF00..0xFFFE
 *       nbr=0x0102,0x0103            bench allowlist, 1..8 unit IDs; nbr=none clears it
 *       led=2                        probe LED GPIO (output-capable pin)
 *       btn=0                        sender button GPIO (input with internal pull-up)
 *       chan=1                       Wi-Fi channel 1..13 (ESP-NOW)
 *       espnow=on|off                ESP-NOW transport (default on). Off on a LAN-side
 *                                    UDP board (spec 12.4); some other transport must be on
 *       uart=on|off                  UART link (second transport, RAW, uart_link.h)
 *       utx=17                       UART link TX GPIO (output-capable, not a strapping pin)
 *       urx=16                       UART link RX GPIO (input with internal pull-up, not a
 *                                    strapping pin); default 16 on ESP32, 18 on ESP32-S3
 *       ubaud=921600                 UART link baud: 9600 19200 38400 57600 115200 230400
 *                                    460800 921600 1000000 1500000 2000000
 *       wifi=on|off                  WiFi station (STA, WIFI_PS_NONE) to an AP: ssid= / pass=,
 *                                    SNTP time from ntp=. Requires espnow=off (association
 *                                    moves the 2.4 GHz channel ESP-NOW is pinned to, 12.4);
 *                                    fine with nrf=on (single-chip nRF24 gateway,
 *                                    firmware/GATEWAY-NRF24.txt). Not a transport by itself
 *       ntp=pool.ntp.org             SNTP server (host name or IPv4, 1..63 characters of
 *                                    A-Z a-z 0-9 . -), default pool.ntp.org; used with wifi=on
 *       udp=on|off                   WiFi UDP link (PACKET, udp_link.h, spec C.4). Requires
 *                                    wifi=on. A line with udp= and no wifi= also sets wifi to
 *                                    the same value (the pre-wifi= behaviour); give wifi=
 *                                    explicitly to decouple (br set udp=off wifi=on)
 *       port=40888                   local UDP port 1..65535 (default 40888, C.4)
 *       mcast=on|off                 floods to 239.255.40.88:<port> (default on); off: floods
 *                                    go to the peers= list, which is then required
 *       peers=ip[:port],...          1..8 unicast peers "a.b.c.d" (port 40888) or
 *                                    "a.b.c.d:port"; peers=none clears the list
 *       ssid=<text>                  AP to associate with (wifi=on), 1..32 characters, no spaces
 *       pass=<text>                  WPA2-PSK passphrase, 8..63 characters, no spaces;
 *                                    pass= (empty) = open AP. Never echoed: br show
 *                                    prints pass=set or pass=unset, and no error text
 *                                    of a line that mentions "pass" quotes any token
 *       nrf=on|off                   nRF24L01+ link (PACKET, nrf24_link.h, spec C.5)
 *       nch=76                       RF channel 76..83; 82 and 83 only with nrate=250k|1m
 *       nrate=250k|1m|2m             air data rate (default 2m)
 *       npa=min|low|high|max         PA level -18 / -12 / -6 / 0 dBm (default max)
 *       nsck=18 nmiso=19 nmosi=23    SPI pins (ESP32 VSPI defaults; S3: 12 / 13 / 11)
 *       ncsn=5 nce=4                 chip select and CE (S3: 10 / 9)
 *       nirq=-1                      IRQ GPIO, -1 (or none) = polling (default); C.6 wired
 *                                    pins: ESP32 35, S3 14
 *   br show        print the stored configuration
 *   br erase       erase the configuration keys (counters are kept)
 *   br reboot      restart the chip
 *   br stats       print one BRSTAT line now
 *
 * Numbers are decimal or 0x-prefixed hex. Every value is range-checked; a
 * line with any bad token changes nothing. Error texts quote a bad token
 * only where it is a key or value of a known key on a line without "pass";
 * an unknown command or verb, a token without '=' and an extra token after
 * show|erase|reboot|stats are never quoted, only their length is given (a
 * passphrase typed without pass= must not reach the log, SPEC-NOTES N72). Values cannot contain spaces or
 * tabs (tokens split on them): an ssid or passphrase with a space cannot be
 * entered through this console.
 *
 * UART link pins: utx and urx must differ from each other and from led and
 * btn whenever uart=on (checked by node_cfg_apply() and node_cfg_ready());
 * strapping pins are refused for both because the PEER drives our RX line
 * (idle high) through our reset, and a TX pin sits at an unknown level
 * until the driver takes it: ESP32 GPIO0/2/5/12/15 (GPIO12 high at reset
 * selects 1.8 V flash), ESP32-S3 GPIO0/3/45/46. Defaults follow spec C.6
 * (IO_MUX pins): ESP32 TX 17 / RX 16 (UART2), ESP32-S3 TX 17 / RX 18
 * (UART1). On ESP32-WROVER modules GPIO16/17 are the PSRAM: pick others.
 *
 * nRF24 pins (node_nrf_pin_ok(), the console side of port_nrf24.cpp's pin
 * policy): every pin must exist and not be flash / console / PSRAM / USB;
 * nsck, nmosi, ncsn and nce are outputs (input-only pins refused); nmiso and
 * nirq are driven by the module (input-only pins such as ESP32 GPIO35
 * accepted). Strapping pins are refused for all six, except ncsn=5 on the
 * ESP32 (C.6 default: CSN idles high, which satisfies the GPIO5 strap). With
 * nrf=on the six pins must be distinct from each other (nirq=-1 excepted),
 * from led and btn, and from utx / urx when uart=on.
 *
 * Transport policy (spec 12.4, node_cfg_apply() and node_cfg_ready()):
 * the WiFi station (wifi=on, and udp=on which rides on it) is refused with
 * espnow=on (a station follows the AP's channel, the ESP-NOW mesh needs a
 * fixed one; the 12.4 gateway is two chips); udp=on needs wifi=on (an
 * explicit `udp=on wifi=off` is refused); at least one of espnow / uart /
 * udp / nrf must be on (wifi alone carries no Braid frames); wifi=on
 * needs ssid=; udp=on with mcast=off needs a peers= list. nrf=on + wifi=on +
 * espnow=off is the single-chip nRF24 gateway and is allowed (the nRF24 is
 * a separate transceiver; firmware/GATEWAY-NRF24.txt).
 *
 * Backward compatibility: a stored configuration with udp=1 and wifi=0
 * (NVS written before wifi= existed) is read as wifi=on everywhere
 * (node_cfg_wifi_on(), node_cfg_ready()); node_cfg_legacy_wifi() sets the
 * field itself when the NVS "wifi" key is absent. `br show` prints the
 * udp group as before when udp=on (wifi is implied there) and a
 * " wifi=on ssid=.. pass=set|unset" group when only the station is on;
 * " ntp=<host>" follows only when it is not the default.
 *
 * Unit IDs: id= takes 0x0010..0xFEFF only. Manager IDs 0x0001..0x000F
 * (SPEC-NOTES N1; 0x0001 = gateway / manager, spec 2) are refused: the
 * protocol core runs a unit (br_node_init, HELLO src_id checks) and has no
 * manager role yet (MGMT not served), so the demo gateway is a probe with a
 * unit ID (GATEWAY-NRF24.txt).
 */
#ifndef NODE_CONSOLE_H
#define NODE_CONSOLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODE_NBR_MAX        8u    /**< = BR_BENCH_ALLOWLIST_MAX */
#define NODE_PEERS_MAX      8u    /**< = UDP_LINK_MAX_PEERS (checked in node_app.cpp) */
#define NODE_SSID_MAX      32u    /**< bytes, without the NUL */
#define NODE_PASS_MAX      63u    /**< bytes, without the NUL (WPA2-PSK passphrase) */
#define NODE_PASS_MIN       8u    /**< WPA2-PSK minimum; 0 (empty) = open AP */
#define NODE_LINE_MAX     400u    /**< longest accepted console line (without CR/LF); udp with 8 peers, ssid and pass needs about 330 */
#define NODE_ERR_MAX      192u
#define NODE_SHOW_MAX     640u    /**< node_cfg_format() output incl. NUL (every link on: about 420) */

#define NODE_DEFAULT_GRP  0xFF10u
#define NODE_DEFAULT_LED  2u      /**< onboard LED on most ESP32-WROOM devkits */
#define NODE_DEFAULT_BTN  0u      /**< BOOT button */
#define NODE_DEFAULT_CHAN 1u
#define NODE_DEFAULT_UTX  17u     /**< spec C.6, both chips */
#define NODE_DEFAULT_URX  16u     /**< spec C.6 ESP32; ESP32-S3 uses 18 (node_uart_default_pins) */
#define NODE_DEFAULT_UBAUD 921600u /**< spec 12.4 gateway figure, C.2 */
#define NODE_DEFAULT_PORT 40888u  /**< spec C.4 (= UDP_LINK_PORT) */
#define NODE_PIN_NONE     0xFFu   /**< nirq: no IRQ wire, poll */
#define NODE_NCH_MIN       76u    /**< spec C.5 */
#define NODE_NCH_MAX       83u
#define NODE_NCH_MAX_2M    81u    /**< 82..83 spill past 2483.5 MHz at 2 Mbps */
#define NODE_DEFAULT_NCH   76u
#define NODE_NTP_MAX       63u    /**< ntp= host name, bytes without the NUL */
#define NODE_DEFAULT_NTP  "pool.ntp.org"
#define NODE_COEX_MIN_MHZ  20     /**< AP band edge to nRF channel clearance below which BRNRF warns */

/** nrate values (= hal_nrf24_rate_t, checked in node_app.cpp). */
typedef enum { NODE_NRATE_250K = 0, NODE_NRATE_1M = 1, NODE_NRATE_2M = 2 } node_nrate_t;
/** npa values (= hal_nrf24_pa_t, checked in node_app.cpp). */
typedef enum { NODE_NPA_MIN = 0, NODE_NPA_LOW = 1, NODE_NPA_HIGH = 2, NODE_NPA_MAX = 3 } node_npa_t;

typedef enum {
    NODE_ROLE_UNSET  = 0,
    NODE_ROLE_SENDER = 1,
    NODE_ROLE_NODE   = 2,         /**< relay: no application */
    NODE_ROLE_PROBE  = 3
} node_role_t;

/** One UDP unicast peer (console peers= entry). */
typedef struct {
    uint32_t ip;                  /**< a.b.c.d = (a << 24) | (b << 16) | (c << 8) | d */
    uint16_t port;
} node_peer_t;

/** Stored demo configuration (NVS namespace "br"). */
typedef struct {
    uint8_t  role;                /**< node_role_t */
    uint16_t uid;                 /**< 0 = unset */
    uint16_t grp;
    uint8_t  n_nbr;               /**< 0 = allowlist disabled (admit every neighbour) */
    uint16_t nbr[NODE_NBR_MAX];
    uint8_t  led;
    uint8_t  btn;
    uint8_t  chan;
    uint8_t  uart;                /**< 1 = UART link transport enabled */
    uint8_t  utx;                 /**< UART link TX GPIO */
    uint8_t  urx;                 /**< UART link RX GPIO */
    uint32_t ubaud;               /**< UART link baud rate */
    uint8_t  espnow;              /**< 1 = ESP-NOW transport enabled (default) */
    uint8_t  udp;                 /**< 1 = WiFi UDP link enabled */
    uint16_t port;                /**< local UDP port */
    uint8_t  mcast;               /**< 1 = floods by multicast (default), 0 = by the peer list */
    uint8_t  n_peers;
    node_peer_t peers[NODE_PEERS_MAX];
    char     ssid[NODE_SSID_MAX + 1u];  /**< NUL-terminated; "" = unset */
    char     pass[NODE_PASS_MAX + 1u];  /**< NUL-terminated; "" = open AP */
    uint8_t  nrf;                 /**< 1 = nRF24 link enabled */
    uint8_t  nch;                 /**< RF channel */
    uint8_t  nrate;               /**< node_nrate_t */
    uint8_t  npa;                 /**< node_npa_t */
    uint8_t  nsck;
    uint8_t  nmiso;
    uint8_t  nmosi;
    uint8_t  ncsn;
    uint8_t  nce;
    uint8_t  nirq;                /**< NODE_PIN_NONE = polling */
    uint8_t  wifi;                /**< 1 = WiFi station on (udp=1 implies it, see node_cfg_wifi_on) */
    char     ntp[NODE_NTP_MAX + 1u];    /**< SNTP server, NUL-terminated; default NODE_DEFAULT_NTP */
    uint32_t nvs_bad;             /**< NODE_F_SSID / NODE_F_PASS / NODE_F_PEERS: a key REQUIRED by this
                                       configuration whose stored NVS value was invalid at load
                                       (node_cfg_load_blobs). Never stored. node_cfg_ready() refuses
                                       naming the key; node_cfg_apply() clears the bit when the key is
                                       set; the app does not overwrite a flagged key in NVS. */
} node_cfg_t;

/** Field bits of node_cmd_t.fields (which keys a `br set` line carried). */
#define NODE_F_ROLE   0x01u
#define NODE_F_UID    0x02u
#define NODE_F_GRP    0x04u
#define NODE_F_NBR    0x08u
#define NODE_F_LED    0x10u
#define NODE_F_BTN    0x20u
#define NODE_F_CHAN   0x40u
#define NODE_F_UART   0x80u
#define NODE_F_UTX    0x100u
#define NODE_F_URX    0x200u
#define NODE_F_UBAUD  0x400u
#define NODE_F_ESPNOW 0x800u
#define NODE_F_UDP    0x1000u
#define NODE_F_PORT   0x2000u
#define NODE_F_MCAST  0x4000u
#define NODE_F_PEERS  0x8000u
#define NODE_F_SSID   0x10000u
#define NODE_F_PASS   0x20000u
#define NODE_F_NRF    0x40000u
#define NODE_F_NCH    0x80000u
#define NODE_F_NRATE  0x100000u
#define NODE_F_NPA    0x200000u
#define NODE_F_NSCK   0x400000u
#define NODE_F_NMISO  0x800000u
#define NODE_F_NMOSI  0x1000000u
#define NODE_F_NCSN   0x2000000u
#define NODE_F_NCE    0x4000000u
#define NODE_F_NIRQ   0x8000000u
#define NODE_F_WIFI   0x10000000u
#define NODE_F_NTP    0x20000000u

typedef enum {
    NODE_CMD_NONE = 0,            /**< empty line: ignore */
    NODE_CMD_SET,
    NODE_CMD_SHOW,
    NODE_CMD_ERASE,
    NODE_CMD_REBOOT,
    NODE_CMD_STATS,
    NODE_CMD_ERROR                /**< err holds the reason */
} node_cmd_kind_t;

typedef struct {
    node_cmd_kind_t kind;
    uint32_t        fields;       /**< NODE_F_* present in a SET */
    node_cfg_t      val;          /**< values of the present fields (others zero) */
    uint8_t         no_echo;      /**< the line mentions "pass": error texts never quote any token of it */
    char            err[NODE_ERR_MAX];
} node_cmd_t;

/* ---- NVS blob keys: decode and validate on load (SPEC-NOTES N70) ---------- */

/** What the key-value store returned for one blob key. */
typedef enum {
    NODE_KV_ABSENT = 0,           /**< key not found: the default stays */
    NODE_KV_PRESENT,              /**< data / len valid */
    NODE_KV_UNREADABLE            /**< present but not readable as a blob of the expected size (too long) */
} node_kv_state_t;

typedef struct {
    node_kv_state_t state;
    const uint8_t  *data;
    size_t          len;
} node_kv_blob_t;

/** The five blob keys of NVS namespace "br" (node_app.cpp cfg_load). */
typedef struct {
    node_kv_blob_t nbr;           /**< "nbr": 2 bytes per unit ID, little endian */
    node_kv_blob_t peers;         /**< "udp_peers": 6 bytes per peer, IPv4 then port, big endian */
    node_kv_blob_t ssid;          /**< "ssid": raw bytes, no NUL */
    node_kv_blob_t pass;          /**< "pass": raw bytes, no NUL */
    node_kv_blob_t ntp;           /**< "ntp": raw bytes, no NUL */
} node_cfg_blobs_t;

/**
 * Decode the stored blob keys into cfg and validate each one on its own, so
 * that one bad blob never blocks the boot. Call AFTER the u32 keys and
 * node_cfg_legacy_wifi() (whether ssid / pass / peers are required depends
 * on wifi, udp and mcast). Rules, per key, for an invalid value (wrong
 * length, bad bytes, a value the console would refuse, NODE_KV_UNREADABLE):
 *   - optional key: the default is used and its NODE_F_* bit is returned
 *     (the app logs "BRCFG <key> invalid in NVS, using default"):
 *       ntp   -> pool.ntp.org       (valid: node_cmd_parse's ntp= rule)
 *       nbr   -> none (allowlist off; valid: 1..8 distinct unit IDs, not uid)
 *       peers -> none, unless required (valid: 1..8 unicast a.b.c.d:port)
 *       ssid  -> "", unless required (valid: 1..32 bytes, no control bytes;
 *                bytes 0x80..0xFF are kept raw for UTF-8 SSIDs)
 *       pass  -> "", unless required (valid: 8..63 of 0x20..0x7E)
 *   - required key: ssid and pass when the station is on
 *     (node_cfg_wifi_on), peers when udp=on mcast=off. The field is left
 *     empty and its bit is set in cfg->nvs_bad, so node_cfg_ready() refuses
 *     with a reason naming the NVS key. A bad pass is never taken as an open
 *     AP (that would let any open AP with the same ssid capture the board).
 * Every other field is left as it was.
 * @return NODE_F_* bits of the optional keys that fell back to the default.
 */
uint32_t node_cfg_load_blobs(node_cfg_t *cfg, const node_cfg_blobs_t *b);

/** NVS key name of a NODE_F_NBR / PEERS / SSID / PASS / NTP bit ("udp_peers" for PEERS), else "?". */
const char *node_cfg_nvs_key(uint32_t field_bit);

/**
 * Zero n bytes through a volatile pointer (not removable by the optimiser).
 * For every copy of the passphrase (SPEC-NOTES N71). NULL or 0 is a no-op.
 */
void node_wipe(void *p, size_t n);

/** Pin rules differ per chip. */
typedef enum {
    NODE_CHIP_ESP32 = 0,
    NODE_CHIP_ESP32S3
} node_chip_t;

/** Which nRF24 signal a pin carries (node_nrf_pin_ok()). */
typedef enum {
    NODE_NRF_PIN_SCK = 0,
    NODE_NRF_PIN_MISO,
    NODE_NRF_PIN_MOSI,
    NODE_NRF_PIN_CSN,
    NODE_NRF_PIN_CE,
    NODE_NRF_PIN_IRQ
} node_nrf_pin_t;

/**
 * role unset, uid unset, grp 0xFF10, no allowlist, led 2, btn 0, chan 1,
 * espnow on, uart off, utx 17, urx 16, ubaud 921600, udp off, port 40888,
 * mcast on, no peers, ssid / pass empty, nrf off, nch 76, nrate 2m, npa
 * max, ESP32 nRF24 pins (18 / 19 / 23 / 5 / 4), nirq none, wifi off, ntp
 * pool.ntp.org (ESP32 pins; call node_uart_default_pins() and
 * node_nrf_default_pins() for the chip's own).
 */
void node_cfg_defaults(node_cfg_t *cfg);

/**
 * true when the WiFi station runs: wifi=on, or udp=on (which needs the
 * station; a pre-wifi= configuration has udp=1 and wifi=0). NULL -> false.
 */
bool node_cfg_wifi_on(const node_cfg_t *cfg);

/**
 * Backward compatibility for configurations stored before the wifi= key:
 * when the NVS "wifi" key was absent (wifi_key_present false) and udp is
 * on, set wifi = 1. Otherwise unchanged.
 */
void node_cfg_legacy_wifi(node_cfg_t *cfg, bool wifi_key_present);

/**
 * Clearance between the occupied band of Wi-Fi channel wifi_ch (1..13:
 * centre 2407 + 5 x ch MHz; 14: 2484 MHz; 22 MHz wide, edges at centre
 * +/- 11) and the nRF24 channel nrf_ch (0..125: 2400 + ch MHz). Positive:
 * MHz from the nearest band edge to the nRF frequency; zero: on the edge;
 * negative: inside the band, by that many MHz from the nearest edge.
 * @return false (out untouched) when a channel is out of range.
 */
bool node_wifi_nrf_clearance_mhz(uint8_t wifi_ch, uint8_t nrf_ch, int32_t *mhz_out);


/** Spec C.6 UART link pins: ESP32 TX 17 / RX 16, ESP32-S3 TX 17 / RX 18. */
void node_uart_default_pins(node_chip_t chip, uint8_t *tx, uint8_t *rx);

/**
 * Spec C.6 nRF24 pins into cfg->nsck .. nce (ESP32: VSPI 18 / 19 / 23, CSN
 * 5, CE 4; ESP32-S3: SPI2 12 / 13 / 11, CSN 10, CE 9) and nirq = NODE_PIN_NONE.
 */
void node_nrf_default_pins(node_chip_t chip, node_cfg_t *cfg);

/**
 * Pin check for the UART link: node_pin_ok() (TX output-capable, RX input
 * with internal pull-up) and not a strapping pin of the chip.
 * @param why  Receives a static reason when false (may be NULL).
 */
bool node_uart_pin_ok(node_chip_t chip, uint8_t pin, bool tx, const char **why);

/**
 * Pin check for one nRF24 signal (see the file header). NODE_PIN_NONE is
 * accepted for NODE_NRF_PIN_IRQ only.
 * @param why  Receives a static reason when false (may be NULL).
 */
bool node_nrf_pin_ok(node_chip_t chip, uint8_t pin, node_nrf_pin_t role, const char **why);

/** true for the baud rates listed in the command reference. */
bool node_baud_ok(uint32_t baud);

/**
 * Parse "a.b.c.d" or "a.b.c.d:port" (NUL-terminated). Port defaults to
 * NODE_DEFAULT_PORT; 0 is refused. The address must be a unicast host
 * address: 0.0.0.0, 127/8, 224/4 (multicast) and 255.255.255.255 are
 * refused. @return false on a malformed string (outputs untouched).
 */
bool node_peer_parse(const char *s, uint32_t *ip_out, uint16_t *port_out);

/** "sender", "node", "probe" or "unset". */
const char *node_role_name(uint8_t role);

/** "250k", "1m", "2m" or "?". */
const char *node_nrate_name(uint8_t rate);

/** "min", "low", "high", "max" or "?". */
const char *node_npa_name(uint8_t pa);

/**
 * Pin check for the demo roles.
 * @param output  true for the LED (must be output-capable), false for the
 *                button (input with the internal pull-up).
 * @param why     Receives a static reason when false (may be NULL).
 */
bool node_pin_ok(node_chip_t chip, uint8_t pin, bool output, const char **why);

/**
 * Parse one console line (no CR/LF). Never modifies any configuration.
 * @return true unless out->kind is NODE_CMD_ERROR.
 */
bool node_cmd_parse(const char *line, node_chip_t chip, node_cmd_t *out);

/**
 * Merge a parsed SET into cfg after cross-field checks (led != btn, own uid
 * not in nbr; with uart on: utx != urx and neither equals led or btn; the
 * transport policy and the nRF24 pin collisions of the file header).
 * cfg is unchanged on failure.
 * @return true on success; false with a reason in err.
 */
bool node_cfg_apply(node_cfg_t *cfg, const node_cmd_t *cmd, char *err, size_t err_cap);

/**
 * Full validation of a stored configuration (also run on what NVS returns).
 * @param why  Receives a static reason when false (may be NULL).
 * @return true if every field is in range and role and uid are set.
 */
bool node_cfg_ready(const node_cfg_t *cfg, node_chip_t chip, const char **why);

/**
 * "role=sender id=0x0101 grp=0xFF10 nbr=0x0102,0x0103 led=2 btn=0 chan=1"
 * (nbr=none when empty, id=unset when 0), followed by
 * " uart=on utx=17 urx=16 ubaud=921600" only when the UART link is on,
 * " espnow=off" only when ESP-NOW is off,
 * " udp=on port=40888 mcast=on peers=<list|none> ssid=<ssid> pass=set|unset"
 * only when the UDP link is on (the passphrase itself is never printed),
 * " wifi=on ssid=<ssid> pass=set|unset" when the station is on without udp,
 * " ntp=<host>" after either group when ntp is not the default, and
 * " nrf=on nch=76 nrate=2m npa=max nsck=18 nmiso=19 nmosi=23 ncsn=5 nce=4 nirq=-1"
 * only when the nRF24 link is on. The phase 1c line is unchanged otherwise.
 * Always NUL-terminated.
 * @return characters written (without NUL).
 */
size_t node_cfg_format(const node_cfg_t *cfg, char *buf, size_t cap);

/* ---- tiny formatter (app code uses no libc formatted output) ------------- */

typedef struct {
    char  *buf;
    size_t cap;                   /**< including the NUL */
    size_t len;
} node_fmt_t;

void node_fmt_init(node_fmt_t *f, char *buf, size_t cap);
void node_fmt_str(node_fmt_t *f, const char *s);
void node_fmt_u32(node_fmt_t *f, uint32_t v);
void node_fmt_i32(node_fmt_t *f, int32_t v);
void node_fmt_hex16(node_fmt_t *f, uint16_t v);   /**< "0x0101" */
void node_fmt_hex8(node_fmt_t *f, uint8_t v);     /**< "a5" (no prefix) */
void node_fmt_peer(node_fmt_t *f, uint32_t ip, uint16_t port); /**< "192.168.1.20:40888" */
/**
 * An SSID for a log line: bytes 0x20..0x7E as they are, every other byte
 * (control, 0x7F, UTF-8 0x80..0xFF) as '?'. The stored ssid keeps the raw
 * bytes for the driver; only the printed form is sanitised.
 */
void node_fmt_ssid(node_fmt_t *f, const char *ssid);

/**
 * ISO-8601 UTC "2026-10-08T12:34:56Z" for unix_s seconds since 1970-01-01
 * (proleptic Gregorian, libc-free; negative values print the epoch).
 */
void node_fmt_iso8601(node_fmt_t *f, int64_t unix_s);

/**
 * The BRNRF coexistence line for an AP on ap_ch and the nRF24 on nch at
 * nrate (node_nrate_t). Clearance below NODE_COEX_MIN_MHZ:
 *   "BRNRF coexist: AP ch 11, nRF ch 76, 3 MHz apart - move the router to ch 1-6"
 * followed by " or set nch=83" (plus " nrate=1m" when nrate is 2m) only when
 * nch 83 would clear NODE_COEX_MIN_MHZ. Enough clearance:
 *   "BRNRF coexist ok: AP ch 1, nRF ch 76, 53 MHz apart"
 * Never retunes anything (every mesh node would have to follow).
 * @return true when the warning was written; false for "ok" or a channel
 *         out of range ("BRNRF coexist: AP channel unknown").
 */
bool node_fmt_coexist(node_fmt_t *f, uint8_t ap_ch, uint8_t nch, uint8_t nrate);

#ifdef __cplusplus
}
#endif

#endif /* NODE_CONSOLE_H */
