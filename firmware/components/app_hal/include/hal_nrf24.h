// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_nrf24.h - vendor-neutral nRF24L01+ radio (Braid PACKET carrier,
// spec 1.2 nRF24 row, Appendix C.5 / C.6). Implemented in
// components/port_esp_idf/port_nrf24.cpp over hal_spi.h + hal_gpio.h; the
// register sequence itself is the portable components/app_nrf24_link
// nrf24_regs.c (host-tested), which the port drives with an SPI transfer,
// the CE line and a microsecond delay.
//
// Model (one radio per board):
//   - 5-byte addresses in the C.5 listed order (index 0 = first listed byte);
//     the driver handles the chip's LSByte-first register order.
//   - Enhanced ShockBurst: 2-byte CRC, dynamic payload length 1..32, auto-ACK
//     with ARC retries on pipe 0 (own address), pipe 1 = shared broadcast
//     address; a payload written with no_ack = true carries the NO_ACK flag
//     and is never acknowledged (floods).
//   - Half duplex: hal_nrf24_start_listening() = PRX (CE high);
//     hal_nrf24_stop_listening() = Standby-I; hal_nrf24_start_tx() pulses CE
//     to transmit the TX FIFO head. One payload in flight at a time: wait
//     for TX_DS or MAX_RT (hal_nrf24_status()) before the next.
//   - MAX_RT leaves the payload in the TX FIFO: hal_nrf24_tx_abort() flushes
//     and clears the flags (11.6: the frame is reported undelivered).
//   - IRQ pin optional: when configured, the callback runs in ISR context
//     on the falling edge and must only give a semaphore / post an event
//     (xQueueSendFromISR); the owner task then drains STATUS. Without it,
//     poll at <= 2 ms while listening (the RX FIFO is 3 payloads deep; the
//     peer's ESB retries give about 7.5 ms of grace at ARC 15 x ARD 500 us).
//   - Presence check: hal_nrf24_init() reads CONFIG / SETUP_AW / RF_CH /
//     FEATURE back and returns HAL_ERR_HW_FAULT when nothing answers (no
//     module, MISO floating, 5 V on VCC).
//
// Thread safety: every function may be called from one task at a time
// (Braid: the protocol task). init is called once at boot.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_NRF24_ADDR_LEN      5u
#define HAL_NRF24_MAX_PAYLOAD  32u
#define HAL_NRF24_PIPES         6u
#define HAL_NRF24_CH_MAX      125u
#define HAL_NRF24_SPI_HZ_DEFAULT  8000000u   // <= 10 MHz (datasheet)
#define HAL_NRF24_SPI_HZ_MAX     10000000u
#define HAL_NRF24_PIN_NONE      (-1)

// STATUS bits as the chip defines them (hal_nrf24_status()).
#define HAL_NRF24_ST_RX_DR      0x40u
#define HAL_NRF24_ST_TX_DS      0x20u
#define HAL_NRF24_ST_MAX_RT     0x10u
#define HAL_NRF24_ST_RX_P_NO(st) (((st) >> 1) & 0x07u)   // 7 = RX FIFO empty
#define HAL_NRF24_ST_TX_FULL    0x01u
#define HAL_NRF24_ST_INVALID    0xFFu                    // bus failure (never a legal STATUS)

typedef enum { HAL_NRF24_RATE_250K = 0, HAL_NRF24_RATE_1M = 1, HAL_NRF24_RATE_2M = 2 } hal_nrf24_rate_t;
typedef enum { HAL_NRF24_PA_MIN = 0, HAL_NRF24_PA_LOW = 1, HAL_NRF24_PA_HIGH = 2, HAL_NRF24_PA_MAX = 3 } hal_nrf24_pa_t;

typedef struct {
    int16_t  sck_pin;        // SPI pins (hal_spi bus); see port_nrf24.cpp / NRF24-LINK.txt for the per-chip defaults
    int16_t  miso_pin;
    int16_t  mosi_pin;
    int16_t  csn_pin;        // SPI chip select, driven by the controller
    int16_t  ce_pin;         // output
    int16_t  irq_pin;        // input, falling edge, no internal pull (module drives it); HAL_NRF24_PIN_NONE = poll
    uint8_t  spi_bus;        // HAL_SPI_BUS_DEFAULT unless the board says otherwise
    uint32_t spi_hz;         // 0 = HAL_NRF24_SPI_HZ_DEFAULT
    uint8_t  channel;        // 0..125; Braid 76..83 (C.5)
    hal_nrf24_rate_t rate;
    hal_nrf24_pa_t   pa;
    uint8_t  ard;            // auto retransmit delay code 0..15 = (ard + 1) x 250 us; C.5: 1
    uint8_t  arc;            // auto retransmit count 0..15; C.5: 15
    uint8_t  addr_width;     // 3..5; Braid 5
} hal_nrf24_cfg_t;

// ISR context: give a semaphore or xQueueSendFromISR, nothing else.
typedef void (*hal_nrf24_irq_cb)(void *user);

typedef struct {
    uint32_t spi_err;        // SPI transfers that failed
    uint32_t rx_bad_width;   // payload width > 32 reported by the chip (RX FIFO flushed)
    uint32_t tx_aborts;      // hal_nrf24_tx_abort() calls
    uint32_t irqs;           // IRQ edges seen (0 when polling)
    uint32_t activate_used;  // init needed ACTIVATE (non-plus chip or clone)
} hal_nrf24_stats_t;

// Fill cfg with the C.6 pin plan of the chip this firmware runs on and the
// C.5 radio defaults (channel 76, 2 Mbps, PA max, ARD 500 us, ARC 15,
// width 5). irq_pin defaults to HAL_NRF24_PIN_NONE (polling): an IRQ input
// configured without the wire floats and storms. C.6 IRQ pins to set when
// wired: ESP32 GPIO35, S3 GPIO14.
//   ESP32-WROOM-32E: VSPI SCK 18, MISO 19, MOSI 23, CSN 5, CE 4
//       (// STRAPPING: GPIO5 must be high at boot; CSN idles high, fine)
//   ESP32-S3-WROOM-1: SPI2 SCK 12, MISO 13, MOSI 11, CSN 10, CE 9
void hal_nrf24_default_cfg(hal_nrf24_cfg_t *cfg);

// Bus + pins + register init to Standby-I (powered, not listening).
// HAL_ERR_INVALID_ARG bad pin / channel / width; HAL_ERR_BUSY already
// initialised; HAL_ERR_HW_FAULT no chip answered; other codes from the SPI
// or GPIO drivers.
hal_result_t hal_nrf24_init(const hal_nrf24_cfg_t *cfg);

// Receive address of a pipe (0 and 1: full 5 bytes; 2..5: last byte only)
// and its enable bit. Pipe 0's address is restored after every transmit.
hal_result_t hal_nrf24_set_rx_address(uint8_t pipe, const uint8_t addr[HAL_NRF24_ADDR_LEN], bool enable);

// Destination for the next transmit (also pipe 0, where its ACK arrives).
// Call while not listening.
hal_result_t hal_nrf24_set_tx_address(const uint8_t addr[HAL_NRF24_ADDR_LEN]);

// Load one payload (1..32 bytes) into the TX FIFO. no_ack = broadcast
// (W_TX_PAYLOAD_NO_ACK). HAL_ERR_BUSY if the TX FIFO is full.
hal_result_t hal_nrf24_write_payload(const uint8_t *buf, uint8_t len, bool no_ack);

// CE pulse: transmit the TX FIFO head (Standby-I -> TX -> Standby-I).
// HAL_ERR_BUSY while listening (stop first).
hal_result_t hal_nrf24_start_tx(void);

// Pop one payload from the RX FIFO: pipe, bytes (buf: 32), length.
// HAL_ERR_NOT_FOUND if empty; HAL_ERR_HW_FAULT if the chip reported a
// width > 32 (RX FIFO flushed).
hal_result_t hal_nrf24_read_payload(uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out);

// STATUS register (NOP command). HAL_NRF24_ST_INVALID on a bus failure.
uint8_t hal_nrf24_status(void);

// Clear RX_DR / TX_DS / MAX_RT (mask of HAL_NRF24_ST_*).
hal_result_t hal_nrf24_clear_irq(uint8_t mask);

// MAX_RT recovery: FLUSH_TX and clear MAX_RT | TX_DS.
hal_result_t hal_nrf24_tx_abort(void);

hal_result_t hal_nrf24_flush_rx(void);
hal_result_t hal_nrf24_start_listening(void);   // PRX, CE high
hal_result_t hal_nrf24_stop_listening(void);    // Standby-I, CE low
hal_result_t hal_nrf24_power(bool up);          // PWR_UP (waits the power-up time) / power down
hal_result_t hal_nrf24_set_channel(uint8_t channel);

// IRQ callback (irq_pin configured): HAL_ERR_UNSUPPORTED when polling.
hal_result_t hal_nrf24_set_irq_cb(hal_nrf24_irq_cb cb, void *user);

// Raw register read for the console dump (reg 0x00..0x1D).
hal_result_t hal_nrf24_read_reg(uint8_t reg, uint8_t *val_out);

hal_result_t hal_nrf24_get_stats(hal_nrf24_stats_t *out);

#ifdef __cplusplus
}
#endif
