// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_regs.h - nRF24L01+ register-level driver, portable part.
 *
 * Everything the chip needs over SPI (register map, command set, the init
 * sequence, payload and FIFO handling, PRX / PTX switching) with the three
 * things that differ per board injected as callbacks: a full-duplex SPI
 * transfer with CSN held low for the whole command, the CE line, and a
 * microsecond delay. No ESP-IDF, FreeRTOS, HAL or braid header, so the
 * register sequence is host-tested against a register-model fake
 * (firmware/test/host/test_nrf24_link.c part B). On the device
 * components/port_esp_idf/port_nrf24.cpp owns one nrf24_regs_t and
 * implements hal_nrf24.h by delegating here over hal_spi + hal_gpio.
 *
 * Chip facts used (nRF24L01+ product specification v1.0):
 *   - SPI mode 0, MSBit first, <= 10 MHz; every command returns STATUS in
 *     the first byte; CSN must go high between commands (Tcwh 50 ns).
 *   - Address registers are written LSByte first. The Braid address
 *     arrays (C.5 "50 4C U_hi U_lo A5") are kept in the listed order, index
 *     0 = first listed byte = most significant on the air; this driver
 *     reverses them when writing RX_ADDR_P0 / P1 / TX_ADDR (see
 *     firmware/NRF24-LINK.txt, SPEC-NOTES candidates).
 *   - Dynamic payload length (FEATURE.EN_DPL + DYNPD) requires EN_AA on the
 *     same pipe, so EN_AA stays set on the broadcast pipe too; a flood is
 *     not acknowledged because the transmitter sends it with
 *     W_TX_PAYLOAD_NO_ACK (FEATURE.EN_DYN_ACK), which sets the NO_ACK flag
 *     in the packet control field (C.5).
 *   - After MAX_RT the failed payload stays in the TX FIFO and the IRQ bit
 *     must be written to clear; nrf24_regs_tx_abort() does both.
 *   - Non-plus chips and some clones need ACTIVATE 0x73 before FEATURE /
 *     DYNPD accept writes; init tries once when the readback fails.
 *   - Power on: PWR_UP -> Standby-I takes Tpd2stby (<= 4.5 ms with the
 *     internal oscillator path, 1.5 ms typical); CE pulse >= 10 us starts a
 *     transmit; Standby-I -> RX/TX settling 130 us is handled by the chip.
 *
 * Threading: one owner task; not reentrant (the port serialises).
 */
#ifndef NRF24_REGS_H
#define NRF24_REGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- register map ----------------------------------------------------- */
#define NRF24_REG_CONFIG       0x00u
#define NRF24_REG_EN_AA        0x01u
#define NRF24_REG_EN_RXADDR    0x02u
#define NRF24_REG_SETUP_AW     0x03u
#define NRF24_REG_SETUP_RETR   0x04u
#define NRF24_REG_RF_CH        0x05u
#define NRF24_REG_RF_SETUP     0x06u
#define NRF24_REG_STATUS       0x07u
#define NRF24_REG_OBSERVE_TX   0x08u
#define NRF24_REG_RPD          0x09u
#define NRF24_REG_RX_ADDR_P0   0x0Au
#define NRF24_REG_RX_ADDR_P1   0x0Bu
#define NRF24_REG_RX_ADDR_P2   0x0Cu
#define NRF24_REG_RX_ADDR_P3   0x0Du
#define NRF24_REG_RX_ADDR_P4   0x0Eu
#define NRF24_REG_RX_ADDR_P5   0x0Fu
#define NRF24_REG_TX_ADDR      0x10u
#define NRF24_REG_RX_PW_P0     0x11u
#define NRF24_REG_RX_PW_P1     0x12u
#define NRF24_REG_RX_PW_P2     0x13u
#define NRF24_REG_RX_PW_P3     0x14u
#define NRF24_REG_RX_PW_P4     0x15u
#define NRF24_REG_RX_PW_P5     0x16u
#define NRF24_REG_FIFO_STATUS  0x17u
#define NRF24_REG_DYNPD        0x1Cu
#define NRF24_REG_FEATURE      0x1Du
#define NRF24_REG_COUNT        0x1Eu   /**< 0x00..0x1D */

/* CONFIG bits */
#define NRF24_CONFIG_MASK_RX_DR  0x40u
#define NRF24_CONFIG_MASK_TX_DS  0x20u
#define NRF24_CONFIG_MASK_MAX_RT 0x10u
#define NRF24_CONFIG_EN_CRC      0x08u
#define NRF24_CONFIG_CRCO        0x04u   /**< 2-byte CRC */
#define NRF24_CONFIG_PWR_UP      0x02u
#define NRF24_CONFIG_PRIM_RX     0x01u

/* STATUS bits (also the first byte of every SPI command) */
#define NRF24_ST_RX_DR           0x40u
#define NRF24_ST_TX_DS           0x20u
#define NRF24_ST_MAX_RT          0x10u
#define NRF24_ST_RX_P_NO_MASK    0x0Eu
#define NRF24_ST_RX_P_NO_SHIFT   1u
#define NRF24_ST_RX_P_NO_EMPTY   7u
#define NRF24_ST_TX_FULL         0x01u
#define NRF24_ST_IRQ_MASK        (NRF24_ST_RX_DR | NRF24_ST_TX_DS | NRF24_ST_MAX_RT)
#define NRF24_ST_INVALID         0xFFu   /**< never a legal STATUS (bit 7 is 0): SPI failure */

/* RF_SETUP bits */
#define NRF24_RF_CONT_WAVE       0x80u
#define NRF24_RF_DR_LOW          0x20u
#define NRF24_RF_PLL_LOCK        0x10u
#define NRF24_RF_DR_HIGH         0x08u
#define NRF24_RF_PWR_MASK        0x06u
#define NRF24_RF_PWR_SHIFT       1u

/* FIFO_STATUS bits */
#define NRF24_FIFO_TX_REUSE      0x40u
#define NRF24_FIFO_TX_FULL       0x20u
#define NRF24_FIFO_TX_EMPTY      0x10u
#define NRF24_FIFO_RX_FULL       0x02u
#define NRF24_FIFO_RX_EMPTY      0x01u

/* FEATURE bits */
#define NRF24_FEATURE_EN_DPL     0x04u
#define NRF24_FEATURE_EN_ACK_PAY 0x02u
#define NRF24_FEATURE_EN_DYN_ACK 0x01u

/* ---- command set ------------------------------------------------------ */
#define NRF24_CMD_R_REGISTER          0x00u   /**< | reg (5 bits) */
#define NRF24_CMD_W_REGISTER          0x20u   /**< | reg */
#define NRF24_CMD_REGISTER_MASK       0x1Fu
#define NRF24_CMD_R_RX_PAYLOAD        0x61u
#define NRF24_CMD_W_TX_PAYLOAD        0xA0u
#define NRF24_CMD_FLUSH_TX            0xE1u
#define NRF24_CMD_FLUSH_RX            0xE2u
#define NRF24_CMD_REUSE_TX_PL         0xE3u
#define NRF24_CMD_R_RX_PL_WID         0x60u
#define NRF24_CMD_W_ACK_PAYLOAD       0xA8u   /**< | pipe */
#define NRF24_CMD_W_TX_PAYLOAD_NO_ACK 0xB0u
#define NRF24_CMD_ACTIVATE            0x50u   /**< + 0x73: non-plus chips / clones */
#define NRF24_CMD_NOP                 0xFFu

#define NRF24_ADDR_LEN      5u
#define NRF24_PAYLOAD_MAX  32u
#define NRF24_PIPES         6u
#define NRF24_CH_MAX      125u
#define NRF24_CE_PULSE_US  15u     /**< >= 10 us (Thce) */
#define NRF24_PWR_UP_US  5000u     /**< >= Tpd2stby 4.5 ms worst case */

typedef enum { NRF24_RATE_250K = 0, NRF24_RATE_1M = 1, NRF24_RATE_2M = 2 } nrf24_rate_t;
typedef enum { NRF24_PA_MIN = 0, NRF24_PA_LOW = 1, NRF24_PA_HIGH = 2, NRF24_PA_MAX = 3 } nrf24_pa_t; /* -18/-12/-6/0 dBm */

typedef enum {
    NRF24_REGS_OK = 0,
    NRF24_REGS_ERR_ARG,
    NRF24_REGS_ERR_SPI,        /**< the SPI transfer callback failed */
    NRF24_REGS_ERR_NO_CHIP,    /**< a readback did not match: no module, wiring, or not a plus chip */
    NRF24_REGS_ERR_FULL,       /**< TX FIFO full */
    NRF24_REGS_ERR_EMPTY,      /**< RX FIFO empty */
    NRF24_REGS_ERR_WIDTH       /**< R_RX_PL_WID > 32: corrupt, RX FIFO flushed (datasheet) */
} nrf24_regs_err_t;

typedef struct {
    uint8_t      channel;     /**< 0..125 (2400 + ch MHz); Braid 76..83 (C.5) */
    nrf24_rate_t rate;        /**< Braid 2 Mbps on 76..81 */
    nrf24_pa_t   pa;
    uint8_t      ard;         /**< auto retransmit delay code 0..15: (ard + 1) x 250 us; C.5 500 us = 1 */
    uint8_t      arc;         /**< auto retransmit count 0..15; C.5 15 */
    uint8_t      addr_width;  /**< 3..5; Braid 5 */
} nrf24_regs_cfg_t;

/**
 * Board glue. spi_transfer: full duplex, len bytes (1..33), CSN low for the
 * whole transfer, rx may receive the same len bytes (rx[0] = STATUS);
 * returns false on a bus error. ce_set drives the CE pin. delay_us blocks
 * the caller for at least us microseconds (task context).
 */
typedef struct {
    void *ctx;
    bool (*spi_transfer)(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len);
    void (*ce_set)(void *ctx, bool high);
    void (*delay_us)(void *ctx, uint32_t us);
} nrf24_regs_io_t;

typedef struct {
    uint32_t spi_err;         /**< transfers refused by the glue */
    uint32_t rx_bad_width;    /**< R_RX_PL_WID > 32 (RX FIFO flushed) */
    uint32_t tx_aborts;       /**< nrf24_regs_tx_abort() calls (MAX_RT or stuck) */
    uint32_t activate_used;   /**< init needed the ACTIVATE command */
} nrf24_regs_stats_t;

typedef struct {
    nrf24_regs_io_t    io;
    nrf24_regs_cfg_t   cfg;
    uint8_t            own_p0[NRF24_ADDR_LEN];   /**< pipe 0 address restored by start_listening */
    bool               have_p0;
    bool               listening;
    bool               powered;
    bool               inited;
    nrf24_regs_stats_t st;
} nrf24_regs_t;

/**
 * Bring the chip to Standby-I with the Braid configuration: CE low,
 * CONFIG EN_CRC | CRCO, FEATURE EN_DPL | EN_DYN_ACK (ACTIVATE once if the
 * readback fails), SETUP_RETR, SETUP_AW, RF_CH, RF_SETUP, EN_AA 0x03,
 * EN_RXADDR 0x03, DYNPD 0x03, RX_PW_Px 32, FLUSH_TX, FLUSH_RX, STATUS
 * cleared, PWR_UP, wait NRF24_PWR_UP_US. CONFIG, SETUP_AW, RF_CH and FEATURE
 * are read back; a mismatch is NRF24_REGS_ERR_NO_CHIP.
 */
nrf24_regs_err_t nrf24_regs_init(nrf24_regs_t *r, const nrf24_regs_io_t *io, const nrf24_regs_cfg_t *cfg);

/**
 * Program a receive address. Pipes 0 and 1 take the full 5 bytes (pipe 0 is
 * remembered as "own" and restored after every transmit); pipes 2..5 take
 * addr[4] (the last listed byte) only, the rest is shared with pipe 1.
 * enable sets or clears the pipe's EN_RXADDR bit.
 */
nrf24_regs_err_t nrf24_regs_set_rx_address(nrf24_regs_t *r, uint8_t pipe, const uint8_t *addr, bool enable);

/** TX_ADDR and RX_ADDR_P0 (for the auto-ACK) = addr. Call while not listening. */
nrf24_regs_err_t nrf24_regs_set_tx_address(nrf24_regs_t *r, const uint8_t *addr);

/** W_TX_PAYLOAD or W_TX_PAYLOAD_NO_ACK. len 1..32. NRF24_REGS_ERR_FULL if the TX FIFO is full. */
nrf24_regs_err_t nrf24_regs_write_payload(nrf24_regs_t *r, const uint8_t *buf, uint8_t len, bool no_ack);

/**
 * Read one payload: STATUS.RX_P_NO gives the pipe, R_RX_PL_WID the length,
 * R_RX_PAYLOAD the bytes (buf: 32 bytes). NRF24_REGS_ERR_EMPTY if none;
 * NRF24_REGS_ERR_WIDTH if the width is > 32 (RX FIFO flushed).
 */
nrf24_regs_err_t nrf24_regs_read_payload(nrf24_regs_t *r, uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out);

/** STATUS by NOP. NRF24_ST_INVALID (0xFF) if the transfer failed. */
uint8_t nrf24_regs_status(nrf24_regs_t *r);

/** Write 1 to the given RX_DR / TX_DS / MAX_RT bits of STATUS to clear them. */
nrf24_regs_err_t nrf24_regs_clear_irq(nrf24_regs_t *r, uint8_t mask);

nrf24_regs_err_t nrf24_regs_flush_tx(nrf24_regs_t *r);
nrf24_regs_err_t nrf24_regs_flush_rx(nrf24_regs_t *r);

/** MAX_RT recovery: FLUSH_TX, clear MAX_RT | TX_DS. CE is left low. */
nrf24_regs_err_t nrf24_regs_tx_abort(nrf24_regs_t *r);

/** PRX: restore RX_ADDR_P0 = own, CONFIG |= PRIM_RX, CE high. */
nrf24_regs_err_t nrf24_regs_start_listening(nrf24_regs_t *r);

/** CE low, CONFIG &= ~PRIM_RX (Standby-I, PTX). */
nrf24_regs_err_t nrf24_regs_stop_listening(nrf24_regs_t *r);

/** CE pulse NRF24_CE_PULSE_US: transmit the TX FIFO head (one packet; back to Standby-I). */
nrf24_regs_err_t nrf24_regs_start_tx(nrf24_regs_t *r);

/** PWR_UP set (then wait NRF24_PWR_UP_US) or cleared (CE low first). */
nrf24_regs_err_t nrf24_regs_power(nrf24_regs_t *r, bool up);

nrf24_regs_err_t nrf24_regs_set_channel(nrf24_regs_t *r, uint8_t channel);

/** Raw register access for diagnostics (console register dump). */
nrf24_regs_err_t nrf24_regs_read(nrf24_regs_t *r, uint8_t reg, uint8_t *val_out);
nrf24_regs_err_t nrf24_regs_write(nrf24_regs_t *r, uint8_t reg, uint8_t val);

void nrf24_regs_get_stats(const nrf24_regs_t *r, nrf24_regs_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NRF24_REGS_H */
