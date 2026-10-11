// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * nrf24_regs.c - nRF24L01+ register-level driver, portable part
 * (see nrf24_regs.h). Host-tested by firmware/test/host/test_nrf24_link.c.
 */
#include "nrf24_regs.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* SPI primitives                                                             */
/* ------------------------------------------------------------------------- */

/* One command: cmd byte then n data bytes out, n bytes in. Returns STATUS. */
static uint8_t xfer(nrf24_regs_t *r, uint8_t cmd, const uint8_t *out, uint8_t *in, uint8_t n)
{
    uint8_t tx[1u + NRF24_PAYLOAD_MAX];
    uint8_t rx[1u + NRF24_PAYLOAD_MAX];
    if (n > NRF24_PAYLOAD_MAX) {
        return NRF24_ST_INVALID;
    }
    tx[0] = cmd;
    if (n > 0u) {
        if (out != NULL) {
            memcpy(tx + 1, out, n);
        } else {
            memset(tx + 1, NRF24_CMD_NOP, n);
        }
    }
    memset(rx, 0, sizeof rx);
    if (!r->io.spi_transfer(r->io.ctx, tx, rx, (size_t)n + 1u)) {
        r->st.spi_err++;
        return NRF24_ST_INVALID;
    }
    if (in != NULL && n > 0u) {
        memcpy(in, rx + 1, n);
    }
    return rx[0];
}

static nrf24_regs_err_t wr(nrf24_regs_t *r, uint8_t reg, uint8_t val)
{
    uint8_t st = xfer(r, (uint8_t)(NRF24_CMD_W_REGISTER | (reg & NRF24_CMD_REGISTER_MASK)), &val, NULL, 1u);
    return st == NRF24_ST_INVALID ? NRF24_REGS_ERR_SPI : NRF24_REGS_OK;
}

static nrf24_regs_err_t rd(nrf24_regs_t *r, uint8_t reg, uint8_t *val)
{
    uint8_t st = xfer(r, (uint8_t)(NRF24_CMD_R_REGISTER | (reg & NRF24_CMD_REGISTER_MASK)), NULL, val, 1u);
    return st == NRF24_ST_INVALID ? NRF24_REGS_ERR_SPI : NRF24_REGS_OK;
}

/* Address register write: the chip takes LSByte first, our arrays are MSByte first. */
static nrf24_regs_err_t wr_addr(nrf24_regs_t *r, uint8_t reg, const uint8_t *addr)
{
    uint8_t rev[NRF24_ADDR_LEN];
    uint8_t aw = r->cfg.addr_width;
    for (uint8_t i = 0; i < aw; i++) {
        rev[i] = addr[(uint8_t)(NRF24_ADDR_LEN - 1u - i)];
    }
    uint8_t st = xfer(r, (uint8_t)(NRF24_CMD_W_REGISTER | reg), rev, NULL, aw);
    return st == NRF24_ST_INVALID ? NRF24_REGS_ERR_SPI : NRF24_REGS_OK;
}

static nrf24_regs_err_t cmd(nrf24_regs_t *r, uint8_t c)
{
    return xfer(r, c, NULL, NULL, 0u) == NRF24_ST_INVALID ? NRF24_REGS_ERR_SPI : NRF24_REGS_OK;
}

/* Write then read back; mismatch means no chip answered (MISO floating). */
static nrf24_regs_err_t wr_verify(nrf24_regs_t *r, uint8_t reg, uint8_t val)
{
    nrf24_regs_err_t e = wr(r, reg, val);
    if (e != NRF24_REGS_OK) {
        return e;
    }
    uint8_t back = (uint8_t)~val;
    e = rd(r, reg, &back);
    if (e != NRF24_REGS_OK) {
        return e;
    }
    return back == val ? NRF24_REGS_OK : NRF24_REGS_ERR_NO_CHIP;
}

static uint8_t config_base(const nrf24_regs_t *r)
{
    (void)r;
    return NRF24_CONFIG_EN_CRC | NRF24_CONFIG_CRCO;
}

static uint8_t rf_setup_value(const nrf24_regs_cfg_t *cfg)
{
    uint8_t v = (uint8_t)(((uint8_t)cfg->pa << NRF24_RF_PWR_SHIFT) & NRF24_RF_PWR_MASK);
    switch (cfg->rate) {
    case NRF24_RATE_250K:
        v |= NRF24_RF_DR_LOW;
        break;
    case NRF24_RATE_2M:
        v |= NRF24_RF_DR_HIGH;
        break;
    case NRF24_RATE_1M:
    default:
        break;
    }
    return v;
}

/* ------------------------------------------------------------------------- */
/* Init                                                                       */
/* ------------------------------------------------------------------------- */

nrf24_regs_err_t nrf24_regs_init(nrf24_regs_t *r, const nrf24_regs_io_t *io, const nrf24_regs_cfg_t *cfg)
{
    if (r == NULL || io == NULL || cfg == NULL || io->spi_transfer == NULL || io->ce_set == NULL ||
        io->delay_us == NULL) {
        return NRF24_REGS_ERR_ARG;
    }
    if (cfg->channel > NRF24_CH_MAX || cfg->ard > 15u || cfg->arc > 15u || cfg->addr_width < 3u ||
        cfg->addr_width > 5u || (unsigned)cfg->rate > (unsigned)NRF24_RATE_2M ||
        (unsigned)cfg->pa > (unsigned)NRF24_PA_MAX) {
        return NRF24_REGS_ERR_ARG;
    }
    memset(r, 0, sizeof *r);
    r->io = *io;
    r->cfg = *cfg;

    r->io.ce_set(r->io.ctx, false);
    r->io.delay_us(r->io.ctx, NRF24_PWR_UP_US); /* power-on reset settle, as RF24 does */

    nrf24_regs_err_t e;
    /* Power down, PTX, 2-byte CRC: also the "is anything there" probe. */
    if ((e = wr_verify(r, NRF24_REG_CONFIG, config_base(r))) != NRF24_REGS_OK) {
        return e;
    }
    /* Dynamic payloads + per-packet NO_ACK; ACTIVATE once for non-plus parts. */
    const uint8_t feat = NRF24_FEATURE_EN_DPL | NRF24_FEATURE_EN_DYN_ACK;
    e = wr_verify(r, NRF24_REG_FEATURE, feat);
    if (e == NRF24_REGS_ERR_NO_CHIP) {
        const uint8_t key = 0x73u;
        if (xfer(r, NRF24_CMD_ACTIVATE, &key, NULL, 1u) == NRF24_ST_INVALID) {
            return NRF24_REGS_ERR_SPI;
        }
        r->st.activate_used++;
        e = wr_verify(r, NRF24_REG_FEATURE, feat);
    }
    if (e != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_SETUP_RETR, (uint8_t)((cfg->ard << 4) | cfg->arc))) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr_verify(r, NRF24_REG_SETUP_AW, (uint8_t)(cfg->addr_width - 2u))) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr_verify(r, NRF24_REG_RF_CH, cfg->channel)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_RF_SETUP, rf_setup_value(cfg))) != NRF24_REGS_OK) {
        return e;
    }
    /* Pipes 0 (own, auto-ACK) and 1 (broadcast). EN_AA on both: DPL needs it. */
    if ((e = wr(r, NRF24_REG_EN_AA, 0x03u)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_EN_RXADDR, 0x03u)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_DYNPD, 0x03u)) != NRF24_REGS_OK) {
        return e;
    }
    for (uint8_t p = 0; p < NRF24_PIPES; p++) {
        if ((e = wr(r, (uint8_t)(NRF24_REG_RX_PW_P0 + p), NRF24_PAYLOAD_MAX)) != NRF24_REGS_OK) {
            return e;
        }
    }
    if ((e = cmd(r, NRF24_CMD_FLUSH_TX)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = cmd(r, NRF24_CMD_FLUSH_RX)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_STATUS, NRF24_ST_IRQ_MASK)) != NRF24_REGS_OK) {
        return e;
    }
    r->inited = true;
    return nrf24_regs_power(r, true);
}

/* ------------------------------------------------------------------------- */
/* Addresses                                                                  */
/* ------------------------------------------------------------------------- */

nrf24_regs_err_t nrf24_regs_set_rx_address(nrf24_regs_t *r, uint8_t pipe, const uint8_t *addr, bool enable)
{
    if (r == NULL || !r->inited || addr == NULL || pipe >= NRF24_PIPES) {
        return NRF24_REGS_ERR_ARG;
    }
    nrf24_regs_err_t e;
    if (pipe <= 1u) {
        e = wr_addr(r, (uint8_t)(NRF24_REG_RX_ADDR_P0 + pipe), addr);
        if (e == NRF24_REGS_OK && pipe == 0u) {
            memcpy(r->own_p0, addr, NRF24_ADDR_LEN);
            r->have_p0 = true;
        }
    } else {
        e = wr(r, (uint8_t)(NRF24_REG_RX_ADDR_P0 + pipe), addr[NRF24_ADDR_LEN - 1u]);
    }
    if (e != NRF24_REGS_OK) {
        return e;
    }
    uint8_t en = 0;
    if ((e = rd(r, NRF24_REG_EN_RXADDR, &en)) != NRF24_REGS_OK) {
        return e;
    }
    uint8_t bit = (uint8_t)(1u << pipe);
    en = enable ? (uint8_t)(en | bit) : (uint8_t)(en & (uint8_t)~bit);
    return wr(r, NRF24_REG_EN_RXADDR, en);
}

nrf24_regs_err_t nrf24_regs_set_tx_address(nrf24_regs_t *r, const uint8_t *addr)
{
    if (r == NULL || !r->inited || addr == NULL) {
        return NRF24_REGS_ERR_ARG;
    }
    nrf24_regs_err_t e = wr_addr(r, NRF24_REG_TX_ADDR, addr);
    if (e != NRF24_REGS_OK) {
        return e;
    }
    return wr_addr(r, NRF24_REG_RX_ADDR_P0, addr); /* the ACK comes back on pipe 0 */
}

/* ------------------------------------------------------------------------- */
/* Payloads                                                                   */
/* ------------------------------------------------------------------------- */

nrf24_regs_err_t nrf24_regs_write_payload(nrf24_regs_t *r, const uint8_t *buf, uint8_t len, bool no_ack)
{
    if (r == NULL || !r->inited || buf == NULL || len == 0u || len > NRF24_PAYLOAD_MAX) {
        return NRF24_REGS_ERR_ARG;
    }
    uint8_t st = nrf24_regs_status(r);
    if (st == NRF24_ST_INVALID) {
        return NRF24_REGS_ERR_SPI;
    }
    if ((st & NRF24_ST_TX_FULL) != 0u) {
        return NRF24_REGS_ERR_FULL;
    }
    st = xfer(r, no_ack ? NRF24_CMD_W_TX_PAYLOAD_NO_ACK : NRF24_CMD_W_TX_PAYLOAD, buf, NULL, len);
    return st == NRF24_ST_INVALID ? NRF24_REGS_ERR_SPI : NRF24_REGS_OK;
}

nrf24_regs_err_t nrf24_regs_read_payload(nrf24_regs_t *r, uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out)
{
    if (r == NULL || !r->inited || pipe_out == NULL || buf == NULL || len_out == NULL) {
        return NRF24_REGS_ERR_ARG;
    }
    uint8_t width = 0;
    uint8_t st = xfer(r, NRF24_CMD_R_RX_PL_WID, NULL, &width, 1u);
    if (st == NRF24_ST_INVALID) {
        return NRF24_REGS_ERR_SPI;
    }
    uint8_t pipe = (uint8_t)((st & NRF24_ST_RX_P_NO_MASK) >> NRF24_ST_RX_P_NO_SHIFT);
    if (pipe == NRF24_ST_RX_P_NO_EMPTY) {
        return NRF24_REGS_ERR_EMPTY;
    }
    if (width == 0u || width > NRF24_PAYLOAD_MAX) {
        r->st.rx_bad_width++;
        (void)cmd(r, NRF24_CMD_FLUSH_RX);
        return NRF24_REGS_ERR_WIDTH;
    }
    st = xfer(r, NRF24_CMD_R_RX_PAYLOAD, NULL, buf, width);
    if (st == NRF24_ST_INVALID) {
        return NRF24_REGS_ERR_SPI;
    }
    *pipe_out = pipe;
    *len_out = width;
    return NRF24_REGS_OK;
}

uint8_t nrf24_regs_status(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_ST_INVALID;
    }
    return xfer(r, NRF24_CMD_NOP, NULL, NULL, 0u);
}

nrf24_regs_err_t nrf24_regs_clear_irq(nrf24_regs_t *r, uint8_t mask)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    return wr(r, NRF24_REG_STATUS, (uint8_t)(mask & NRF24_ST_IRQ_MASK));
}

nrf24_regs_err_t nrf24_regs_flush_tx(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    return cmd(r, NRF24_CMD_FLUSH_TX);
}

nrf24_regs_err_t nrf24_regs_flush_rx(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    return cmd(r, NRF24_CMD_FLUSH_RX);
}

nrf24_regs_err_t nrf24_regs_tx_abort(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    r->st.tx_aborts++;
    r->io.ce_set(r->io.ctx, false);
    nrf24_regs_err_t e = cmd(r, NRF24_CMD_FLUSH_TX);
    if (e != NRF24_REGS_OK) {
        return e;
    }
    return wr(r, NRF24_REG_STATUS, NRF24_ST_MAX_RT | NRF24_ST_TX_DS);
}

/* ------------------------------------------------------------------------- */
/* Modes                                                                      */
/* ------------------------------------------------------------------------- */

nrf24_regs_err_t nrf24_regs_start_listening(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    nrf24_regs_err_t e;
    if (r->have_p0) {
        if ((e = wr_addr(r, NRF24_REG_RX_ADDR_P0, r->own_p0)) != NRF24_REGS_OK) {
            return e;
        }
    }
    uint8_t cfgv = (uint8_t)(config_base(r) | NRF24_CONFIG_PWR_UP | NRF24_CONFIG_PRIM_RX);
    if ((e = wr(r, NRF24_REG_CONFIG, cfgv)) != NRF24_REGS_OK) {
        return e;
    }
    if ((e = wr(r, NRF24_REG_STATUS, NRF24_ST_IRQ_MASK)) != NRF24_REGS_OK) {
        return e;
    }
    r->io.ce_set(r->io.ctx, true);
    r->listening = true;
    r->powered = true;
    return NRF24_REGS_OK;
}

nrf24_regs_err_t nrf24_regs_stop_listening(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    r->io.ce_set(r->io.ctx, false);
    r->listening = false;
    uint8_t cfgv = (uint8_t)(config_base(r) | NRF24_CONFIG_PWR_UP);
    r->powered = true;
    return wr(r, NRF24_REG_CONFIG, cfgv);
}

nrf24_regs_err_t nrf24_regs_start_tx(nrf24_regs_t *r)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    if (r->listening) {
        return NRF24_REGS_ERR_ARG; /* stop_listening first */
    }
    r->io.ce_set(r->io.ctx, true);
    r->io.delay_us(r->io.ctx, NRF24_CE_PULSE_US);
    r->io.ce_set(r->io.ctx, false);
    return NRF24_REGS_OK;
}

nrf24_regs_err_t nrf24_regs_power(nrf24_regs_t *r, bool up)
{
    if (r == NULL || !r->inited) {
        return NRF24_REGS_ERR_ARG;
    }
    uint8_t cfgv = config_base(r);
    if (up) {
        cfgv |= NRF24_CONFIG_PWR_UP;
        if (r->listening) {
            cfgv |= NRF24_CONFIG_PRIM_RX;
        }
    } else {
        r->io.ce_set(r->io.ctx, false);
        r->listening = false;
    }
    nrf24_regs_err_t e = wr(r, NRF24_REG_CONFIG, cfgv);
    if (e != NRF24_REGS_OK) {
        return e;
    }
    if (up && !r->powered) {
        r->io.delay_us(r->io.ctx, NRF24_PWR_UP_US);
    }
    r->powered = up;
    return NRF24_REGS_OK;
}

nrf24_regs_err_t nrf24_regs_set_channel(nrf24_regs_t *r, uint8_t channel)
{
    if (r == NULL || !r->inited || channel > NRF24_CH_MAX) {
        return NRF24_REGS_ERR_ARG;
    }
    nrf24_regs_err_t e = wr_verify(r, NRF24_REG_RF_CH, channel);
    if (e == NRF24_REGS_OK) {
        r->cfg.channel = channel;
    }
    return e;
}

nrf24_regs_err_t nrf24_regs_read(nrf24_regs_t *r, uint8_t reg, uint8_t *val_out)
{
    if (r == NULL || !r->inited || val_out == NULL || reg >= NRF24_REG_COUNT) {
        return NRF24_REGS_ERR_ARG;
    }
    return rd(r, reg, val_out);
}

nrf24_regs_err_t nrf24_regs_write(nrf24_regs_t *r, uint8_t reg, uint8_t val)
{
    if (r == NULL || !r->inited || reg >= NRF24_REG_COUNT) {
        return NRF24_REGS_ERR_ARG;
    }
    return wr(r, reg, val);
}

void nrf24_regs_get_stats(const nrf24_regs_t *r, nrf24_regs_stats_t *out)
{
    if (r == NULL || out == NULL) {
        return;
    }
    *out = r->st;
}
