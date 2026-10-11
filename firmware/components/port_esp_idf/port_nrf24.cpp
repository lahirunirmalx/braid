// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_nrf24.cpp - ESP-IDF implementation of hal_nrf24.h.
//
// Thin: the register sequence, FIFO handling and PRX / PTX switching are
// the portable components/app_nrf24_link/src/nrf24_regs.c (host-tested
// against a register-model fake). This file owns the one nrf24_regs_t of
// the board and gives it the three board-specific primitives:
//   - SPI transfer  -> hal_spi (port_spi.cpp; mode 0, 8 MHz default, CSN
//                      driven by the controller for the whole command),
//   - CE line       -> hal_gpio output,
//   - delay         -> esp_rom_delay_us below 1 ms, vTaskDelay above,
// plus the optional IRQ pin (hal_gpio falling-edge interrupt; the ISR only
// calls the registered callback, which must only post to a queue / give a
// semaphore) and the per-chip pin plan of spec C.6.
//
// Pin plan (C.6; dev boards may differ, the console may override):
//   ESP32-WROOM-32E / -32UE   VSPI IO_MUX  SCK GPIO18, MISO GPIO19, MOSI GPIO23
//                             CSN GPIO5    // STRAPPING: GPIO5 must be high at
//                                          // boot (SDIO slave timing strap);
//                                          // CSN idles high (module pull-up on
//                                          // most boards, controller drives
//                                          // high after init), fine.
//                             CE GPIO4, IRQ GPIO35 (input only: fine for an IRQ;
//                                          // default is polling, set irq_pin when wired)
//   ESP32-S3-WROOM-1 / -1U    SPI2 IO_MUX  SCK GPIO12, MISO GPIO13, MOSI GPIO11
//                             CSN GPIO10, CE GPIO9, IRQ GPIO14
//                             (none strapping; 35-37 octal PSRAM and 19/20 USB
//                             untouched; no collision with led 2, btn 0,
//                             UART link 17/18)
// Refused by hal_nrf24_init(): flash pins (ESP32 6-11, S3 26-32), S3 PSRAM
// 33-37 and USB 19/20, strapping pins for CE / CSN other than GPIO5 CSN
// (ESP32 0/2/12/15, S3 0/3/45/46), input-only ESP32 34-39 for outputs.
//
// NOT YET RUN ON HARDWARE and not yet listed in this component's
// CMakeLists.txt (needs SRCS port_spi.cpp port_nrf24.cpp, PRIV_REQUIRES
// esp_driver_spi app_nrf24_link): see firmware/NRF24-LINK.txt, Integration
// TODO. Compile-checked per chip with the port_espnow.cpp command line.

#include <atomic>
#include <cstring>

#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"

#include "hal_gpio.h"
#include "hal_nrf24.h"
#include "hal_spi.h"
#include "nrf24_regs.h"

namespace {

constexpr char TAG[] = "port_nrf24";
constexpr TickType_t kLockWait = pdMS_TO_TICKS(50);

struct Radio {
    nrf24_regs_t     regs;
    hal_spi_dev_t    spi = 0;
    int16_t          ce_pin = -1;
    int16_t          irq_pin = -1;
    std::atomic<bool> up{false};
    hal_nrf24_irq_cb irq_cb = nullptr;
    void            *irq_user = nullptr;
    std::atomic<uint32_t> irqs{0};
};

Radio g_r;
StaticSemaphore_t g_lock_buf;
SemaphoreHandle_t g_lock = nullptr;

// ---- nrf24_regs_io_t glue ---------------------------------------------------

bool io_spi(void *, const uint8_t *tx, uint8_t *rx, size_t len) {
    return hal_spi_transfer(g_r.spi, tx, rx, len) == HAL_OK;
}

void io_ce(void *, bool high) { (void)hal_gpio_set(static_cast<uint8_t>(g_r.ce_pin), high); }

void io_delay(void *, uint32_t us) {
    if (us >= 1000) {
        vTaskDelay(pdMS_TO_TICKS((us + 999) / 1000) + 1);
    } else {
        esp_rom_delay_us(us);
    }
}

void IRAM_ATTR irq_isr(uint8_t, void *) {
    g_r.irqs.fetch_add(1, std::memory_order_relaxed);
    if (g_r.irq_cb != nullptr) g_r.irq_cb(g_r.irq_user);
}

// ---- pin policy ---------------------------------------------------------------

bool pin_exists(int16_t p) { return p >= 0 && p < SOC_GPIO_PIN_COUNT; }

bool pin_reserved(int16_t p) {
#if CONFIG_IDF_TARGET_ESP32
    return p >= 6 && p <= 11;                                  // flash
#elif CONFIG_IDF_TARGET_ESP32S3
    return (p >= 26 && p <= 37) || p == 19 || p == 20;         // flash, PSRAM (kept free on N8 too), USB
#else
    return false;
#endif
}

bool pin_strapping(int16_t p) {
#if CONFIG_IDF_TARGET_ESP32
    return p == 0 || p == 2 || p == 5 || p == 12 || p == 15;
#elif CONFIG_IDF_TARGET_ESP32S3
    return p == 0 || p == 3 || p == 45 || p == 46;
#else
    return false;
#endif
}

bool pin_input_only(int16_t p) {
#if CONFIG_IDF_TARGET_ESP32
    return p >= 34 && p <= 39;
#elif CONFIG_IDF_TARGET_ESP32S3
    return p == 46;
#else
    return false;
#endif
}

bool output_pin_ok(int16_t p, bool allow_gpio5_csn) {
    if (!pin_exists(p) || pin_reserved(p) || pin_input_only(p)) return false;
    if (pin_strapping(p)) {
#if CONFIG_IDF_TARGET_ESP32
        return allow_gpio5_csn && p == 5;   // STRAPPING: GPIO5 high at boot; CSN idles high
#else
        (void)allow_gpio5_csn;
        return false;
#endif
    }
    return true;
}

hal_result_t map_regs(nrf24_regs_err_t e) {
    switch (e) {
        case NRF24_REGS_OK:          return HAL_OK;
        case NRF24_REGS_ERR_ARG:     return HAL_ERR_INVALID_ARG;
        case NRF24_REGS_ERR_SPI:     return HAL_ERR_HW_FAULT;
        case NRF24_REGS_ERR_NO_CHIP: return HAL_ERR_HW_FAULT;
        case NRF24_REGS_ERR_FULL:    return HAL_ERR_BUSY;
        case NRF24_REGS_ERR_EMPTY:   return HAL_ERR_NOT_FOUND;
        case NRF24_REGS_ERR_WIDTH:   return HAL_ERR_HW_FAULT;
        default:                     return HAL_ERR_INTERNAL;
    }
}

bool lock() { return g_lock != nullptr && xSemaphoreTake(g_lock, kLockWait) == pdTRUE; }
void unlock() { xSemaphoreGive(g_lock); }

template <typename F>
hal_result_t guarded(F &&f) {
    if (!g_r.up.load()) return HAL_ERR_BUSY;
    if (!lock()) return HAL_ERR_BUSY;
    const hal_result_t r = f();
    unlock();
    return r;
}

}  // namespace

extern "C" void hal_nrf24_default_cfg(hal_nrf24_cfg_t *cfg) {
    if (cfg == nullptr) return;
    std::memset(cfg, 0, sizeof *cfg);
#if CONFIG_IDF_TARGET_ESP32
    cfg->sck_pin = 18;
    cfg->miso_pin = 19;
    cfg->mosi_pin = 23;
    cfg->csn_pin = 5;    // STRAPPING: GPIO5 must be high at boot; CSN idles high, fine
    cfg->ce_pin = 4;
#else
    cfg->sck_pin = 12;
    cfg->miso_pin = 13;
    cfg->mosi_pin = 11;
    cfg->csn_pin = 10;
    cfg->ce_pin = 9;
#endif
    // Polling by default: an IRQ pin configured but not wired is a floating
    // edge-triggered input (GPIO35 has no internal pull at all) and storms.
    // The C.6 IRQ pins (ESP32 GPIO35, S3 GPIO14) are the values to set when
    // the wire is there.
    cfg->irq_pin = HAL_NRF24_PIN_NONE;
    cfg->spi_bus = HAL_SPI_BUS_DEFAULT;
    cfg->spi_hz = HAL_NRF24_SPI_HZ_DEFAULT;
    cfg->channel = 76;
    cfg->rate = HAL_NRF24_RATE_2M;
    cfg->pa = HAL_NRF24_PA_MAX;
    cfg->ard = 1;        // 500 us (C.5)
    cfg->arc = 15;       // C.5
    cfg->addr_width = HAL_NRF24_ADDR_LEN;
}

extern "C" hal_result_t hal_nrf24_init(const hal_nrf24_cfg_t *cfg) {
    if (cfg == nullptr) return HAL_ERR_INVALID_ARG;
    if (g_r.up.load()) return HAL_ERR_BUSY;
    if (!pin_exists(cfg->sck_pin) || !pin_exists(cfg->miso_pin) || !pin_exists(cfg->mosi_pin) ||
        pin_reserved(cfg->sck_pin) || pin_reserved(cfg->miso_pin) || pin_reserved(cfg->mosi_pin) ||
        pin_input_only(cfg->sck_pin) || pin_input_only(cfg->mosi_pin) || !output_pin_ok(cfg->csn_pin, true) ||
        !output_pin_ok(cfg->ce_pin, false)) {
        return HAL_ERR_INVALID_ARG;
    }
    if (cfg->irq_pin != HAL_NRF24_PIN_NONE && (!pin_exists(cfg->irq_pin) || pin_reserved(cfg->irq_pin))) {
        return HAL_ERR_INVALID_ARG;
    }
    if (cfg->channel > HAL_NRF24_CH_MAX || cfg->addr_width < 3 || cfg->addr_width > 5 || cfg->ard > 15 ||
        cfg->arc > 15 || cfg->spi_hz > HAL_NRF24_SPI_HZ_MAX) {
        return HAL_ERR_INVALID_ARG;
    }
    if (g_lock == nullptr) {
        g_lock = xSemaphoreCreateMutexStatic(&g_lock_buf);
        if (g_lock == nullptr) return HAL_ERR_NO_MEM;
    }

    // CE low before anything else (Standby / power down regardless of SPI).
    hal_gpio_cfg_t ce = {};
    ce.pin = static_cast<uint8_t>(cfg->ce_pin);
    ce.dir = HAL_GPIO_DIR_OUT;
    ce.pull = HAL_GPIO_PULL_NONE;
    ce.intr = HAL_GPIO_INT_NONE;
    hal_result_t r = hal_gpio_init(&ce);
    if (r != HAL_OK) return r;
    g_r.ce_pin = cfg->ce_pin;
    (void)hal_gpio_set(ce.pin, false);

    hal_spi_bus_cfg_t bc = {};
    bc.bus = cfg->spi_bus;
    bc.sck_pin = cfg->sck_pin;
    bc.miso_pin = cfg->miso_pin;
    bc.mosi_pin = cfg->mosi_pin;
    if ((r = hal_spi_bus_init(&bc)) != HAL_OK) {
        ESP_LOGE(TAG, "spi bus init failed: %s", hal_result_name(r));
        return r;
    }
    hal_spi_dev_cfg_t dc = {};
    dc.bus = cfg->spi_bus;
    dc.cs_pin = cfg->csn_pin;
    dc.clock_hz = cfg->spi_hz == 0 ? HAL_NRF24_SPI_HZ_DEFAULT : cfg->spi_hz;
    dc.mode = 0;
    if ((r = hal_spi_dev_add(&dc, &g_r.spi)) != HAL_OK) {
        ESP_LOGE(TAG, "spi device add failed: %s", hal_result_name(r));
        return r;
    }

    nrf24_regs_io_t io = {nullptr, io_spi, io_ce, io_delay};
    nrf24_regs_cfg_t rc = {};
    rc.channel = cfg->channel;
    rc.rate = static_cast<nrf24_rate_t>(cfg->rate);
    rc.pa = static_cast<nrf24_pa_t>(cfg->pa);
    rc.ard = cfg->ard;
    rc.arc = cfg->arc;
    rc.addr_width = cfg->addr_width;
    const nrf24_regs_err_t e = nrf24_regs_init(&g_r.regs, &io, &rc);
    if (e != NRF24_REGS_OK) {
        ESP_LOGE(TAG, "nRF24 register init failed (%d): no module answering on SCK%d MISO%d MOSI%d CSN%d?",
                 static_cast<int>(e), cfg->sck_pin, cfg->miso_pin, cfg->mosi_pin, cfg->csn_pin);
        return map_regs(e);
    }

    g_r.irq_pin = cfg->irq_pin;
    if (cfg->irq_pin != HAL_NRF24_PIN_NONE) {
        hal_gpio_cfg_t ic = {};
        ic.pin = static_cast<uint8_t>(cfg->irq_pin);
        ic.dir = HAL_GPIO_DIR_IN;
        ic.pull = HAL_GPIO_PULL_NONE;   // the module drives IRQ push-pull (active low); 34-39 have no pulls anyway
        ic.intr = HAL_GPIO_INT_FALLING;
        if ((r = hal_gpio_init(&ic)) != HAL_OK) return r;
        if ((r = hal_gpio_attach_isr(ic.pin, irq_isr, nullptr)) != HAL_OK) return r;
    }
    g_r.up.store(true);
    ESP_LOGI(TAG, "nRF24L01+ up: ch %u rate %d pa %d ard %u arc %u aw %u irq %s", cfg->channel,
             static_cast<int>(cfg->rate), static_cast<int>(cfg->pa), cfg->ard, cfg->arc, cfg->addr_width,
             cfg->irq_pin == HAL_NRF24_PIN_NONE ? "poll" : "pin");
    return HAL_OK;
}

extern "C" hal_result_t hal_nrf24_set_rx_address(uint8_t pipe, const uint8_t addr[HAL_NRF24_ADDR_LEN], bool enable) {
    if (addr == nullptr) return HAL_ERR_INVALID_ARG;
    return guarded([&] { return map_regs(nrf24_regs_set_rx_address(&g_r.regs, pipe, addr, enable)); });
}

extern "C" hal_result_t hal_nrf24_set_tx_address(const uint8_t addr[HAL_NRF24_ADDR_LEN]) {
    if (addr == nullptr) return HAL_ERR_INVALID_ARG;
    return guarded([&] { return map_regs(nrf24_regs_set_tx_address(&g_r.regs, addr)); });
}

extern "C" hal_result_t hal_nrf24_write_payload(const uint8_t *buf, uint8_t len, bool no_ack) {
    if (buf == nullptr || len == 0 || len > HAL_NRF24_MAX_PAYLOAD) return HAL_ERR_INVALID_ARG;
    return guarded([&] { return map_regs(nrf24_regs_write_payload(&g_r.regs, buf, len, no_ack)); });
}

extern "C" hal_result_t hal_nrf24_start_tx(void) {
    return guarded([&] {
        if (g_r.regs.listening) return HAL_ERR_BUSY;
        return map_regs(nrf24_regs_start_tx(&g_r.regs));
    });
}

extern "C" hal_result_t hal_nrf24_read_payload(uint8_t *pipe_out, uint8_t *buf, uint8_t *len_out) {
    if (pipe_out == nullptr || buf == nullptr || len_out == nullptr) return HAL_ERR_INVALID_ARG;
    return guarded([&] { return map_regs(nrf24_regs_read_payload(&g_r.regs, pipe_out, buf, len_out)); });
}

extern "C" uint8_t hal_nrf24_status(void) {
    if (!g_r.up.load() || !lock()) return HAL_NRF24_ST_INVALID;
    const uint8_t st = nrf24_regs_status(&g_r.regs);
    unlock();
    return st;
}

extern "C" hal_result_t hal_nrf24_clear_irq(uint8_t mask) {
    return guarded([&] { return map_regs(nrf24_regs_clear_irq(&g_r.regs, mask)); });
}

extern "C" hal_result_t hal_nrf24_tx_abort(void) {
    return guarded([&] { return map_regs(nrf24_regs_tx_abort(&g_r.regs)); });
}

extern "C" hal_result_t hal_nrf24_flush_rx(void) {
    return guarded([&] { return map_regs(nrf24_regs_flush_rx(&g_r.regs)); });
}

extern "C" hal_result_t hal_nrf24_start_listening(void) {
    return guarded([&] { return map_regs(nrf24_regs_start_listening(&g_r.regs)); });
}

extern "C" hal_result_t hal_nrf24_stop_listening(void) {
    return guarded([&] { return map_regs(nrf24_regs_stop_listening(&g_r.regs)); });
}

extern "C" hal_result_t hal_nrf24_power(bool up) {
    return guarded([&] { return map_regs(nrf24_regs_power(&g_r.regs, up)); });
}

extern "C" hal_result_t hal_nrf24_set_channel(uint8_t channel) {
    return guarded([&] { return map_regs(nrf24_regs_set_channel(&g_r.regs, channel)); });
}

extern "C" hal_result_t hal_nrf24_set_irq_cb(hal_nrf24_irq_cb cb, void *user) {
    if (!g_r.up.load()) return HAL_ERR_BUSY;
    if (g_r.irq_pin == HAL_NRF24_PIN_NONE) return HAL_ERR_UNSUPPORTED;
    g_r.irq_user = user;
    g_r.irq_cb = cb;
    return HAL_OK;
}

extern "C" hal_result_t hal_nrf24_read_reg(uint8_t reg, uint8_t *val_out) {
    if (val_out == nullptr) return HAL_ERR_INVALID_ARG;
    return guarded([&] { return map_regs(nrf24_regs_read(&g_r.regs, reg, val_out)); });
}

extern "C" hal_result_t hal_nrf24_get_stats(hal_nrf24_stats_t *out) {
    if (out == nullptr) return HAL_ERR_INVALID_ARG;
    nrf24_regs_stats_t rs = {};
    nrf24_regs_get_stats(&g_r.regs, &rs);
    out->spi_err = rs.spi_err;
    out->rx_bad_width = rs.rx_bad_width;
    out->tx_aborts = rs.tx_aborts;
    out->activate_used = rs.activate_used;
    out->irqs = g_r.irqs.load(std::memory_order_relaxed);
    return HAL_OK;
}
