// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_platform.h - platform services injected into the Braid core.
 *
 * The core never includes ESP-IDF or FreeRTOS headers. Time, randomness and
 * logging reach it through this table, filled by the device (main/ bridges the
 * app_hal layer, which port_esp_idf implements) or by a host test.
 *
 * Crypto is NOT in this table: the backend is mbedtls on both host and device
 * (br_crypto.h); CONFIG_MBEDTLS_HARDWARE_AES / _SHA change latency only
 * (12.12).
 */
#ifndef BRAID_BR_PLATFORM_H
#define BRAID_BR_PLATFORM_H

#include "braid/br_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BR_LOG_ERROR = 0,
    BR_LOG_WARN  = 1,
    BR_LOG_INFO  = 2,
    BR_LOG_DEBUG = 3
} br_log_level_t;

/**
 * Platform service table. All function pointers are mandatory.
 *
 * Contract for implementers:
 * - now_us: monotonic microseconds since boot; never goes backwards; callable
 *   from any task (not from ISR). Section 9 timers are built on it, never on
 *   CPU cycle counts (12.12).
 * - random_bytes: fill buf with len bytes from a CSPRNG (esp_fill_random on
 *   the device, OS RNG on the host). Returns BR_OK or BR_ERR_CRYPTO. Nonces
 *   are additionally hashed per 4.1.14, so the RNG quality is not the only
 *   defence (12.12).
 * - log: msg is a NUL-terminated ASCII line without trailing newline. Must not
 *   block longer than a few ms. tag is a short static string ("br", "rs", ...).
 * - user: opaque pointer passed back unchanged to every callback.
 */
typedef struct {
    uint64_t (*now_us)(void *user);
    br_err_t (*random_bytes)(void *user, uint8_t *buf, size_t len);
    void     (*log)(void *user, br_log_level_t level, const char *tag, const char *msg);
    void      *user;
} br_platform_t;

/**
 * Install the platform table used by the core.
 *
 * The table is copied; the caller may free its copy afterwards. Call once at
 * boot before any other br_* function that needs time, randomness or logging
 * (the codecs in br_crc16.h, br_cobs.h, br_rs.h, br_fec.h, br_frame.h and the
 * primitives in br_crypto.h do not need it). Not thread-safe against
 * concurrent br_* calls.
 *
 * @param p  Table with all pointers non-NULL.
 * @return BR_OK; BR_ERR_ARG if p or any function pointer is NULL.
 */
br_err_t br_platform_set(const br_platform_t *p);

/**
 * Get the installed platform table.
 *
 * @param out  Receives a copy of the table.
 * @return BR_OK; BR_ERR_ARG if out is NULL; BR_ERR_STATE if br_platform_set()
 *         has not succeeded yet.
 */
br_err_t br_platform_get(br_platform_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BRAID_BR_PLATFORM_H */
