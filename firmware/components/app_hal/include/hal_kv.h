// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_kv.h - vendor-neutral persistent key-value store (NVS on ESP-IDF,
// implemented in components/port_esp_idf/port_kv.cpp).
//
// Every setter commits before it returns (the value survives a reset that
// happens right after the call). Namespaces and keys are at most 15 chars.
// Thread-safe; blocking for the duration of one flash write (a few ms).

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hal_result.h"

#ifdef __cplusplus
extern "C" {
#endif

// Mount the store; erases and re-creates it when its layout is from another
// version or it has no free pages (boot-time invariant).
hal_result_t hal_kv_init(void);

// HAL_ERR_NOT_FOUND if the key does not exist.
hal_result_t hal_kv_get_u32(const char *ns, const char *key, uint32_t *out);
hal_result_t hal_kv_set_u32(const char *ns, const char *key, uint32_t value);

// *len_out receives the stored length. HAL_ERR_NOT_FOUND if absent,
// HAL_ERR_NO_MEM if cap is too small (nothing copied).
hal_result_t hal_kv_get_blob(const char *ns, const char *key, void *buf, size_t cap, size_t *len_out);
hal_result_t hal_kv_set_blob(const char *ns, const char *key, const void *data, size_t len);

// Remove one key; HAL_OK also when it did not exist.
hal_result_t hal_kv_erase_key(const char *ns, const char *key);

#ifdef __cplusplus
}
#endif
