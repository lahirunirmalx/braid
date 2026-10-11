// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// hal_result.h - canonical error type for all HAL functions.
// Pure C, zero ESP-IDF dependency. Consumable from C and C++.

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HAL_OK              = 0,
    HAL_ERR_INVALID_ARG = 1,
    HAL_ERR_NO_MEM      = 2,
    HAL_ERR_TIMEOUT     = 3,
    HAL_ERR_NOT_FOUND   = 4,
    HAL_ERR_BUSY        = 5,
    HAL_ERR_HW_FAULT    = 6,
    HAL_ERR_UNSUPPORTED = 7,
    HAL_ERR_INTERNAL    = 255
} hal_result_t;

static inline int hal_is_ok(hal_result_t r) { return r == HAL_OK; }

const char *hal_result_name(hal_result_t r);

#ifdef __cplusplus
}
#endif
