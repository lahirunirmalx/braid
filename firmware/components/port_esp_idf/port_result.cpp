// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_result.cpp - hal_result_name() (declared in hal_result.h).
#include "hal_result.h"

extern "C" const char *hal_result_name(hal_result_t r) {
    switch (r) {
        case HAL_OK:              return "HAL_OK";
        case HAL_ERR_INVALID_ARG: return "HAL_ERR_INVALID_ARG";
        case HAL_ERR_NO_MEM:      return "HAL_ERR_NO_MEM";
        case HAL_ERR_TIMEOUT:     return "HAL_ERR_TIMEOUT";
        case HAL_ERR_NOT_FOUND:   return "HAL_ERR_NOT_FOUND";
        case HAL_ERR_BUSY:        return "HAL_ERR_BUSY";
        case HAL_ERR_HW_FAULT:    return "HAL_ERR_HW_FAULT";
        case HAL_ERR_UNSUPPORTED: return "HAL_ERR_UNSUPPORTED";
        case HAL_ERR_INTERNAL:    return "HAL_ERR_INTERNAL";
        default:                  return "HAL_ERR_?";
    }
}
