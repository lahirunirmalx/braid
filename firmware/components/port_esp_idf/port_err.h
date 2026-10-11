// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_err.h - esp_err_t -> hal_result_t mapping shared by port_*.cpp.
#pragma once

#include "esp_err.h"
#include "hal_result.h"

namespace port {

inline hal_result_t map_err(esp_err_t e) {
    switch (e) {
        case ESP_OK:                return HAL_OK;
        case ESP_ERR_INVALID_ARG:   return HAL_ERR_INVALID_ARG;
        case ESP_ERR_NO_MEM:        return HAL_ERR_NO_MEM;
        case ESP_ERR_TIMEOUT:       return HAL_ERR_TIMEOUT;
        case ESP_ERR_NOT_FOUND:     return HAL_ERR_NOT_FOUND;
        case ESP_ERR_INVALID_STATE: return HAL_ERR_BUSY;
        case ESP_ERR_NOT_SUPPORTED: return HAL_ERR_UNSUPPORTED;
        default:                    return HAL_ERR_INTERNAL;
    }
}

}  // namespace port
