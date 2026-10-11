// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// port_kv.cpp - ESP-IDF NVS implementation of hal_kv.h.
#include <cstring>

#include "nvs.h"
#include "nvs_flash.h"

#include "hal_kv.h"
#include "port_err.h"

namespace {

hal_result_t map_nvs(esp_err_t e) {
    switch (e) {
        case ESP_ERR_NVS_NOT_FOUND:        return HAL_ERR_NOT_FOUND;
        case ESP_ERR_NVS_INVALID_LENGTH:   return HAL_ERR_NO_MEM;
        case ESP_ERR_NVS_NOT_ENOUGH_SPACE: return HAL_ERR_NO_MEM;
        case ESP_ERR_NVS_INVALID_NAME:
        case ESP_ERR_NVS_KEY_TOO_LONG:
        case ESP_ERR_NVS_VALUE_TOO_LONG:   return HAL_ERR_INVALID_ARG;
        default:                           return port::map_err(e);
    }
}

// RAII for an NVS handle: closed on every path.
class Handle {
  public:
    Handle(const char *ns, nvs_open_mode_t mode) { err_ = nvs_open(ns, mode, &h_); }
    ~Handle() {
        if (err_ == ESP_OK) nvs_close(h_);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    esp_err_t err() const { return err_; }
    nvs_handle_t get() const { return h_; }

  private:
    nvs_handle_t h_ = 0;
    esp_err_t err_ = ESP_FAIL;
};

bool names_ok(const char *ns, const char *key) {
    return ns != nullptr && key != nullptr && std::strlen(ns) < NVS_KEY_NAME_MAX_SIZE &&
           std::strlen(key) < NVS_KEY_NAME_MAX_SIZE;
}

}  // namespace

extern "C" hal_result_t hal_kv_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        err = nvs_flash_erase();
        if (err == ESP_OK) err = nvs_flash_init();
    }
    return map_nvs(err);
}

extern "C" hal_result_t hal_kv_get_u32(const char *ns, const char *key, uint32_t *out) {
    if (!names_ok(ns, key) || out == nullptr) return HAL_ERR_INVALID_ARG;
    Handle h(ns, NVS_READONLY);
    if (h.err() != ESP_OK) return map_nvs(h.err());  // namespace absent -> NOT_FOUND
    return map_nvs(nvs_get_u32(h.get(), key, out));
}

extern "C" hal_result_t hal_kv_set_u32(const char *ns, const char *key, uint32_t value) {
    if (!names_ok(ns, key)) return HAL_ERR_INVALID_ARG;
    Handle h(ns, NVS_READWRITE);
    if (h.err() != ESP_OK) return map_nvs(h.err());
    esp_err_t e = nvs_set_u32(h.get(), key, value);
    if (e == ESP_OK) e = nvs_commit(h.get());
    return map_nvs(e);
}

extern "C" hal_result_t hal_kv_get_blob(const char *ns, const char *key, void *buf, size_t cap,
                                        size_t *len_out) {
    if (!names_ok(ns, key) || buf == nullptr || len_out == nullptr) return HAL_ERR_INVALID_ARG;
    *len_out = 0;
    Handle h(ns, NVS_READONLY);
    if (h.err() != ESP_OK) return map_nvs(h.err());
    size_t len = 0;
    esp_err_t e = nvs_get_blob(h.get(), key, nullptr, &len);
    if (e != ESP_OK) return map_nvs(e);
    if (len > cap) return HAL_ERR_NO_MEM;
    e = nvs_get_blob(h.get(), key, buf, &len);
    if (e == ESP_OK) *len_out = len;
    return map_nvs(e);
}

extern "C" hal_result_t hal_kv_set_blob(const char *ns, const char *key, const void *data, size_t len) {
    if (!names_ok(ns, key) || (data == nullptr && len > 0)) return HAL_ERR_INVALID_ARG;
    Handle h(ns, NVS_READWRITE);
    if (h.err() != ESP_OK) return map_nvs(h.err());
    esp_err_t e = nvs_set_blob(h.get(), key, data, len);
    if (e == ESP_OK) e = nvs_commit(h.get());
    return map_nvs(e);
}

extern "C" hal_result_t hal_kv_erase_key(const char *ns, const char *key) {
    if (!names_ok(ns, key)) return HAL_ERR_INVALID_ARG;
    Handle h(ns, NVS_READWRITE);
    if (h.err() != ESP_OK) return map_nvs(h.err());
    esp_err_t e = nvs_erase_key(h.get(), key);
    if (e == ESP_ERR_NVS_NOT_FOUND) return HAL_OK;
    if (e == ESP_OK) e = nvs_commit(h.get());
    return map_nvs(e);
}
