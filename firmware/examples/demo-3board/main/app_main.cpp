// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// app_main.cpp - Braid 3-board demo supervisor.
//
// Responsibilities (and nothing more):
//   1. Boot invariants: persistent store (hal_kv_init, NVS).
//   2. Bridge app_hal services into the Braid core (br_platform_t).
//   3. Hand over to the demo (components/app_node, node_app_run()):
//      serial console + NVS configuration, then the pinned tasks of
//      Appendix B / 12.12, identical on ESP32 and ESP32-S3:
//        - "br"  core 1 (APP_CPU): the single protocol task (br_task);
//        - "led" / "btn" core 1: role helpers (probe LED, sender button);
//        - "disp" core 1: optional status display;
//        - "con" core 0 (PRO_CPU): serial console.
//      The radio callbacks run in the Wi-Fi task on core 0 and only enqueue
//      (timeout 0) for "br". See node_app.cpp for the full layout.
//
// The on-chip self-test is a separate image: firmware/main (envs
// esp32_selftest / esp32s3_selftest, firmware/SELFTEST.txt).

#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "soc/soc_caps.h"

#include "hal_kv.h"
#include "hal_result.h"
#include "hal_sys.h"

#include "node_app.h"
#include "braid/br_platform.h"
#include "braid/br_types.h"

namespace {

constexpr char TAG[] = "app";

// ---- br_platform_t bridge (HAL -> core) ----------------------------------

uint64_t plat_now_us(void *) { return hal_sys_time_us(); }

br_err_t plat_random(void *, uint8_t *buf, size_t len) {
    return hal_sys_random_fill(buf, len) == HAL_OK ? BR_OK : BR_ERR_CRYPTO;
}

void plat_log(void *, br_log_level_t level, const char *tag, const char *msg) {
    switch (level) {
        case BR_LOG_ERROR: ESP_LOGE(tag, "%s", msg); break;
        case BR_LOG_WARN:  ESP_LOGW(tag, "%s", msg); break;
        case BR_LOG_INFO:  ESP_LOGI(tag, "%s", msg); break;
        case BR_LOG_DEBUG:
        default:           ESP_LOGD(tag, "%s", msg); break;
    }
}

constexpr br_platform_t kPlatform = {plat_now_us, plat_random, plat_log, nullptr};

}  // namespace

extern "C" void app_main(void) {
    ESP_LOGI(TAG, "Braid node: cores=%d idf=%s", SOC_CPU_CORES_NUM, esp_get_idf_version());

    ESP_ERROR_CHECK(hal_kv_init() == HAL_OK ? ESP_OK : ESP_FAIL);  // boot-time invariant

    ESP_ERROR_CHECK(br_platform_set(&kPlatform) == BR_OK ? ESP_OK : ESP_FAIL);

    node_app_run();  // console + config gate, then the role's pinned tasks
}
