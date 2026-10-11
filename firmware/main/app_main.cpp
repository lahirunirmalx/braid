// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// app_main.cpp - Braid node supervisor.
//
// Responsibilities (and nothing more):
//   1. Boot invariants: persistent store (hal_kv_init, NVS).
//   2. Bridge app_hal services into the Braid core (br_platform_t).
//   3. Hand over to the phase 1c demo (components/app_node, node_app_run()):
//      serial console + NVS configuration, then the pinned tasks of
//      Appendix B / 12.12, identical on ESP32 and ESP32-S3:
//        - "br"  core 1 (APP_CPU): the single protocol task (br_task);
//        - "led" / "btn" core 1: role helpers (probe LED, sender button);
//        - "con" core 0 (PRO_CPU): serial console.
//      The radio callbacks run in the Wi-Fi task on core 0 and only enqueue
//      (timeout 0) for "br". See node_app.cpp for the full layout.
//
// BR_SELFTEST builds (envs esp32_selftest / esp32s3_selftest, see
// firmware/SELFTEST.txt) replace the demo with one "selftest" task on
// core 1 that runs br_selftest_run() (Appendix A replay), logs per-group
// timing (br_platform_t.now_us -> hal_sys_time_us -> esp_timer), stack
// high-water mark and heap before / after, then prints
// "BR_SELFTEST RESULT: PASS n/n" or "BR_SELFTEST RESULT: FAIL k/n".

#include <cinttypes>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/soc_caps.h"

#include "hal_kv.h"
#include "hal_result.h"
#include "hal_sys.h"

#include "node_app.h"
#include "braid/br_platform.h"
#include "braid/br_types.h"

#if defined(BR_SELFTEST) && BR_SELFTEST
#include "esp_heap_caps.h"
#include "braid/br_selftest.h"
#endif

namespace {

constexpr char TAG[] = "app";

#if SOC_CPU_CORES_NUM >= 2
constexpr BaseType_t kCoreBr = 1;  // APP_CPU: br_task / selftest (Appendix B)
#else
constexpr BaseType_t kCoreBr = 0;  // single-core fallback (not a Braid target)
#endif

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

#if defined(BR_SELFTEST) && BR_SELFTEST
// Stack: known worst frames in the core are br_rs_decode 896 B and the CCM
// path 432 B (+ mbedtls AES / SHA). The selftest keeps frame buffers static,
// but every log line goes through plat_log -> ESP_LOGx (newlib formatted output,
// about 1.5 KB) with a 160-byte line on the stack. ~3 KB expected; 8 KB
// gives > 2x margin.
// The measured high-water mark is logged below; size br_task from it.
constexpr uint32_t kStackSelftest = 8192;
constexpr UBaseType_t kPrioSelftest = tskIDLE_PRIORITY + 5;
constexpr TickType_t kResultRepeat = pdMS_TO_TICKS(10000);

void plat_log_quiet(void *, br_log_level_t, const char *, const char *) {}

void selftest_task(void *) {
    constexpr uint32_t kCaps = MALLOC_CAP_DEFAULT;

    // Warm-up pass with logging muted: absorbs one-time lazy allocations
    // outside the core (e.g. newlib / driver locks created on first use of
    // the AES and SHA engines), so the measured pass shows steady state.
    {
        const br_platform_t quiet = {plat_now_us, plat_random, plat_log_quiet, nullptr};
        uint32_t wr = 0;
        uint32_t wf = 0;
        const size_t w0 = heap_caps_get_free_size(kCaps);
        ESP_ERROR_CHECK(br_platform_set(&quiet) == BR_OK ? ESP_OK : ESP_FAIL);
        (void)br_selftest_run(&wr, &wf);
        ESP_ERROR_CHECK(br_platform_set(&kPlatform) == BR_OK ? ESP_OK : ESP_FAIL);
        const size_t w1 = heap_caps_get_free_size(kCaps);
        ESP_LOGI(TAG, "selftest warm-up: %" PRIu32 " checks, %" PRIu32 " failed, heap delta %d (one-time lazy init)",
                 wr, wf, static_cast<int>(w1) - static_cast<int>(w0));
    }

    const size_t heap_before = heap_caps_get_free_size(kCaps);
    // Track the lowest free heap during the run (transient allocations).
    const bool monitoring = heap_caps_monitor_local_minimum_free_size_start() == ESP_OK;

    uint32_t run = 0;
    uint32_t failed = 0;
    const uint64_t t0 = hal_sys_time_us();
    const br_err_t rc = br_selftest_run(&run, &failed);
    const uint64_t t1 = hal_sys_time_us();

    const size_t heap_low = monitoring ? heap_caps_get_minimum_free_size(kCaps) : 0;
    if (monitoring) {
        (void)heap_caps_monitor_local_minimum_free_size_stop();
    }
    const size_t heap_after = heap_caps_get_free_size(kCaps);
    const uint32_t hwm_free = static_cast<uint32_t>(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t));

    ESP_LOGI(TAG, "selftest: %" PRIu32 " checks, %" PRIu32 " failed, rc=%d, total %" PRIu64 " us", run, failed,
             static_cast<int>(rc), t1 - t0);
    ESP_LOGI(TAG, "selftest stack: %" PRIu32 " of %" PRIu32 " bytes used (high-water mark %" PRIu32 " free)",
             kStackSelftest - hwm_free, kStackSelftest, hwm_free);
    ESP_LOGI(TAG, "selftest heap: free before=%u after=%u delta=%d", static_cast<unsigned>(heap_before),
             static_cast<unsigned>(heap_after), static_cast<int>(heap_after) - static_cast<int>(heap_before));
    if (monitoring) {
        ESP_LOGI(TAG, "selftest heap: lowest during run=%u, peak transient use=%u bytes "
                      "(expected: br_crypto_init HMAC state only, freed after each crypto group)",
                 static_cast<unsigned>(heap_low), static_cast<unsigned>(heap_before - heap_low));
    }

    const bool pass = (rc == BR_OK) && (failed == 0) && (run > 0) && (heap_after == heap_before);
    if (heap_after != heap_before) {
        ESP_LOGE(TAG, "selftest heap: free heap changed across the run (leak or foreign allocation)");
    }
    for (;;) {
        if (pass) {
            ESP_LOGI(TAG, "BR_SELFTEST RESULT: PASS %" PRIu32 "/%" PRIu32, run, run);
        } else {
            ESP_LOGE(TAG, "BR_SELFTEST RESULT: FAIL %" PRIu32 "/%" PRIu32, failed, run);
        }
        vTaskDelay(kResultRepeat);  // repeat for a monitor attached late; press RST to rerun
    }
}
#endif  // BR_SELFTEST

}  // namespace

extern "C" void app_main(void) {
    ESP_LOGI(TAG, "Braid node: cores=%d idf=%s", SOC_CPU_CORES_NUM, esp_get_idf_version());

    ESP_ERROR_CHECK(hal_kv_init() == HAL_OK ? ESP_OK : ESP_FAIL);  // boot-time invariant

    ESP_ERROR_CHECK(br_platform_set(&kPlatform) == BR_OK ? ESP_OK : ESP_FAIL);

#if defined(BR_SELFTEST) && BR_SELFTEST
    // Selftest build: only the selftest task, so heap and log are not shared.
    const BaseType_t st = xTaskCreatePinnedToCore(selftest_task, "selftest", kStackSelftest, nullptr,
                                                  kPrioSelftest, nullptr, kCoreBr);
    ESP_ERROR_CHECK(st == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_LOGI(TAG, "selftest task up on core%d, stack %" PRIu32 " bytes", static_cast<int>(kCoreBr), kStackSelftest);
#else
    node_app_run();  // console + config gate, then the role's pinned tasks
#endif
}
