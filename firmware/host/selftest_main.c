// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * selftest_main.c - host runner for br_selftest_run() (ctest target br_selftest).
 *
 * Installs a host br_platform_t (CLOCK_MONOTONIC, /dev/urandom, stdout) and
 * runs exactly the code the *_selftest firmware envs run on the chip. Prints
 * the same final line as the device:
 *   BR_SELFTEST RESULT: PASS n/n     or     BR_SELFTEST RESULT: FAIL k/n
 * Exit status 0 only on PASS.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>

#include "braid/br_platform.h"
#include "braid/br_selftest.h"

static uint64_t host_now_us(void *user)
{
    (void)user;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static br_err_t host_random(void *user, uint8_t *buf, size_t len)
{
    (void)user;
    if (buf == NULL && len > 0u) {
        return BR_ERR_ARG;
    }
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return BR_ERR_CRYPTO;
    }
    const size_t got = fread(buf, 1u, len, f);
    (void)fclose(f);
    return (got == len) ? BR_OK : BR_ERR_CRYPTO;
}

static void host_log(void *user, br_log_level_t level, const char *tag, const char *msg)
{
    (void)user;
    static const char lv[] = {'E', 'W', 'I', 'D'};
    const char c = ((unsigned)level < sizeof lv) ? lv[level] : '?';
    printf("%c (%s) %s\n", c, tag, msg);
}

int main(void)
{
    const br_platform_t plat = {host_now_us, host_random, host_log, NULL};
    if (br_platform_set(&plat) != BR_OK) {
        printf("br_platform_set failed\n");
        return 2;
    }
    uint32_t run = 0u;
    uint32_t failed = 0u;
    const br_err_t rc = br_selftest_run(&run, &failed);
    if (rc == BR_OK && failed == 0u && run > 0u) {
        printf("BR_SELFTEST RESULT: PASS %lu/%lu\n", (unsigned long)run, (unsigned long)run);
        return 0;
    }
    printf("BR_SELFTEST RESULT: FAIL %lu/%lu (rc %d)\n", (unsigned long)failed, (unsigned long)run, (int)rc);
    return 1;
}
