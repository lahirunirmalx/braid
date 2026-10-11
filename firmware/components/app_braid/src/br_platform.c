// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
/*
 * br_platform.c - storage for the injected platform service table.
 *
 * Real (not a stub): it is plumbing, not protocol logic, and main/ needs it
 * to wire the device services.
 */
#include "braid/br_platform.h"

static br_platform_t s_platform;
static bool s_platform_set;

br_err_t br_platform_set(const br_platform_t *p)
{
    if (p == NULL || p->now_us == NULL || p->random_bytes == NULL || p->log == NULL) {
        return BR_ERR_ARG;
    }
    s_platform = *p;
    s_platform_set = true;
    return BR_OK;
}

br_err_t br_platform_get(br_platform_t *out)
{
    if (out == NULL) {
        return BR_ERR_ARG;
    }
    if (!s_platform_set) {
        return BR_ERR_STATE;
    }
    *out = s_platform;
    return BR_OK;
}
