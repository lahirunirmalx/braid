// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 lahiru
// node_app.h - phase 1c Braid demo node (sender / relay / probe).
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Boot gate and role start. Preconditions: hal_kv_init() and
// br_platform_set() done. Starts the serial console (UART0, core 0), loads
// the NVS "br" configuration and
//   - with no valid configuration: waits (indefinitely) for `br set ...`;
//   - with one: gives 3 s for console commands, then starts the role:
//     radio, the UART link when `br set uart=on` (second transport, RAW,
//     see src/uart_link.h), protocol task "br" (core 1) and the role's
//     helper task.
// Returns once the role runs, or if the radio failed (logged; the console
// stays up so the configuration can be fixed).
void node_app_run(void);

#ifdef __cplusplus
}
#endif
