# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# app_hal - vendor-neutral HAL interfaces (header-only).
# The directory and component MUST NOT be named `hal` (collides with the
# ESP-IDF `hal` component). Implementations live in port_esp_idf.
idf_component_register(INCLUDE_DIRS "include")
