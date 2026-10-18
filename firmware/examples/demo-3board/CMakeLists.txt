# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# Braid 3-board demo - ESP-IDF project file (kept in git, unlike
# firmware/CMakeLists.txt which PlatformIO generates): it adds the Braid
# stack components from firmware/components next to this example's own
# components/ (app_node).
cmake_minimum_required(VERSION 3.16.0)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../../version.txt" PROJECT_VER LIMIT_COUNT 1)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(braid_demo_3board)
