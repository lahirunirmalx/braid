# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# Host build of the Braid core (components/app_braid) as a static
# library, plus a CTest hook for unit tests.
#
#   cmake -S firmware/host -B firmware/host/build [-DBR_SANITIZE=ON] [-DMBEDTLS_SRC=/path/to/mbedtls]
#   cmake --build firmware/host/build && ctest --test-dir firmware/host/build
#
# Also builds the host mesh simulator library `brsim` (firmware/sim) and its
# self-tests (firmware/sim/test/test_*.c).
#
# Tests: every firmware/test/host/test_*.c becomes one executable named after
# the file (test_foo.c -> test_foo), linked against braid (which carries
# mbedcrypto and the include dir "braid/..."), registered with CTest.
# A test passes when main() returns 0. Re-run cmake after adding a file
# (the glob uses CONFIGURE_DEPENDS, so a plain rebuild usually picks it up).
cmake_minimum_required(VERSION 3.16)
project(braid_host C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BR_SANITIZE "Build braid and tests with ASan + UBSan" OFF)
option(BR_SELFTEST "Build src/br_selftest.c into braid and the br_selftest ctest target" ON)

set(MBEDTLS_SRC "$ENV{HOME}/.platformio/packages/framework-espidf/components/mbedtls/mbedtls"
    CACHE PATH "mbedtls source tree (default: the one shipped in the PlatformIO ESP-IDF package)")
if(NOT EXISTS "${MBEDTLS_SRC}/CMakeLists.txt")
    message(FATAL_ERROR "MBEDTLS_SRC=${MBEDTLS_SRC} has no CMakeLists.txt; pass -DMBEDTLS_SRC=<mbedtls tree>")
endif()

if(BR_SANITIZE)
    # Applied to everything below (mbedtls included) so UBSan sees the whole
    # call chain and no ASan/non-ASan ABI mix occurs.
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
endif()

# mbedtls from source: library only, its own warnings are not ours.
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory("${MBEDTLS_SRC}" mbedtls EXCLUDE_FROM_ALL)

set(BR_COMPONENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../components/app_braid")
file(GLOB BR_SOURCES CONFIGURE_DEPENDS "${BR_COMPONENT_DIR}/src/*.c")
if(NOT BR_SELFTEST)
    list(FILTER BR_SOURCES EXCLUDE REGEX "/br_selftest\\.c$")
endif()

add_library(braid STATIC ${BR_SOURCES})
target_include_directories(braid
    PUBLIC  "${BR_COMPONENT_DIR}/include"
    PRIVATE "${BR_COMPONENT_DIR}/src")
target_link_libraries(braid PUBLIC MbedTLS::mbedcrypto)
# Four transport slots (espnow + uart + udp + nrf24), the same value as the
# device image (platformio.ini build_flags). PUBLIC: br_node_init() refuses a
# sizeof(br_node_t) mismatch between translation units, so every host target
# that includes br_node.h (brsim, the tests, br_selftest) inherits it here.
target_compile_definitions(braid PUBLIC BR_NODE_MAX_TRANSPORTS=4)
target_compile_options(braid PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wcast-align -Wstrict-prototypes -Wconversion -Wsign-conversion)
if(BR_SELFTEST)
    # Same as the ESP-IDF component with BR_SELFTEST: vectors from test/host, define public.
    target_include_directories(braid PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../test/host")
    target_compile_definitions(braid PUBLIC BR_SELFTEST=1)
endif()

# ---- tests ---------------------------------------------------------------
enable_testing()
file(GLOB BR_TESTS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../test/host/test_*.c")
foreach(test_src IN LISTS BR_TESTS)
    get_filename_component(test_name "${test_src}" NAME_WE)
    add_executable(${test_name} "${test_src}")
    if(test_name MATCHES "^test_scen_")
        # Scenario tests drive br_node through the simulator; brsim carries braid.
        target_link_libraries(${test_name} PRIVATE brsim)
    else()
        target_link_libraries(${test_name} PRIVATE braid)
    endif()
    target_compile_options(${test_name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
# On-chip self-test, run on the host through the same br_selftest_run().
if(BR_SELFTEST)
    add_executable(br_selftest "${CMAKE_CURRENT_SOURCE_DIR}/selftest_main.c")
    target_link_libraries(br_selftest PRIVATE braid)
    target_compile_options(br_selftest PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME br_selftest COMMAND br_selftest)
endif()

# ---- host mesh simulator (firmware/sim) ---------------------------------
# Library brsim: deterministic virtual medium + clock driving real br_node_t
# instances (or test doubles). Self-tests: firmware/sim/test/test_*.c, each
# linked against brsim (+ test/host for test_util.h) and registered in CTest.
set(BR_SIM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../sim")
file(GLOB BRSIM_SOURCES CONFIGURE_DEPENDS "${BR_SIM_DIR}/src/*.c")
add_library(brsim STATIC ${BRSIM_SOURCES})
target_include_directories(brsim PUBLIC "${BR_SIM_DIR}/include")
target_link_libraries(brsim PUBLIC braid)
target_compile_options(brsim PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wcast-align -Wstrict-prototypes -Wconversion -Wsign-conversion)
file(GLOB BRSIM_TESTS CONFIGURE_DEPENDS "${BR_SIM_DIR}/test/test_*.c")
foreach(test_src IN LISTS BRSIM_TESTS)
    get_filename_component(test_name "${test_src}" NAME_WE)
    add_executable(${test_name} "${test_src}")
    target_link_libraries(${test_name} PRIVATE brsim)
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../test/host")
    target_compile_options(${test_name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

list(LENGTH BR_TESTS BR_TEST_COUNT)
message(STATUS "braid: ${BR_TEST_COUNT} host test(s) found in test/host")
