# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Native (host) conformance runner: executes the exact guest entrypoint
# (z6m::run_stateless_guest) against EEST stateless fixtures and byte-compares
# the public values with statelessOutputBytes. Fast tier of the EEST
# conformance pipeline (per-PR CI); the zkVM tier reuses the int-test
# harnesses on the same extracted pairs.

cmake_minimum_required(VERSION 3.28)

if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
include(FetchContent)

# Fetch zilkworm (same tag as the guest builds)
FetchContent_Declare(
    zilkworm
    GIT_REPOSITORY https://github.com/developeruche/zilkworm.git
    GIT_TAG        644b6ca2490a9bd52ae0fdd2bfba1bbbd4e5a85d # feat/canonical-witness
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(zilkworm)
if(NOT zilkworm_POPULATED)
    FetchContent_Populate(zilkworm)
endif()

include(${zilkworm_SOURCE_DIR}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

project(z6m_conformance C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SILKWORM_MAIN_DIR "${zilkworm_SOURCE_DIR}")

# Z6M_NATIVE_DEBUG enables stderr diagnostics at failure points in the guest
# core AND the zilkworm engine (native runner only; guest builds never define
# it). Must precede every add_subdirectory to reach all targets.
add_compile_definitions(Z6M_NATIVE_DEBUG)

# Native build — no zkVM defines, no bare-metal flags.
set(_ZW_BIN "${CMAKE_BINARY_DIR}/zilkworm")
add_subdirectory("${zilkworm_SOURCE_DIR}/third_party" "${_ZW_BIN}/third_party")
add_subdirectory("${zilkworm_SOURCE_DIR}/zilk_core"   "${_ZW_BIN}/zilk_core")

# z6m guest core (the exact code the guests run)
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../core"
    "${CMAKE_BINARY_DIR}/z6m_core"
)

add_executable(z6m_conformance
    main.cpp
)

target_include_directories(z6m_conformance PRIVATE
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib"
)

target_link_libraries(z6m_conformance PRIVATE
    z6m_core
    silkworm_core
    silkworm_dev
    evmone
)

target_compile_options(z6m_conformance PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-missing-field-initializers
)
