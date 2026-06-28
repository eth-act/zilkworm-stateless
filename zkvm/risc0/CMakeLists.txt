# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

# Fetch zilkworm (same tag as SP1 build)
# CMP0169 is unknown on CMake < 3.30; guard so the policy is only set when available.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

include(FetchContent)

FetchContent_Declare(
    zilkworm
    GIT_REPOSITORY https://github.com/developeruche/zilkworm.git
    GIT_TAG        feat/spec-v0.2
    GIT_SHALLOW    TRUE
)

FetchContent_GetProperties(zilkworm)
if(NOT zilkworm_POPULATED)
    FetchContent_Populate(zilkworm)
endif()

# Bootstrap Cable
include(${zilkworm_SOURCE_DIR}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

# Project (rv32im bare-metal for RISC0)
project(z6m_guest_risc0 C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SILKWORM_MAIN_DIR "${zilkworm_SOURCE_DIR}")

# Signal to all compilation units that we are targeting RISC0.
# This enables the `#ifdef RISC0` acceleration guards in evmone, routing the
# crypto operations RISC0 has native accelerators for through ecalls:
#   - SHA-256 compression  -> ecall ecall::SHA    (3)   (sha256.cpp)
#   - 256-bit modular mul  -> ecall ecall::BIGINT (4)   (BN254 base field)
# RISC0 has no native keccak / EC-point / Fp2 accelerator, so those paths fall
# back to evmone's (correct) software implementations.
add_compile_definitions(RISC0)

# Build info
include(CableBuildInfo)
cable_add_buildinfo_library(
    PROJECT_NAME z6m_guest_risc0
    GIT_DESCRIBE ""
    GIT_BRANCH   ""
)

include(GNUInstallDirs)

# Global include path for risc0_syscalls.hpp (used by evmone and zilk_core
# translation units that include it conditionally via #ifdef RISC0).
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src/include")

# zilkworm third-party dependencies
set(_ZW_BIN "${CMAKE_BINARY_DIR}/zilkworm")
add_subdirectory("${zilkworm_SOURCE_DIR}/third_party" "${_ZW_BIN}/third_party")
add_subdirectory("${zilkworm_SOURCE_DIR}/zilk_core"   "${_ZW_BIN}/zilk_core")

# z6m core library
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../core"
    "${CMAKE_BINARY_DIR}/z6m_core"
)

# RISC0 guest binary
set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/linker/risc0.xn")

add_executable(z6m_guest
    src/risc0_entrypoint.S
    src/risc0_runtime.cpp
    src/main.cpp
    src/atomic_stubs.c
    src/memcpy.cpp
    src/memmove.cpp
)

target_include_directories(z6m_guest PRIVATE
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib"
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib/evmone_precompiles"
)

# Bare-metal linker options (rv32im)
target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nostartfiles
    -T${LINKER_SCRIPT}
    -z norelro
    -Wl,--gc-sections
    -Wl,-e,_start
)

# Locate the rv32im/ilp32 sysroot and libgcc
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv32im -mabi=ilp32 -print-sysroot
    OUTPUT_VARIABLE _SYSROOT OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv32im -mabi=ilp32 -print-multi-directory
    OUTPUT_VARIABLE _MULTIDIR OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv32im -mabi=ilp32 -print-libgcc-file-name
    OUTPUT_VARIABLE _LIBGCC_FILE OUTPUT_STRIP_TRAILING_WHITESPACE
)
get_filename_component(_LIBGCC_DIR "${_LIBGCC_FILE}" DIRECTORY)
target_link_directories(z6m_guest PRIVATE
    "${_SYSROOT}/lib/${_MULTIDIR}"
    "${_LIBGCC_DIR}"
)

target_link_libraries(z6m_guest PRIVATE
    z6m_core
    silkworm_dev
    silkworm_core
    evmone
    stdc++ c m gcc nosys
)

target_compile_options(z6m_guest PRIVATE
    -fno-asynchronous-unwind-tables
    $<$<COMPILE_LANGUAGE:CXX>:
        -fno-exceptions
        -fno-rtti
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-class-memaccess
        -Wno-ignored-attributes
        -Wno-psabi
        -Wno-narrowing
        -Wno-attributes
        -Wno-register
        -Wno-unused-function
        -Wno-cpp
        -Wno-int-in-bool-context
    >
)

set_target_properties(z6m_guest PROPERTIES
    SUFFIX                   ".elf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Post-build: flat binary images
set(OBJCOPY "${CMAKE_OBJCOPY}")
if(NOT OBJCOPY)
    find_program(OBJCOPY
        NAMES riscv-none-elf-objcopy riscv64-elf-objcopy
        REQUIRED
    )
endif()

add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${OBJCOPY} -O binary
        "$<TARGET_FILE:z6m_guest>"
        "${CMAKE_BINARY_DIR}/z6m_guest.bin"
    COMMAND ${OBJCOPY} -O binary -j .text
        "$<TARGET_FILE:z6m_guest>"
        "${CMAKE_BINARY_DIR}/z6m_guest.text"
    COMMENT "Generating flat binary images from z6m_guest.elf (RISC0 rv32im)"
)
