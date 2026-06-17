# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

# Fetch zilkworm
# We use FetchContent_Populate rather than FetchContent_MakeAvailable so we can
# bootstrap Cable from the fetched source BEFORE calling project().  Cable must
# come first because it manipulates cmake_policy before the project is declared.
#
# cmake_policy CMP0169 controls whether the deprecated form of
# FetchContent_Populate is allowed.  We opt in explicitly to silence the warning
# and future-proof against CMake removing the old behaviour.
# Guard with if(POLICY ...) so this is a no-op on CMake < 3.30, which does not
# know this policy yet and would error if we set it unconditionally.
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

# Project 
project(z6m_guest_sp1 C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

# Required by zilkworm's cmake helpers (targets.cmake, etc.)
set(SILKWORM_MAIN_DIR "${zilkworm_SOURCE_DIR}")

# Tell the whole build (zilkworm + core + our binary) that we are targeting SP1.
add_compile_definitions(SP1)

# Build info
include(CableBuildInfo)
cable_add_buildinfo_library(
    PROJECT_NAME z6m_guest_sp1
    GIT_DESCRIBE ""
    GIT_BRANCH   ""
)

include(GNUInstallDirs)

# Global include path
# sp1_syscalls.hpp is #included by evmone and zilk_core when compiled with -DSP1.
# It must be on the global include path BEFORE those subdirectories are processed.
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src/include")

# zilkworm third-party dependencies (provides evmone, intx, etc.)
set(_ZW_BIN "${CMAKE_BINARY_DIR}/zilkworm")
add_subdirectory("${zilkworm_SOURCE_DIR}/third_party" "${_ZW_BIN}/third_party")
add_subdirectory("${zilkworm_SOURCE_DIR}/zilk_core"   "${_ZW_BIN}/zilk_core")

# z6m core library (SSZ decode, hash_tree_root, stateless EVM execution).
# Must come AFTER zilkworm subdirectories so silkworm_dev / silkworm_core exist.
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../core"
    "${CMAKE_BINARY_DIR}/z6m_core"
)

# SP1 guest binary
set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/linker/elf64lriscv.xn")

add_executable(z6m_guest
    src/sp1_entrypoint.S
    src/sp1_runtime.cpp
    src/main.cpp
    src/atomic_stubs.c
    src/memcpy.cpp
    src/memmove.cpp
)

target_include_directories(z6m_guest PRIVATE
    # evmone precompiles header (sha256.hpp used by sp1_runtime.cpp)
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib"
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib/evmone_precompiles"
)

# Bare-metal linker options.
target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nostartfiles
    -T${LINKER_SCRIPT}
    -z norelro
    -Wl,--gc-sections
    -Wl,-e,_start
)

# Locate the toolchain's rv64im/lp64 sysroot and libgcc so the linker can find
# libc/libm/libgcc even with -nostdlib.
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-sysroot
    OUTPUT_VARIABLE _SYSROOT OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-multi-directory
    OUTPUT_VARIABLE _MULTIDIR OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-libgcc-file-name
    OUTPUT_VARIABLE _LIBGCC_FILE OUTPUT_STRIP_TRAILING_WHITESPACE
)
get_filename_component(_LIBGCC_DIR "${_LIBGCC_FILE}" DIRECTORY)
target_link_directories(z6m_guest PRIVATE
    "${_SYSROOT}/lib/${_MULTIDIR}"
    "${_LIBGCC_DIR}"
)

target_link_libraries(z6m_guest PRIVATE
    z6m_core        # stateless guest logic (SSZ decode, hash_tree_root, EVM execution)
    silkworm_dev    # Blockchain, StateTransition, check_root
    silkworm_core   # EVM types, RLP, trie
    evmone          # SHA-256 precompile used by sp1_runtime.cpp + z6m_core
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
    COMMENT "Generating flat binary images from z6m_guest.elf"
)
