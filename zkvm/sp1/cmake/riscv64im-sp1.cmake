# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Cross-compilation toolchain for SP1 zkVM guest (rv64im bare-metal).
#
# Requires a RISC-V bare-metal GCC with a bundled newlib sysroot.
# The Homebrew riscv64-elf-gcc does NOT include newlib, so we use the
# xPack riscv-none-elf-gcc toolchain which bundles it.
#
# One-time global install (no project files required):
#   npm install --location=global xpm@latest
#   xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global
#
# CMake will auto-detect the toolchain from:
#   macOS : ~/Library/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/
#   Linux : ~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

# Toolchain auto-detection
file(GLOB _XPACK_HINTS
    "$ENV{HOME}/Library/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin"
    "$ENV{HOME}/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin"
)

find_program(_RISCV_GCC
    NAMES riscv-none-elf-gcc
    HINTS ${_XPACK_HINTS}
)

if(NOT _RISCV_GCC)
    message(FATAL_ERROR
        "Could not find riscv-none-elf-gcc.\n"
        "Install it globally with xpm (no project files required):\n"
        "  npm install --location=global xpm@latest\n"
        "  xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global\n"
    )
endif()

get_filename_component(_RISCV_BIN "${_RISCV_GCC}" DIRECTORY)
message(STATUS "RISC-V toolchain: ${_RISCV_BIN}/riscv-none-elf-*")

set(CMAKE_C_COMPILER   "${_RISCV_BIN}/riscv-none-elf-gcc")
set(CMAKE_CXX_COMPILER "${_RISCV_BIN}/riscv-none-elf-g++")
set(CMAKE_ASM_COMPILER "${_RISCV_BIN}/riscv-none-elf-gcc")
set(CMAKE_AR           "${_RISCV_BIN}/riscv-none-elf-ar")
set(CMAKE_RANLIB       "${_RISCV_BIN}/riscv-none-elf-ranlib")
set(CMAKE_OBJCOPY      "${_RISCV_BIN}/riscv-none-elf-objcopy")


set(BUILD_SHARED_LIBS OFF)

set(_common_flags "-march=rv64im -mabi=lp64 -ffunction-sections -fdata-sections -fno-PIC")
set(_opt_flags    "-O3 -DNDEBUG -fno-stack-protector -fno-builtin-trap")
set(_no_cxx       "-fno-exceptions -fno-rtti -fno-threadsafe-statics")

set(CMAKE_C_FLAGS   "${_common_flags} ${_opt_flags}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${_common_flags} ${_opt_flags} ${_no_cxx}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${_common_flags}" CACHE STRING "" FORCE)

# Suppress CMake's default Release flags so our opt_flags are the sole source.
set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

# Disable features incompatible with bare-metal.
set(BUILD_TESTING              OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API          OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING        OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL   OFF CACHE BOOL "" FORCE)

# Use static-library test mode so CMake's compiler checks pass on bare-metal.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
