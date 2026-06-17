cmake_minimum_required(VERSION 3.28)

# CMP0169 is unknown on CMake < 3.30; guard so the policy is only set when available.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
include(FetchContent)

# Fetch zilkworm (same tag as the guest build)
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

# Bootstrap Cable (needed before project())
include(${zilkworm_SOURCE_DIR}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

project(z6m_test C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SILKWORM_MAIN_DIR "${zilkworm_SOURCE_DIR}")

# Native (x86_64) build — no SP1 define, no bare-metal flags
set(_ZW_BIN "${CMAKE_BINARY_DIR}/zilkworm")
add_subdirectory("${zilkworm_SOURCE_DIR}/third_party" "${_ZW_BIN}/third_party")
add_subdirectory("${zilkworm_SOURCE_DIR}/zilk_core"   "${_ZW_BIN}/zilk_core")

# nlohmann/json (already pulled in by zilkworm third-party; expose as target)
# If not available as a cmake target, fetch it directly.
if(NOT TARGET nlohmann_json::nlohmann_json)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

add_executable(z6m_test
    main.cpp
    blockchain_test.cpp
)

target_include_directories(z6m_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib"
)

target_link_libraries(z6m_test PRIVATE
    silkworm_core
    silkworm_dev
    evmone
    nlohmann_json::nlohmann_json
)

target_compile_options(z6m_test PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-missing-field-initializers
)
