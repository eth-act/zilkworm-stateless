# z6m_core — platform-agnostic EVM execution library.
#
# This CMakeLists.txt defines the z6m_core static library.
# It is NOT a standalone CMake project — it is always consumed as a
# subdirectory by a zkVM-specific CMakeLists.txt (e.g. zkvm/sp1/CMakeLists.txt)
# which has already fetched zilkworm and defined the required targets:
#   - silkworm_dev   (Blockchain, StateTransition, InMemoryState)
#   - silkworm_core  (EVM types, RLP, trie)
#
# Usage in a zkVM CMakeLists.txt:
#   # After zilkworm targets exist:
#   add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../core" "${CMAKE_BINARY_DIR}/z6m_core")
#   target_link_libraries(my_guest PRIVATE z6m_core)

add_library(z6m_core STATIC
    src/stateless.cpp   # spec-compliant stateless guest logic (Amsterdam fork)
)

# Public include: consumers get <z6m/stateless.hpp> and the ssz.hpp helpers.
# The evmone precompiles path is needed by ssz.hpp (<evmone_precompiles/sha256.hpp>).
target_include_directories(z6m_core
    PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${SILKWORM_MAIN_DIR}/third_party/evmone/lib"
            "${SILKWORM_MAIN_DIR}/third_party/evmone/lib/evmone_precompiles"
)

# evmone provides evmone::crypto::sha256 (ssz.hpp / stateless.cpp).
# silkworm_dev / silkworm_core provide Blockchain, StateTransition, InMemoryState, etc.
target_link_libraries(z6m_core
    PRIVATE
        evmone
        silkworm_dev
        silkworm_core
)

target_compile_features(z6m_core PUBLIC cxx_std_23)
