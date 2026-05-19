// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* SP1 stateless-validator guest entry point.
 */

#include <z6m/stateless.hpp>
#include "include/sp1_syscalls.hpp"

#include <cstdint>
#include <cstring>
#include <evmone_precompiles/sha256.hpp>

extern "C" int main()
{
    // Read SSZ-encoded SszStatelessInput
    ReadVecResult input_buf = read_vec_raw();

    // Run spec-compliant stateless validation
    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input_buf.ptr, input_buf.len);

    // Serialise: root[0..32] || success[32] (33 bytes)
    uint8_t raw[33];
    std::memcpy(raw, result.new_payload_request_root, 32);
    raw[32] = result.successful_validation ? 1 : 0;

    // SHA-256 the 33-byte output
    uint8_t digest[32];
    evmone::crypto::sha256(
        reinterpret_cast<std::byte*>(digest),
        reinterpret_cast<const std::byte*>(raw), 33);

    // Write digest to public-values FD; runtime will SHA-256 again
    syscall_write(SP1_FD_PUBLIC_VALUES, digest, sizeof(digest));

    return 0;
}
