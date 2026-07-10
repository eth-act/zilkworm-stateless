// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* OpenVM stateless-validator guest entry point.
 */

#include <z6m/stateless.hpp>
#include "include/openvm_syscalls.hpp"

#include <cstdint>
#include <cstring>

extern "C" int main()
{
    // Read SSZ-encoded SszStatelessInput
    openvm::ReadVecResult input_buf = read_vec_raw();

    // Run spec-compliant stateless validation
    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input_buf.ptr, input_buf.len);

    // Commit SHA-256(root[32] || success[1] || chain_id LE[8]) — 32 bytes.
    uint8_t digest[32];
    z6m::commit_public_values(result, digest);

    // Publish as 8 public-output words (OpenVM's reveal ABI — see
    // openvm_syscalls.hpp — rather than a single writev-style syscall).
    for (size_t i = 0; i < sizeof(digest) / 4; ++i) {
        uint32_t word;
        std::memcpy(&word, digest + i * 4, 4);
        openvm::reveal_u32(word, i);
    }

    return 0;
}
