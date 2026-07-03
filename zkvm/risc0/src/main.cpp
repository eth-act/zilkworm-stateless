// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* RISC0 stateless-validator guest entry point. */

#include <z6m/stateless.hpp>
#include "include/risc0_syscalls.hpp"

#include <cstdint>
#include <cstring>

extern "C" int main()
{
    // Read SSZ-encoded SszStatelessInput from stdin (length-prefixed frame)
    ReadVecResult input_buf = read_vec_raw();

    // Run spec-compliant stateless validation
    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input_buf.ptr, input_buf.len);

    // Commit SHA-256(root[32] || success[1] || chain_id LE[8]) — 32 bytes.
    uint8_t digest[32];
    z6m::commit_public_values(result, digest);

    syscall_write(RISC0_FD_JOURNAL, digest, sizeof(digest));

    return 0;
}
