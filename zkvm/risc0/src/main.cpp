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

    // Journal layout: root[0..32] || success[32] (33 bytes total, unencrypted)
    //
    // The host can read byte [32] directly to determine validation status.
    // For production proofs the verifier supplies the expected root + status
    // and checks the journal commitment.
    uint8_t journal[33];
    std::memcpy(journal, result.new_payload_request_root, 32);
    journal[32] = result.successful_validation ? 1 : 0;

    // Commit to journal; RISC0 runtime hashes this via its output-state circuit
    syscall_write(RISC0_FD_JOURNAL, journal, sizeof(journal));

    return 0;
}
