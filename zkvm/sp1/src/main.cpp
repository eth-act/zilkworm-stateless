// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* SP1 stateless-validator guest entry point.
 */

#include <z6m/stateless.hpp>
#include "include/sp1_syscalls.hpp"

#include <cstdint>
#include <cstring>

extern "C" int main()
{
    // Read SSZ-encoded SszStatelessInput
    ReadVecResult input_buf = read_vec_raw();

    // Run spec-compliant stateless validation
    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input_buf.ptr, input_buf.len);

    // Commit the canonical SSZ StatelessValidationResult (variable length):
    //   root[32] || success[1] || offset(=37)[4] || chain_config echo
    uint8_t pv[z6m::MAX_PUBLIC_VALUES_SIZE];
    const size_t pv_len = z6m::encode_public_values(result, pv, sizeof(pv));

    syscall_write(SP1_FD_PUBLIC_VALUES, pv, pv_len);

    return 0;
}
