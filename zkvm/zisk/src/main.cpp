// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* ZisK stateless-validator guest entry point.
 *
 * Mirrors zkvm/sp1/src/main.cpp but uses the ZisK I/O ABI:
 *   - Input  : read_input_raw()  → reads from memory-mapped INPUT_ADDR
 *   - Output : write_output_bytes() → stores u32 LE slots at OUTPUT_ADDR
 *
 * Output format (variable length, matching every other zkVM guest): the
 * canonical SSZ StatelessValidationResult —
 *   root[32] || success[1] || offset(=37)[4] || chain_config echo
 */

#include <z6m/stateless.hpp>
#include "include/zisk_syscalls.hpp"

#include <cstdint>
#include <cstring>

extern "C" int main()
{
    ZiskInputBuf input = read_input_raw();
    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input.ptr, input.len);

    // Commit the canonical SSZ StatelessValidationResult (variable length).
    // write_output_bytes zero-pads the final u32 slot; zkboost requires all
    // public-value bytes past the SSZ result to be zero.
    uint8_t pv[z6m::MAX_PUBLIC_VALUES_SIZE];
    const size_t pv_len = z6m::encode_public_values(result, pv, sizeof(pv));

    write_output_bytes(pv, pv_len);

    return 0;
}
