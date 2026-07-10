// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* ZisK stateless-validator guest entry point.
 *
 * Mirrors zkvm/sp1/src/main.cpp but uses the ZisK I/O ABI:
 *   - Input  : read_input_raw()  → reads from memory-mapped INPUT_ADDR
 *   - Output : write_output_bytes() → stores u32 LE slots at OUTPUT_ADDR
 *
 * Output format (32 bytes, matching every other zkVM guest):
 *   SHA-256(root[32] || successful_validation[1] || chain_id LE[8])
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

    // Commit SHA-256(root[32] || success[1] || chain_id LE[8]) — 32 bytes.
    uint8_t digest[32];
    z6m::commit_public_values(result, digest);

    write_output_bytes(digest, sizeof(digest));

    return 0;
}
