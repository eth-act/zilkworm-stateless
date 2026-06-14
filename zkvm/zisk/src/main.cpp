// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* ZisK stateless-validator guest entry point.
 *
 * Mirrors zkvm/sp1/src/main.cpp but uses the ZisK I/O ABI:
 *   - Input  : read_input_raw()  → reads from memory-mapped INPUT_ADDR
 *   - Output : write_output_bytes() → stores u32 LE slots at OUTPUT_ADDR
 *
 * Output format (33 bytes, matching SP1 and RISC0 guests):
 *   new_payload_request_root[0..32] || successful_validation[32]
 *   where successful_validation is 0x01 (true) or 0x00 (false).
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

    uint8_t raw[33];
    std::memcpy(raw, result.new_payload_request_root, 32);
    raw[32] = result.successful_validation ? 1 : 0;

    write_output_bytes(raw, sizeof(raw));

    return 0;
}
