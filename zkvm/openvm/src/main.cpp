// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

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

    // Commit the canonical SSZ StatelessValidationResult (variable length):
    //   root[32] || success[1] || offset(=37)[4] || chain_config echo
    // MAX_PUBLIC_VALUES_SIZE (256) matches OpenVM's public-values ceiling.
    uint8_t pv[z6m::MAX_PUBLIC_VALUES_SIZE];
    const size_t pv_len = z6m::encode_public_values(result, pv, sizeof(pv));

    // Publish word-by-word (OpenVM's reveal ABI — see openvm_syscalls.hpp).
    // The final partial word is zero-padded; unrevealed words stay zero, which
    // zkboost requires for all bytes past the SSZ result.
    for (size_t i = 0; i * 4 < pv_len; ++i) {
        uint32_t word = 0;
        const size_t n = (pv_len - i * 4 < 4) ? pv_len - i * 4 : 4;
        std::memcpy(&word, pv + i * 4, n);
        openvm::reveal_u32(word, i);
    }

    return 0;
}
