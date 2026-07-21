// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* zkvm-standards c-interface-accelerators — vendor stand-in implementation.
 *
 * The runtimes in this repo play the vendor role until zkVM vendors ship
 * standards-conformant static libraries. This file exports the standard
 * hash accelerators over the per-zkVM accelerated primitives already linked
 * into every guest (zvm1's keccak/sha implementations dispatch to SP1/ZisK/
 * OpenVM syscalls internally). The remaining zkvm_accelerators.h functions
 * (curve ops, modexp, ...) are intentionally not defined yet: consuming
 * code would fail to link rather than silently degrade — they get real
 * implementations when zvm1's internal hooks flip to this ABI (see
 * zkvm/STANDARDS_AUDIT.md §8).
 */

#include "zkvm_accelerators.h"

#include <evmone_precompiles/keccak.hpp>
#include <evmone_precompiles/sha256.hpp>

#include <cstring>

// used+retain: exported ABI surface — keep through -gc-sections even with
// no in-tree callers yet.
extern "C" __attribute__((used, retain)) zkvm_status zkvm_keccak256(
    const uint8_t* data, size_t len, zkvm_keccak256_hash* output) {
    const auto h = ethash::keccak256(data, len);
    std::memcpy(output->data, h.bytes, 32);
    return ZKVM_EOK;
}

extern "C" __attribute__((used, retain)) zkvm_status zkvm_sha256(
    const uint8_t* data, size_t len, zkvm_sha256_hash* output) {
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(output->data),
                           reinterpret_cast<const std::byte*>(data), len);
    return ZKVM_EOK;
}
