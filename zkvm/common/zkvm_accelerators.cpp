// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* zkvm-standards c-interface-accelerators — vendor stand-in implementation.
 *
 * The runtimes in this repo play the vendor role until zkVM vendors ship
 * standards-conformant static libraries. Every function of
 * zkvm_accelerators.h is exported over the cryptographic engines already
 * linked into each guest (zvm1's evmone_precompiles), whose inner
 * primitives (keccak-f[1600], SHA-256 compress, bn254 field ops) dispatch
 * to the per-zkVM accelerated syscalls internally.
 *
 * Precompile-shaped operations are marshalled through
 * evmone::state::call_precompile — the exact EEST-tested execution path of
 * the corresponding EVM precompile — rather than re-implementing crypto.
 *
 * NOTE (standards granularity finding): zvm1's acceleration hooks live at
 * the inner-primitive level, below the whole-operation granularity of this
 * ABI. A "pure" vendor library will need to own the full algorithm engines;
 * that lands with the eth-act ere-guests reference vendor libraries.
 */

#include "zkvm_accelerators.h"

#include <evmone_precompiles/keccak.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <evmone_precompiles/sha256.hpp>
#include <evmone/test/state/precompiles.hpp>

#include <evmc/evmc.hpp>

#include <cstring>
#include <span>

#define ZKVM_EXPORT extern "C" __attribute__((used, retain))

namespace {

/// Runs the EVM precompile at address 0x00..<id_hi><id_lo> on `input`,
/// expecting exactly `out_len` output bytes copied to `out`. Uses the
/// latest revision so every registered precompile is available.
bool run_precompile(uint8_t id_lo, uint8_t id_hi, const uint8_t* input, size_t input_len,
    uint8_t* out, size_t out_len) noexcept
{
    evmc::address addr{};
    addr.bytes[18] = id_hi;
    addr.bytes[19] = id_lo;
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 0x7fffffffffffffff;
    msg.recipient = addr;
    msg.code_address = addr;
    msg.input_data = input;
    msg.input_size = input_len;
    const auto res = evmone::state::call_precompile(EVMC_MAX_REVISION, msg);
    if (res.status_code != EVMC_SUCCESS || res.output_size != out_len)
        return false;
    std::memcpy(out, res.output_data, out_len);
    return true;
}

/// EVM ABI encodes a BLS12-381 fp as 64 bytes (16 zero + 48 value).
void pad_fp(uint8_t out[64], const uint8_t in[48]) noexcept
{
    std::memset(out, 0, 16);
    std::memcpy(out + 16, in, 48);
}

void unpad_fp(uint8_t out[48], const uint8_t in[64]) noexcept
{
    std::memcpy(out, in + 16, 48);
}

// EVM-ABI-padded sizes: G1 = 2 fp = 128 bytes, G2 = 4 fp = 256 bytes.
void pad_g1(uint8_t out[128], const uint8_t in[96]) noexcept
{
    pad_fp(out, in);
    pad_fp(out + 64, in + 48);
}
void unpad_g1(uint8_t out[96], const uint8_t in[128]) noexcept
{
    unpad_fp(out, in);
    unpad_fp(out + 48, in + 64);
}
void pad_g2(uint8_t out[256], const uint8_t in[192]) noexcept
{
    for (int i = 0; i < 4; ++i)
        pad_fp(out + 64 * i, in + 48 * i);
}
void unpad_g2(uint8_t out[192], const uint8_t in[256]) noexcept
{
    for (int i = 0; i < 4; ++i)
        unpad_fp(out + 48 * i, in + 64 * i);
}

}  // namespace


ZKVM_EXPORT zkvm_status zkvm_keccak256(
    const uint8_t* data, size_t len, zkvm_keccak256_hash* output)
{
    const auto h = ethash::keccak256(data, len);
    std::memcpy(output->data, h.bytes, 32);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_sha256(const uint8_t* data, size_t len, zkvm_sha256_hash* output)
{
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(output->data),
        reinterpret_cast<const std::byte*>(data), len);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_ripemd160(
    const uint8_t* data, size_t len, zkvm_ripemd160_hash* output)
{
    return run_precompile(0x03, 0, data, len, output->data, 32) ? ZKVM_EOK : ZKVM_EFAIL;
}


ZKVM_EXPORT zkvm_status zkvm_secp256k1_ecrecover(const zkvm_secp256k1_hash* msg,
    const zkvm_secp256k1_signature* sig, uint8_t recid, zkvm_secp256k1_pubkey* output)
{
    if (recid > 1)
        return ZKVM_EFAIL;
    const auto pt = evmmax::secp256k1::secp256k1_ecdsa_recover(
        std::span<const uint8_t, 32>{msg->data, 32},
        std::span<const uint8_t, 32>{sig->data, 32},
        std::span<const uint8_t, 32>{sig->data + 32, 32}, recid != 0);
    if (!pt.has_value())
        return ZKVM_EFAIL;
    pt->x.to_bytes(std::span<uint8_t, 32>{output->data, 32});
    pt->y.to_bytes(std::span<uint8_t, 32>{output->data + 32, 32});
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_secp256k1_verify(const zkvm_secp256k1_hash* msg,
    const zkvm_secp256k1_signature* sig, const zkvm_secp256k1_pubkey* pubkey, bool* verified)
{
    // Verify by recovery: an (r, s) signature is valid for `pubkey` iff one
    // of the two recovery ids recovers exactly that public key.
    *verified = false;
    for (uint8_t recid = 0; recid <= 1; ++recid)
    {
        zkvm_secp256k1_pubkey recovered;
        if (zkvm_secp256k1_ecrecover(msg, sig, recid, &recovered) == ZKVM_EOK &&
            std::memcmp(recovered.data, pubkey->data, 64) == 0)
        {
            *verified = true;
            break;
        }
    }
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_secp256r1_verify(const zkvm_secp256r1_hash* msg,
    const zkvm_secp256r1_signature* sig, const zkvm_secp256r1_pubkey* pubkey, bool* verified)
{
    // P256VERIFY precompile (EIP-7951) at 0x0100: input
    // h(32) ‖ r(32) ‖ s(32) ‖ x(32) ‖ y(32); success output = 32-byte BE 1.
    uint8_t input[160];
    std::memcpy(input, msg->data, 32);
    std::memcpy(input + 32, sig->data, 64);
    std::memcpy(input + 96, pubkey->data, 64);
    uint8_t out[32];
    // P256VERIFY returns empty output for an invalid signature (not a failure
    // of the primitive itself).
    evmc::address addr{};
    addr.bytes[18] = 0x01;
    evmc_message msg2{};
    msg2.kind = EVMC_CALL;
    msg2.gas = 0x7fffffffffffffff;
    msg2.recipient = addr;
    msg2.code_address = addr;
    msg2.input_data = input;
    msg2.input_size = sizeof(input);
    const auto res = evmone::state::call_precompile(EVMC_MAX_REVISION, msg2);
    if (res.status_code != EVMC_SUCCESS)
        return ZKVM_EFAIL;
    *verified = res.output_size == 32 && res.output_data[31] == 1;
    (void)out;
    return ZKVM_EOK;
}


ZKVM_EXPORT zkvm_status zkvm_modexp(const uint8_t* base, size_t base_len, const uint8_t* exp,
    size_t exp_len, const uint8_t* mod, size_t mod_len, uint8_t* output)
{
    // EVM ABI: base_len(32) ‖ exp_len(32) ‖ mod_len(32) ‖ base ‖ exp ‖ mod.
    // Operand sizes bounded per EIP-7823 (1024 bytes) — stack buffer suffices.
    if (base_len > 1024 || exp_len > 1024 || mod_len > 1024)
        return ZKVM_EFAIL;
    uint8_t input[96 + 3 * 1024] = {};
    const auto put_len = [&input](size_t off, size_t v) {
        for (int i = 0; i < 8; ++i)
            input[off + 31 - static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
    };
    put_len(0, base_len);
    put_len(32, exp_len);
    put_len(64, mod_len);
    uint8_t* p = input + 96;
    std::memcpy(p, base, base_len);
    p += base_len;
    std::memcpy(p, exp, exp_len);
    p += exp_len;
    std::memcpy(p, mod, mod_len);
    const size_t input_len = 96 + base_len + exp_len + mod_len;
    return run_precompile(0x05, 0, input, input_len, output, mod_len) ? ZKVM_EOK : ZKVM_EFAIL;
}

/* ── BN254 ──────────────────────────────────────────────────────────────── */

ZKVM_EXPORT zkvm_status zkvm_bn254_g1_add(
    const zkvm_bn254_g1_point* p1, const zkvm_bn254_g1_point* p2, zkvm_bn254_g1_point* output)
{
    uint8_t input[128];
    std::memcpy(input, p1->data, 64);
    std::memcpy(input + 64, p2->data, 64);
    return run_precompile(0x06, 0, input, sizeof(input), output->data, 64) ? ZKVM_EOK :
                                                                             ZKVM_EFAIL;
}

ZKVM_EXPORT zkvm_status zkvm_bn254_g1_mul(
    const zkvm_bn254_g1_point* point, const zkvm_bn254_scalar* scalar, zkvm_bn254_g1_point* output)
{
    uint8_t input[96];
    std::memcpy(input, point->data, 64);
    std::memcpy(input + 64, scalar->data, 32);
    return run_precompile(0x07, 0, input, sizeof(input), output->data, 64) ? ZKVM_EOK :
                                                                             ZKVM_EFAIL;
}

ZKVM_EXPORT zkvm_status zkvm_bn254_pairing(
    const zkvm_bn254_pairing_pair* pairs, size_t num_pairs, bool* output)
{
    // The EVM ABI pair layout (g1 ‖ g2, 192 bytes) matches the struct layout.
    static_assert(sizeof(zkvm_bn254_pairing_pair) == 192);
    uint8_t out[32];
    if (!run_precompile(
            0x08, 0, reinterpret_cast<const uint8_t*>(pairs), num_pairs * 192, out, 32))
        return ZKVM_EFAIL;
    *output = out[31] == 1;
    return ZKVM_EOK;
}

/* ── BLAKE2f ────────────────────────────────────────────────────────────── */

ZKVM_EXPORT zkvm_status zkvm_blake2f(uint32_t rounds, zkvm_blake2f_state* state,
    const zkvm_blake2f_message* message, const zkvm_blake2f_offset* offset, uint8_t final_block)
{
    // EVM ABI: rounds(4 BE) ‖ h(64) ‖ m(128) ‖ t(16) ‖ f(1) = 213 bytes.
    uint8_t input[213];
    input[0] = static_cast<uint8_t>(rounds >> 24);
    input[1] = static_cast<uint8_t>(rounds >> 16);
    input[2] = static_cast<uint8_t>(rounds >> 8);
    input[3] = static_cast<uint8_t>(rounds);
    std::memcpy(input + 4, state->data, 64);
    std::memcpy(input + 68, message->data, 128);
    std::memcpy(input + 196, offset->data, 16);
    input[212] = final_block;
    return run_precompile(0x09, 0, input, sizeof(input), state->data, 64) ? ZKVM_EOK :
                                                                            ZKVM_EFAIL;
}

/* ── KZG point evaluation ───────────────────────────────────────────────── */

ZKVM_EXPORT zkvm_status zkvm_kzg_point_eval(const zkvm_kzg_commitment* commitment,
    const zkvm_kzg_field_element* z, const zkvm_kzg_field_element* y, const zkvm_kzg_proof* proof,
    bool* verified)
{
    // EVM ABI: versioned_hash(32) ‖ z(32) ‖ y(32) ‖ commitment(48) ‖ proof(48),
    // where versioned_hash = 0x01 ‖ sha256(commitment)[1..32).
    uint8_t input[192];
    zkvm_sha256_hash vh;
    if (zkvm_sha256(commitment->data, 48, &vh) != ZKVM_EOK)
        return ZKVM_EFAIL;
    vh.data[0] = 0x01;
    std::memcpy(input, vh.data, 32);
    std::memcpy(input + 32, z->data, 32);
    std::memcpy(input + 64, y->data, 32);
    std::memcpy(input + 96, commitment->data, 48);
    std::memcpy(input + 144, proof->data, 48);
    uint8_t out[64];
    *verified = run_precompile(0x0a, 0, input, sizeof(input), out, 64);
    return ZKVM_EOK;
}

/* ── BLS12-381 ──────────────────────────────────────────────────────────── */

ZKVM_EXPORT zkvm_status zkvm_bls12_g1_add(const zkvm_bls12_381_g1_point* p1,
    const zkvm_bls12_381_g1_point* p2, zkvm_bls12_381_g1_point* output)
{
    uint8_t input[256];
    uint8_t out[128];
    pad_g1(input, p1->data);
    pad_g1(input + 128, p2->data);
    if (!run_precompile(0x0b, 0, input, sizeof(input), out, 128))
        return ZKVM_EFAIL;
    unpad_g1(output->data, out);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_g1_msm(
    const zkvm_bls12_381_g1_msm_pair* pairs, size_t num_pairs, zkvm_bls12_381_g1_point* output)
{
    if (num_pairs == 0 || num_pairs > 64)
        return ZKVM_EFAIL;
    uint8_t input[64 * 160];
    uint8_t out[128];
    for (size_t i = 0; i < num_pairs; ++i)
    {
        pad_g1(input + i * 160, pairs[i].point.data);
        std::memcpy(input + i * 160 + 128, pairs[i].scalar.data, 32);
    }
    if (!run_precompile(0x0c, 0, input, num_pairs * 160, out, 128))
        return ZKVM_EFAIL;
    unpad_g1(output->data, out);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_g2_add(const zkvm_bls12_381_g2_point* p1,
    const zkvm_bls12_381_g2_point* p2, zkvm_bls12_381_g2_point* output)
{
    uint8_t input[512];
    uint8_t out[256];
    pad_g2(input, p1->data);
    pad_g2(input + 256, p2->data);
    if (!run_precompile(0x0d, 0, input, sizeof(input), out, 256))
        return ZKVM_EFAIL;
    unpad_g2(output->data, out);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_g2_msm(
    const zkvm_bls12_381_g2_msm_pair* pairs, size_t num_pairs, zkvm_bls12_381_g2_point* output)
{
    if (num_pairs == 0 || num_pairs > 32)
        return ZKVM_EFAIL;
    uint8_t input[32 * 288];
    uint8_t out[256];
    for (size_t i = 0; i < num_pairs; ++i)
    {
        pad_g2(input + i * 288, pairs[i].point.data);
        std::memcpy(input + i * 288 + 256, pairs[i].scalar.data, 32);
    }
    if (!run_precompile(0x0e, 0, input, num_pairs * 288, out, 256))
        return ZKVM_EFAIL;
    unpad_g2(output->data, out);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_pairing(
    const zkvm_bls12_381_pairing_pair* pairs, size_t num_pairs, bool* output)
{
    if (num_pairs == 0 || num_pairs > 32)
        return ZKVM_EFAIL;
    uint8_t input[32 * 384];
    uint8_t out[32];
    for (size_t i = 0; i < num_pairs; ++i)
    {
        pad_g1(input + i * 384, pairs[i].g1.data);
        pad_g2(input + i * 384 + 128, pairs[i].g2.data);
    }
    if (!run_precompile(0x0f, 0, input, num_pairs * 384, out, 32))
        return ZKVM_EFAIL;
    *output = out[31] == 1;
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_map_fp_to_g1(
    const zkvm_bls12_381_fp* field_element, zkvm_bls12_381_g1_point* output)
{
    uint8_t input[64];
    uint8_t out[128];
    pad_fp(input, field_element->data);
    if (!run_precompile(0x10, 0, input, sizeof(input), out, 128))
        return ZKVM_EFAIL;
    unpad_g1(output->data, out);
    return ZKVM_EOK;
}

ZKVM_EXPORT zkvm_status zkvm_bls12_map_fp2_to_g2(
    const zkvm_bls12_381_fp2* field_element, zkvm_bls12_381_g2_point* output)
{
    uint8_t input[128];
    uint8_t out[256];
    pad_fp(input, field_element->data);
    pad_fp(input + 64, field_element->data + 48);
    if (!run_precompile(0x11, 0, input, sizeof(input), out, 256))
        return ZKVM_EFAIL;
    unpad_g2(output->data, out);
    return ZKVM_EOK;
}
