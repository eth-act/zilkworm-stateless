/* z6m/stateless.hpp — Spec-compliant stateless guest API. */
#pragma once
#include <cstddef>
#include <cstdint>

namespace z6m {

/// Two-byte big-endian schema identifier prefixing the SSZ `SszStatelessInput`
/// on the wire (EIP-8025 / stateless_ssz.py). The spec fixes this to the
/// Amsterdam payload shape.
///
/// Matches `stateless-validator-common` (ere-guests) constants
/// `STATELESS_INPUT_SCHEMA_ID` / `STATELESS_INPUT_SCHEMA_ID_SIZE`.
static constexpr uint16_t STATELESS_INPUT_SCHEMA_ID      = 0x0001;
static constexpr size_t   STATELESS_INPUT_SCHEMA_ID_SIZE = 2;

/// Output mirroring `StatelessValidatorOutput` in ere-guests
/// `stateless-validator-common` (tag v0.12.1).
///
/// Canonical serialisation (`serialize()` in the Rust type), 41 bytes:
///   root[0..32] || (successful_validation as u8)[32] || chain_id LE[33..41]
/// The guest commits `SHA-256(serialize())` (32 bytes) as its public values;
/// zkboost checks `public_values[..32] == sha256(serialize())`.
struct StatelessValidatorOutput {
    uint8_t  new_payload_request_root[32];
    bool     successful_validation;
    uint64_t chain_id;
};

/// Byte length of the canonical serialised output.
static constexpr size_t STATELESS_VALIDATOR_OUTPUT_SIZE = 32 + 1 + 8;

/// Run the full spec-compliant stateless guest flow on the wire input:
/// a 2-byte big-endian schema id (`STATELESS_INPUT_SCHEMA_ID`) followed by the
/// SSZ-encoded `SszStatelessInput`. An absent/mismatched prefix yields a
/// deterministic failure output (zeroed root, `successful_validation = false`).
/// Spec ref: stateless_guest.py::run_stateless_guest
StatelessValidatorOutput run_stateless_guest(const uint8_t* data, size_t len);

/// Build the canonical 41-byte serialisation and SHA-256 it into `digest`,
/// producing the 32-byte public-values commitment every zkVM target writes.
/// Keeping this in the core guarantees byte-identical output across every zkVM target.
void commit_public_values(const StatelessValidatorOutput& out, uint8_t digest[32]);

} // namespace z6m
