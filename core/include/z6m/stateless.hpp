/* z6m/stateless.hpp — Spec-compliant stateless guest API. */
#pragma once
#include <cstddef>
#include <cstdint>

namespace z6m {

/// Two-byte big-endian schema identifier prefixing the SSZ `SszStatelessInput`
/// on the wire (EIP-8025 / stateless_ssz.py).
///
/// Matches `stateless-validator-common` (ere-guests v0.13.0) constants
/// `STATELESS_INPUT_SCHEMA_ID` / `STATELESS_INPUT_SCHEMA_ID_SIZE`.
static constexpr uint16_t STATELESS_INPUT_SCHEMA_ID      = 0x0001;
static constexpr size_t   STATELESS_INPUT_SCHEMA_ID_SIZE = 2;

/// Output mirroring `StatelessValidationResult` in ere-guests
/// `stateless-validator-common` (tag v0.13.0):
///   { new_payload_request_root: Bytes32,
///     successful_validation:    bool,
///     chain_config:             ChainConfig }   // echoed byte-exact from input
///
/// The public values are the plain SSZ encoding (no schema prefix, no hash):
///   root[32] || success[1] || offset(=37)[4] || chain_config bytes
/// `chain_config_ssz` points into the guest input buffer (which outlives the
/// run) or, when decoding failed, at the canonical default-config constant.
struct StatelessValidatorOutput {
    uint8_t        new_payload_request_root[32];
    bool           successful_validation;
    const uint8_t* chain_config_ssz;
    size_t         chain_config_len;
};

/// Upper bound on the encoded public values. The canonical result for a
/// singleton blob schedule is ~105 bytes; 256 keeps headroom while staying
/// within every zkVM's public-output ceiling (OpenVM caps at 256).
static constexpr size_t MAX_PUBLIC_VALUES_SIZE = 256;

/// Run the full spec-compliant stateless guest flow on the wire input:
/// a 2-byte big-endian schema id (`STATELESS_INPUT_SCHEMA_ID`) followed by the
/// SSZ-encoded `SszStatelessInput`. A missing/mismatched prefix or an input
/// that fails to decode yields the canonical default failure output (zero
/// root, `false`, default chain config) — mirroring the Rust guests'
/// `StatelessValidationResult::default()` path.
/// Spec ref: stateless_guest.py::run_stateless_guest
StatelessValidatorOutput run_stateless_guest(const uint8_t* data, size_t len);

/// Encode the canonical SSZ `StatelessValidationResult` public values into
/// `out` (capacity `cap`, use `MAX_PUBLIC_VALUES_SIZE`). Returns the number of
/// bytes written, or 0 if the result does not fit. Keeping this in the core
/// guarantees byte-identical output across every zkVM target.
size_t encode_public_values(const StatelessValidatorOutput& out, uint8_t* buf, size_t cap);

} // namespace z6m
