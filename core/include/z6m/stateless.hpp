/* z6m/stateless.hpp — Spec-compliant stateless guest API. */
#pragma once
#include <cstddef>
#include <cstdint>

namespace z6m {

/// Output matching StatelessValidatorOutput (Rust) / SszStatelessValidationResult (spec).
/// Serialised as: root[0..32] || success[32]  (33 bytes), then SHA-256'd before commit.
struct StatelessValidatorOutput {
    uint8_t new_payload_request_root[32];
    bool    successful_validation;
};

/// Run the full spec-compliant stateless guest flow on SSZ-encoded SszStatelessInput.
/// Spec ref: stateless_guest.py::run_stateless_guest
StatelessValidatorOutput run_stateless_guest(const uint8_t* data, size_t len);

} // namespace z6m
