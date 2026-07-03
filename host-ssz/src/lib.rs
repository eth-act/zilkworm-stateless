//! Host-side canonical SSZ encoder for the zilkworm C++ stateless-validator
//! guest input.
//!
//! The zilkworm guest reads a wire payload of a 2-byte big-endian schema id
//! (`0x0001`, Amsterdam) followed by the SSZ-encoded `SszStatelessInput`. This
//! crate produces exactly those bytes from the primitive [`StatelessInput`]
//! (which mirrors `stateless_ssz.py` / the guest's `stateless_types.hpp`), so a
//! host such as zkboost can build guest input without embedding the guest.
//!
//! SSZ serialization is provided by `libssz`; byte compatibility with the guest
//! decoder is guarded by a test that reproduces `int-test/gen_mock_input.py`'s
//! output exactly.

mod types;

use libssz::SszEncode;

pub use types::{
    ChainConfig, ConsolidationRequest, DepositRequest, ExecutionPayload, ExecutionRequests,
    ExecutionWitness, NewPayloadRequest, StatelessInput, Withdrawal, WithdrawalRequest,
};

/// Two-byte big-endian schema identifier (Amsterdam), matching the guest's
/// `STATELESS_INPUT_SCHEMA_ID`.
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x0001;

impl StatelessInput {
    /// Serialize to the canonical wire payload the guest decodes:
    /// `schema_id (u16 BE) || SSZ(SszStatelessInput)`.
    pub fn to_schema_prefixed_ssz(&self) -> Vec<u8> {
        let body = self.to_ssz();
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&STATELESS_INPUT_SCHEMA_ID.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reconstructs the synthetic input produced by `int-test/gen_mock_input.py`
    /// (all-zero block, chain_id = 1, empty witness/lists) and asserts the bytes
    /// match — proving this encoder's layout is identical to what the C++ guest
    /// decodes.
    #[test]
    fn matches_gen_mock_input() {
        let input = StatelessInput {
            new_payload_request: NewPayloadRequest {
                execution_payload: ExecutionPayload {
                    block_number: 1,
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp: 1_700_000_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            witness: ExecutionWitness::default(),
            chain_config: ChainConfig { chain_id: 1 },
            public_keys: Vec::new(),
        };

        let got = input.to_schema_prefixed_ssz();
        let expected = include_bytes!("../testdata/mock_input.bin");
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "encoder output must match gen_mock_input.py byte-for-byte"
        );
    }
}
