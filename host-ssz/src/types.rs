//! Container structs mirroring `stateless_ssz.py` (Amsterdam) and the zilkworm
//! C++ decoder in `core/include/z6m/stateless_types.hpp`.
//!
//! SSZ serialization is derived by `libssz` (lambdaclass/libssz): the derive
//! lays out each container's fixed part (fixed-size fields inline, a 4-byte
//! offset per variable-size field) followed by the variable part, exactly as
//! the guest decoder expects. Variable-length lists are plain `Vec<_>`
//! (`libssz` implements `SszEncode` for `Vec<T>`, `[u8; N]`, and the integers),
//! and fixed byte fields are `[u8; N]`.
//!
//! Consumers fill these from their own block/witness types; [`StatelessInput`]
//! serializes to the canonical schema-prefixed SSZ (see `lib.rs`).

use libssz::SszEncode;
use libssz_derive::SszEncode;

/// `SszWithdrawal` — fixed-size (8 + 8 + 20 + 8 = 44 bytes).
#[derive(Clone, Debug, Default, SszEncode)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

/// `SszDepositRequest` — fixed-size (48 + 32 + 8 + 96 + 8 = 192 bytes).
#[derive(Clone, Debug, SszEncode)]
pub struct DepositRequest {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
    pub index: u64,
}

/// `SszWithdrawalRequest` — fixed-size (20 + 48 + 8 = 76 bytes).
#[derive(Clone, Debug, SszEncode)]
pub struct WithdrawalRequest {
    pub source_address: [u8; 20],
    pub validator_pubkey: [u8; 48],
    pub amount: u64,
}

/// `SszConsolidationRequest` — fixed-size (20 + 48 + 48 = 116 bytes).
#[derive(Clone, Debug, SszEncode)]
pub struct ConsolidationRequest {
    pub source_address: [u8; 20],
    pub source_pubkey: [u8; 48],
    pub target_pubkey: [u8; 48],
}

/// `SszExecutionRequests` — three variable lists of fixed-size elements.
#[derive(Clone, Debug, Default, SszEncode)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
}

/// `SszExecutionPayload` — the 18 spec fields, in order (incl. `block_access_list`).
#[derive(Clone, Debug, SszEncode)]
pub struct ExecutionPayload {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// `ByteList[MAX_EXTRA_DATA_BYTES]`.
    pub extra_data: Vec<u8>,
    /// LE uint256.
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: [u8; 32],
    /// `List[ByteList[MAX_BYTES_PER_TRANSACTION], MAX_TRANSACTIONS_PER_PAYLOAD]`.
    pub transactions: Vec<Vec<u8>>,
    pub withdrawals: Vec<Withdrawal>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    /// `ByteList[MAX_BLOCK_ACCESS_LIST_BYTES]` (EIP-7928).
    pub block_access_list: Vec<u8>,
}

impl Default for ExecutionPayload {
    fn default() -> Self {
        Self {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            base_fee_per_gas: [0; 32],
            block_hash: [0; 32],
            transactions: Vec::new(),
            withdrawals: Vec::new(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Vec::new(),
        }
    }
}

/// `SszNewPayloadRequest`.
#[derive(Clone, Debug, Default, SszEncode)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    pub versioned_hashes: Vec<[u8; 32]>,
    pub parent_beacon_block_root: [u8; 32],
    pub execution_requests: ExecutionRequests,
}

/// `SszExecutionWitness` — three variable `List[ByteList]` fields.
#[derive(Clone, Debug, Default, SszEncode)]
pub struct ExecutionWitness {
    pub state: Vec<Vec<u8>>,
    pub codes: Vec<Vec<u8>>,
    pub headers: Vec<Vec<u8>>,
}

/// `SszChainConfig`.
///
/// In the canonical `SszStatelessInput` this field is **offset-referenced**
/// (variable-size), confirmed against the spec-CLI output `real_input.bin`
/// (16-byte header, `chain_config` at an offset) and the guest decoder, even
/// though its payload is just the 8-byte little-endian `chain_id`. A `libssz`
/// derive would treat a plain `{ chain_id: u64 }` as fixed-size and inline it,
/// so `SszEncode` is implemented by hand to report a variable size while
/// emitting the 8-byte chain_id — reproducing the canonical layout exactly.
#[derive(Clone, Debug, Default)]
pub struct ChainConfig {
    pub chain_id: u64,
}

impl SszEncode for ChainConfig {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        core::mem::size_of::<u64>()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
    }
}

/// `SszStatelessInput` — the top-level container. All four fields are
/// variable-size, so the fixed header is four 4-byte offsets (16 bytes).
#[derive(Clone, Debug, Default, SszEncode)]
pub struct StatelessInput {
    pub new_payload_request: NewPayloadRequest,
    pub witness: ExecutionWitness,
    pub chain_config: ChainConfig,
    /// `List[ByteList[MAX_BYTES_PER_PUBLIC_KEY], MAX_PUBLIC_KEYS]` — 65-byte
    /// uncompressed transaction public keys, in payload order.
    pub public_keys: Vec<Vec<u8>>,
}
