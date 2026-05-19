/* z6m/stateless_types.hpp — SSZ container types for Amsterdam stateless validation.
 *
 * Spec reference: stateless_ssz.py (Amsterdam fork)
 *
 * Each struct mirrors the Python Container class in stateless_ssz.py exactly.
 * Field order matches the spec (field order determines SSZ serialization and
 * hash_tree_root calculation).
 *
 * Naming convention: Ssz* matches the Python class names.
 *
 * Maximum length constants match stateless_ssz.py verbatim.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <z6m/ssz.hpp>

// ─── Max-length constants (spec §stateless_ssz.py) ───────────────────────────

static constexpr size_t MAX_EXTRA_DATA_BYTES                    = 32;
static constexpr size_t MAX_BYTES_PER_TRANSACTION               = 1u << 30;
static constexpr size_t MAX_TRANSACTIONS_PER_PAYLOAD            = 1u << 20;
static constexpr size_t MAX_WITHDRAWALS_PER_PAYLOAD             = 1u << 16;   // spec raised from 16
static constexpr size_t MAX_BLOB_COMMITMENTS_PER_BLOCK          = 4096;
static constexpr size_t MAX_DEPOSIT_REQUESTS_PER_PAYLOAD        = 1u << 13;
static constexpr size_t MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD     = 1u << 4;
static constexpr size_t MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD  = 1u << 1;
static constexpr size_t MAX_BLOCK_ACCESS_LIST_BYTES             = 1u << 24;
static constexpr size_t MAX_WITNESS_NODES                       = 1u << 20;
static constexpr size_t MAX_WITNESS_CODES                       = 1u << 16;
static constexpr size_t MAX_WITNESS_HEADERS                     = 256;
static constexpr size_t MAX_BYTES_PER_WITNESS_NODE              = 1u << 20;
static constexpr size_t MAX_BYTES_PER_CODE                      = 1u << 24;
static constexpr size_t MAX_BYTES_PER_HEADER                    = 1u << 10;
static constexpr size_t MAX_PUBLIC_KEYS                         = 1u << 20;
static constexpr size_t MAX_BYTES_PER_PUBLIC_KEY                = 65;

// ─── Opaque byte-span view (no ownership) ────────────────────────────────────
// Reuse ByteSpan from ssz.hpp.

// ─── Decoded container structs ────────────────────────────────────────────────
// These are lightweight views / decoded representations, not full SSZ containers.
// Only the fields needed for hash_tree_root and logical processing are stored.

// SszWithdrawal (spec §stateless_ssz.py::SszWithdrawal)
struct SszWithdrawal {
    uint64_t index;
    uint64_t validator_index;
    uint8_t  address[20];
    uint64_t amount;
};

// SszDepositRequest
struct SszDepositRequest {
    uint8_t  pubkey[48];
    uint8_t  withdrawal_credentials[32];
    uint64_t amount;
    uint8_t  signature[96];
    uint64_t index;
};

// SszWithdrawalRequest
struct SszWithdrawalRequest {
    uint8_t  source_address[20];
    uint8_t  validator_pubkey[48];
    uint64_t amount;
};

// SszConsolidationRequest
struct SszConsolidationRequest {
    uint8_t source_address[20];
    uint8_t source_pubkey[48];
    uint8_t target_pubkey[48];
};

// SszExecutionRequests
struct SszExecutionRequests {
    std::vector<SszDepositRequest>       deposits;
    std::vector<SszWithdrawalRequest>    withdrawals;
    std::vector<SszConsolidationRequest> consolidations;
};

// SszExecutionPayload — all 17 fields per spec
struct SszExecutionPayload {
    uint8_t              parent_hash[32];
    uint8_t              fee_recipient[20];
    uint8_t              state_root[32];
    uint8_t              receipts_root[32];
    uint8_t              logs_bloom[256];
    uint8_t              prev_randao[32];
    uint64_t             block_number;
    uint64_t             gas_limit;
    uint64_t             gas_used;
    uint64_t             timestamp;
    ByteSpan             extra_data;     // ByteList[MAX_EXTRA_DATA_BYTES]
    uint8_t              base_fee_per_gas[32]; // uint256 LE
    uint8_t              block_hash[32];
    std::vector<ByteSpan> transactions;  // List[ByteList[MAX_BYTES_PER_TRANSACTION], MAX_TRANSACTIONS_PER_PAYLOAD]
    std::vector<SszWithdrawal> withdrawals;
    uint64_t             blob_gas_used;
    uint64_t             excess_blob_gas;
    ByteSpan             block_access_list; // ByteList[MAX_BLOCK_ACCESS_LIST_BYTES]
};

// SszNewPayloadRequest
struct SszNewPayloadRequest {
    SszExecutionPayload                      execution_payload;
    std::vector<std::array<uint8_t, 32>>     versioned_hashes; // List[Bytes32, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    uint8_t                                  parent_beacon_block_root[32];
    SszExecutionRequests                     execution_requests;
};

// SszExecutionWitness
struct SszExecutionWitness {
    std::vector<ByteSpan> state;    // List[ByteList[MAX_BYTES_PER_WITNESS_NODE], MAX_WITNESS_NODES]
    std::vector<ByteSpan> codes;    // List[ByteList[MAX_BYTES_PER_CODE], MAX_WITNESS_CODES]
    std::vector<ByteSpan> headers;  // List[ByteList[MAX_BYTES_PER_HEADER], MAX_WITNESS_HEADERS]
};

// SszChainConfig
struct SszChainConfig {
    uint64_t chain_id;
};

// SszStatelessInput (top-level input container)
struct SszStatelessInput {
    SszNewPayloadRequest   new_payload_request;
    SszExecutionWitness    witness;
    SszChainConfig         chain_config;
    std::vector<ByteSpan>  public_keys; // List[ByteList[MAX_BYTES_PER_PUBLIC_KEY], MAX_PUBLIC_KEYS]
};

// ─── SSZ fixed sizes for well-known structures (used during deserialization) ──

// SszWithdrawal is fixed-size: 8+8+20+8 = 44 bytes
static constexpr size_t SSZ_WITHDRAWAL_FIXED_SIZE = 44;

// SszDepositRequest is fixed-size: 48+32+8+96+8 = 192 bytes
static constexpr size_t SSZ_DEPOSIT_REQUEST_FIXED_SIZE = 192;

// SszWithdrawalRequest is fixed-size: 20+48+8 = 76 bytes
static constexpr size_t SSZ_WITHDRAWAL_REQUEST_FIXED_SIZE = 76;

// SszConsolidationRequest is fixed-size: 20+48+48 = 116 bytes
static constexpr size_t SSZ_CONSOLIDATION_REQUEST_FIXED_SIZE = 116;
