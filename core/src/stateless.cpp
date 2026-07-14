// Stateless guest — SSZ input decoding, hash_tree_root commitment, EVM execution.

#include <z6m/stateless.hpp>
#include <z6m/stateless_types.hpp>
#include <z6m/ssz.hpp>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/execution/execution.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state/in_memory_state.hpp>
#include <zilk_core/core/state/witness_state.hpp>
#include <zilk_core/core/trie_zz/flat_store.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/print.hpp>

#include <cstring>
#include <vector>

namespace z6m {

static SszWithdrawal decode_withdrawal(ByteSpan s) {
    SszWithdrawal w{};
    w.index           = read_u64le(s.ptr);  s = s.from(8);
    w.validator_index = read_u64le(s.ptr);  s = s.from(8);
    std::memcpy(w.address, s.ptr, 20);      s = s.from(20);
    w.amount          = read_u64le(s.ptr);
    return w;
}

static SszDepositRequest decode_deposit_request(ByteSpan s) {
    SszDepositRequest d{};
    std::memcpy(d.pubkey,                s.ptr, 48);  s = s.from(48);
    std::memcpy(d.withdrawal_credentials, s.ptr, 32); s = s.from(32);
    d.amount = read_u64le(s.ptr);                     s = s.from(8);
    std::memcpy(d.signature,             s.ptr, 96);  s = s.from(96);
    d.index  = read_u64le(s.ptr);
    return d;
}

static SszWithdrawalRequest decode_withdrawal_request(ByteSpan s) {
    SszWithdrawalRequest w{};
    std::memcpy(w.source_address,   s.ptr, 20);  s = s.from(20);
    std::memcpy(w.validator_pubkey, s.ptr, 48);  s = s.from(48);
    w.amount = read_u64le(s.ptr);
    return w;
}

static SszConsolidationRequest decode_consolidation_request(ByteSpan s) {
    SszConsolidationRequest c{};
    std::memcpy(c.source_address, s.ptr, 20);  s = s.from(20);
    std::memcpy(c.source_pubkey,  s.ptr, 48);  s = s.from(48);
    std::memcpy(c.target_pubkey,  s.ptr, 48);
    return c;
}

template <typename T, typename DecFn>
static std::vector<T> decode_fixed_list(ByteSpan data, size_t item_size, DecFn fn) {
    std::vector<T> out;
    size_t n = data.len / item_size;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i)
        out.push_back(fn(data.slice(i * item_size, item_size)));
    return out;
}

static std::vector<ByteSpan> decode_bytelist_list(ByteSpan data) {
    std::vector<ByteSpan> out;
    if (data.len < 4) return out;
    uint32_t first = read_u32le(data.ptr);
    if (first % 4 != 0 || first > data.len) return out;
    size_t n = first / 4;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        uint32_t lo = read_u32le(data.ptr + i * 4);
        uint32_t hi = (i + 1 < n)
            ? read_u32le(data.ptr + (i + 1) * 4)
            : static_cast<uint32_t>(data.len);
        out.push_back(data.slice(lo, hi - lo));
    }
    return out;
}

static constexpr size_t EXEC_REQ_FIXED    = 12;
// ExecutionPayloadV3 (ElectraFulu shape): 13 fixed fields + 3 offsets = 528.
static constexpr size_t PAYLOAD_V3_FIXED  = 528;
// ExecutionPayloadV4 (Gloas shape): V3 + block_access_list offset + slot_number.
static constexpr size_t PAYLOAD_V4_FIXED  = 540;
static constexpr size_t NPR_FIXED         = 44;
static constexpr size_t WITNESS_FIXED     = 12;
// ChainConfig fixed part: chain_id u64 + active_fork offset = 12.
static constexpr size_t CHAIN_CONFIG_FIXED = 12;
// ForkConfig fixed part: fork u64 + activation offset + blob_schedule offset = 16.
static constexpr size_t FORK_CONFIG_FIXED  = 16;
// SszStatelessInput fixed header (spec / stateless_ssz.py): four u32 offsets
// (new_payload_request, witness, chain_config, public_keys) = 16 bytes.
// chain_config is offset-referenced (variable field), confirmed against the
// canonical spec-CLI output (tools/real_input/real_input.bin).
static constexpr size_t STATELESS_INPUT_FIXED = 16;

static SszExecutionRequests decode_execution_requests(ByteSpan s) {
    SszExecutionRequests er{};
    if (s.len < EXEC_REQ_FIXED) return er;
    uint32_t off0 = read_u32le(s.ptr);
    uint32_t off1 = read_u32le(s.ptr + 4);
    uint32_t off2 = read_u32le(s.ptr + 8);
    uint32_t end  = static_cast<uint32_t>(s.len);
    er.deposits      = decode_fixed_list<SszDepositRequest>(
        s.slice(off0, off1 - off0), SSZ_DEPOSIT_REQUEST_FIXED_SIZE, decode_deposit_request);
    er.withdrawals   = decode_fixed_list<SszWithdrawalRequest>(
        s.slice(off1, off2 - off1), SSZ_WITHDRAWAL_REQUEST_FIXED_SIZE, decode_withdrawal_request);
    er.consolidations = decode_fixed_list<SszConsolidationRequest>(
        s.slice(off2, end - off2), SSZ_CONSOLIDATION_REQUEST_FIXED_SIZE, decode_consolidation_request);
    return er;
}

// Payload container shape for a fork, mirroring stateless-validator-common
// v0.13.0 `StatelessInput::from_ssz_bytes`.
static PayloadShape payload_shape_for_fork(uint64_t fork) {
    switch (fork) {
        case FORK_PRAGUE:
        case FORK_OSAKA:
        case FORK_BPO1:
        case FORK_BPO2:
            return PayloadShape::ElectraFulu;
        case FORK_AMSTERDAM:
            return PayloadShape::Gloas;
        default:
            // Bellatrix/Capella/Deneb shapes (Paris/Shanghai/Cancun) are out of
            // scope for this guest; BPO3–5 are rejected upstream too.
            return PayloadShape::Unsupported;
    }
}

static SszExecutionPayload decode_execution_payload(ByteSpan s, PayloadShape shape) {
    SszExecutionPayload p{};
    p.shape = shape;
    const size_t fixed =
        (shape == PayloadShape::Gloas) ? PAYLOAD_V4_FIXED : PAYLOAD_V3_FIXED;
    if (s.len < fixed) { p.shape = PayloadShape::Unsupported; return p; }
    size_t cur = 0;
    auto next = [&](size_t n) -> const uint8_t* {
        const uint8_t* r = s.ptr + cur; cur += n; return r;
    };
    std::memcpy(p.parent_hash,    next(32),  32);
    std::memcpy(p.fee_recipient,  next(20),  20);
    std::memcpy(p.state_root,     next(32),  32);
    std::memcpy(p.receipts_root,  next(32),  32);
    std::memcpy(p.logs_bloom,     next(256), 256);
    std::memcpy(p.prev_randao,    next(32),  32);
    p.block_number  = read_u64le(next(8));
    p.gas_limit     = read_u64le(next(8));
    p.gas_used      = read_u64le(next(8));
    p.timestamp     = read_u64le(next(8));
    uint32_t off_extra = read_u32le(next(4));
    std::memcpy(p.base_fee_per_gas, next(32), 32);
    std::memcpy(p.block_hash,       next(32), 32);
    uint32_t off_tx  = read_u32le(next(4));
    uint32_t off_wdl = read_u32le(next(4));
    p.blob_gas_used   = read_u64le(next(8));
    p.excess_blob_gas = read_u64le(next(8));
    uint32_t total    = static_cast<uint32_t>(s.len);
    if (shape == PayloadShape::Gloas) {
        uint32_t off_bal  = read_u32le(next(4));
        p.slot_number     = read_u64le(next(8));
        p.block_access_list = s.slice(off_bal, total - off_bal);
        p.extra_data        = s.slice(off_extra, off_tx - off_extra);
        p.transactions      = decode_bytelist_list(s.slice(off_tx, off_wdl - off_tx));
        p.withdrawals       = decode_fixed_list<SszWithdrawal>(
            s.slice(off_wdl, off_bal - off_wdl), SSZ_WITHDRAWAL_FIXED_SIZE, decode_withdrawal);
    } else {
        p.extra_data        = s.slice(off_extra, off_tx - off_extra);
        p.transactions      = decode_bytelist_list(s.slice(off_tx, off_wdl - off_tx));
        p.withdrawals       = decode_fixed_list<SszWithdrawal>(
            s.slice(off_wdl, total - off_wdl), SSZ_WITHDRAWAL_FIXED_SIZE, decode_withdrawal);
        p.block_access_list = ByteSpan{nullptr, 0};
        p.slot_number       = 0;
    }
    return p;
}

static SszNewPayloadRequest decode_new_payload_request(ByteSpan s, PayloadShape shape) {
    SszNewPayloadRequest r{};
    if (s.len < NPR_FIXED) return r;
    uint32_t off_payload = read_u32le(s.ptr);
    uint32_t off_hashes  = read_u32le(s.ptr + 4);
    std::memcpy(r.parent_beacon_block_root, s.ptr + 8, 32);
    uint32_t off_er = read_u32le(s.ptr + 40);
    uint32_t total  = static_cast<uint32_t>(s.len);
    r.execution_payload =
        decode_execution_payload(s.slice(off_payload, off_hashes - off_payload), shape);
    ByteSpan vh = s.slice(off_hashes, off_er - off_hashes);
    size_t n_vh = vh.len / 32;
    r.versioned_hashes.reserve(n_vh);
    for (size_t i = 0; i < n_vh; ++i) {
        std::array<uint8_t, 32> h;
        std::memcpy(h.data(), vh.ptr + i * 32, 32);
        r.versioned_hashes.push_back(h);
    }
    r.execution_requests = decode_execution_requests(s.slice(off_er, total - off_er));
    return r;
}

static SszExecutionWitness decode_witness(ByteSpan s) {
    SszExecutionWitness w{};
    if (s.len < WITNESS_FIXED) return w;
    uint32_t off_state   = read_u32le(s.ptr);
    uint32_t off_codes   = read_u32le(s.ptr + 4);
    uint32_t off_headers = read_u32le(s.ptr + 8);
    uint32_t total       = static_cast<uint32_t>(s.len);
    w.state   = decode_bytelist_list(s.slice(off_state,   off_codes   - off_state));
    w.codes   = decode_bytelist_list(s.slice(off_codes,   off_headers - off_codes));
    w.headers = decode_bytelist_list(s.slice(off_headers, total       - off_headers));
    return w;
}

// Decode a canonical ChainConfig (v0.13.0):
//   { chain_id: u64, active_fork: ForkConfig }  — active_fork offset-referenced.
//   ForkConfig     = { fork: u64, activation: ForkActivation (offset),
//                      blob_schedule: List[BlobSchedule, 1] (offset) }
//   ForkActivation = { block_number: List[u64, 1] (offset),
//                      timestamp:    List[u64, 1] (offset) }
// The full slice is retained in `raw` for the byte-exact output echo.
static SszChainConfig decode_chain_config(ByteSpan s) {
    SszChainConfig cc{};
    cc.raw = s;
    if (s.len < CHAIN_CONFIG_FIXED) return cc;
    cc.chain_id = read_u64le(s.ptr);
    uint32_t off_fc = read_u32le(s.ptr + 8);
    if (off_fc != CHAIN_CONFIG_FIXED || s.len < off_fc + FORK_CONFIG_FIXED) return cc;

    ByteSpan fc = s.from(off_fc);
    cc.fork = read_u64le(fc.ptr);
    uint32_t off_act = read_u32le(fc.ptr + 8);
    uint32_t off_bs  = read_u32le(fc.ptr + 12);
    if (off_act != FORK_CONFIG_FIXED || off_bs < off_act || off_bs > fc.len) return cc;

    // ForkActivation: two u32 offsets, then 0 or 1 u64 per list.
    ByteSpan act = fc.slice(off_act, off_bs - off_act);
    if (act.len < 8) return cc;
    uint32_t off_bn = read_u32le(act.ptr);
    uint32_t off_ts = read_u32le(act.ptr + 4);
    if (off_bn != 8 || off_ts < off_bn || off_ts > act.len) return cc;
    size_t bn_len = off_ts - off_bn;
    size_t ts_len = act.len - off_ts;
    if ((bn_len != 0 && bn_len != 8) || (ts_len != 0 && ts_len != 8)) return cc;
    if (bn_len == 8) {
        cc.has_activation_block_number = true;
        cc.activation_block_number     = read_u64le(act.ptr + off_bn);
    }
    if (ts_len == 8) {
        cc.has_activation_timestamp = true;
        cc.activation_timestamp     = read_u64le(act.ptr + off_ts);
    }

    // blob_schedule: List[BlobSchedule, 1] — 0 or 24 bytes of fixed items.
    ByteSpan bs = fc.from(off_bs);
    if (bs.len != 0 && bs.len != 24) return cc;
    if (bs.len == 24) {
        cc.blob_schedule.present                  = true;
        cc.blob_schedule.target                   = read_u64le(bs.ptr);
        cc.blob_schedule.max                      = read_u64le(bs.ptr + 8);
        cc.blob_schedule.base_fee_update_fraction = read_u64le(bs.ptr + 16);
    }

    cc.valid = true;
    return cc;
}

// validate_chain_config (spec): at least one activation value must be present,
// and the activation point must be active for the target payload.
static bool validate_chain_config(const SszChainConfig& cc,
                                  uint64_t block_number, uint64_t timestamp) {
    if (!cc.has_activation_block_number && !cc.has_activation_timestamp)
        return false;
    if (cc.has_activation_block_number && block_number < cc.activation_block_number)
        return false;
    if (cc.has_activation_timestamp && timestamp < cc.activation_timestamp)
        return false;
    return true;
}

static SszStatelessInput decode_stateless_input(ByteSpan s) {
    SszStatelessInput si{};
    if (s.len < STATELESS_INPUT_FIXED) return si;
    // Canonical StatelessInput (stateless_ssz.py, confirmed against spec-CLI
    // output real_input.bin): all four fields are offset-referenced, so the fixed
    // header is 4 u32 offsets = 16 bytes.
    uint32_t off_npr = read_u32le(s.ptr);
    uint32_t off_wit = read_u32le(s.ptr + 4);
    uint32_t off_cc  = read_u32le(s.ptr + 8);
    uint32_t off_pk  = read_u32le(s.ptr + 12);
    uint32_t total   = static_cast<uint32_t>(s.len);
    if (off_npr != STATELESS_INPUT_FIXED || off_wit < off_npr || off_cc < off_wit ||
        off_pk < off_cc || off_pk > total)
        return si;

    // Chain config first: its active fork selects the payload container shape.
    si.chain_config = decode_chain_config(s.slice(off_cc, off_pk - off_cc));
    if (!si.chain_config.valid) return si;
    const PayloadShape shape = payload_shape_for_fork(si.chain_config.fork);
    if (shape == PayloadShape::Unsupported) return si;

    si.new_payload_request  = decode_new_payload_request(s.slice(off_npr, off_wit - off_npr), shape);
    if (si.new_payload_request.execution_payload.shape == PayloadShape::Unsupported) return si;
    si.witness              = decode_witness(s.slice(off_wit, off_cc - off_wit));
    si.public_keys          = decode_bytelist_list(s.slice(off_pk, total - off_pk));
    si.valid = true;
    return si;
}

static void htr_withdrawal(uint8_t out[32], const SszWithdrawal& w) {
    uint8_t f[4][32] = {};
    htr_uint64(f[0], w.index);
    htr_uint64(f[1], w.validator_index);
    htr_byte_vector(f[2], w.address, 20);
    htr_uint64(f[3], w.amount);
    htr_container(out, f, 4);
}

static void htr_deposit_request(uint8_t out[32], const SszDepositRequest& d) {
    uint8_t f[5][32] = {};
    htr_byte_vector(f[0], d.pubkey, 48);
    htr_uint256(f[1], d.withdrawal_credentials);
    htr_uint64(f[2], d.amount);
    htr_byte_vector(f[3], d.signature, 96);
    htr_uint64(f[4], d.index);
    htr_container(out, f, 5);
}

static void htr_withdrawal_request(uint8_t out[32], const SszWithdrawalRequest& w) {
    uint8_t f[3][32] = {};
    htr_byte_vector(f[0], w.source_address, 20);
    htr_byte_vector(f[1], w.validator_pubkey, 48);
    htr_uint64(f[2], w.amount);
    htr_container(out, f, 3);
}

static void htr_consolidation_request(uint8_t out[32], const SszConsolidationRequest& c) {
    uint8_t f[3][32] = {};
    htr_byte_vector(f[0], c.source_address, 20);
    htr_byte_vector(f[1], c.source_pubkey, 48);
    htr_byte_vector(f[2], c.target_pubkey, 48);
    htr_container(out, f, 3);
}

template <typename T, typename HtrFn>
static void htr_container_list(uint8_t out[32], const std::vector<T>& items,
                                size_t limit, HtrFn item_htr) {
    size_t n = items.size();
    std::vector<uint8_t> chunks(n * 32, 0);
    for (size_t i = 0; i < n; ++i)
        item_htr(chunks.data() + i * 32, items[i]);
    uint8_t root[32];
    merkleize(root, chunks.data(), n * 32, limit);
    mix_in_length(out, root, n);
}

static void htr_execution_requests(uint8_t out[32], const SszExecutionRequests& er) {
    uint8_t f[3][32] = {};
    htr_container_list(f[0], er.deposits,       MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,       htr_deposit_request);
    htr_container_list(f[1], er.withdrawals,    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,    htr_withdrawal_request);
    htr_container_list(f[2], er.consolidations, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, htr_consolidation_request);
    htr_container(out, f, 3);
}

static void htr_execution_payload(uint8_t out[32], const SszExecutionPayload& p) {
    // ExecutionPayloadV3 (ElectraFulu): 17 fields. ExecutionPayloadV4 (Gloas):
    // 19 fields — V3 + block_access_list + slot_number. Field count changes the
    // container merkleization, so the shape must match the wire exactly.
    uint8_t f[19][32] = {};
    htr_uint256(f[0],  p.parent_hash);
    htr_byte_vector(f[1], p.fee_recipient, 20);
    htr_uint256(f[2],  p.state_root);
    htr_uint256(f[3],  p.receipts_root);
    htr_byte_vector(f[4], p.logs_bloom, 256);
    htr_uint256(f[5],  p.prev_randao);
    htr_uint64(f[6],   p.block_number);
    htr_uint64(f[7],   p.gas_limit);
    htr_uint64(f[8],   p.gas_used);
    htr_uint64(f[9],   p.timestamp);
    htr_byte_list(f[10], p.extra_data.ptr, p.extra_data.len, MAX_EXTRA_DATA_BYTES);
    htr_uint256(f[11], p.base_fee_per_gas);
    htr_uint256(f[12], p.block_hash);
    {
        size_t ntx = p.transactions.size();
        std::vector<uint8_t> chunks(ntx * 32, 0);
        for (size_t i = 0; i < ntx; ++i)
            htr_byte_list(chunks.data() + i * 32,
                          p.transactions[i].ptr, p.transactions[i].len,
                          MAX_BYTES_PER_TRANSACTION);
        uint8_t root[32];
        merkleize(root, chunks.data(), ntx * 32, MAX_TRANSACTIONS_PER_PAYLOAD);
        mix_in_length(f[13], root, ntx);
    }
    htr_container_list(f[14], p.withdrawals, MAX_WITHDRAWALS_PER_PAYLOAD, htr_withdrawal);
    htr_uint64(f[15], p.blob_gas_used);
    htr_uint64(f[16], p.excess_blob_gas);
    if (p.shape == PayloadShape::Gloas) {
        htr_byte_list(f[17], p.block_access_list.ptr, p.block_access_list.len,
                      MAX_BLOCK_ACCESS_LIST_BYTES);
        htr_uint64(f[18], p.slot_number);
        htr_container(out, f, 19);
    } else {
        htr_container(out, f, 17);
    }
}

static void htr_new_payload_request(uint8_t out[32], const SszNewPayloadRequest& r) {
    uint8_t f[4][32] = {};
    htr_execution_payload(f[0], r.execution_payload);
    {
        size_t n = r.versioned_hashes.size();
        std::vector<uint8_t> chunks(n * 32, 0);
        for (size_t i = 0; i < n; ++i)
            std::memcpy(chunks.data() + i * 32, r.versioned_hashes[i].data(), 32);
        uint8_t root[32];
        merkleize(root, chunks.data(), n * 32, MAX_BLOB_COMMITMENTS_PER_BLOCK);
        mix_in_length(f[1], root, n);
    }
    htr_uint256(f[2], r.parent_beacon_block_root);
    htr_execution_requests(f[3], r.execution_requests);
    htr_container(out, f, 4);
}

// Canonical SSZ encoding of `ChainConfig::default()` in
// stateless-validator-common v0.13.0: chain_id 0, Frontier fork, empty
// activation lists, empty blob schedule. Used to mirror the Rust guests'
// `StatelessValidationResult::default()` output when the input fails to
// decode.
static const uint8_t kDefaultChainConfigSsz[36] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // chain_id = 0
    0x0c, 0x00, 0x00, 0x00,                          // offset(active_fork) = 12
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // fork = 0 (Frontier)
    0x10, 0x00, 0x00, 0x00,                          // offset(activation) = 16
    0x18, 0x00, 0x00, 0x00,                          // offset(blob_schedule) = 24
    0x08, 0x00, 0x00, 0x00,                          // activation.block_number off = 8
    0x08, 0x00, 0x00, 0x00,                          // activation.timestamp off = 8
                                                     // (both lists empty; blob empty)
};

// Deterministic failure output for undecodable inputs, mirroring the Rust
// guests: `StatelessValidationResult::default().to_ssz()`.
static StatelessValidatorOutput default_failure_output() {
    StatelessValidatorOutput out{};
    out.successful_validation = false;
    out.chain_config_ssz = kDefaultChainConfigSsz;
    out.chain_config_len = sizeof(kDefaultChainConfigSsz);
    return out;
}

StatelessValidatorOutput run_stateless_guest(const uint8_t* data, size_t len) {
    // Wire format (EIP-8025 / stateless_ssz.py): a 2-byte big-endian schema id
    // followed by the SSZ-encoded SszStatelessInput. Strip and validate the
    // prefix before decoding. A missing/wrong prefix or undecodable body means
    // a malformed request: return the canonical default failure output (zero
    // root, default chain config) — zkboost then rejects it on mismatch.
    if (len < STATELESS_INPUT_SCHEMA_ID_SIZE ||
        (static_cast<uint16_t>((data[0] << 8) | data[1]) != STATELESS_INPUT_SCHEMA_ID)) {
        return default_failure_output();
    }
    data += STATELESS_INPUT_SCHEMA_ID_SIZE;
    len  -= STATELESS_INPUT_SCHEMA_ID_SIZE;

    ByteSpan input{data, len};

    SszStatelessInput si = decode_stateless_input(input);
    if (!si.valid) {
        return default_failure_output();
    }

    uint8_t npr_root[32];
    htr_new_payload_request(npr_root, si.new_payload_request);

    // Prepared early: every path below commits the root + echoed chain config.
    StatelessValidatorOutput failure{};
    std::memcpy(failure.new_payload_request_root, npr_root, 32);
    failure.successful_validation = false;
    failure.chain_config_ssz = si.chain_config.raw.ptr;
    failure.chain_config_len = si.chain_config.raw.len;

    // validate_chain_config (spec): inactive/unset activation fails validation
    // without executing.
    if (!validate_chain_config(si.chain_config,
                               si.new_payload_request.execution_payload.block_number,
                               si.new_payload_request.execution_payload.timestamp)) {
        return failure;
    }

    bool ok = false;
    evmc::bytes32 computed_state_root{};

    const auto& wit = si.witness;
    const SszExecutionPayload& ep = si.new_payload_request.execution_payload;

    // Execution rules come from the INPUT's chain config (spec: the stateless
    // guest runs the state-transition function of `active_fork`), not from a
    // chain_id lookup: devnets/testnets reuse well-known chain ids with their
    // own fork schedules. A stateless guest executes exactly one block, so a
    // config with every fork up to `active_fork` enabled from genesis is the
    // faithful mapping; silkworm's per-fork blob parameters then match the
    // echoed blob schedule (e.g. BPO2 → {14, 21, 11684671}).
    silkworm::ChainConfig chain_cfg{};
    chain_cfg.chain_id                  = si.chain_config.chain_id;
    chain_cfg.homestead_block           = 0;
    chain_cfg.tangerine_whistle_block   = 0;
    chain_cfg.spurious_dragon_block     = 0;
    chain_cfg.byzantium_block           = 0;
    chain_cfg.constantinople_block      = 0;
    chain_cfg.petersburg_block          = 0;
    chain_cfg.istanbul_block            = 0;
    chain_cfg.berlin_block              = 0;
    chain_cfg.london_block              = 0;
    chain_cfg.terminal_total_difficulty = intx::uint256{};
    chain_cfg.merge_netsplit_block      = 0;
    chain_cfg.shanghai_time             = 0;
    chain_cfg.cancun_time               = 0;
    chain_cfg.prague_time               = 0;
    if (si.chain_config.fork >= FORK_OSAKA) chain_cfg.osaka_time = 0;
    if (si.chain_config.fork >= FORK_BPO1)  chain_cfg.bpo1_time  = 0;
    if (si.chain_config.fork >= FORK_BPO2)  chain_cfg.bpo2_time  = 0;
    if (si.chain_config.fork >= FORK_AMSTERDAM) {
        // Amsterdam EVM rules ride on the Osaka+BPO switches silkworm knows;
        // refine when silkworm grows an explicit Amsterdam time switch.
        chain_cfg.bpo3_time = 0;
        chain_cfg.bpo4_time = 0;
    }

    if (wit.headers.size() > 256) {
        return failure;
    }
    // Compute keccak256 of each header RLP so we can check the chain.
    std::vector<evmc::bytes32> header_hashes(wit.headers.size());
    for (size_t i = 0; i < wit.headers.size(); ++i) {
        if (!wit.headers[i].len) { header_hashes[i] = {}; continue; }
        auto h = ethash_keccak256(wit.headers[i].ptr, wit.headers[i].len);
        std::memcpy(header_hashes[i].bytes, h.bytes, 32);
    }
    // Check each header's parent_hash equals hash of the preceding header.
    for (size_t i = 1; i < wit.headers.size(); ++i) {
        if (!wit.headers[i].len) continue;
        silkworm::ByteView rlp{wit.headers[i].ptr, wit.headers[i].len};
        silkworm::BlockHeader hdr;
        if (!silkworm::rlp::decode(rlp, hdr) || hdr.parent_hash != header_hashes[i - 1]) {
            return failure;
        }
    }

    // Canonical witness ingestion (EIP-8025 / stateless_ssz.py): witness.state
    // is a flat list of raw MPT node preimages. Build the node store by
    // hashing each preimage; execution-time reads resolve lazily through the
    // trie from the pre-state root (WitnessState), since leaf keys are
    // keccak(address)/keccak(slot) and cannot be inverted into an eager map.
    silkworm::mpt::FlatNodeStore node_store;
    {
        std::vector<silkworm::ByteView> preimages;
        preimages.reserve(wit.state.size());
        for (const ByteSpan& n : wit.state)
            preimages.emplace_back(n.ptr, n.len);
        node_store.populate_from_preimages(preimages);
    }

    // Pre-state root: state_root of the parent header — matched by hash
    // against the payload's parent_hash (do NOT assume headers[0]). A missing
    // parent leaves the root zeroed: every trie walk then misses, execution
    // diverges, and the block deterministically fails validation.
    evmc::bytes32 pre_state_root{};
    for (size_t i = 0; i < wit.headers.size(); ++i) {
        if (!wit.headers[i].len) continue;
        if (std::memcmp(header_hashes[i].bytes, ep.parent_hash, 32) == 0) {
            silkworm::ByteView rlp{wit.headers[i].ptr, wit.headers[i].len};
            silkworm::BlockHeader parent_hdr;
            if (silkworm::rlp::decode(rlp, parent_hdr))
                pre_state_root = parent_hdr.state_root;
            break;
        }
    }

    silkworm::WitnessState state{node_store, pre_state_root};

    // Register contract bytecode
    for (const ByteSpan& cs : wit.codes) {
        if (!cs.len) continue;
        silkworm::ByteView code{cs.ptr, cs.len};
        silkworm::Bytes code_bytes(code.begin(), code.end());
        auto hash = std::bit_cast<evmc::bytes32>(ethash_keccak256(code.data(), code.size()).bytes);
        state.update_account_code(evmc::address{}, hash, code_bytes);
    }

    // Load ancestor headers
    for (const ByteSpan& hs : wit.headers) {
        if (!hs.len) continue;
        silkworm::ByteView rlp{hs.ptr, hs.len};
        silkworm::Block anc;
        if (silkworm::rlp::decode(rlp, anc.header))
            state.insert_block(anc, anc.header.hash());
    }

    // Build parent/genesis block
    silkworm::Block genesis;
    if (!wit.headers.empty() && wit.headers[0].len > 0) {
        silkworm::ByteView rlp{wit.headers[0].ptr, wit.headers[0].len};
        silkworm::rlp::decode(rlp, genesis.header);
    } else {
        std::memcpy(genesis.header.parent_hash.bytes, ep.parent_hash, 32);
        genesis.header.number = ep.block_number > 0 ? ep.block_number - 1 : 0;
    }

    // Build execution block from SSZ payload
    silkworm::Block block;
    std::memcpy(block.header.parent_hash.bytes,   ep.parent_hash,   32);
    std::memcpy(block.header.beneficiary.bytes,   ep.fee_recipient, 20);
    std::memcpy(block.header.state_root.bytes,    ep.state_root,    32);
    std::memcpy(block.header.receipts_root.bytes, ep.receipts_root, 32);
    std::memcpy(block.header.logs_bloom.data(),   ep.logs_bloom,   256);
    std::memcpy(block.header.prev_randao.bytes,   ep.prev_randao,   32);
    block.header.number          = ep.block_number;
    block.header.gas_limit       = ep.gas_limit;
    block.header.gas_used        = ep.gas_used;
    block.header.timestamp       = ep.timestamp;
    block.header.extra_data      = silkworm::Bytes(ep.extra_data.ptr, ep.extra_data.ptr + ep.extra_data.len);
    // SSZ uint256 is little-endian on the wire (stateless_ssz.py), unlike the
    // RLP/EVM big-endian convention used everywhere else in silkworm.
    block.header.base_fee_per_gas = intx::le::load<intx::uint256>(ep.base_fee_per_gas);
    block.header.blob_gas_used   = ep.blob_gas_used;
    block.header.excess_blob_gas = ep.excess_blob_gas;
    {
        evmc::bytes32 pbr{};
        std::memcpy(pbr.bytes, si.new_payload_request.parent_beacon_block_root, 32);
        block.header.parent_beacon_block_root = pbr;
    }

    // Canonical payload transactions are raw EIP-2718 envelopes (a leading
    // type byte for typed txs, engine-API style) — NOT RLP-string-wrapped.
    // `kBoth` accepts either form; a tx that still fails to decode fails the
    // whole block deterministically rather than being silently skipped
    // (skipping used to hide the divergence until the block-gas check).
    block.transactions.reserve(ep.transactions.size());
    for (const ByteSpan& ts : ep.transactions) {
        silkworm::Transaction tx;
        silkworm::ByteView view{ts.ptr, ts.len};
        if (!silkworm::rlp::decode_transaction(view, tx, silkworm::rlp::Eip2718Wrapping::kBoth)) {
            return failure;
        }
        block.transactions.push_back(std::move(tx));
    }

    block.withdrawals.emplace();
    for (const SszWithdrawal& sw : ep.withdrawals) {
        silkworm::Withdrawal w;
        w.index           = sw.index;
        w.validator_index = sw.validator_index;
        w.amount          = sw.amount;
        std::memcpy(w.address.bytes, sw.address, 20);
        block.withdrawals->push_back(w);
    }

    // PoS blocks have no ommers; roots are computed from decoded body
    block.header.ommers_hash       = silkworm::kEmptyListHash;
    block.header.transactions_root = silkworm::protocol::compute_transaction_root(block);
    block.header.withdrawals_root  = silkworm::protocol::compute_withdrawals_root(block);

    // Execute block
    silkworm::protocol::Blockchain blockchain{state, chain_cfg, genesis};
    silkworm::ValidationResult res = blockchain.insert_block(block, /*check_state_root=*/false);

    if (res == silkworm::ValidationResult::kOk) {
        // Verify post-state root via incremental MPT delta rebuild
        const auto& acc_changes  = state.account_changes().at(block.header.number);
        const auto& stor_changes = state.storage_changes().at(block.header.number);

        std::vector<silkworm::mpt::TrieNodeFlat> acc_updates;
        silkworm::Bytes val_rlp;
        val_rlp.reserve(33);
        for (auto& [addr, acc_opt] : acc_changes) {
            const silkworm::Account& acc = acc_opt.value_or(silkworm::Account{});
            evmc::bytes32 storage_root   = acc.storage_root_;

            auto sit = stor_changes.find(addr);
            if (sit != stor_changes.end()) {
                std::vector<silkworm::mpt::TrieNodeFlat> stor_updates;
                for (auto& [key, val] : sit->second) {
                    auto cur = state.read_storage(addr, key);
                    if (cur == val) continue;
                    val_rlp.clear();
                    silkworm::rlp::encode(val_rlp, silkworm::zeroless_view(cur.bytes));
                    stor_updates.emplace_back(silkworm::keccak_bytes32(key), val_rlp);
                }
                if (!stor_updates.empty()) {
                    if (silkworm::mpt::is_zero_quick(acc.storage_root_))
                        storage_root = silkworm::kEmptyRoot;
                    silkworm::mpt::GridMPT<true> stor_trie{node_store, storage_root};
                    std::sort(stor_updates.begin(), stor_updates.end());
                    storage_root = stor_trie.calc_root_from_updates(stor_updates);
                }
            }

            auto cur_acc = state.read_account(addr);
            if (!cur_acc || (acc == *cur_acc && storage_root == acc.storage_root_)) continue;

            acc_updates.emplace_back(silkworm::keccak_bytes(addr.bytes), cur_acc->rlp(storage_root));
        }

        std::sort(acc_updates.begin(), acc_updates.end());
        auto parent_hdr  = state.read_header(block.header.number - 1, block.header.parent_hash);
        evmc::bytes32 prev_root = parent_hdr ? parent_hdr->state_root : evmc::bytes32{};
        silkworm::mpt::GridMPT<false> acc_trie{node_store, prev_root};
        computed_state_root = acc_trie.calc_root_from_updates(acc_updates);
        ok = (computed_state_root == block.header.state_root);
    }

    StatelessValidatorOutput out{};
    std::memcpy(out.new_payload_request_root, npr_root, 32);
    out.successful_validation = ok;
    out.chain_config_ssz = si.chain_config.raw.ptr;
    out.chain_config_len = si.chain_config.raw.len;
    return out;
}

size_t encode_public_values(const StatelessValidatorOutput& out, uint8_t* buf, size_t cap) {
    // Canonical SSZ of StatelessValidationResult (stateless-validator-common
    // v0.13.0): root[32] || success[1] || offset(=37)[4] || chain_config bytes.
    // chain_config is the only variable field, so its offset equals the fixed
    // part size (32 + 1 + 4 = 37). The chain_config bytes are echoed exactly
    // as decoded from the input.
    static constexpr size_t FIXED = 32 + 1 + 4;
    const size_t total = FIXED + out.chain_config_len;
    if (total > cap) return 0;

    std::memcpy(buf, out.new_payload_request_root, 32);
    buf[32] = out.successful_validation ? 1 : 0;
    const uint32_t offset = FIXED;
    std::memcpy(buf + 33, &offset, 4); // u32 LE
    std::memcpy(buf + FIXED, out.chain_config_ssz, out.chain_config_len);
    return total;
}

} // namespace z6m
