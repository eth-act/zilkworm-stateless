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
static constexpr size_t PAYLOAD_FIXED     = 532;
static constexpr size_t NPR_FIXED         = 44;
static constexpr size_t WITNESS_FIXED     = 12;
// SszStatelessInput fixed header (spec / stateless_ssz.py): four u32 offsets
// (new_payload_request, witness, chain_config, public_keys) = 16 bytes.
// chain_config is offset-referenced (variable field), confirmed against the
// canonical spec-CLI output (int-test-risc0/real_input.bin).
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

static SszExecutionPayload decode_execution_payload(ByteSpan s) {
    SszExecutionPayload p{};
    if (s.len < PAYLOAD_FIXED) return p;
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
    uint32_t off_bal  = read_u32le(next(4));
    uint32_t total    = static_cast<uint32_t>(s.len);
    p.extra_data        = s.slice(off_extra, off_tx - off_extra);
    p.transactions      = decode_bytelist_list(s.slice(off_tx, off_wdl - off_tx));
    p.withdrawals       = decode_fixed_list<SszWithdrawal>(
        s.slice(off_wdl, off_bal - off_wdl), SSZ_WITHDRAWAL_FIXED_SIZE, decode_withdrawal);
    p.block_access_list = s.slice(off_bal, total - off_bal);
    return p;
}

static SszNewPayloadRequest decode_new_payload_request(ByteSpan s) {
    SszNewPayloadRequest r{};
    if (s.len < NPR_FIXED) return r;
    uint32_t off_payload = read_u32le(s.ptr);
    uint32_t off_hashes  = read_u32le(s.ptr + 4);
    std::memcpy(r.parent_beacon_block_root, s.ptr + 8, 32);
    uint32_t off_er = read_u32le(s.ptr + 40);
    uint32_t total  = static_cast<uint32_t>(s.len);
    r.execution_payload = decode_execution_payload(s.slice(off_payload, off_hashes - off_payload));
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

static SszStatelessInput decode_stateless_input(ByteSpan s) {
    SszStatelessInput si{};
    if (s.len < STATELESS_INPUT_FIXED) return si;
    // Canonical StatelessInput (stateless_ssz.py, confirmed against spec-CLI
    // output real_input.bin): all four fields are offset-referenced, so the fixed
    // header is 4 u32 offsets = 16 bytes. chain_config is a variable field whose
    // payload is the 8-byte chain_id.
    uint32_t off_npr = read_u32le(s.ptr);
    uint32_t off_wit = read_u32le(s.ptr + 4);
    uint32_t off_cc  = read_u32le(s.ptr + 8);
    uint32_t off_pk  = read_u32le(s.ptr + 12);
    uint32_t total   = static_cast<uint32_t>(s.len);
    si.new_payload_request  = decode_new_payload_request(s.slice(off_npr, off_wit - off_npr));
    si.witness              = decode_witness(s.slice(off_wit, off_cc - off_wit));
    si.chain_config.chain_id = read_u64le(s.ptr + off_cc);
    si.public_keys          = decode_bytelist_list(s.slice(off_pk, total - off_pk));
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
    merkleize(root, chunks.data(), n, limit);
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
    uint8_t f[18][32] = {};
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
        merkleize(root, chunks.data(), ntx, MAX_TRANSACTIONS_PER_PAYLOAD);
        mix_in_length(f[13], root, ntx);
    }
    htr_container_list(f[14], p.withdrawals, MAX_WITHDRAWALS_PER_PAYLOAD, htr_withdrawal);
    htr_uint64(f[15], p.blob_gas_used);
    htr_uint64(f[16], p.excess_blob_gas);
    htr_byte_list(f[17], p.block_access_list.ptr, p.block_access_list.len, MAX_BLOCK_ACCESS_LIST_BYTES);
    htr_container(out, f, 18);
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
        merkleize(root, chunks.data(), n, MAX_BLOB_COMMITMENTS_PER_BLOCK);
        mix_in_length(f[1], root, n);
    }
    htr_uint256(f[2], r.parent_beacon_block_root);
    htr_execution_requests(f[3], r.execution_requests);
    htr_container(out, f, 4);
}

StatelessValidatorOutput run_stateless_guest(const uint8_t* data, size_t len) {
    // Wire format (EIP-8025 / stateless_ssz.py): a 2-byte big-endian schema id
    // followed by the SSZ-encoded SszStatelessInput. Strip and validate the
    // prefix before decoding. A missing/wrong prefix means a malformed request:
    // return a deterministic failure output (zeroed root) rather than decoding
    // untrusted bytes — zkboost then rejects it on root mismatch.
    if (len < STATELESS_INPUT_SCHEMA_ID_SIZE ||
        (static_cast<uint16_t>((data[0] << 8) | data[1]) != STATELESS_INPUT_SCHEMA_ID)) {
        return StatelessValidatorOutput{};
    }
    data += STATELESS_INPUT_SCHEMA_ID_SIZE;
    len  -= STATELESS_INPUT_SCHEMA_ID_SIZE;

    ByteSpan input{data, len};

    SszStatelessInput si = decode_stateless_input(input);

    uint8_t npr_root[32];
    htr_new_payload_request(npr_root, si.new_payload_request);

    bool ok = false;
    evmc::bytes32 computed_state_root{};

    const auto& wit = si.witness;
    const SszExecutionPayload& ep = si.new_payload_request.execution_payload;

    static const silkworm::ChainConfig kAllForksConfig{
        .chain_id                  = 0,
        .homestead_block           = 0,
        .tangerine_whistle_block   = 0,
        .spurious_dragon_block     = 0,
        .byzantium_block           = 0,
        .constantinople_block      = 0,
        .petersburg_block          = 0,
        .istanbul_block            = 0,
        .berlin_block              = 0,
        .london_block              = 0,
        .terminal_total_difficulty = intx::uint256{},
        .merge_netsplit_block      = 0,
        .shanghai_time             = 0,
        .cancun_time               = 0,
        .prague_time               = 0,
        .osaka_time                = 0,
    };
    const silkworm::ChainConfig* const* found =
        silkworm::kKnownChainConfigs.find(si.chain_config.chain_id);
    const silkworm::ChainConfig& chain_cfg = found ? **found : kAllForksConfig;

    if (wit.headers.size() > 256) {
        StatelessValidatorOutput out{};
        std::memcpy(out.new_payload_request_root, npr_root, 32);
        out.successful_validation = false;
        return out;
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
            StatelessValidatorOutput out{};
            std::memcpy(out.new_payload_request_root, npr_root, 32);
            out.successful_validation = false;
            return out;
        }
    }

    // Decode pre-state and MPT witness nodes
    silkworm::InMemoryState state;
    silkworm::mpt::FlatNodeStore node_store;

    if (wit.state.size() >= 1 && wit.state[0].len > 0)
        state = silkworm::read_pre_state_from_rlp({wit.state[0].ptr, wit.state[0].len});

    if (wit.state.size() >= 2 && wit.state[1].len > 0)
        node_store.populate_from_rlp({wit.state[1].ptr, wit.state[1].len});

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
    block.header.base_fee_per_gas = intx::be::load<intx::uint256>(ep.base_fee_per_gas);
    block.header.blob_gas_used   = ep.blob_gas_used;
    block.header.excess_blob_gas = ep.excess_blob_gas;
    {
        evmc::bytes32 pbr{};
        std::memcpy(pbr.bytes, si.new_payload_request.parent_beacon_block_root, 32);
        block.header.parent_beacon_block_root = pbr;
    }

    block.transactions.reserve(ep.transactions.size());
    for (const ByteSpan& ts : ep.transactions) {
        silkworm::Transaction tx;
        silkworm::ByteView view{ts.ptr, ts.len};
        if (silkworm::rlp::decode(view, tx))
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
    out.chain_id              = si.chain_config.chain_id;
    return out;
}

void commit_public_values(const StatelessValidatorOutput& out, uint8_t digest[32]) {
    // Canonical serialisation, mirroring StatelessValidatorOutput::serialize()
    // in ere-guests stateless-validator-common (tag v0.12.1):
    //   root[0..32] || success[32] || chain_id LE[33..41]
    uint8_t buf[STATELESS_VALIDATOR_OUTPUT_SIZE];
    std::memcpy(buf, out.new_payload_request_root, 32);
    buf[32] = out.successful_validation ? 1 : 0;
    const uint64_t chain_id = out.chain_id;
    for (size_t i = 0; i < 8; ++i)
        buf[33 + i] = static_cast<uint8_t>(chain_id >> (8 * i)); // little-endian

    sha256_bytes(digest, buf, STATELESS_VALIDATOR_OUTPUT_SIZE);
}

} // namespace z6m
