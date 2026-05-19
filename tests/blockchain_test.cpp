// blockchain_test.cpp — EF BlockchainTest execution using zilkworm

#include "blockchain_test.hpp"
#include "skip_list.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state/in_memory_state.hpp>
#include <zilk_core/core/types/account.hpp>
#include <zilk_core/core/types/block.hpp>

// Fork name → ChainConfig
//
// EF tests activate all forks up to the named level at block/time 0.
// We construct per-fork configs accordingly. The merge is treated as
// "post-merge from genesis" (NoPreMergeConfig, terminal_total_difficulty=0).

static silkworm::ChainConfig make_config(const std::string& network) {
    using C = silkworm::ChainConfig;

    // Helper lambdas for fork activation (all at block/time 0)
    auto pre_london = [](C& c) {
        c.homestead_block        = 0;
        c.tangerine_whistle_block = 0;
        c.spurious_dragon_block  = 0;
        c.byzantium_block        = 0;
        c.constantinople_block   = 0;
        c.petersburg_block       = 0;
        c.istanbul_block         = 0;
        c.berlin_block           = 0;
    };

    C c;
    c.chain_id = 1;
    c.rule_set_config = silkworm::protocol::NoPreMergeConfig{};

    if (network == "Frontier") return c;

    if (network == "Homestead") { c.homestead_block = 0; return c; }
    if (network == "HomesteadToDaoAt5") {
        c.homestead_block = 0; c.dao_block = 5; return c;
    }
    if (network == "HomesteadToEIP150At5") {
        c.homestead_block = 0; c.tangerine_whistle_block = 5; return c;
    }
    if (network == "EIP150") { c.homestead_block = 0; c.tangerine_whistle_block = 0; return c; }
    if (network == "EIP158") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; return c;
    }
    if (network == "EIP158ToByzantiumAt5") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 5; return c;
    }
    if (network == "Byzantium") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0; return c;
    }
    if (network == "ByzantiumToConstantinopleFixAt5") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0;
        c.constantinople_block = 5; c.petersburg_block = 5; return c;
    }
    if (network == "ConstantinopleFix") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0;
        c.constantinople_block = 0; c.petersburg_block = 0; return c;
    }
    if (network == "Istanbul") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0;
        c.constantinople_block = 0; c.petersburg_block = 0;
        c.istanbul_block = 0; return c;
    }
    if (network == "Berlin") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0;
        c.constantinople_block = 0; c.petersburg_block = 0;
        c.istanbul_block = 0; c.berlin_block = 0; return c;
    }
    if (network == "BerlinToLondonAt5") {
        c.homestead_block = 0; c.tangerine_whistle_block = 0;
        c.spurious_dragon_block = 0; c.byzantium_block = 0;
        c.constantinople_block = 0; c.petersburg_block = 0;
        c.istanbul_block = 0; c.berlin_block = 0;
        c.london_block = 5; return c;
    }
    if (network == "London") {
        pre_london(c); c.london_block = 0; return c;
    }
    // Post-merge forks: terminal_total_difficulty = 0 triggers merge at genesis
    auto post_merge = [&](C& cfg) {
        pre_london(cfg);
        cfg.london_block = 0;
        cfg.terminal_total_difficulty = 0;
    };
    if (network == "Merge" || network == "Paris") { post_merge(c); return c; }
    if (network == "ParisToShanghaiAtTime15k") {
        post_merge(c); c.shanghai_time = 15000; return c;
    }
    if (network == "Shanghai") { post_merge(c); c.shanghai_time = 0; return c; }
    if (network == "ShanghaiToCancunAtTime15k") {
        post_merge(c); c.shanghai_time = 0; c.cancun_time = 15000; return c;
    }
    if (network == "Cancun") { post_merge(c); c.shanghai_time = 0; c.cancun_time = 0; return c; }
    if (network == "CancunToPragueAtTime15k") {
        post_merge(c); c.shanghai_time = 0; c.cancun_time = 0; c.prague_time = 15000; return c;
    }
    if (network == "Prague") {
        post_merge(c); c.shanghai_time = 0; c.cancun_time = 0; c.prague_time = 0; return c;
    }
    if (network == "Osaka") {
        post_merge(c); c.shanghai_time = 0; c.cancun_time = 0;
        c.prague_time = 0; c.osaka_time = 0; return c;
    }
    // Unsupported/unknown fork — fall back to mainnet
    return silkworm::kMainnetConfig;
}

// ── Excluded forks ────────────────────────────────────────────────────────────

static bool excluded_fork(const std::string& network) {
    return network == "ByzantiumToConstantinopleAt5"
        || network == "Constantinople"
        || network == "MergeEOF"
        || network == "Merge+3540+3670"
        || network == "MergeMeterInitCode"
        || network == "Merge+3860"
        || network == "MergePush0"
        || network == "Merge+3855";
}

// ── State initialisation from JSON pre-allocation ────────────────────────────

static silkworm::InMemoryState build_initial_state(
    const std::map<evmc::address, EfAccount>& pre)
{
    silkworm::InMemoryState state;
    // begin_block at 0 to record genesis changes
    state.begin_block(0, pre.size());

    for (auto& [addr, ea] : pre) {
        silkworm::Account acc;
        acc.balance  = ea.balance;
        acc.nonce    = ea.nonce;

        if (!ea.code.empty()) {
            auto hash = silkworm::keccak256(ea.code);
            evmc::bytes32 h{};
            std::memcpy(h.bytes, hash.bytes, 32);
            acc.code_hash = h;
            state.update_account_code(addr, h, ea.code);
        }

        state.update_account(addr, std::nullopt, acc);

        for (auto& [key, val] : ea.storage) {
            state.update_storage(addr, key, {}, val);
        }
    }

    return state;
}

// Build silkworm::Block from RLP bytes

static std::optional<silkworm::Block> decode_block_rlp(const silkworm::Bytes& rlp) {
    silkworm::Block block;
    silkworm::ByteView view{rlp.data(), rlp.size()};
    if (!silkworm::rlp::decode(view, block)) return std::nullopt;
    return block;
}

// Run one BlockchainTest

static TestReport run_single_test(const EfBlockchainTest& tc) {
    if (excluded_fork(tc.network))
        return {TestResult::Skip, "excluded fork: " + tc.network};

    silkworm::ChainConfig chain_cfg = make_config(tc.network);

    // Build genesis block
    silkworm::Block genesis;
    if (tc.genesis_rlp) {
        silkworm::ByteView view{tc.genesis_rlp->data(), tc.genesis_rlp->size()};
        if (!silkworm::rlp::decode(view, genesis))
            return {TestResult::Fail, "failed to decode genesisRLP"};
    } else {
        // Construct minimal genesis header from the parsed header fields
        const auto& gh = tc.genesis_block_header;
        std::memcpy(genesis.header.parent_hash.bytes, gh.parent_hash.bytes, 32);
        std::memcpy(genesis.header.beneficiary.bytes, gh.coinbase.bytes,    20);
        std::memcpy(genesis.header.state_root.bytes,  gh.state_root.bytes,  32);
        std::memcpy(genesis.header.logs_bloom.data(),  gh.bloom.data(),    256);
        genesis.header.number    = gh.number;
        genesis.header.gas_limit = gh.gas_limit;
        genesis.header.gas_used  = gh.gas_used;
        genesis.header.timestamp = gh.timestamp;
        genesis.header.extra_data = gh.extra_data;
        if (gh.base_fee_per_gas)
            genesis.header.base_fee_per_gas = *gh.base_fee_per_gas;
    }

    // Build initial state from pre-allocation
    silkworm::InMemoryState state = build_initial_state(tc.pre);

    // Register the genesis block in state so Blockchain can anchor the chain
    auto genesis_hash = genesis.header.hash();
    state.insert_block(genesis, genesis_hash);
    state.canonize_block(genesis.header.number, genesis_hash);

    // Construct Blockchain executor
    silkworm::protocol::Blockchain blockchain{state, chain_cfg, genesis};

    // Execute each block
    for (size_t i = 0; i < tc.blocks.size(); ++i) {
        const auto& ef_blk  = tc.blocks[i];
        uint64_t block_num  = static_cast<uint64_t>(i + 1);

        auto block_opt = decode_block_rlp(ef_blk.rlp);

        if (!block_opt) {
            if (ef_blk.expect_exception)
                continue;  // expected RLP failure — OK
            return {TestResult::Fail,
                    "block " + std::to_string(block_num) + ": RLP decode failed (no exception expected)"};
        }

        silkworm::ValidationResult res =
            blockchain.insert_block(*block_opt, /*check_state_root=*/true);

        bool expected_fail = ef_blk.expect_exception.has_value();

        if (res == silkworm::ValidationResult::kOk) {
            if (expected_fail)
                return {TestResult::Fail,
                        "block " + std::to_string(block_num) + ": expected exception \"" +
                        *ef_blk.expect_exception + "\" but block succeeded"};
        } else {
            if (!expected_fail)
                return {TestResult::Fail,
                        "block " + std::to_string(block_num) + ": unexpected validation error"};
            // Expected failure — continue to next block
        }
    }

    // Validate post-state accounts
    if (tc.post_state) {
        for (auto& [addr, expected] : *tc.post_state) {
            auto got = state.read_account(addr);
            if (!got)
                return {TestResult::Fail,
                        "post-state: account " + std::string(addr.bytes, addr.bytes + 20) + " missing"};
            if (got->balance != expected.balance)
                return {TestResult::Fail, "post-state: balance mismatch for account"};
            if (got->nonce != expected.nonce)
                return {TestResult::Fail, "post-state: nonce mismatch for account"};

            // Storage checks
            for (auto& [key, exp_val] : expected.storage) {
                auto got_val = state.read_storage(addr, key);
                if (got_val != exp_val)
                    return {TestResult::Fail, "post-state: storage slot mismatch"};
            }
        }
    }

    return {TestResult::Pass, {}};
}

// File-level runner

std::vector<FileReport> run_blockchain_test_file(const std::filesystem::path& json_path) {
    std::vector<FileReport> results;

    std::string path_str = json_path.string();
    std::string filename = json_path.filename().string();

    // Path-level skip (e.g. EIPTests/stEOF subtree)
    if (should_skip_path(path_str)) {
        results.push_back({path_str, "*", {TestResult::Skip, "path-level skip"}});
        return results;
    }

    // File-name skip
    if (should_skip(filename)) {
        results.push_back({path_str, "*", {TestResult::Skip, "file in skip list"}});
        return results;
    }

    std::map<std::string, EfBlockchainTest> tests;
    try {
        tests = load_blockchain_tests(path_str);
    } catch (const std::exception& e) {
        results.push_back({path_str, "*", {TestResult::Fail, std::string("JSON parse error: ") + e.what()}});
        return results;
    }

    for (auto& [name, tc] : tests) {
        results.push_back({path_str, name, run_single_test(tc)});
    }

    return results;
}
