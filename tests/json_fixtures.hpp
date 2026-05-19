#pragma once
// json_fixtures.hpp — EF BlockchainTest JSON → C++ structs (nlohmann/json)

#include <array>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/util.hpp>

// Parsing helpers

// Strip "0x" prefix and decode hex → bytes
inline silkworm::Bytes hex_to_bytes(const std::string& s) {
    std::string_view sv = s;
    if (sv.starts_with("0x") || sv.starts_with("0X")) sv.remove_prefix(2);
    if (sv.empty()) return {};
    // Odd length: prepend implicit zero nibble
    std::string padded;
    if (sv.size() % 2 != 0) { padded = "0"; padded += sv; sv = padded; }
    silkworm::Bytes out(sv.size() / 2, 0);
    for (size_t i = 0; i < out.size(); ++i) {
        auto hi = sv[2 * i],     lo = sv[2 * i + 1];
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out[i] = static_cast<uint8_t>((nibble(hi) << 4) | nibble(lo));
    }
    return out;
}

inline uint64_t hex_to_u64(const std::string& s) {
    auto b = hex_to_bytes(s);
    uint64_t v = 0;
    for (auto byte : b) v = (v << 8) | byte;
    return v;
}

inline intx::uint256 hex_to_u256(const std::string& s) {
    auto b = hex_to_bytes(s);
    // Big-endian decode into uint256
    intx::uint256 v{0};
    for (auto byte : b) v = (v << 8) | byte;
    return v;
}

inline evmc::bytes32 hex_to_bytes32(const std::string& s) {
    auto b = hex_to_bytes(s);
    evmc::bytes32 out{};
    if (b.size() <= 32) std::memcpy(out.bytes + (32 - b.size()), b.data(), b.size());
    return out;
}

inline evmc::address hex_to_address(const std::string& s) {
    auto b = hex_to_bytes(s);
    evmc::address out{};
    if (b.size() <= 20) std::memcpy(out.bytes + (20 - b.size()), b.data(), b.size());
    return out;
}

// EF test data structures

struct EfAccount {
    intx::uint256 balance;
    uint64_t      nonce{0};
    silkworm::Bytes code;
    std::map<evmc::bytes32, evmc::bytes32> storage;
};

struct EfHeader {
    evmc::bytes32   parent_hash{};
    evmc::address   coinbase{};
    evmc::bytes32   state_root{};
    evmc::bytes32   receipt_trie{};
    std::array<uint8_t, 256> bloom{};
    uint64_t        number{0};
    uint64_t        gas_limit{0};
    uint64_t        gas_used{0};
    uint64_t        timestamp{0};
    silkworm::Bytes extra_data;
    evmc::bytes32   hash{};
    // Post-merge optional fields
    std::optional<intx::uint256>  base_fee_per_gas;
    std::optional<evmc::bytes32>  withdrawals_root;
    std::optional<uint64_t>       blob_gas_used;
    std::optional<uint64_t>       excess_blob_gas;
    std::optional<evmc::bytes32>  parent_beacon_block_root;
    std::optional<evmc::bytes32>  requests_hash;
};

struct EfBlock {
    silkworm::Bytes            rlp;
    std::optional<std::string> expect_exception;
    std::optional<EfHeader>   block_header;
};

struct EfBlockchainTest {
    EfHeader genesis_block_header;
    std::optional<silkworm::Bytes>               genesis_rlp;
    std::vector<EfBlock>                         blocks;
    std::map<evmc::address, EfAccount>           pre;
    std::optional<std::map<evmc::address, EfAccount>> post_state;
    std::string network;       // "London", "Shanghai", etc.
    std::string last_block_hash;
};

//  nlohmann/json deserialization

inline EfAccount parse_account(const nlohmann::json& j) {
    EfAccount a;
    a.balance = hex_to_u256(j.at("balance").get<std::string>());
    a.nonce   = hex_to_u64(j.at("nonce").get<std::string>());
    a.code    = hex_to_bytes(j.at("code").get<std::string>());
    if (j.contains("storage")) {
        for (auto& [k, v] : j.at("storage").items()) {
            a.storage[hex_to_bytes32(k)] = hex_to_bytes32(v.get<std::string>());
        }
    }
    return a;
}

inline EfHeader parse_header(const nlohmann::json& j) {
    EfHeader h;
    h.parent_hash  = hex_to_bytes32(j.at("parentHash").get<std::string>());
    h.coinbase     = hex_to_address(j.at("coinbase").get<std::string>());
    h.state_root   = hex_to_bytes32(j.at("stateRoot").get<std::string>());
    h.receipt_trie = hex_to_bytes32(j.at("receiptTrie").get<std::string>());
    {
        auto bloom_b = hex_to_bytes(j.at("bloom").get<std::string>());
        if (bloom_b.size() == 256) std::memcpy(h.bloom.data(), bloom_b.data(), 256);
    }
    h.number    = hex_to_u64(j.at("number").get<std::string>());
    h.gas_limit = hex_to_u64(j.at("gasLimit").get<std::string>());
    h.gas_used  = hex_to_u64(j.at("gasUsed").get<std::string>());
    h.timestamp = hex_to_u64(j.at("timestamp").get<std::string>());
    h.extra_data = hex_to_bytes(j.at("extraData").get<std::string>());
    if (j.contains("hash")) h.hash = hex_to_bytes32(j.at("hash").get<std::string>());
    if (j.contains("baseFeePerGas"))
        h.base_fee_per_gas = hex_to_u256(j.at("baseFeePerGas").get<std::string>());
    if (j.contains("withdrawalsRoot"))
        h.withdrawals_root = hex_to_bytes32(j.at("withdrawalsRoot").get<std::string>());
    if (j.contains("blobGasUsed"))
        h.blob_gas_used = hex_to_u64(j.at("blobGasUsed").get<std::string>());
    if (j.contains("excessBlobGas"))
        h.excess_blob_gas = hex_to_u64(j.at("excessBlobGas").get<std::string>());
    if (j.contains("parentBeaconBlockRoot"))
        h.parent_beacon_block_root = hex_to_bytes32(j.at("parentBeaconBlockRoot").get<std::string>());
    if (j.contains("requestsHash"))
        h.requests_hash = hex_to_bytes32(j.at("requestsHash").get<std::string>());
    return h;
}

inline EfBlockchainTest parse_blockchain_test(const nlohmann::json& j) {
    EfBlockchainTest t;
    t.genesis_block_header = parse_header(j.at("genesisBlockHeader"));
    if (j.contains("genesisRLP") && !j.at("genesisRLP").is_null())
        t.genesis_rlp = hex_to_bytes(j.at("genesisRLP").get<std::string>());
    t.network         = j.at("network").get<std::string>();
    t.last_block_hash = j.value("lastblockhash", "");

    for (auto& [addr_str, acc_j] : j.at("pre").items())
        t.pre[hex_to_address(addr_str)] = parse_account(acc_j);

    if (j.contains("postState") && !j.at("postState").is_null()) {
        std::map<evmc::address, EfAccount> ps;
        for (auto& [addr_str, acc_j] : j.at("postState").items())
            ps[hex_to_address(addr_str)] = parse_account(acc_j);
        t.post_state = std::move(ps);
    }

    for (auto& blk_j : j.at("blocks")) {
        EfBlock b;
        b.rlp = hex_to_bytes(blk_j.at("rlp").get<std::string>());
        if (blk_j.contains("expectException"))
            b.expect_exception = blk_j.at("expectException").get<std::string>();
        if (blk_j.contains("blockHeader"))
            b.block_header = parse_header(blk_j.at("blockHeader"));
        t.blocks.push_back(std::move(b));
    }

    return t;
}

// a .json file is a map of test-name → BlockchainTest
inline std::map<std::string, EfBlockchainTest> load_blockchain_tests(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("Cannot open: " + path);
    nlohmann::json j;
    f >> j;
    std::map<std::string, EfBlockchainTest> out;
    for (auto& [name, test_j] : j.items())
        out[name] = parse_blockchain_test(test_j);
    return out;
}
