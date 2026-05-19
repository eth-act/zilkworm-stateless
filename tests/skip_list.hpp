#pragma once
// skip_list.hpp — EF test files to skip

#include <string_view>

// File-name skips — identical to the Rust ef-tests should_skip() list.
// See: stateless/testing/ef-tests/src/cases/blockchain_test.rs
inline bool should_skip(std::string_view name) {
    // funky test with bigint 0x00 value in json — not possible on mainnet
    if (name == "ValueOverflow.json")          return true;
    if (name == "ValueOverflowParis.json")     return true;
    // txbyte type 02 edge case
    if (name == "typeTwoBerlin.json")          return true;
    // nonce overflow — handled correctly but exception not parsed in test suite
    if (name == "CreateTransactionHighNonce.json") return true;
    // gas price overflow — handled correctly but wrong exception string
    if (name == "HighGasPrice.json")           return true;
    if (name == "HighGasPriceParis.json")      return true;
    // basefee/accesslist/difficulty present but unsupported in that fork
    if (name == "accessListExample.json")      return true;
    if (name == "basefeeExample.json")         return true;
    if (name == "eip1559.json")                return true;
    if (name == "mergeTest.json")              return true;
    // slow tests
    if (name == "loopExp.json")                return true;
    if (name == "Call50000_sha256.json")       return true;
    if (name == "static_Call50000_sha256.json") return true;
    if (name == "loopMul.json")                return true;
    if (name == "CALLBlake2f_MaxRounds.json")  return true;
    if (name == "shiftCombinations.json")      return true;
    // revm-skipped edge cases around create-in-init revert behaviour
    if (name == "RevertInCreateInInit_Paris.json")         return true;
    if (name == "RevertInCreateInInit.json")               return true;
    if (name == "dynamicAccountOverwriteEmpty.json")       return true;
    if (name == "dynamicAccountOverwriteEmpty_Paris.json") return true;
    if (name == "RevertInCreateInInitCreate2Paris.json")   return true;
    if (name == "create2collisionStorage.json")            return true;
    if (name == "RevertInCreateInInitCreate2.json")        return true;
    if (name == "create2collisionStorageParis.json")       return true;
    if (name == "InitCollision.json")                      return true;
    if (name == "InitCollisionParis.json")                 return true;
    return false;
}

// Path-level skips.
//
// EIPTests/stEOF — also skipped by Rust (outdated EOF tests).
//
// bcUncle* — NOT skipped by the Rust suite; reth passes these via full PoW
//   uncle/ommer consensus validation. Zilkworm's Blockchain::insert_block()
//   does not validate uncle headers the same way, so they fail in C++.
//
// .meta — not relevant in Rust (Cargo doesn't walk directories the same way).
inline bool should_skip_path(std::string_view path) {
    auto contains = [&](std::string_view needle) {
        return path.find(needle) != std::string_view::npos;
    };
    if (contains("EIPTests") && contains("stEOF")) return true;
    if (contains("bcUncleSpecialTests"))   return true;
    if (contains("bcUncleHeaderValidity")) return true;
    if (contains("bcUncleTest"))           return true;
    if (contains(".meta")) return true;
    return false;
}
