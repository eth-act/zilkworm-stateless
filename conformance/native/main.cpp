// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Native EEST conformance runner.
//
// Runs the exact guest entrypoint (z6m::run_stateless_guest) on
// statelessInputBytes and byte-compares the encoded public values with
// statelessOutputBytes. Two modes:
//
//   z6m_conformance --input in.bin --expected out.bin
//   z6m_conformance --pairs DIR       # every *.input.bin with a sibling
//                                     # *.expected.bin under DIR (recursive)
//
// Exit code 0 iff every case matches byte-exactly.

#include <z6m/stateless.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::vector<uint8_t> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        std::cerr << "cannot open " << p << "\n";
        std::exit(2);
    }
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

static std::string hex(const uint8_t* d, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; ++i) {
        s += k[d[i] >> 4];
        s += k[d[i] & 15];
    }
    return s;
}

// Runs one case; returns true on byte-exact match.
static bool run_case(const fs::path& input_path, const fs::path& expected_path,
                     bool verbose_on_fail) {
    const std::vector<uint8_t> input = read_file(input_path);
    const std::vector<uint8_t> expected = read_file(expected_path);

    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(input.data(), input.size());

    uint8_t pv[z6m::MAX_PUBLIC_VALUES_SIZE];
    const size_t pv_len = z6m::encode_public_values(result, pv, sizeof(pv));

    const bool ok =
        pv_len == expected.size() && std::memcmp(pv, expected.data(), pv_len) == 0;

    if (!ok && verbose_on_fail) {
        std::cerr << "  input    : " << input_path << "\n"
                  << "  got   (" << pv_len << "B): " << hex(pv, pv_len) << "\n"
                  << "  expect(" << expected.size() << "B): "
                  << hex(expected.data(), expected.size()) << "\n";
    }
    return ok;
}

int main(int argc, char** argv) {
    std::string input, expected, pairs_dir, fail_log;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::cerr << a << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--input") input = next();
        else if (a == "--expected") expected = next();
        else if (a == "--pairs") pairs_dir = next();
        else if (a == "--fail-log") fail_log = next();
        else {
            std::cerr << "unknown arg: " << a << "\n";
            return 2;
        }
    }

    if (!pairs_dir.empty()) {
        size_t pass = 0, fail = 0;
        std::vector<std::string> failures;
        for (const auto& entry : fs::recursive_directory_iterator(pairs_dir)) {
            if (!entry.is_regular_file()) continue;
            const fs::path p = entry.path();
            const std::string name = p.filename().string();
            constexpr std::string_view kSuffix = ".input.bin";
            if (name.size() <= kSuffix.size() ||
                name.compare(name.size() - kSuffix.size(), kSuffix.size(), kSuffix) != 0)
                continue;
            fs::path exp = p;
            exp.replace_filename(name.substr(0, name.size() - kSuffix.size()) +
                                 ".expected.bin");
            if (!fs::exists(exp)) {
                std::cerr << "missing expected file for " << p << "\n";
                ++fail;
                failures.push_back(name);
                continue;
            }
            if (run_case(p, exp, /*verbose_on_fail=*/false)) {
                ++pass;
            } else {
                ++fail;
                failures.push_back(name.substr(0, name.size() - kSuffix.size()));
            }
        }
        std::cout << "conformance: " << pass << " passed, " << fail << " failed\n";
        if (!fail_log.empty()) {
            std::ofstream fl(fail_log);
            for (const auto& f : failures) fl << f << "\n";
        }
        if (fail) {
            std::cout << "failing cases:\n";
            size_t shown = 0;
            for (const auto& f : failures) {
                std::cout << "  " << f << "\n";
                if (++shown == 50) {
                    std::cout << "  ... (" << (failures.size() - shown) << " more)\n";
                    break;
                }
            }
        }
        return fail == 0 ? 0 : 1;
    }

    if (input.empty() || expected.empty()) {
        std::cerr << "usage: z6m_conformance --input in.bin --expected out.bin\n"
                  << "       z6m_conformance --pairs DIR\n";
        return 2;
    }
    const bool ok = run_case(input, expected, /*verbose_on_fail=*/true);
    std::cout << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}
