// main.cpp — Z6m EF blockchain test runner
//
// Usage: z6m_test <path-to-BlockchainTests-dir> [subdir]
//   e.g. z6m_test ethereum-tests/BlockchainTests
//        z6m_test ethereum-tests/BlockchainTests ValidBlocks

#include "blockchain_test.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::vector<fs::path> collect_json_files(const fs::path& root) {
    std::vector<fs::path> files;
    if (!fs::exists(root)) {
        std::cerr << "error: path does not exist: " << root << "\n";
        return files;
    }
    for (auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
            files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    return files;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: z6m_test <BlockchainTests-dir> [subdir-filter]\n";
        return 1;
    }

    fs::path root = argv[1];
    if (argc >= 3) root /= argv[2];

    auto files = collect_json_files(root);
    if (files.empty()) {
        std::cerr << "no .json files found under " << root << "\n";
        return 1;
    }

    int passed = 0, skipped = 0, failed = 0;

    for (size_t i = 0; i < files.size(); ++i) {
        auto reports = run_blockchain_test_file(files[i]);
        for (auto& r : reports) {
            switch (r.report.result) {
            case TestResult::Pass:   ++passed;  break;
            case TestResult::Skip:   ++skipped; break;
            case TestResult::Fail:
                ++failed;
                std::cout << "[FAIL] " << r.path;
                if (r.test_name != "*") std::cout << " [" << r.test_name << "]";
                std::cout << "\n       " << r.report.message << "\n";
                break;
            }
        }
    }

    std::cout << "\n"
              << passed  << " passed, "
              << skipped << " skipped, "
              << failed  << " failed"
              << "  (total: " << (passed + skipped + failed) << ")\n";

    return failed > 0 ? 1 : 0;
}
