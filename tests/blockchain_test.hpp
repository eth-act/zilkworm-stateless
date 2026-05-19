#pragma once
// blockchain_test.hpp — EF BlockchainTest execution and validation

#include "json_fixtures.hpp"

#include <filesystem>
#include <string>

enum class TestResult { Pass, Skip, Fail };

struct TestReport {
    TestResult  result;
    std::string message;  // non-empty on Fail
};

// Execute all test cases in a single .json fixture file.
// Returns one report per (file, test-name) pair.
struct FileReport {
    std::string path;
    std::string test_name;
    TestReport  report;
};

std::vector<FileReport> run_blockchain_test_file(const std::filesystem::path& json_path);
