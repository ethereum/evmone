// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <iostream>

namespace
{
class StateTest : public testing::Test
{
    fs::path m_json_test_file;
    evmc::VM& m_vm;

public:
    explicit StateTest(fs::path json_test_file, evmc::VM& vm) noexcept
      : m_json_test_file{std::move(json_test_file)}, m_vm{vm}
    {}

    void TestBody() final
    {
        evmone::test::run_state_test(evmone::test::load_state_test(m_json_test_file), m_vm);
    }
};
}  // namespace

int main(int argc, char* argv[])
{
    static constexpr std::string_view filter_flag_name = "--gtest_filter";
    const auto has_user_filter = std::count_if(argv, argv + argc, [](const char* arg) noexcept {
        return std::string_view{arg}.substr(0, filter_flag_name.size()) == filter_flag_name;
    }) != 0;

    testing::InitGoogleTest(&argc, argv);  // Process GoogleTest flags.

    if (argc != 2)
    {
        std::cerr << "Missing argument with the path to the tests directory\n";
        return -1;
    }

    if (!has_user_filter)
    {
        // Set default test filter if none provided.
        // To enable all tests use `--gtest_filter=*`.
        testing::FLAGS_gtest_filter =
            "-"
            // Slow tests:
            "stCreateTest.CreateOOGafterMaxCodesize:"      // pass
            "stQuadraticComplexityTest.Call50000_sha256:"  // pass
            "stTimeConsuming.static_Call50000_sha256:"     // pass
            "stTimeConsuming.CALLBlake2f_MaxRounds:"       // pass
            "VMTests/vmPerformance.*:"                     // pass
            ;
    }

    evmc::VM vm{evmc_create_evmone(), {{"O", "0"}, /*{"trace", "1"}*/}};

    std::vector<fs::path> test_files;
    const fs::path root_test_dir{argv[1]};
    std::copy_if(fs::recursive_directory_iterator{root_test_dir},
        fs::recursive_directory_iterator{}, std::back_inserter(test_files),
        [](const fs::directory_entry& entry) {
            return entry.is_regular_file() && entry.path().extension() == ".json";
        });
    std::sort(test_files.begin(), test_files.end());
    for (const auto& p : test_files)
    {
        const auto d = fs::relative(p, root_test_dir);
        testing::RegisterTest(d.parent_path().string().c_str(), d.stem().string().c_str(), nullptr,
            nullptr, p.string().c_str(), 0,
            [p, &vm]() -> testing::Test* { return new StateTest(p, vm); });
    }

    return RUN_ALL_TESTS();
}
