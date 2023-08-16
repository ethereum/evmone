// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "statetest.hpp"
#include <CLI/CLI.hpp>
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <iostream>

namespace
{
class StateTest : public testing::Test
{
    fs::path m_json_test_file;
    evmc::VM& m_vm;
    bool m_trace = false;

public:
    explicit StateTest(fs::path json_test_file, evmc::VM& vm, bool trace) noexcept
      : m_json_test_file{std::move(json_test_file)}, m_vm{vm}, m_trace{trace}
    {}

    void TestBody() final
    {
        std::ifstream f{m_json_test_file};
        evmone::test::run_state_test(evmone::test::load_state_test(f), m_vm, m_trace);
    }
};

void register_test(const std::string& suite_name, const fs::path& file, evmc::VM& vm, bool trace)
{
    testing::RegisterTest(suite_name.c_str(), file.stem().string().c_str(), nullptr, nullptr,
        file.string().c_str(), 0,
        [file, &vm, trace]() -> testing::Test* { return new StateTest(file, vm, trace); });
}

void register_test_files(const fs::path& root, evmc::VM& vm, bool trace)
{
    if (is_directory(root))
    {
        std::vector<fs::path> test_files;
        std::copy_if(fs::recursive_directory_iterator{root}, fs::recursive_directory_iterator{},
            std::back_inserter(test_files), [](const fs::directory_entry& entry) {
                return entry.is_regular_file() && entry.path().extension() == ".json";
            });
        std::sort(test_files.begin(), test_files.end());

        for (const auto& p : test_files)
            register_test(fs::relative(p, root).parent_path().string(), p, vm, trace);
    }
    else  // Treat as a file.
    {
        register_test(root.parent_path().string(), root, vm, trace);
    }
}
}  // namespace


int main(int argc, char* argv[])
{
    // The default test filter. To enable all tests use `--gtest_filter=*`.
    testing::FLAGS_gtest_filter =
        "-"
        // Slow tests:
        "stCreateTest.CreateOOGafterMaxCodesize:"      // pass
        "stQuadraticComplexityTest.Call50000_sha256:"  // pass
        "stTimeConsuming.static_Call50000_sha256:"     // pass
        "stTimeConsuming.CALLBlake2f_MaxRounds:"       // pass
        "VMTests/vmPerformance.*:"                     // pass
        ;

    try
    {
        testing::InitGoogleTest(&argc, argv);  // Process GoogleTest flags.

        CLI::App app{"evmone state test runner"};

        std::vector<std::string> paths;
        app.add_option("path", paths, "Path to test file or directory")
            ->required()
            ->check(CLI::ExistingPath);

        bool trace = false;
        bool trace_summary = false;
        const auto trace_opt = app.add_flag("--trace", trace, "Enable EVM tracing");
        app.add_flag("--trace-summary", trace_summary, "Output trace summary only")
            ->excludes(trace_opt);

        CLI11_PARSE(app, argc, argv);

        evmc::VM vm{evmc_create_evmone(), {{"O", "0"}}};

        if (trace)
            vm.set_option("trace", "1");

        for (const auto& p : paths)
            register_test_files(p, vm, trace || trace_summary);

        return RUN_ALL_TESTS();
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
