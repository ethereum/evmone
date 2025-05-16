// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "helpers.hpp"
#include "synthetic_benchmarks.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/statetest/statetest.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>

namespace fs = std::filesystem;

using namespace benchmark;

namespace evmone::test
{
std::map<std::string_view, evmc::VM> registered_vms;

namespace
{
struct BenchmarkCase
{
    StateTransitionTest state_test;
    std::string name;
};

/// Loads a benchmark case from a file at `path` and all its inputs from the matching inputs file.
std::vector<BenchmarkCase> load_benchmark(const fs::path& path, const std::string& name_prefix)
{
    std::ifstream f{path};
    std::vector<BenchmarkCase> result;

    auto state_tests = load_state_tests(f);
    result.reserve(state_tests.size());
    for (const auto& state_test : state_tests)
    {
        result.emplace_back(
            BenchmarkCase{state_test, name_prefix + path.stem().string() + "/" + state_test.name});
    }

    return result;
}

/// Loads all benchmark cases from the given directory and all its subdirectories.
std::vector<BenchmarkCase> load_benchmarks_from_dir(  // NOLINT(misc-no-recursion)
    const fs::path& path, const std::string& name_prefix = {})
{
    std::vector<fs::path> subdirs;
    std::vector<fs::path> files;

    if (fs::is_directory(path))
    {
        for (auto& e : fs::directory_iterator{path})
        {
            if (e.is_directory())
                subdirs.emplace_back(e);
            else if (e.path().extension() == ".json")
                files.emplace_back(e);
        }
    }
    else
    {
        if (path.extension() == ".json")
        {
            if (fs::exists(path))
                files.emplace_back(path);
            else
                throw std::invalid_argument{"Path '" + path.string() + "' does not exist."};
        }
    }

    std::ranges::sort(subdirs);
    std::ranges::sort(files);

    std::vector<BenchmarkCase> benchmark_cases;

    for (const auto& f : files)
    {
        auto file_benchmarks = load_benchmark(f, name_prefix);
        benchmark_cases.insert(benchmark_cases.end(),
            std::make_move_iterator(file_benchmarks.begin()),
            std::make_move_iterator(file_benchmarks.end()));
    }

    for (const auto& d : subdirs)
    {
        auto t = load_benchmarks_from_dir(d, name_prefix + d.filename().string() + '/');
        benchmark_cases.insert(benchmark_cases.end(), std::make_move_iterator(t.begin()),
            std::make_move_iterator(t.end()));
    }

    return benchmark_cases;
}

void register_benchmarks(std::span<const BenchmarkCase> benchmark_cases)
{
    evmc::VM* advanced_vm = nullptr;
    evmc::VM* baseline_vm = nullptr;
    if (const auto it = registered_vms.find("advanced"); it != registered_vms.end())
        advanced_vm = &it->second;
    if (const auto it = registered_vms.find("baseline"); it != registered_vms.end())
        baseline_vm = &it->second;

    evmc::VM check_test_vm = evmc::VM{evmc_create_evmone()};

    for (const auto& b : benchmark_cases)
    {
        run_state_test(b.state_test, check_test_vm, false);

        if (::testing::Test::HasFailure())
            throw std::invalid_argument{"State test you want to bench failed."};

        const auto code = b.state_test.pre_state.get_account_code(b.state_test.multi_tx.to.value());
        for (const auto& [rev, cases, block_info] : b.state_test.cases)
        {
            if (advanced_vm != nullptr)
            {
                RegisterBenchmark("advanced/analyse/" + b.name, [code, &rev](State& state) {
                    bench_analyse<advanced::AdvancedCodeAnalysis, advanced_analyse>(
                        state, rev, code);
                })->Unit(kMicrosecond);
            }

            if (baseline_vm != nullptr)
            {
                RegisterBenchmark("baseline/analyse/" + b.name, [code, &rev](State& state) {
                    bench_analyse<baseline::CodeAnalysis, baseline_analyse>(state, rev, code);
                })->Unit(kMicrosecond);
            }

            for (size_t case_index = 0; case_index != cases.size(); ++case_index)
            {
                const auto& expected = cases[case_index];
                const auto tx = b.state_test.multi_tx.get(expected.indexes);

                for (auto& [vm_name, vm] : registered_vms)
                {
                    const auto name = std::string{vm_name} + "/execute/" + b.name + '/' +
                                      std::to_string(case_index);

                    // `tx` is temporary.
                    RegisterBenchmark(name, [tx, &vm, &b, &block_info, &rev](State& state) {
                        bench_transition(state, vm, tx, b.state_test.pre_state, block_info,
                            b.state_test.block_hashes, rev);
                    })->Unit(kMicrosecond);
                }
            }
        }
    }
}


/// The error code for CLI arguments parsing error in evmone-bench.
/// The number tries to be different from EVMC loading error codes.
constexpr auto cli_parsing_error = -3;

/// Parses evmone-bench CLI arguments and registers benchmark cases.
///
/// The following variants of number arguments are supported (including argv[0]):
///
/// 1: evmone-bench
///    Uses evmone VMs, only synthetic benchmarks are available.
/// 2: evmone-bench benchmarks_dir
///    Uses evmone VMs, loads all benchmarks from benchmarks_dir.
/// NO LONGER SUPPORTED
/// 3: evmone-bench evmc_config benchmarks_dir
///    The same as (2) but loads additional custom EVMC VM.
/// 4: evmone-bench code_hex_file input_hex expected_output_hex.
///    Uses evmone VMs, registers custom benchmark with the code from the given file,
///    and the given input. The benchmark will compare the output with the provided
///    expected one.
std::variant<int, std::vector<BenchmarkCase>> parseargs(int argc, char** argv)
{
    // Arguments' placeholders:
    std::string evmc_config;
    std::string benchmarks_dir;
    std::string code_hex_file;

    switch (argc)
    {
    case 1:
        // Run with built-in synthetic benchmarks only.
        break;
    case 2:
        benchmarks_dir = argv[1];
        break;
    case 3:
        evmc_config = argv[1];
        benchmarks_dir = argv[2];
        break;
    case 4:
        code_hex_file = argv[1];
        break;
    default:
        std::cerr << "Too many arguments\n";
        return cli_parsing_error;
    }

    if (!evmc_config.empty())
        assert(false);  // Unsupported. Benchmarks should be run as a state tests.

    if (!benchmarks_dir.empty())
    {
        return load_benchmarks_from_dir(benchmarks_dir);
    }

    if (!code_hex_file.empty())
        assert(false);  // Unsupported. Benchmarks should be run as a state tests.

    return std::vector<BenchmarkCase>{};
}
}  // namespace
}  // namespace evmone::test

int main(int argc, char** argv)
{
    using namespace evmone::test;
    try
    {
        Initialize(&argc, argv);  // Consumes --benchmark_ options.
        const auto ec_or_benchmark_cases = parseargs(argc, argv);
        if (std::holds_alternative<int>(ec_or_benchmark_cases))
        {
            const auto ec = std::get<int>(ec_or_benchmark_cases);
            if (ec == cli_parsing_error && ReportUnrecognizedArguments(argc, argv))
                return ec;

            if (ec != 0)
                return ec;
        }
        else
        {
            const auto benchmark_cases =
                std::get<std::vector<BenchmarkCase>>(ec_or_benchmark_cases);
            registered_vms["advanced"] = evmc::VM{evmc_create_evmone(), {{"advanced", ""}}};
            registered_vms["baseline"] = evmc::VM{evmc_create_evmone()};
            registered_vms["bnocgoto"] = evmc::VM{evmc_create_evmone(), {{"cgoto", "no"}}};
            register_benchmarks(benchmark_cases);
            register_synthetic_benchmarks();
            RunSpecifiedBenchmarks();
            return 0;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
