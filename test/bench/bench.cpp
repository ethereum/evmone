// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "helpers.hpp"
#include "synthetic_benchmarks.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/evmone.h>
#include <fstream>
#include <iostream>


#if HAVE_STD_FILESYSTEM
#include <evmone/baseline.hpp>
#include <filesystem>
namespace fs = std::filesystem;
#else
#include "filesystem.hpp"
namespace fs = ghc::filesystem;
#endif

using namespace benchmark;

namespace evmone::test
{
std::map<std::string_view, evmc::VM> registered_vms;

namespace
{
struct BenchmarkCase
{
    struct Input
    {
        std::string name;
        bytes input;
        bytes expected_output;

        Input(std::string _name, bytes _input, bytes _expected_output) noexcept
          : name{std::move(_name)},
            input{std::move(_input)},
            expected_output{std::move(_expected_output)}
        {}
    };

    std::string name;
    bytes code;
    std::vector<Input> inputs;

    /// Create a benchmark case without input.
    BenchmarkCase(std::string _name, bytes _code) noexcept
      : name{std::move(_name)}, code{std::move(_code)}
    {}
};


constexpr auto inputs_extension = ".inputs";

/// Loads the benchmark case's inputs from the inputs file at the given path.
std::vector<BenchmarkCase::Input> load_inputs(const fs::path& path)
{
    enum class state
    {
        name,
        input,
        expected_output
    };

    auto inputs_file = std::ifstream{path};

    std::vector<BenchmarkCase::Input> inputs;
    auto st = state::name;
    std::string input_name;
    bytes input;
    for (std::string l; std::getline(inputs_file, l);)
    {
        switch (st)
        {
        case state::name:
            if (l.empty())
                continue;  // Skip any empty line.
            input_name = std::move(l);
            st = state::input;
            break;

        case state::input:
            input = from_hexx(l);
            st = state::expected_output;
            break;

        case state::expected_output:
            inputs.emplace_back(std::move(input_name), std::move(input), from_hexx(l));
            st = state::name;
            break;
        }
    }

    return inputs;
}

/// Loads a benchmark case from a file at `path` and all its inputs from the matching inputs file.
BenchmarkCase load_benchmark(const fs::path& path, const std::string& name_prefix)
{
    const auto name = name_prefix + path.stem().string();

    std::ifstream file{path};
    std::string code_hexx{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};

    code_hexx.erase(
        std::remove_if(code_hexx.begin(), code_hexx.end(), [](auto x) { return std::isspace(x); }),
        code_hexx.end());

    BenchmarkCase b{name, from_hexx(code_hexx)};

    auto inputs_path = path;
    inputs_path.replace_extension(inputs_extension);
    if (fs::exists(inputs_path))
        b.inputs = load_inputs(inputs_path);

    if (b.inputs.empty())  // Add at least one input for simpler registration logic.
        b.inputs.emplace_back("", bytes{}, bytes{});

    return b;
}

/// Loads all benchmark cases from the given directory and all its subdirectories.
std::vector<BenchmarkCase> load_benchmarks_from_dir(
    const fs::path& path, const std::string& name_prefix = {})
{
    std::vector<fs::path> subdirs;
    std::vector<fs::path> files;

    for (auto& e : fs::directory_iterator{path})
    {
        if (e.is_directory())
            subdirs.emplace_back(e);
        else if (e.path().extension() != inputs_extension)
            files.emplace_back(e);
    }

    std::sort(std::begin(subdirs), std::end(subdirs));
    std::sort(std::begin(files), std::end(files));

    std::vector<BenchmarkCase> benchmark_cases;

    for (const auto& f : files)
        benchmark_cases.emplace_back(load_benchmark(f, name_prefix));

    for (const auto& d : subdirs)
    {
        auto t = load_benchmarks_from_dir(d, name_prefix + d.filename().string() + '/');
        benchmark_cases.insert(benchmark_cases.end(), std::make_move_iterator(t.begin()),
            std::make_move_iterator(t.end()));
    }

    return benchmark_cases;
}

void register_benchmarks(const std::vector<BenchmarkCase>& benchmark_cases)
{
    evmc::VM* advanced_vm = nullptr;
    evmc::VM* baseline_vm = nullptr;
    if (const auto it = registered_vms.find("advanced"); it != registered_vms.end())
        advanced_vm = &it->second;
    if (const auto it = registered_vms.find("baseline"); it != registered_vms.end())
        baseline_vm = &it->second;

    for (const auto& b : benchmark_cases)
    {
        if (advanced_vm)
        {
            RegisterBenchmark(("advanced/analyse/" + b.name).c_str(), [&b](State& state) {
                bench_analyse<AdvancedCodeAnalysis, advanced_analyse>(
                    state, default_revision, b.code);
            })->Unit(kMicrosecond);
        }

        if (baseline_vm)
        {
            RegisterBenchmark(("baseline/analyse/" + b.name).c_str(), [&b](State& state) {
                bench_analyse<baseline::CodeAnalysis, baseline_analyse>(
                    state, default_revision, b.code);
            })->Unit(kMicrosecond);
        }

        for (const auto& input : b.inputs)
        {
            const auto case_name = b.name + (!input.name.empty() ? '/' + input.name : "");

            if (advanced_vm)
            {
                const auto name = "advanced/execute/" + case_name;
                RegisterBenchmark(name.c_str(), [&vm = *advanced_vm, &b, &input](State& state) {
                    bench_advanced_execute(state, vm, b.code, input.input, input.expected_output);
                })->Unit(kMicrosecond);
            }

            if (baseline_vm)
            {
                const auto name = "baseline/execute/" + case_name;
                RegisterBenchmark(name.c_str(), [&vm = *baseline_vm, &b, &input](State& state) {
                    bench_baseline_execute(state, vm, b.code, input.input, input.expected_output);
                })->Unit(kMicrosecond);
            }

            for (auto& [vm_name, vm] : registered_vms)
            {
                const auto name = std::string{vm_name} + "/total/" + case_name;
                RegisterBenchmark(name.c_str(), [&vm = vm, &b, &input](State& state) {
                    bench_evmc_execute(state, vm, b.code, input.input, input.expected_output);
                })->Unit(kMicrosecond);
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
/// 3: evmone-bench evmc_config benchmarks_dir
///    The same as (2) but loads additional custom EVMC VM.
/// 4: evmone-bench code_hex_file input_hex expected_output_hex.
///    Uses evmone VMs, registers custom benchmark with the code from the given file,
///    and the given input. The benchmark will compare the output with the provided
///    expected one.
std::tuple<int, std::vector<BenchmarkCase>> parseargs(int argc, char** argv)
{
    // Arguments' placeholders:
    std::string evmc_config;
    std::string benchmarks_dir;
    std::string code_hex_file;
    std::string input_hex;
    std::string expected_output_hex;

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
        input_hex = argv[2];
        expected_output_hex = argv[3];
        break;
    default:
        std::cerr << "Too many arguments\n";
        return {cli_parsing_error, {}};
    }

    if (!evmc_config.empty())
    {
        auto ec = evmc_loader_error_code{};
        registered_vms["external"] = evmc::VM{evmc_load_and_configure(evmc_config.c_str(), &ec)};

        if (ec != EVMC_LOADER_SUCCESS)
        {
            if (const auto error = evmc_last_error_msg())
                std::cerr << "EVMC loading error: " << error << "\n";
            else
                std::cerr << "EVMC loading error " << ec << "\n";
            return {static_cast<int>(ec), {}};
        }

        std::cout << "External VM: " << evmc_config << "\n";
    }

    if (!benchmarks_dir.empty())
    {
        return {0, load_benchmarks_from_dir(benchmarks_dir)};
    }

    if (!code_hex_file.empty())
    {
        std::ifstream file{code_hex_file};
        std::string code_hex{
            std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
        code_hex.erase(std::remove_if(code_hex.begin(), code_hex.end(),
                           [](auto x) { return std::isspace(x); }),
            code_hex.end());

        BenchmarkCase b{code_hex_file, from_hex(code_hex)};
        b.inputs.emplace_back("", from_hex(input_hex), from_hex(expected_output_hex));

        return {0, {std::move(b)}};
    }

    return {0, {}};
}
}  // namespace
}  // namespace evmone::test

int main(int argc, char** argv)
{
    using namespace evmone::test;
    try
    {
        Initialize(&argc, argv);  // Consumes --benchmark_ options.
        const auto [ec, benchmark_cases] = parseargs(argc, argv);
        if (ec == cli_parsing_error && ReportUnrecognizedArguments(argc, argv))
            return ec;

        if (ec != 0)
            return ec;

        registered_vms["advanced"] = evmc::VM{evmc_create_evmone(), {{"O", "2"}}};
        registered_vms["baseline"] = evmc::VM{evmc_create_evmone(), {{"O", "0"}}};
        register_benchmarks(benchmark_cases);
        register_synthetic_benchmarks();
        RunSpecifiedBenchmarks();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
