// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/analysis.hpp>
#include <evmone/evmone.h>
#include <test/utils/utils.hpp>

#include <cctype>
#include <fstream>
#include <iostream>


#if HAVE_STD_FILESYSTEM
#include <filesystem>
namespace fs = std::filesystem;
#else
#include "filesystem.hpp"
namespace fs = ghc::filesystem;
#endif

using namespace benchmark;

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

constexpr auto gas_limit = std::numeric_limits<int64_t>::max();
auto vm = evmc::VM{};

constexpr auto inputs_extension = ".inputs";

inline evmc::result execute(bytes_view code, bytes_view input) noexcept
{
    auto msg = evmc_message{};
    msg.gas = gas_limit;
    msg.input_data = input.data();
    msg.input_size = input.size();
    return vm.execute(EVMC_ISTANBUL, msg, code.data(), code.size());
}

void execute(State& state, bytes_view code, bytes_view input) noexcept
{
    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};
    for (auto _ : state)
    {
        auto r = execute(code, input);
        iteration_gas_used = gas_limit - r.gas_left;
        total_gas_used += iteration_gas_used;
    }
    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}

void analyse(State& state, bytes_view code) noexcept
{
    auto bytes_analysed = uint64_t{0};
    for (auto _ : state)
    {
        auto r = evmone::analyze(EVMC_ISTANBUL, code.data(), code.size());
        DoNotOptimize(r);
        bytes_analysed += code.size();
    }
    state.counters["size"] = Counter(static_cast<double>(code.size()));
    state.counters["rate"] = Counter(static_cast<double>(bytes_analysed), Counter::kIsRate);
}

void execute(State& state, bytes_view code, bytes_view input, bytes_view expected_output) noexcept
{
    {  // Test run.
        auto r = execute(code, input);
        if (r.status_code != EVMC_SUCCESS)
        {
            state.SkipWithError(("failure: " + std::to_string(r.status_code)).c_str());
            return;
        }

        if (!expected_output.empty())
        {
            auto output = bytes_view{r.output_data, r.output_size};
            if (output != expected_output)
            {
                auto error = "got: " + hex(output) + "  expected: " + hex(expected_output);
                state.SkipWithError(error.c_str());
                return;
            }
        }
    }

    execute(state, code, input);
}

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

/// The error code for CLI arguments parsing error in evmone-bench.
/// The number tries to be different from EVMC loading error codes.
constexpr auto cli_parsing_error = -3;


/// Parses evmone-bench CLI arguments and registers benchmark cases.
///
/// The following variants of number arguments are supported (including argv[0]):
///
/// 2: evmone-bench benchmarks_dir
///    Uses evmone VM, loads all benchmarks from benchmarks_dir.
/// 3: evmone-bench evmc_config benchmarks_dir
///    The same as (2) but loads custom EVMC VM.
/// 4: evmone-bench code_hex_file input_hex expected_output_hex.
///    Uses evmone VM, registers custom benchmark with the code from the given file,
///    and the given input. The benchmark will compare the output with the provided
///    expected one.
std::tuple<int, std::vector<BenchmarkCase>> parseargs(int argc, char** argv)
{
    // Arguments' placeholders:
    const char* evmc_config{};
    const char* benchmarks_dir{};
    const char* code_hex_file{};
    const char* input_hex{};
    const char* expected_output_hex{};

    if (argc == 2)
    {
        benchmarks_dir = argv[1];
    }
    else if (argc == 3)
    {
        evmc_config = argv[1];
        benchmarks_dir = argv[2];
    }
    else if (argc == 4)
    {
        code_hex_file = argv[1];
        input_hex = argv[2];
        expected_output_hex = argv[3];
    }
    else
        return {cli_parsing_error, {}};  // Incorrect number of arguments.


    if (evmc_config)
    {
        auto ec = evmc_loader_error_code{};
        vm = evmc::VM{evmc_load_and_configure(evmc_config, &ec)};

        if (ec != EVMC_LOADER_SUCCESS)
        {
            if (const auto error = evmc_last_error_msg())
                std::cerr << "EVMC loading error: " << error << "\n";
            else
                std::cerr << "EVMC loading error " << ec << "\n";
            return {static_cast<int>(ec), {}};
        }

        std::cout << "Benchmarking " << evmc_config << "\n\n";
    }
    else
    {
        vm = evmc::VM{evmc_create_evmone()};
        std::cout << "Benchmarking evmone\n\n";
    }

    if (benchmarks_dir)
    {
        return {0, load_benchmarks_from_dir(benchmarks_dir)};
    }
    else
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
}

void register_benchmarks(const std::vector<BenchmarkCase>& benchmark_cases)
{
    for (const auto& b : benchmark_cases)
    {
        RegisterBenchmark(("analyse/" + b.name).c_str(), [&b](State& state) {
            analyse(state, b.code);
        })->Unit(kMicrosecond);

        for (const auto& input : b.inputs)
        {
            const auto name = "execute/" + b.name + (!input.name.empty() ? '/' + input.name : "");
            RegisterBenchmark(name.c_str(), [&b, &input](State& state) {
                execute(state, b.code, input.input, input.expected_output);
            })->Unit(kMicrosecond);
        }
    }
}
}  // namespace

int main(int argc, char** argv)
{
    try
    {
        Initialize(&argc, argv);
        const auto [ec, benchmark_cases] = parseargs(argc, argv);
        if (ec == cli_parsing_error && ReportUnrecognizedArguments(argc, argv))
            return ec;

        if (ec != 0)
            return ec;

        register_benchmarks(benchmark_cases);
        RunSpecifiedBenchmarks();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
