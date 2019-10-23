// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/analysis.hpp>
#include <evmone/evmone.h>

#include <benchmark/benchmark.h>
#include <test/utils/utils.hpp>
#include <cctype>
#include <fstream>
#include <iostream>
#include <memory>


#if HAVE_STD_FILESYSTEM
#include <filesystem>
namespace fs = std::filesystem;
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include "filesystem.hpp"
namespace fs = ghc::filesystem;
#pragma GCC diagnostic pop
#endif

using namespace benchmark;

namespace
{
constexpr auto gas_limit = std::numeric_limits<int64_t>::max();
auto vm = evmc::vm{};

constexpr auto inputs_extension = ".inputs";

inline evmc::result execute(bytes_view code, bytes_view input) noexcept
{
    auto msg = evmc_message{};
    msg.gas = gas_limit;
    msg.input_data = input.data();
    msg.input_size = input.size();
    auto null_ctx = evmc_context{};
    return vm.execute(null_ctx, EVMC_CONSTANTINOPLE, msg, code.data(), code.size());
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
        auto r = evmone::analyze(EVMC_PETERSBURG, code.data(), code.size());
        DoNotOptimize(r);
        bytes_analysed += code.size();
    }
    state.counters["size"] = Counter(static_cast<double>(code.size()));
    state.counters["rate"] = Counter(static_cast<double>(bytes_analysed), Counter::kIsRate);
}

struct benchmark_case
{
    std::shared_ptr<bytes> code;
    bytes input;
    bytes expected_output;

    void operator()(State& state) noexcept
    {
        {
            auto r = execute(*code, input);
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
                    auto error =
                        "got: " + to_hex(output) + "  expected: " + to_hex(expected_output);
                    state.SkipWithError(error.c_str());
                    return;
                }
            }
        }

        execute(state, *code, input);
    }
};


void load_benchmark(const fs::path& path, const std::string& name_prefix)
{
    const auto base_name = name_prefix + path.stem().string();

    std::ifstream file{path};
    std::string code_hex{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};

    code_hex.erase(
        std::remove_if(code_hex.begin(), code_hex.end(), [](auto x) { return std::isspace(x); }),
        code_hex.end());

    auto code = std::make_shared<bytes>(from_hex(code_hex));

    RegisterBenchmark((base_name + "/analysis").c_str(), [code](State& state) {
        analyse(state, *code);
    })->Unit(kMicrosecond);

    enum class state
    {
        name,
        input,
        expected_output
    };

    auto base = benchmark_case{};
    base.code = std::move(code);

    auto inputs_path = path;
    inputs_path.replace_extension(inputs_extension);
    if (!fs::exists(inputs_path))
    {
        RegisterBenchmark(base_name.c_str(), base)->Unit(kMicrosecond);
    }
    else
    {
        auto st = state::name;
        auto inputs_file = std::ifstream{inputs_path};
        auto input = benchmark_case{};
        auto name = std::string{};
        for (std::string l; std::getline(inputs_file, l);)
        {
            switch (st)
            {
            case state::name:
                if (l.empty())
                    continue;
                input = base;
                name = base_name + '/' + std::move(l);
                st = state::input;
                break;

            case state::input:
                input.input = from_hexx(l);
                st = state::expected_output;
                break;

            case state::expected_output:
                input.expected_output = from_hexx(l);
                RegisterBenchmark(name.c_str(), input)->Unit(kMicrosecond);
                st = state::name;
                break;
            }
        }
    }
}

void load_benchmarks_from_dir(const fs::path& path, const std::string& name_prefix = {})
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

    for (const auto& f : files)
        load_benchmark(f, name_prefix);

    for (const auto& d : subdirs)
        load_benchmarks_from_dir(d, name_prefix + d.filename().string() + '/');
}

/// The error code for CLI arguments parsing error in evmone-bench.
/// The number tries to be different from EVMC loading error codes.
constexpr auto cli_parsing_error = -3;

int parseargs(int argc, char** argv)
{
    if (argc == 2)
    {
        vm = evmc::vm{evmc_create_evmone()};
        std::cout << "Benchmarking evmone\n\n";
        load_benchmarks_from_dir(argv[1]);
        return 0;
    }

    if (argc == 3)
    {
        const auto evmc_config = argv[1];
        auto ec = evmc_loader_error_code{};
        vm = evmc::vm{evmc_load_and_configure(evmc_config, &ec)};

        if (ec != EVMC_LOADER_SUCCESS)
        {
            if (const auto error = evmc_last_error_msg())
                std::cerr << "EVMC loading error: " << error << "\n";
            else
                std::cerr << "EVMC loading error " << ec << "\n";
            return static_cast<int>(ec);
        }

        std::cout << "Benchmarking " << evmc_config << "\n\n";
        load_benchmarks_from_dir(argv[2]);
        return 0;
    }

    if (argc != 4)
        return cli_parsing_error;

    std::ifstream file{argv[1]};
    std::string code_hex{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
    code_hex.erase(
        std::remove_if(code_hex.begin(), code_hex.end(), [](auto x) { return std::isspace(x); }),
        code_hex.end());

    auto b = benchmark_case{};
    b.code = std::make_shared<bytes>(from_hex(code_hex));
    b.input = from_hex(argv[2]);
    b.expected_output = from_hex(argv[3]);
    RegisterBenchmark("external_evm_code", b)->Unit(kMicrosecond);
    return 0;
}
}  // namespace

int main(int argc, char** argv)
{
    try
    {
        Initialize(&argc, argv);

        const auto ec = parseargs(argc, argv);

        if (ec == cli_parsing_error && ReportUnrecognizedArguments(argc, argv))
            return ec;

        if (ec != 0)
            return ec;

        RunSpecifiedBenchmarks();
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        return -1;
    }
}
