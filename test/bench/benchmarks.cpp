// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/evmc.hpp>
#include <evmone/evmone.h>

#include <benchmark/benchmark.h>
#include <test/utils/utils.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace benchmark;

extern const bytes empty_code;
extern const bytes sha1_divs_code;
extern const bytes sha1_shifts_code;
extern const bytes blake2b_shifts_code;

namespace
{
auto vm = evmc::vm{evmc_create_evmone()};

bytes external_code;
bytes external_input;
std::string expected_output_hex;

bool parseargs(int argc, char** argv)
{
    if (argc != 4)
        return false;

    std::ifstream file{argv[1]};
    std::string code_hex{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};

    std::cout << "hex code length: " << code_hex.length() << std::endl;
    external_code = from_hex(code_hex);

    external_input = from_hex(argv[2]);
    std::cout << "input size: " << external_input.size() << std::endl;

    expected_output_hex = argv[3];
    std::cout << "expected output: " << expected_output_hex << std::endl;

    return true;
}

int64_t execute(bytes_view code, bytes_view input) noexcept
{
    constexpr auto gas = std::numeric_limits<int64_t>::max();
    auto msg = evmc_message{};
    msg.gas = gas;
    msg.input_data = input.data();
    msg.input_size = input.size();
    auto null_ctx = evmc_context{};
    auto r = vm.execute(null_ctx, EVMC_CONSTANTINOPLE, msg, code.data(), code.size());
    return gas - r.gas_left;
}

void empty(State& state) noexcept
{
    for (auto _ : state)
        execute(empty_code, {});
}
BENCHMARK(empty);

void sha1_divs(State& state) noexcept
{
    const auto input_size = static_cast<size_t>(state.range(0));

    auto abi_input =
        from_hex("1605782b0000000000000000000000000000000000000000000000000000000000000020");

    auto oss = std::ostringstream{};
    oss << std::hex << std::setfill('0') << std::setw(64) << input_size;
    abi_input += from_hex(oss.str());

    abi_input.resize(abi_input.size() + input_size, 0);

    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};
    for (auto _ : state)
        total_gas_used += iteration_gas_used = execute(sha1_divs_code, abi_input);

    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK(sha1_divs)->Arg(0)->Arg(1351)->Arg(2737)->Arg(5311)->Arg(64 * 1024)->Unit(kMicrosecond);


void sha1_shifts(State& state) noexcept
{
    const auto input_size = static_cast<size_t>(state.range(0));

    auto abi_input =
        from_hex("1605782b0000000000000000000000000000000000000000000000000000000000000020");

    auto oss = std::ostringstream{};
    oss << std::hex << std::setfill('0') << std::setw(64) << input_size;
    abi_input += from_hex(oss.str());

    abi_input.resize(abi_input.size() + input_size, 0);

    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};
    for (auto _ : state)
        total_gas_used += iteration_gas_used = execute(sha1_shifts_code, abi_input);

    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK(sha1_shifts)->Arg(0)->Arg(1351)->Arg(2737)->Arg(5311)->Arg(64 * 1024)->Unit(kMicrosecond);


void blake2b_shifts(State& state) noexcept
{
    const auto input_size = static_cast<size_t>(state.range(0));

    auto abi_input = from_hex(
        "d299dac0"
        "0000000000000000000000000000000000000000000000000000000000000060"
        "0000000000000000000000000000000000000000000000000000000000000080"
        "0000000000000000000000000000000000000000000000000000000000000040");

    auto oss = std::ostringstream{};
    oss << std::hex << std::setfill('0') << std::setw(64) << input_size;
    abi_input += from_hex(oss.str());

    abi_input.resize(abi_input.size() + input_size, 0);

    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};
    for (auto _ : state)
        total_gas_used += iteration_gas_used = execute(blake2b_shifts_code, abi_input);

    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK(blake2b_shifts)
    ->Arg(0)
    ->Arg(2805)
    ->Arg(5610)
    ->Arg(8415)
    ->Arg(64 * 1024)
    ->Unit(kMicrosecond);


void external_evm_code(State& state) noexcept
{
    constexpr auto gas = std::numeric_limits<int64_t>::max();
    auto msg = evmc_message{};
    msg.gas = gas;
    msg.input_data = external_input.data();
    msg.input_size = external_input.size();
    auto null_ctx = evmc_context{};
    auto r =
        vm.execute(null_ctx, EVMC_CONSTANTINOPLE, msg, external_code.data(), external_code.size());

    const auto output_hex = to_hex({r.output_data, r.output_size});
    if (output_hex != expected_output_hex)
    {
        static auto error = "got: " + output_hex + "  expected: " + expected_output_hex;
        state.SkipWithError(error.c_str());
        return;
    }

    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};

    for (auto _ : state)
        total_gas_used += iteration_gas_used = execute(external_code, external_input);

    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}

}  // namespace

int main(int argc, char** argv)
{
    Initialize(&argc, argv);

    if (parseargs(argc, argv))
        RegisterBenchmark("external_evm_code", external_evm_code)->Unit(kMicrosecond);
    else if (ReportUnrecognizedArguments(argc, argv))
        return 1;

    RunSpecifiedBenchmarks();
    return 0;
}
