// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <state/precompiles_internal.hpp>

#ifdef EVMONE_PRECOMPILES_SILKPRE
#include <state/precompiles_silkpre.hpp>
#endif

namespace
{
using ExecuteFn = evmone::state::ExecutionResult(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

template <ExecuteFn Fn>
void identity(benchmark::State& state)
{
    const uint8_t input[4096]{};
    uint8_t output[sizeof(input)];

    const auto [gas_cost, max_output_size] =
        evmone::state::identity_analyze({input, std::size(input)}, EVMC_LATEST_STABLE_REVISION);
    if (max_output_size > std::size(output))
        return state.SkipWithError("too small output");

    int64_t total_gas_used = 0;
    for ([[maybe_unused]] auto _ : state)
    {
        const auto [status, _2] = Fn(input, std::size(input), output, std::size(output));
        if (status != EVMC_SUCCESS) [[unlikely]]
            return state.SkipWithError("invalid result");
        total_gas_used += gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK_TEMPLATE(identity, evmone::state::identity_execute);

template <ExecuteFn Fn>
void ecrecover(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
        "000000000000000000000000000000000000000000000000000000000000001c"
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549")
                           .value();
    uint8_t output[32];

    const auto [gas_cost, max_output_size] =
        evmone::state::ecrecover_analyze(input, EVMC_LATEST_STABLE_REVISION);
    if (max_output_size > std::size(output))
        return state.SkipWithError("too small output");

    int64_t total_gas_used = 0;
    for ([[maybe_unused]] auto _ : state)
    {
        const auto [_2, output_size] = Fn(input.data(), input.size(), output, std::size(output));
        if (output_size != std::size(output)) [[unlikely]]
            return state.SkipWithError("invalid result");
        total_gas_used += gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK_TEMPLATE(ecrecover, evmone::state::ecrecover_execute);
#ifdef EVMONE_PRECOMPILES_SILKPRE
BENCHMARK_TEMPLATE(ecrecover, evmone::state::silkpre_ecrecover_execute);
#endif

template <ExecuteFn Fn>
void ecadd(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
        "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
        "1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc286"
        "0217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4")
                           .value();
    uint8_t output[64];

    const auto [gas_cost, max_output_size] =
        evmone::state::ecadd_analyze(input, EVMC_LATEST_STABLE_REVISION);
    if (max_output_size > std::size(output))
        return state.SkipWithError("too small output");

    int64_t total_gas_used = 0;
    for ([[maybe_unused]] auto _ : state)
    {
        const auto [status, _2] = Fn(input.data(), input.size(), output, std::size(output));
        if (status != EVMC_SUCCESS) [[unlikely]]
            return state.SkipWithError("invalid result");
        total_gas_used += gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK_TEMPLATE(ecadd, evmone::state::ecadd_execute);
#ifdef EVMONE_PRECOMPILES_SILKPRE
BENCHMARK_TEMPLATE(ecadd, evmone::state::silkpre_ecadd_execute);
#endif

template <ExecuteFn Fn>
void ecmul(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
        "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
        "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3")
                           .value();
    uint8_t output[64];

    const auto [gas_cost, max_output_size] =
        evmone::state::ecmul_analyze(input, EVMC_LATEST_STABLE_REVISION);
    if (max_output_size > std::size(output))
        return state.SkipWithError("too small output");

    int64_t total_gas_used = 0;
    for ([[maybe_unused]] auto _ : state)
    {
        const auto [status, _2] = Fn(input.data(), input.size(), output, std::size(output));
        if (status != EVMC_SUCCESS) [[unlikely]]
            return state.SkipWithError("invalid result");
        total_gas_used += gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
BENCHMARK_TEMPLATE(ecmul, evmone::state::ecmul_execute);
#ifdef EVMONE_PRECOMPILES_SILKPRE
BENCHMARK_TEMPLATE(ecmul, evmone::state::silkpre_ecmul_execute);
#endif


template <ExecuteFn Fn>
void ecpairing(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "105456a333e6d636854f987ea7bb713dfd0ae8371a72aea313ae0c32c0bf10160cf031d41b41557f3e7e3ba0c5"
        "1bebe5da8e6ecd855ec50fc87efcdeac168bcc0476be093a6d2b4bbf907172049874af11e1b6267606e00804d3"
        "ff0037ec57fd3010c68cb50161b7d1d96bb71edfec9880171954e56871abf3d93cc94d745fa114c059d74e5b6c"
        "4ec14ae5864ebe23a71781d86c29fb8fb6cce94f70d3de7a2101b33461f39d9e887dbb100f170a2345dde3c07e"
        "256d1dfa2b657ba5cd030427000000000000000000000000000000000000000000000000000000000000000100"
        "000000000000000000000000000000000000000000000000000000000000021a2c3013d2ea92e13c800cde68ef"
        "56a294b883f6ac35d25f587c09b1b3c635f7290158a80cd3d66530f74dc94c94adb88f5cdb481acca997b6e600"
        "71f08a115f2f997f3dbd66a7afe07fe7862ce239edba9e05c5afff7f8a1259c9733b2dfbb929d1691530ca701b"
        "4a106054688728c9972c8512e9789e9567aae23e302ccd75000000000000000000000000000000000000000000"
        "000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000")
                           .value();
    uint8_t output[32];

    const auto [gas_cost, max_output_size] =
        evmone::state::ecpairing_analyze(input, EVMC_LATEST_STABLE_REVISION);
    if (max_output_size > std::size(output))
        return state.SkipWithError("too small output");

    int64_t total_gas_used = 0;
    for ([[maybe_unused]] auto _ : state)
    {
        const auto [status, _2] = Fn(input.data(), input.size(), output, std::size(output));
        if (status != EVMC_SUCCESS) [[unlikely]]
            return state.SkipWithError("invalid result");
        total_gas_used += gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}

BENCHMARK_TEMPLATE(ecpairing, evmone::state::ecpairing_execute);
#ifdef EVMONE_PRECOMPILES_SILKPRE
BENCHMARK_TEMPLATE(ecpairing, evmone::state::silkpre_ecpairing_execute);
#endif

}  // namespace

BENCHMARK_MAIN();
