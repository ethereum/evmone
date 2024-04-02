// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <benchmark/benchmark.h>
#include <state/precompiles.hpp>
#include <state/precompiles_internal.hpp>
#include <array>
#include <memory>

#ifdef EVMONE_PRECOMPILES_SILKPRE
#include <state/precompiles_silkpre.hpp>
#endif

namespace
{
using evmc::bytes;
using namespace evmone::state;

using ExecuteFn = ExecutionResult(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

template <PrecompileId>
constexpr auto analyze = 0;
template <>
constexpr auto analyze<PrecompileId::identity> = identity_analyze;
template <>
constexpr auto analyze<PrecompileId::ecrecover> = ecrecover_analyze;
template <>
constexpr auto analyze<PrecompileId::ecadd> = ecadd_analyze;
template <>
constexpr auto analyze<PrecompileId::ecmul> = ecmul_analyze;

template <PrecompileId>
const inline std::array inputs{0};

template <>
const inline std::array inputs<PrecompileId::identity>{
    bytes(4096, 0),
    bytes(4096, 1),
};

template <>
const inline std::array inputs<PrecompileId::ecrecover>{
    "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
    "000000000000000000000000000000000000000000000000000000000000001c"
    "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
    "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"_hex,
};

template <>
const inline std::array inputs<PrecompileId::ecadd>{
    "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
    "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
    "1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc286"
    "0217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4"_hex,
};

template <>
const inline std::array inputs<PrecompileId::ecmul>{
    "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2"
    "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba"
    "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3"_hex,
};

template <PrecompileId Id, ExecuteFn Fn>
void precompile(benchmark::State& state)
{
    int64_t batch_gas_cost = 0;
    size_t max_output_size = 0;
    for (const auto& input : inputs<Id>)
    {
        const auto r = analyze<Id>(input, EVMC_LATEST_STABLE_REVISION);
        batch_gas_cost += r.gas_cost;
        max_output_size = std::max(max_output_size, r.max_output_size);
    }
    const auto output = std::make_unique_for_overwrite<uint8_t[]>(max_output_size);


    int64_t total_gas_used = 0;
    while (state.KeepRunningBatch(inputs<Id>.size()))
    {
        for (const auto& input : inputs<Id>)
        {
            const auto [status, _] = Fn(input.data(), input.size(), output.get(), max_output_size);
            if (status != EVMC_SUCCESS) [[unlikely]]
                return state.SkipWithError("invalid result");
        }
        total_gas_used += batch_gas_cost;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(batch_gas_cost));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}

BENCHMARK_TEMPLATE(precompile, PrecompileId::identity, identity_execute);

namespace bench_ecrecovery
{
constexpr auto evmmax_cpp = ecrecover_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecrecover, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libsecp256k1 = silkpre_ecrecover_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecrecover, libsecp256k1);
#endif
}  // namespace bench_ecrecovery

namespace bench_ecadd
{
constexpr auto evmmax_cpp = ecadd_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecadd, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libff = silkpre_ecadd_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecadd, libff);
#endif
}  // namespace bench_ecadd

namespace bench_ecmul
{
constexpr auto evmmax_cpp = ecmul_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecmul, evmmax_cpp);
#ifdef EVMONE_PRECOMPILES_SILKPRE
constexpr auto libff = silkpre_ecmul_execute;
BENCHMARK_TEMPLATE(precompile, PrecompileId::ecmul, libff);
#endif
}  // namespace bench_ecmul

}  // namespace

BENCHMARK_MAIN();
