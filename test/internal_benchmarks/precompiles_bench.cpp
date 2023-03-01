// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmmax/bn254.hpp>

template <decltype(evmmax::bn254::bn254_add_precompile) Fn>
void bn254_add(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53"
        "c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97"
        "da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4")
                           .value();
    uint8_t output[64];

    uint64_t total_gas_used = 0;
    for (auto _ : state)
    {
        Fn(input.data(), input.size(), output);
        total_gas_used += 150;
    }

    state.counters["gas_rate"] =
        benchmark::Counter(static_cast<double>(total_gas_used), benchmark::Counter::kIsRate);
}

BENCHMARK_TEMPLATE(bn254_add, evmmax::bn254::bn254_add_precompile);
