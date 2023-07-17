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

template <decltype(evmmax::bn254::bn254_mul_precompile) Fn>
void bn254_mul(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a13"
        "3a996eb6300b44da664d64251d05381bb8a02e183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10"
        "460b6c3e7ea3")
                           .value();
    uint8_t output[64];

    uint64_t total_gas_used = 0;
    for (auto _ : state)
    {
        Fn(input.data(), input.size(), output);
        total_gas_used += 6000;
    }

    state.counters["gas_rate"] =
        benchmark::Counter(static_cast<double>(total_gas_used), benchmark::Counter::kIsRate);
}

template <decltype(evmmax::bn254::bn254_ecpairing_precompile) Fn>
void bn254_ecpairing(benchmark::State& state)
{
    const auto input = evmc::from_hex(
        "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
        "3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
        "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
        "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
        "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
        "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
        "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"
        "2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
        "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
                           .value();
    uint8_t output[32];

    uint64_t total_gas_used = 45000;

    for (auto _ : state)
    {
        Fn(input.data(), input.size(), output);
        total_gas_used += 2 * 34000;
    }

    state.counters["gas_rate"] =
        benchmark::Counter(static_cast<double>(total_gas_used), benchmark::Counter::kIsRate);
}

// BENCHMARK_TEMPLATE(bn254_add, evmone::state::silkpre_ecadd_execute);
BENCHMARK_TEMPLATE(bn254_add, evmmax::bn254::bn254_add_precompile);
// BENCHMARK_TEMPLATE(bn254_mul, evmone::state::silkpre_ecmul_execute);
BENCHMARK_TEMPLATE(bn254_mul, evmmax::bn254::bn254_mul_precompile);
BENCHMARK_TEMPLATE(bn254_ecpairing, evmmax::bn254::bn254_ecpairing_precompile);
