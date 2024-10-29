// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <benchmark/benchmark.h>
#include <state/precompiles.hpp>
#include <state/precompiles_internal.hpp>
#include <memory>
#include <random>

#include <blst.h>


namespace
{
using namespace evmone::state;
using namespace evmone::test;
using enum PrecompileId;

std::mt19937_64 rng{std::random_device{}()};

bytes rand_scalar()
{
    bytes ret;
    ret.resize(32);
    for (auto& b : ret)
        b = static_cast<byte>(rng());
    return ret;
}

bytes rand_p1()
{
    const auto scalar = rand_scalar();
    blst_p1 out;
    blst_p1_mult(&out, blst_p1_generator(), scalar.data(), 256);
    blst_p1_affine r;
    blst_p1_to_affine(&r, &out);

    bytes o;
    o.resize(128);
    blst_bendian_from_fp(&o[16], &r.x);
    blst_bendian_from_fp(&o[64 + 16], &r.y);
    return o;
}

bytes rand_p2()
{
    const auto scalar = rand_scalar();
    blst_p2 out;
    blst_p2_mult(&out, blst_p2_generator(), scalar.data(), 256);
    blst_p2_affine r;
    blst_p2_to_affine(&r, &out);

    bytes o;
    o.resize(256);
    blst_bendian_from_fp(&o[16], &r.x.fp[0]);
    blst_bendian_from_fp(&o[64 + 16], &r.x.fp[1]);
    blst_bendian_from_fp(&o[128 + 16], &r.y.fp[0]);
    blst_bendian_from_fp(&o[128 + 64 + 16], &r.y.fp[1]);
    return o;
}

template <PrecompileId>
struct PrecompileTrait;

template <>
struct PrecompileTrait<bls12_g1add>
{
    static constexpr auto analyze = bls12_g1add_analyze;
    static constexpr auto execute = bls12_g1add_execute;

    static bytes get_input(size_t) { return rand_p1() + rand_p1(); }
};

template <>
struct PrecompileTrait<bls12_g1mul>
{
    static constexpr auto analyze = bls12_g1mul_analyze;
    static constexpr auto execute = bls12_g1mul_execute;

    static bytes get_input(size_t) { return rand_p1() + rand_scalar(); }
};

template <>
struct PrecompileTrait<bls12_g2add>
{
    static constexpr auto analyze = bls12_g2add_analyze;
    static constexpr auto execute = bls12_g2add_execute;

    static bytes get_input(size_t) { return rand_p2() + rand_p2(); }
};

template <PrecompileId Id>
void precompile_bls(benchmark::State& state)
{
    using Trait = PrecompileTrait<Id>;

    const auto input = Trait::get_input(static_cast<size_t>(state.range(0)));
    const auto [gas_cost, max_output_size] = Trait::analyze(input, EVMC_MAX_REVISION);

    const auto output = std::make_unique_for_overwrite<uint8_t[]>(max_output_size);

    for (auto _ : state)
    {
        const auto [status, _2] =
            Trait::execute(input.data(), input.size(), output.get(), max_output_size);
        if (status != EVMC_SUCCESS) [[unlikely]]
        {
            state.SkipWithError("invalid result");
            return;
        }
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(gas_cost));
    state.counters["gas_rate"] =
        Counter(static_cast<double>(gas_cost * state.max_iterations), Counter::kIsRate);
}
BENCHMARK(precompile_bls<bls12_g1add>)->Arg(1);
BENCHMARK(precompile_bls<bls12_g1mul>)->Arg(1);
BENCHMARK(precompile_bls<bls12_g2add>)->Arg(1);

}  // namespace
