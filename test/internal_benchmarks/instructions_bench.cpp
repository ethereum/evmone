// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../../lib/evmone/instructions.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>

[[gnu::noinline]] evmc_status_code add_v1(evmone::ExecutionState& state) noexcept
{
    if (INTX_UNLIKELY(state.stack.size() < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    evmone::instr::impl<OP_ADD>(state);
    return EVMC_SUCCESS;
}

[[gnu::noinline]] int64_t add_v2(intx::uint256*& top, size_t& stack_size, int64_t& gas) noexcept
{
    if (stack_size < 2)
        return EVMC_STACK_UNDERFLOW;

    gas -= 3;
    if (gas < 0)
        return EVMC_OUT_OF_GAS;

    stack_size -= 1;

    const auto arg = top - 1;
    *arg += *top;
    top = arg;

    return EVMC_SUCCESS;
}

[[gnu::noinline]] int64_t add_v3(intx::uint256*& top, size_t& stack_size, int64_t& gas) noexcept
{
    gas -= 3;
    stack_size -= 1;

    const auto arg = top - 1;
    *arg += *top;
    top = arg;

    if (stack_size < 1)
        return EVMC_STACK_UNDERFLOW;

    if (gas < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}

[[gnu::noinline]] int64_t add_v4(intx::uint256*& top, size_t& stack_size, int64_t& gas) noexcept
{
    gas -= 3;
    stack_size -= 1;

    const auto arg = top - 1;
    *arg += *top;
    top = arg;
    return (stack_size < 1) | (gas < 0);
}


template <evmc_status_code Fn(evmone::ExecutionState&)>
static void instr(benchmark::State& state)
{
    evmone::ExecutionState es;
    es.gas_left = std::numeric_limits<int64_t>::max();
    es.stack.push(1);
    es.stack.push(2);
    const auto stack_top = es.stack.top_item;

    for (auto _ : state)
    {
        Fn(es);
        es.stack.top_item = stack_top;
    }
}
BENCHMARK_TEMPLATE(instr, add_v1);

template <decltype(add_v2) Fn>
static void instr2(benchmark::State& state)
{
    evmone::ExecutionState es;
    es.gas_left = std::numeric_limits<int64_t>::max();
    es.stack.push(1);
    es.stack.push(2);
    const auto stack_top = es.stack.top_item;

    for (auto _ : state)
    {
        size_t stack_size = 2;
        Fn(es.stack.top_item, stack_size, es.gas_left);
        es.stack.top_item = stack_top;
    }
}
BENCHMARK_TEMPLATE(instr2, add_v2);
BENCHMARK_TEMPLATE(instr2, add_v3);
BENCHMARK_TEMPLATE(instr2, add_v4);
