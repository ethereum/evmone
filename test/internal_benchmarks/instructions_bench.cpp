// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../../lib/evmone/instructions.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>

using namespace evmone;

using instr_v1 = evmc_status_code (*)(size_t pc, ExecutionState& state) noexcept;

instr_v1 instr_table_v1[] = {nullptr};

[[gnu::noinline]] evmc_status_code loop_v1(const uint8_t* code, ExecutionState& state) noexcept
{
    return instr_table_v1[code[0]](0, state);
}

evmc_status_code add_v1(size_t pc, ExecutionState& state) noexcept
{
    if (INTX_UNLIKELY(state.stack.size() < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::impl<OP_ADD>(state);

    pc += 1;
    [[clang::musttail]] return instr_table_v1[state.code[pc]](pc, state);
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


template <instr_v1 Instr>
static void run_v1(benchmark::State& state)
{
    instr_table_v1[0] = Instr;
    uint8_t code[1024]{};
    evmone::ExecutionState es;
    es.code = {code, std::size(code)};
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (uint64_t i = 0; i < 1024; ++i)
        es.stack.push(i);

    const auto stack_top = es.stack.top_item;
    for (auto _ : state)
    {
        es.stack.top_item = stack_top;
        const auto r = loop_v1(code, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v1, add_v1);

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
