// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../../lib/evmone/instructions.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>

// TODO: Speculative execution - check conditions after computation is done.
// TODO: Single branch - merge condition checks.

using namespace evmone;

using instr_v1 = evmc_status_code (*)(size_t pc, ExecutionState& state) noexcept;
using instr_v2 = evmc_status_code (*)(size_t pc, uint256* top, ExecutionState& state) noexcept;
using instr_v3 = evmc_status_code (*)(
    size_t pc, uint256* top, const uint256* bottom, ExecutionState& state) noexcept;

instr_v1 instr_table_v1[] = {nullptr};
instr_v2 instr_table_v2[] = {nullptr};
instr_v3 instr_table_v3[] = {nullptr};

[[gnu::noinline]] evmc_status_code loop_v1(const uint8_t* code, ExecutionState& state) noexcept
{
    return instr_table_v1[code[0]](0, state);
}

[[gnu::noinline]] evmc_status_code loop_v2(
    const uint8_t* code, uint256* top, ExecutionState& state) noexcept
{
    return instr_table_v2[code[0]](0, top, state);
}

[[gnu::noinline]] evmc_status_code loop_v3(
    const uint8_t* code, uint256* top, const uint256* bottom, ExecutionState& state) noexcept
{
    return instr_table_v3[code[0]](0, top, bottom, state);
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

evmc_status_code add_v2(size_t pc, uint256* stack, ExecutionState& state) noexcept
{
    const auto stack_size = stack - state.stack.top_item;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    stack[-1] += stack[0];

    pc += 1;
    [[clang::musttail]] return instr_table_v2[state.code[pc]](pc, stack - 1, state);
}

evmc_status_code add_v3(
    size_t pc, uint256* stack, const uint256* bottom, ExecutionState& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    stack[-1] += stack[0];

    pc += 1;
    [[clang::musttail]] return instr_table_v3[state.code[pc]](pc, stack - 1, bottom, state);
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


template <instr_v2 Instr>
static void run_v2(benchmark::State& state)
{
    instr_table_v2[0] = Instr;
    uint8_t code[1024]{};
    evmone::ExecutionState es;
    es.code = {code, std::size(code)};
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (uint64_t i = 0; i < 1024; ++i)
        es.stack.push(i);

    const auto top = es.stack.top_item;
    es.stack.clear();
    const auto bottom = es.stack.top_item;
    for (auto _ : state)
    {
        es.stack.top_item = bottom;
        const auto r = loop_v2(code, top, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v2, add_v2);


template <instr_v3 Instr>
static void run_v3(benchmark::State& state)
{
    instr_table_v3[0] = Instr;
    uint8_t code[1024]{};
    evmone::ExecutionState es;
    es.code = {code, std::size(code)};
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (uint64_t i = 0; i < 1024; ++i)
        es.stack.push(i);

    const auto top = es.stack.top_item;
    es.stack.clear();
    const auto bottom = es.stack.top_item;
    for (auto _ : state)
    {
        es.stack.top_item = bottom;
        const auto r = loop_v3(code, top, bottom, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v3, add_v3);
