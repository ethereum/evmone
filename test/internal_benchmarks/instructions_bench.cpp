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
using instr_v4 = evmc_status_code (*)(
    size_t pc, uint256* top, const uint256* bottom, int64_t gas, ExecutionState& state) noexcept;
using instr_v5 = evmc_status_code (*)(
    size_t pc, uint256* bottom, int size, ExecutionState& state) noexcept;

instr_v1 instr_table_v1[] = {nullptr};
instr_v2 instr_table_v2[] = {nullptr};
instr_v3 instr_table_v3[] = {nullptr};
instr_v4 instr_table_v4[] = {nullptr};
instr_v5 instr_table_v5[] = {nullptr};

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

[[gnu::noinline]] evmc_status_code loop_v4(const uint8_t* code, uint256* top, const uint256* bottom,
    int64_t gas, ExecutionState& state) noexcept
{
    return instr_table_v4[code[0]](0, top, bottom, gas, state);
}

[[gnu::noinline]] evmc_status_code loop_v5(
    const uint8_t* code, uint256* bottom, int size, ExecutionState& state) noexcept
{
    return instr_table_v5[code[0]](0, bottom, size, state);
}

template <evmc_opcode Op>
evmc_status_code op_v1(size_t pc, ExecutionState& state) noexcept
{
    if (INTX_UNLIKELY(state.stack.size() < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::impl<Op>(state);

    pc += 1;
    [[clang::musttail]] return instr_table_v1[state.code[pc]](pc, state);
}

template <evmc_opcode Op>
evmc_status_code op_v2(size_t pc, uint256* stack, ExecutionState& state) noexcept
{
    const auto stack_size = stack - state.stack.top_item;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v2[state.code[pc]](pc, stack - 1, state);
}

template <evmc_opcode Op>
evmc_status_code op_v3(
    size_t pc, uint256* stack, const uint256* bottom, ExecutionState& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v3[state.code[pc]](pc, stack - 1, bottom, state);
}

template <evmc_opcode Op>
evmc_status_code op_v3a(
    size_t pc, uint256* stack, const uint256* bottom, ExecutionState& state) noexcept
{
    pc += 1;
    auto next = instr_table_v3[state.code[pc]];

    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    [[clang::musttail]] return next(pc, stack - 1, bottom, state);
}

template <evmc_opcode Op>
evmc_status_code op_v4(
    size_t pc, uint256* stack, const uint256* bottom, int64_t gas, ExecutionState& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    gas -= 3;
    if (INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v4[state.code[pc]](pc, stack - 1, bottom, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v4a(
    size_t pc, uint256* stack, const uint256* bottom, int64_t gas, ExecutionState& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    instr::core::impl<Op>(stack);

    // Speculative.
    gas -= 3;
    if (INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;

    pc += 1;
    [[clang::musttail]] return instr_table_v4[state.code[pc]](pc, stack - 1, bottom, gas, state);
}

evmc_status_code ADD_v5(size_t pc, uint256* bottom, int size, ExecutionState& state) noexcept
{
    if (INTX_UNLIKELY((size + 1) < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    bottom[size - 1] += bottom[size];

    pc += 1;
    [[clang::musttail]] return instr_table_v5[state.code[pc]](pc, bottom, size - 1, state);
}

evmc_status_code XOR_v5(size_t pc, uint256* bottom, int size, ExecutionState& state) noexcept
{
    if (INTX_UNLIKELY((size + 1) < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    bottom[size - 1] |= bottom[size];

    pc += 1;
    [[clang::musttail]] return instr_table_v5[state.code[pc]](pc, bottom, size - 1, state);
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
BENCHMARK_TEMPLATE(run_v1, op_v1<OP_ADD>);
BENCHMARK_TEMPLATE(run_v1, op_v1<OP_XOR>);


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
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_ADD>);
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_XOR>);


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
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_ADD>);
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_XOR>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_ADD>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_XOR>);


template <instr_v4 Instr>
static void run_v4(benchmark::State& state)
{
    instr_table_v4[0] = Instr;
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
        const auto r = loop_v4(code, top, bottom, es.gas_left, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_ADD>);
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_XOR>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_ADD>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_XOR>);


template <instr_v5 Instr>
static void run_v5(benchmark::State& state)
{
    instr_table_v5[0] = Instr;
    uint8_t code[1024]{};
    evmone::ExecutionState es;
    es.code = {code, std::size(code)};
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (uint64_t i = 0; i < 1024; ++i)
        es.stack.push(i);

    es.stack.clear();
    const auto bottom = es.stack.top_item;
    for (auto _ : state)
    {
        es.stack.top_item = bottom;
        const auto r = loop_v5(code, bottom, 1023, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v5, ADD_v5);
BENCHMARK_TEMPLATE(run_v5, XOR_v5);
