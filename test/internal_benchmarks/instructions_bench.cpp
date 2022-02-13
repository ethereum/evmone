// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../../lib/evmone/instructions.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>

// TODO: Speculative execution - check conditions after computation is done.
// TODO: Single branch - merge condition checks.

using namespace evmone;

struct State
{
    int64_t gas_left;
    const uint256* stack_bottom;
    const uint8_t* code;
    const void* tbl;
};

template <evmc_opcode Op>
inline bool check_stack(ptrdiff_t stack_size) noexcept
{
    if constexpr (instr::traits[Op].stack_height_change > 0)
    {
        static_assert(instr::traits[Op].stack_height_change == 1);
        if (INTX_UNLIKELY(stack_size == Stack::limit))
            return false;
    }
    if constexpr (instr::traits[Op].stack_height_required > 0)
    {
        if (INTX_UNLIKELY(stack_size < instr::traits[Op].stack_height_required))
            return false;
    }

    return true;
}

template <evmc_opcode Op>
inline int64_t check_gas(int64_t gas_left) noexcept
{
    static_assert(instr::has_const_gas_cost(Op));
    constexpr auto gas_cost = instr::gas_costs[EVMC_FRONTIER][Op];  // Init assuming const cost.
    return gas_left - gas_cost;
}

using instr_v2 = evmc_status_code (*)(const uint8_t* pc, uint256* top, State& state) noexcept;
using instr_v3 = evmc_status_code (*)(
    const uint8_t* pc, uint256* top, const uint256* bottom, State& state) noexcept;
using instr_v4 = evmc_status_code (*)(
    const uint8_t* pc, uint256* top, const uint256* bottom, int64_t gas, State& state) noexcept;
using instr_v5 = evmc_status_code (*)(
    const uint8_t* pc, uint256* top, int size, int64_t gas, State& state) noexcept;
using instr_v7 = evmc_status_code (*)(
    const void* tbl, const uint8_t* pc, uint256* top, int size, int64_t gas, State& state) noexcept;
using instr_v10 = evmc_status_code (*)(
    const uint8_t* pc, uint256* bottom, int size, State& state) noexcept;

instr_v2 instr_table_v2[] = {nullptr};
instr_v3 instr_table_v3[] = {nullptr};
instr_v4 instr_table_v4[] = {nullptr};
instr_v5 instr_table_v5[] = {nullptr};
instr_v7 instr_table_v7[] = {nullptr};
instr_v10 instr_table_v10[] = {nullptr};

[[gnu::noinline]] evmc_status_code loop_v2(uint256* top, State& state) noexcept
{
    return instr_table_v2[state.code[0]](state.code, top, state);
}

[[gnu::noinline]] evmc_status_code loop_v3(
    uint256* top, const uint256* bottom, State& state) noexcept
{
    return instr_table_v3[state.code[0]](state.code, top, bottom, state);
}

[[gnu::noinline]] evmc_status_code loop_v4(
    uint256* top, const uint256* bottom, int64_t gas, State& state) noexcept
{
    return instr_table_v4[state.code[0]](state.code, top, bottom, gas, state);
}

[[gnu::noinline]] evmc_status_code loop_v5(
    uint256* top, int size, int64_t gas, State& state) noexcept
{
    return instr_table_v5[state.code[0]](state.code, top, size, gas, state);
}

[[gnu::noinline]] evmc_status_code loop_v7(
    uint256* top, int size, int64_t gas, State& state) noexcept
{
    return instr_table_v7[state.code[0]](instr_table_v7, state.code, top, size, gas, state);
}

[[gnu::noinline]] evmc_status_code loop_v10(uint256* bottom, int size, State& state) noexcept
{
    return instr_table_v10[state.code[0]](state.code, bottom, size, state);
}

template <evmc_opcode Op>
evmc_status_code op_v2(const uint8_t* pc, uint256* stack, State& state) noexcept
{
    const auto stack_size = stack - state.stack_bottom;

    if (INTX_UNLIKELY(!check_stack<Op>(stack_size)))
        return EVMC_STACK_UNDERFLOW;

    if (state.gas_left = check_gas<Op>(state.gas_left); INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;
    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v2[*pc](pc, stack - 1, state);
}

template <evmc_opcode Op>
evmc_status_code op_v3(
    const uint8_t* pc, uint256* stack, const uint256* bottom, State& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v3[*pc](pc, stack - 1, bottom, state);
}

template <evmc_opcode Op>
evmc_status_code op_v3a(
    const uint8_t* pc, uint256* stack, const uint256* bottom, State& state) noexcept
{
    pc += 1;
    auto next = instr_table_v3[*pc];

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
    const uint8_t* pc, uint256* stack, const uint256* bottom, int64_t gas, State& state) noexcept
{
    const auto stack_size = stack - bottom;
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    gas -= 3;
    if (INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v4[*pc](pc, stack - 1, bottom, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v4a(
    const uint8_t* pc, uint256* stack, const uint256* bottom, int64_t gas, State& state) noexcept
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
    [[clang::musttail]] return instr_table_v4[*pc](pc, stack - 1, bottom, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v5(
    const uint8_t* pc, uint256* stack, int stack_size, int64_t gas, State& state) noexcept
{
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    if (gas = check_gas<Op>(gas); INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;
    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_table_v5[*pc](pc, stack - 1, stack_size - 1, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v5t(
    const uint8_t* pc, uint256* stack, int stack_size, int64_t gas, State& state) noexcept
{
    auto instr_tbl = reinterpret_cast<const instr_v5*>(state.tbl);

    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    if (gas = check_gas<Op>(gas); INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;
    instr::core::impl<Op>(stack);

    pc += 1;
    [[clang::musttail]] return instr_tbl[*pc](pc, stack - 1, stack_size - 1, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v5u(
    const uint8_t* pc, uint256* stack, int stack_size, int64_t gas, State& state) noexcept
{
    auto instr_tbl = reinterpret_cast<const instr_v5*>(state.tbl);
    pc += 1;
    auto next = instr_tbl[*pc];

    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    if (gas = check_gas<Op>(gas); INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;
    instr::core::impl<Op>(stack);

    [[clang::musttail]] return next(pc, stack - 1, stack_size - 1, gas, state);
}

template <evmc_opcode Op>
evmc_status_code op_v7(const void* tbl, const uint8_t* pc, uint256* stack, int stack_size,
    int64_t gas, State& state) noexcept
{
    if (INTX_UNLIKELY(stack_size < 2))
        return EVMC_STACK_UNDERFLOW;

    gas -= 3;
    if (INTX_UNLIKELY(gas < 0))
        return EVMC_OUT_OF_GAS;

    instr::core::impl<Op>(stack);

    pc += 1;
    auto instr_tbl = reinterpret_cast<const instr_v7*>(tbl);
    [[clang::musttail]] return instr_tbl[*pc](tbl, pc, stack - 1, stack_size - 1, gas, state);
}

evmc_status_code ADD_v10(const uint8_t* pc, uint256* bottom, int size, State& state) noexcept
{
    if (INTX_UNLIKELY((size + 1) < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    bottom[size - 1] += bottom[size];

    pc += 1;
    [[clang::musttail]] return instr_table_v10[*pc](pc, bottom, size - 1, state);
}

evmc_status_code XOR_v10(const uint8_t* pc, uint256* bottom, int size, State& state) noexcept
{
    if (INTX_UNLIKELY((size + 1) < 2))
        return EVMC_STACK_UNDERFLOW;

    state.gas_left -= 3;
    if (INTX_UNLIKELY(state.gas_left < 0))
        return EVMC_OUT_OF_GAS;

    bottom[size - 1] |= bottom[size];

    pc += 1;
    [[clang::musttail]] return instr_table_v10[*pc](pc, bottom, size - 1, state);
}


template <instr_v2 Instr>
static void run_v2(benchmark::State& state)
{
    instr_table_v2[0] = Instr;
    uint8_t code[1024]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    es.gas_left = std::numeric_limits<int64_t>::max();
    es.stack_bottom = stack - 1;

    for (auto _ : state)
    {
        const auto r = loop_v2(stack + 1023, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_ADD>);
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_XOR>);
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v2, op_v2<OP_MUL>);


template <instr_v3 Instr>
static void run_v3(benchmark::State& state)
{
    instr_table_v3[0] = Instr;
    uint8_t code[1024 + 1]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (auto _ : state)
    {
        const auto r = loop_v3(stack + 1023, stack - 1, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_ADD>);
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_XOR>);
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v3, op_v3<OP_MUL>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_ADD>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_XOR>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v3, op_v3a<OP_MUL>);


template <instr_v4 Instr>
static void run_v4(benchmark::State& state)
{
    instr_table_v4[0] = Instr;
    uint8_t code[1024]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    for (auto _ : state)
    {
        const auto r = loop_v4(stack + 1023, stack - 1, std::numeric_limits<int64_t>::max(), es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_ADD>);
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_XOR>);
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v4, op_v4<OP_MUL>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_ADD>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_XOR>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v4, op_v4a<OP_MUL>);


template <instr_v5 Instr>
static void run_v5(benchmark::State& state)
{
    instr_table_v5[0] = Instr;
    uint8_t code[1024]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    es.tbl = instr_table_v5;
    for (auto _ : state)
    {
        const auto r = loop_v5(stack + 1023, 1024, std::numeric_limits<int64_t>::max(), es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v5, op_v5<OP_ADD>);
BENCHMARK_TEMPLATE(run_v5, op_v5<OP_XOR>);
BENCHMARK_TEMPLATE(run_v5, op_v5<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v5, op_v5<OP_MUL>);
BENCHMARK_TEMPLATE(run_v5, op_v5t<OP_ADD>);
BENCHMARK_TEMPLATE(run_v5, op_v5t<OP_XOR>);
BENCHMARK_TEMPLATE(run_v5, op_v5t<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v5, op_v5t<OP_MUL>);
BENCHMARK_TEMPLATE(run_v5, op_v5u<OP_ADD>);
BENCHMARK_TEMPLATE(run_v5, op_v5u<OP_XOR>);
BENCHMARK_TEMPLATE(run_v5, op_v5u<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v5, op_v5u<OP_MUL>);

template <instr_v7 Instr>
static void run_v7(benchmark::State& state)
{
    instr_table_v7[0] = Instr;
    uint8_t code[1024]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    for (auto _ : state)
    {
        const auto r = loop_v7(stack + 1023, 1024, std::numeric_limits<int64_t>::max(), es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v7, op_v7<OP_ADD>);
BENCHMARK_TEMPLATE(run_v7, op_v7<OP_XOR>);
BENCHMARK_TEMPLATE(run_v7, op_v7<OP_BYTE>);
BENCHMARK_TEMPLATE(run_v7, op_v7<OP_MUL>);


template <instr_v10 Instr>
static void run_v10(benchmark::State& state)
{
    instr_table_v10[0] = Instr;
    uint8_t code[1024]{};
    uint256 stack[1024]{};

    State es;
    es.code = code;
    es.gas_left = std::numeric_limits<int64_t>::max();
    for (auto _ : state)
    {
        const auto r = loop_v10(stack, 1023, es);
        if (INTX_UNLIKELY(r != EVMC_STACK_UNDERFLOW))
            state.SkipWithError("wrong exit code");
    }
}
BENCHMARK_TEMPLATE(run_v10, ADD_v10);
BENCHMARK_TEMPLATE(run_v10, XOR_v10);
