// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"

#include <evmc/instructions.h>

namespace evmone
{
namespace
{
bool check_memory(execution_state& state, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)
        return true;

    constexpr auto limit = uint32_t(-1);

    if (limit < offset || limit < size)  // TODO: Revert order of args in <.
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return false;
    }

    const auto o = static_cast<int64_t>(offset);
    const auto s = static_cast<int64_t>(size);

    const auto m = static_cast<int64_t>(state.memory.size());

    const auto new_size = o + s;
    if (m < new_size)
    {
        auto w = (new_size + 31) / 32;
        auto new_cost = 3 * w + w * w / 512;
        auto cost = new_cost - state.memory_prev_cost;
        state.memory_prev_cost = new_cost;

        state.gas_left -= cost;
        if (state.gas_left < 0)
        {
            state.run = false;
            state.status = EVMC_OUT_OF_GAS;
            return false;
        }

        state.memory.resize(static_cast<size_t>(w * 32));
    }

    return true;
}


void op_stop(execution_state& state, instr_argument) noexcept
{
    state.run = false;
}

void op_add(execution_state& state, instr_argument) noexcept
{
    state.item(1) += state.item(0);
    state.stack.pop_back();
}

void op_mul(execution_state& state, instr_argument) noexcept
{
    state.item(1) *= state.item(0);
    state.stack.pop_back();
}

void op_sub(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) - state.item(1);
    state.stack.pop_back();
}

void op_div(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) / state.item(1);
    state.stack.pop_back();
}

void op_sdiv(execution_state& state, instr_argument) noexcept
{
    state.item(1) = intx::sdivrem(state.item(0), state.item(1)).quot;
    state.stack.pop_back();
}

void op_mod(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) % state.item(1);
    state.stack.pop_back();
}

void op_smod(execution_state& state, instr_argument) noexcept
{
    state.item(1) = intx::sdivrem(state.item(0), state.item(1)).rem;
    state.stack.pop_back();
}

void op_addmod(execution_state& state, instr_argument) noexcept
{
    auto x = state.item(0);
    auto y = state.item(1);
    auto m = state.item(2);

    auto r = (intx::uint512(x) + intx::uint512(y)) % intx::uint512(m);

    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = r.lo;
}

void op_mulmod(execution_state& state, instr_argument) noexcept
{
    auto x = state.item(0);
    auto y = state.item(1);
    auto m = state.item(2);

    auto r = (intx::uint512(x) * intx::uint512(y)) % intx::uint512(m);

    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = r.lo;
}

void op_exp(execution_state& state, instr_argument arg) noexcept
{
    auto base = state.item(0);
    auto& exponent = state.item(1);

    auto exponent_significant_bytes = intx::count_significant_words<uint8_t>(exponent);

    auto additional_cost = exponent_significant_bytes * arg.number;
    state.gas_left -= additional_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    exponent = intx::exp(base, exponent);
    state.stack.pop_back();
}

void op_signextend(execution_state& state, instr_argument) noexcept
{
    auto ext = state.item(0);
    state.stack.pop_back();
    auto& x = state.item(0);

    if (ext < 31)
    {
        auto sign_bit = static_cast<int>(ext) * 8 + 7;
        auto sign_mask = intx::uint256{1} << sign_bit;
        // TODO: Fix intx operator- overloading: X - 1 does not work.
        auto value_mask = sign_mask - intx::uint256{1};
        auto is_neg = (x & sign_mask) != 0;
        x = is_neg ? x | ~value_mask : x & value_mask;
    }
}

void op_lt(execution_state& state, instr_argument) noexcept
{
    // OPT: Have single function implementing all comparisons.
    state.item(1) = state.item(0) < state.item(1);
    state.stack.pop_back();
}

void op_gt(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(1) < state.item(0);
    state.stack.pop_back();
}

void op_slt(execution_state& state, instr_argument) noexcept
{
    // TODO: Move implementation to intx.
    // OPT: Find better way, __int128 provides some hints.
    auto x = state.item(0);
    auto y = state.item(1);
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.item(1) = x_neg ? y_neg ? y < x : true : y_neg ? false : x < y;
    state.stack.pop_back();
}

void op_sgt(execution_state& state, instr_argument) noexcept
{
    auto x = state.item(1);
    auto y = state.item(0);
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.item(1) = x_neg ? y_neg ? y < x : true : y_neg ? false : x < y;
    state.stack.pop_back();
}

void op_eq(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) == state.item(1);
    state.stack.pop_back();
}

void op_iszero(execution_state& state, instr_argument) noexcept
{
    state.item(0) = state.item(0) == 0;
}

void op_and(execution_state& state, instr_argument) noexcept
{
    // TODO: Add operator&= to intx.
    state.item(1) = state.item(0) & state.item(1);
    state.stack.pop_back();
}

void op_or(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) | state.item(1);
    state.stack.pop_back();
}

void op_xor(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) ^ state.item(1);
    state.stack.pop_back();
}

void op_not(execution_state& state, instr_argument) noexcept
{
    state.item(0) = ~state.item(0);
}

void op_byte(execution_state& state, instr_argument) noexcept
{
    auto n = state.item(0);
    auto& x = state.item(1);

    if (31 < n)
        x = 0;
    else
    {
        auto sh = (31 - static_cast<unsigned>(n)) * 8;
        auto y = x >> sh;
        x = y & intx::uint256(0xff);  // TODO: Fix intx operator&.
    }

    state.stack.pop_back();
}

void op_calldataload(execution_state& state, instr_argument) noexcept
{
    auto& index = state.item(0);

    if (state.msg->input_size < index)
        index = 0;
    else
    {
        const auto begin = static_cast<size_t>(index);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        index = intx::be::uint256(data);
    }
}

void op_mload(execution_state& state, instr_argument) noexcept
{
    auto& index = state.item(0);

    if (!check_memory(state, index, 32))
        return;

    index = intx::be::uint256(&state.memory[static_cast<size_t>(index)]);
}

void op_mstore(execution_state& state, instr_argument) noexcept
{
    auto index = state.item(0);
    auto x = state.item(1);

    if (!check_memory(state, index, 32))
        return;

    intx::be::store(&state.memory[static_cast<size_t>(index)], x);

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_mstore8(execution_state& state, instr_argument) noexcept
{
    auto index = state.item(0);
    auto x = state.item(1);

    if (!check_memory(state, index, 1))
        return;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(x);

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_jump(execution_state& state, instr_argument) noexcept
{
    auto dst = state.item(0);
    int pc = -1;
    if (std::numeric_limits<int>::max() < dst ||
        (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
    {
        state.run = false;
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return;
    }

    state.pc = static_cast<size_t>(pc);
    state.stack.pop_back();
}

void op_jumpi(execution_state& state, instr_argument) noexcept
{
    auto condition = state.item(1);
    if (condition != 0)
    {
        // TODO: Call op_jump here.
        auto dst = state.item(0);
        int pc = -1;
        if (std::numeric_limits<int>::max() < dst ||
            (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
        {
            state.run = false;
            state.status = EVMC_BAD_JUMP_DESTINATION;
            return;
        }
        state.pc = static_cast<size_t>(pc);
    }

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_pc(execution_state& state, instr_argument arg) noexcept
{
    // TODO: Using temporary object does not work with push_back().
    intx::uint256 size = arg.number;
    state.stack.push_back(size);
}

void op_msize(execution_state& state, instr_argument) noexcept
{
    // TODO: Using temporary object does not work with push_back().
    intx::uint256 size = state.memory.size();
    state.stack.push_back(size);
}

void op_gas(execution_state& state, instr_argument arg) noexcept
{
    auto correction = state.current_block_cost - arg.number;
    intx::uint256 gas = static_cast<uint64_t>(state.gas_left + correction);
    state.stack.push_back(gas);
}

void op_jumpdest(execution_state&, instr_argument) noexcept
{
    // OPT: We can skip JUMPDEST instruction in analysis.
}

void op_push_full(execution_state& state, instr_argument arg) noexcept
{
    // OPT: For smaller pushes, use pointer data directly.
    auto x = intx::be::uint256(arg.data);
    state.stack.push_back(x);
}

void op_pop(execution_state& state, instr_argument) noexcept
{
    state.stack.pop_back();
}

void op_dup(execution_state& state, instr_argument arg) noexcept
{
    state.stack.push_back(state.item(static_cast<size_t>(arg.number)));
}

void op_swap(execution_state& state, instr_argument arg) noexcept
{
    std::swap(state.item(0), state.item(static_cast<size_t>(arg.number)));
}

void op_return(execution_state& state, instr_argument) noexcept
{
    auto offset = state.item(0);
    auto size = state.item(1);

    if (!check_memory(state, offset, size))
        return;

    state.run = false;
    state.output_offset = static_cast<size_t>(offset);
    state.output_size = static_cast<size_t>(size);
}

exec_fn_table op_table = []() noexcept
{
    exec_fn_table table{};
    table[OP_STOP] = op_stop;
    table[OP_ADD] = op_add;
    table[OP_MUL] = op_mul;
    table[OP_SUB] = op_sub;
    table[OP_DIV] = op_div;
    table[OP_SDIV] = op_sdiv;
    table[OP_MOD] = op_mod;
    table[OP_SMOD] = op_smod;
    table[OP_ADDMOD] = op_addmod;
    table[OP_MULMOD] = op_mulmod;
    table[OP_EXP] = op_exp;
    table[OP_SIGNEXTEND] = op_signextend;
    table[OP_LT] = op_lt;
    table[OP_GT] = op_gt;
    table[OP_SLT] = op_slt;
    table[OP_SGT] = op_sgt;
    table[OP_EQ] = op_eq;
    table[OP_ISZERO] = op_iszero;
    table[OP_AND] = op_and;
    table[OP_OR] = op_or;
    table[OP_XOR] = op_xor;
    table[OP_NOT] = op_not;
    table[OP_BYTE] = op_byte;
    table[OP_CALLDATALOAD] = op_calldataload;
    table[OP_POP] = op_pop;
    table[OP_MLOAD] = op_mload;
    table[OP_MSTORE] = op_mstore;
    table[OP_MSTORE8] = op_mstore8;
    table[OP_JUMP] = op_jump;
    table[OP_JUMPI] = op_jumpi;
    table[OP_PC] = op_pc;
    table[OP_MSIZE] = op_msize;
    table[OP_GAS] = op_gas;
    table[OP_JUMPDEST] = op_jumpdest;
    for (size_t op = OP_PUSH1; op <= OP_PUSH32; ++op)
        table[op] = op_push_full;
    for (size_t op = OP_DUP1; op <= OP_DUP16; ++op)
        table[op] = op_dup;
    for (size_t op = OP_SWAP1; op <= OP_SWAP16; ++op)
        table[op] = op_swap;
    table[OP_RETURN] = op_return;
    return table;
}
();
}  // namespace


evmc_result execute(const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto analysis = analyze(op_table, code, code_size);

    execution_state state;
    state.analysis = &analysis;
    state.msg = msg;
    state.gas_left = msg->gas;
    while (state.run)
    {
        auto& instr = analysis.instrs[state.pc];
        if (instr.block_index >= 0)
        {
            auto& block = analysis.blocks[static_cast<size_t>(instr.block_index)];

            state.gas_left -= block.gas_cost;
            if (state.gas_left < 0)
            {
                state.status = EVMC_OUT_OF_GAS;
                break;
            }

            if (static_cast<int>(state.stack.size()) < block.stack_req)
            {
                state.status = EVMC_STACK_UNDERFLOW;
                break;
            }

            if (static_cast<int>(state.stack.size()) + block.stack_max > 1024)
            {
                state.status = EVMC_STACK_OVERFLOW;
                break;
            }

            state.current_block_cost = block.gas_cost;
        }

        // Advance the PC not to allow jump opcodes to overwrite it.
        ++state.pc;

        instr.fn(state, instr.arg);
    }

    evmc_result result{};
    result.status_code = state.status;
    if (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
        result.gas_left = state.gas_left;

    if (state.output_size > 0)
    {
        result.output_size = state.output_size;
        auto output_data = static_cast<uint8_t*>(std::malloc(result.output_size));
        std::memcpy(output_data, &state.memory[state.output_offset], result.output_size);
        result.output_data = output_data;
        result.release = [](const evmc_result* result) noexcept
        {
            std::free(const_cast<uint8_t*>(result->output_data));
        };
    }

    return result;
}

}  // namespace evmone
