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
void op_stop(execution_state& state, const bytes32*) noexcept
{
    state.run = false;
}

void op_gas(execution_state& state, const bytes32* extra) noexcept
{
    (void)extra;
    (void)state;
}

void op_push_full(execution_state& state, const bytes32* extra) noexcept
{
    auto x = intx::be::uint256(extra->bytes);
    state.stack.push_back(x);
}

void op_pop(execution_state& state, const bytes32*) noexcept
{
    state.stack.pop_back();
}

exec_fn_table op_table = []() noexcept
{
    exec_fn_table table{};
    table[OP_STOP] = op_stop;
    table[OP_GAS] = op_gas;
    table[OP_POP] = op_pop;
    for (size_t op = OP_PUSH1; op <= OP_PUSH32; ++op)
        table[op] = op_push_full;
    return table;
}
();
}  // namespace


evmc_result execute(int64_t gas, const uint8_t* code, size_t code_size) noexcept
{
    auto analysis = analyze(op_table, code, code_size);

    execution_state state;
    state.gas_left = gas;
    while (state.run)
    {
        auto& instr = analysis.instrs[state.pc];
        if (instr.block_index >= 0)
        {
            auto& block = analysis.blocks[static_cast<size_t>(instr.block_index)];

            state.gas_left -= block.gas_cost;
            if (state.gas_left <= 0)
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
        }

        // TODO: Change to pointer in analysis.
        auto* extra = &analysis.extra[static_cast<size_t>(instr.extra_data_index)];

        // Advance the PC not to allow jump opcodes to overwrite it.
        ++state.pc;

        instr.fn(state, extra);
    }

    evmc_result result{};
    result.status_code = state.status;
    if (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
        result.gas_left = state.gas_left;
    return result;
}

}  // namespace evmone
