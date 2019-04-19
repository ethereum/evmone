// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"

#include <evmc/instructions.h>

#include <stdio.h>
#include <iostream>

namespace evmone
{
namespace
{
bool is_terminator(uint8_t c) noexcept
{
    return c == OP_JUMP || c == OP_JUMPI || c == OP_STOP || c == OP_RETURN || c == OP_REVERT ||
        c == OP_SELFDESTRUCT;
}

bytes32 init_zero_bytes() noexcept
{
    bytes32 data;
    for (auto& b : data)
        b = 0;
    return data;
}

}  // namespace

static const bytes32 zero_bytes = init_zero_bytes();

code_analysis analyze(const void** labels, const block_info** blocks,
    const instruction_info** instruction_data, evmc_revision rev, const size_t code_size, const uint8_t* code, const void** jump_table) noexcept
{
    auto* instr_table = evmc_get_instruction_metrics_table(rev);

    block_info* block = nullptr;
    code_analysis analysis;
    for (size_t i = 0; i < code_size; ++i)
    {
        uint8_t c = code[i];
        labels[i] = jump_table[c];
        if (!block || (c == OP_JUMPDEST))
        {
            block = &analysis.blocks.emplace_back();
            blocks[i] = block;
        }
        else
        {
            blocks[i] = nullptr;
        }
        auto metrics = instr_table[c];
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - block->stack_diff;
        block->stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, block->stack_diff);
        if (c >= OP_PUSH1 && c <= OP_PUSH32)
        {
            size_t push_size = size_t(c - OP_PUSH1 + 1);
            size_t leading_zeroes = size_t(32 - push_size);
            instruction_info& instruction = analysis.instruction_data.emplace_back();
            memcpy(&instruction.push_data[0], &evmone::zero_bytes, 32);
            memcpy(&instruction.push_data[leading_zeroes], code + i + 1, push_size);
            instruction_data[i] = &instruction;
            i += push_size;
        }
        else if (c == OP_GAS || c == OP_DELEGATECALL || c == OP_CALL || c == OP_CALLCODE ||
                 c == OP_STATICCALL || c == OP_CREATE || c == OP_CREATE2)
        {
            instruction_info& instruction = analysis.instruction_data.emplace_back();
            instruction.gas_data = block->gas_cost;
            instruction_data[i] = &instruction;
        }
        else if (evmone::is_terminator(c))
        {
            instruction_data[i] = nullptr;
            block = nullptr;
        }
        else
        {
            instruction_data[i] = nullptr;
        }
    }
    blocks[code_size] = nullptr;
    blocks[code_size + 1] = nullptr;
    labels[code_size] = jump_table[0];
    labels[code_size + 1] = jump_table[0];  // TODO fix;
    return analysis;
}
}  // namespace evmone
