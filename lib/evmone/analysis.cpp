// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"

#include <evmc/instructions.h>

namespace evmone
{
namespace
{
bool is_terminator(uint8_t c) noexcept
{
    return c == OP_JUMP || c == OP_JUMPI || c == OP_STOP || c == OP_RETURN || c == OP_REVERT ||
           c == OP_SELFDESTRUCT;
}
}

int code_analysis::find_jumpdest(int offset) noexcept
{
    // TODO: Replace with lower_bound().
    for (const auto& d : jumpdest_map)
    {
        if (d.first == offset)
            return d.second;
    }
    return -1;
}

code_analysis analyze(const exec_fn_table& fns, const uint8_t* code, size_t code_size) noexcept
{
    code_analysis analysis;
    analysis.instrs.reserve(code_size + 1);

    auto* instr_table = evmc_get_instruction_metrics_table(EVMC_BYZANTIUM);

    block_info* block = nullptr;
    int instr_index = 0;
    for (size_t i = 0; i < code_size; ++i, ++instr_index)
    {
        const auto c = code[i];
        auto& instr = analysis.instrs.emplace_back(fns[c]);

        const bool jumpdest = c == OP_JUMPDEST;
        if (!block || jumpdest)
        {
            // Create new block.
            block = &analysis.blocks.emplace_back();
            instr.block_index = static_cast<int>(analysis.blocks.size() - 1);

            if (jumpdest)
                analysis.jumpdest_map.emplace_back(static_cast<int>(i), instr_index);
        }

        auto metrics = instr_table[c];
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - block->stack_diff;
        block->stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, block->stack_diff);

        // Skip PUSH data.
        if (c >= OP_PUSH1 && c <= OP_PUSH32)
        {
            // OPT: bswap data here.
            ++i;
            auto push_size = size_t(c - OP_PUSH1 + 1);
            analysis.args_storage.emplace_back();
            auto& data = analysis.args_storage.back();

            auto leading_zeros = 32 - push_size;
            for (auto& b : data)
                b = 0;
            for (size_t j = 0; j < push_size && (i + j) < code_size; ++j)
                data[leading_zeros + j] = code[i + j];
            instr.arg.data = &data[0];
            i += push_size - 1;
        }
        else if (c >= OP_DUP1 && c <= OP_DUP16)
            instr.arg.number = c - OP_DUP1;
        else if (c >= OP_SWAP1 && c <= OP_SWAP16)
            instr.arg.number = c - OP_SWAP1 + 1;
        else if (is_terminator(c))
            block = nullptr;
    }

    // Not terminated block.
    if (block)
        analysis.instrs.emplace_back(fns[OP_STOP]);

    return analysis;
}

}  // namespace evmone
