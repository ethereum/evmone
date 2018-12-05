// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"

#include <evmc/instructions.h>

namespace evmone
{
code_analysis analyze(const exec_fn_table& fns, const uint8_t* code, size_t code_size) noexcept
{
    code_analysis analysis;
    analysis.instrs.reserve(code_size + 1);

    auto* instr_table = evmc_get_instruction_metrics_table(EVMC_BYZANTIUM);

    block_info block{};
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto c = code[i];
        auto metrics = instr_table[c];
        block.gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - block.stack_diff;
        block.stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block.stack_req = std::max(block.stack_req, stack_req);
        block.stack_max = std::max(block.stack_max, block.stack_diff);

        // Skip PUSH data.
        if (c >= OP_PUSH1 && c <= OP_PUSH2)
            i += size_t(c - OP_PUSH1 + 1);

        analysis.instrs.emplace_back(instr_info{fns[c]});
    }
    analysis.blocks.emplace_back(block);

    // Additional STOP:
    analysis.instrs.emplace_back(instr_info{nullptr});

    return analysis;
}

}  // namespace evmone
