// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"
#include "opcodes_helpers.h"
#include <evmc/instructions.h>
#include <cassert>

namespace evmone
{
inline constexpr evmc_call_kind op2call_kind(uint8_t opcode) noexcept
{
    switch (opcode)
    {
    case OP_CREATE:
        return EVMC_CREATE;
    case OP_CALL:
        return EVMC_CALL;
    case OP_CALLCODE:
        return EVMC_CALLCODE;
    case OP_DELEGATECALL:
        return EVMC_DELEGATECALL;
    case OP_CREATE2:
        return EVMC_CREATE2;
    default:
        return evmc_call_kind(-1);
    }
}

code_analysis analyze(
    const exec_fn_table& fns, evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    code_analysis analysis;

    const auto max_instrs_size = code_size + 1;
    analysis.instrs.reserve(max_instrs_size);

    // This is 2x more than needed but using (code_size / 2 + 1) increases page-faults 1000x.
    const auto max_args_storage_size = code_size + 1;
    analysis.args_storage.reserve(max_args_storage_size);

    const auto* instr_table = evmc_get_instruction_metrics_table(rev);

    block_info* block = nullptr;

    int instr_index = 0;

    for (auto code_pos = code; code_pos < code + code_size; ++code_pos, ++instr_index)
    {
        // TODO: Loop in reverse order for easier GAS analysis.
        const auto opcode = *code_pos;

        const bool jumpdest = opcode == OP_JUMPDEST;

        if (!block || jumpdest)
        {
            // Create new block.
            block = &analysis.blocks.emplace_back();

            // Create BEGINBLOCK instruction which either replaces JUMPDEST or is injected
            // in case there is no JUMPDEST.
            auto& beginblock_instr = analysis.instrs.emplace_back(fns[OPX_BEGINBLOCK]);
            beginblock_instr.arg.p.number = static_cast<int>(analysis.blocks.size() - 1);

            if (jumpdest)  // Add the jumpdest to the map.
            {
                analysis.jumpdest_offsets.emplace_back(static_cast<int16_t>(code_pos - code));
                analysis.jumpdest_targets.emplace_back(static_cast<int16_t>(instr_index));
            }
            else  // Increase instruction count because additional BEGINBLOCK was injected.
                ++instr_index;
        }

        auto& instr = jumpdest ? analysis.instrs.back() : analysis.instrs.emplace_back(fns[opcode]);

        const auto metrics = instr_table[opcode];
        const auto instr_stack_req = metrics.num_stack_arguments;
        const auto instr_stack_change = metrics.num_stack_returned_items - instr_stack_req;

        block->stack_req = std::max(block->stack_req, instr_stack_req - block->stack_change);
        block->stack_change += instr_stack_change;
        block->stack_max = std::max(block->stack_max, block->stack_change);

        if (metrics.gas_cost > 0)  // can be -1 for undefined instruction
            block->gas_cost += metrics.gas_cost;

        switch (opcode)
        {
        case ANY_PUSH:
        {
            // OPT: bswap data here.
            const auto push_size = size_t(opcode - OP_PUSH1 + 1);
            auto& data = analysis.args_storage.emplace_back();

            const auto leading_zeros = 32 - push_size;
            const auto i = code_pos - code + 1;
            for (size_t j = 0; j < push_size && (i + j) < code_size; ++j)
                data[leading_zeros + j] = code[i + j];
            instr.arg.data = &data[0];
            code_pos += push_size;
            break;
        }

        case ANY_DUP:
            instr.arg.p.number = opcode - OP_DUP1;
            break;

        case ANY_SWAP:
            instr.arg.p.number = opcode - OP_SWAP1 + 1;
            break;

        case OP_GAS:
            instr.arg.p.number = static_cast<int>(block->gas_cost);
            break;

        case OP_CALL:
        case OP_CALLCODE:
        case OP_DELEGATECALL:
        case OP_STATICCALL:
        case OP_CREATE:
        case OP_CREATE2:
            instr.arg.p.number = static_cast<int>(block->gas_cost);
            instr.arg.p.call_kind =
                op2call_kind(opcode == OP_STATICCALL ? uint8_t{OP_CALL} : opcode);
            break;

        case OP_PC:
            instr.arg.p.number = static_cast<int>(code_pos - code);
            break;

        case OP_LOG0:
        case OP_LOG1:
        case OP_LOG2:
        case OP_LOG3:
        case OP_LOG4:
            instr.arg.p.number = opcode - OP_LOG0;
            break;

        case OP_JUMP:
        case OP_JUMPI:
        case OP_STOP:
        case OP_RETURN:
        case OP_REVERT:
        case OP_SELFDESTRUCT:
            block = nullptr;
            break;
        }
    }

    // Not terminated block or empty code.
    if (block || code_size == 0 || code[code_size - 1] == OP_JUMPI)
        analysis.instrs.emplace_back(fns[OP_STOP]);

    // FIXME: assert(analysis.instrs.size() <= max_instrs_size);

    // Make sure the args_storage has not been reallocated. Otherwise iterators are invalid.
    assert(analysis.args_storage.size() <= max_args_storage_size);

    return analysis;
}

}  // namespace evmone
