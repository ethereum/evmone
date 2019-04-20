// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"
#include "constants.hpp"

#include <evmc/instructions.h>

namespace evmone
{
namespace
{
bytes32 init_zero_bytes() noexcept
{
    bytes32 data;
    for (auto& b : data)
        b = 0;
    return data;
}
static const bytes32 zero_bytes = init_zero_bytes();
}  // namespace

void analyze(instruction* instructions, instruction** jumpdest_map, evmc_revision rev,
    const size_t code_size, const uint8_t* code, const void** jump_table) noexcept
{
    auto* instr_table = evmc_get_instruction_metrics_table(rev);
    int stack_diff = 0;
    block_info* block = nullptr;
    size_t instr_index = 0;
    for (size_t i = 0; i < code_size; ++i, ++instr_index)
    {
        uint8_t c = code[i];
        instruction& instr = instructions[instr_index];

        if (!block || (c == OP_JUMPDEST))
        {
            block = &instr.block_data;
            stack_diff = 0;
            instr.opcode_dest = jump_table[c];
        }
        else
        {
            instr.opcode_dest = jump_table[c + JUMP_TABLE_CHECK_BOUNDARY];
        }
        auto metrics = instr_table[c];
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - stack_diff;
        stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, stack_diff);
        switch (c)
        {
        case OP_GAS:
        case OP_CREATE:
        case OP_CALL:
        case OP_CALLCODE:
        case OP_DELEGATECALL:
        case OP_CREATE2:
        case OP_STATICCALL:
        {
            instr.instruction_data.number = block->gas_cost;
            break;
        }
        case OP_PUSH1:
        case OP_PUSH2:
        case OP_PUSH3:
        case OP_PUSH4:
        case OP_PUSH5:
        case OP_PUSH6:
        case OP_PUSH7:
        case OP_PUSH8:
        case OP_PUSH9:
        case OP_PUSH10:
        case OP_PUSH11:
        case OP_PUSH12:
        case OP_PUSH13:
        case OP_PUSH14:
        case OP_PUSH15:
        case OP_PUSH16:
        case OP_PUSH17:
        case OP_PUSH18:
        case OP_PUSH19:
        case OP_PUSH20:
        case OP_PUSH21:
        case OP_PUSH22:
        case OP_PUSH23:
        case OP_PUSH24:
        case OP_PUSH25:
        case OP_PUSH26:
        case OP_PUSH27:
        case OP_PUSH28:
        case OP_PUSH29:
        case OP_PUSH30:
        case OP_PUSH31:
        case OP_PUSH32:
        {
            size_t push_size = static_cast<size_t>(c - OP_PUSH1 + 1);
            size_t leading_zeroes = size_t(32 - push_size);
            memcpy(&instr.instruction_data.push_data[0], &evmone::zero_bytes, 32);
            memcpy(&instr.instruction_data.push_data[leading_zeroes], code + i + 1, push_size);
            i += push_size;
            break;
        }
        // TODO: what's slower, the additional lookup or fetching more code for separate
        // subroutines?
        /*
        case OP_DUP1:
        case OP_DUP2:
        case OP_DUP3:
        case OP_DUP4:
        case OP_DUP5:
        case OP_DUP6:
        case OP_DUP7:
        case OP_DUP8:
        case OP_DUP9:
        case OP_DUP10:
        case OP_DUP11:
        case OP_DUP12:
        case OP_DUP13:
        case OP_DUP14:
        case OP_DUP15:
        case OP_DUP16:
        {
            instr.instruction_data.number = c - OP_DUP1;
            break;
        }
        case OP_SWAP1:
        case OP_SWAP2:
        case OP_SWAP3:
        case OP_SWAP4:
        case OP_SWAP5:
        case OP_SWAP6:
        case OP_SWAP7:
        case OP_SWAP8:
        case OP_SWAP9:
        case OP_SWAP10:
        case OP_SWAP11:
        case OP_SWAP12:
        case OP_SWAP13:
        case OP_SWAP14:
        case OP_SWAP15:
        case OP_SWAP16:
        {
            instr.instruction_data.number = c - OP_SWAP1 + 1;
            break;
        }
        */
        case OP_PC:
        {
            instr.instruction_data.number = static_cast<int64_t>(i);
            break;
        }
        case OP_STOP:
        case OP_JUMP:
        case OP_JUMPI:
        case OP_RETURN:
        case OP_REVERT:
        case OP_SELFDESTRUCT:
        {
            block = nullptr;
            break;
        }
        case OP_JUMPDEST:
        {
            // point to the instruction before the instruction we want to jump to, as main loop will
            // increase the pointer prior to jumping
            jumpdest_map[i] = &instructions[instr_index - 1];
            break;
        }
        }
    }
    instructions[instr_index].opcode_dest = jump_table[0];
    instructions[code_size].opcode_dest = jump_table[0];
    instructions[code_size + 1].opcode_dest = jump_table[0];
}
}  // namespace evmone
