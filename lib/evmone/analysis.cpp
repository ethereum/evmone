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

void analyze(instruction* instructions, instruction** jumpdest_map, const void** jump_table, evmc_revision rev,
     const uint8_t* code, const size_t code_size) noexcept
{
    auto* instr_table = evmc_get_instruction_metrics_table(rev);

    // temp variable to track the stack difference within the current basic block
    int stack_diff = 0;

    // when we map program opcode -> jump label, we apply an offset if
    // the opcode is NOT an entry point into a basic block.
    // i.e. first 256 entries in jump table = jump destinations that will perform
    // validation logic on the given basic block.
    // the subsequent 256 entries in jump table = jump destinations that skip this
    // (this removes a conditional branch that is normally required for every opcode)
    // (even better, this was a branch that was non trivial to predict)
    // The variable 'delta' represents this offset.
    // The first entry will always be entry into a basic block, so initialize to 0
    int delta = 0;

    // temporary variable to cache whether the NEXT entry will be a basic block. Default to 'no'
    int next_delta = JUMP_TABLE_CHECK_BOUNDARY;

    // pointer to the current basic block we're working on
    block_info* block = &instructions[0].block_data;
    // initialize our new block (we don't initialize instructions to default values to save some time)
    block->gas_cost = 0;
    block->stack_req = 0;
    block->stack_max = 0;

    // instr_index indexes entries to instructions.
    // i is the program counter index.
    // we don't use i to index instructions, because some program opcodes (i.e. PUSH) use more
    // than 1 byte of bytecode data. Therefore, using i would create a sparse array, where there
    // would be groups of 'empty' entries in 'instructions'. Which would (probably?) increase the number of cache misses
    size_t instr_index = 0;
    for (size_t i = 0; i < code_size; ++i, ++instr_index)
    {
        // get the current opcode
        uint8_t c = code[i];

        // get the metrics for the current 
        auto metrics = instr_table[c];

        // update the current block's stack and gas metrics
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - stack_diff;
        stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, stack_diff);

        // Maybe the compiler can do something clever with this, if we frame it as a giant switch statement...
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
            instructions[instr_index].instruction_data.number = block->gas_cost;
            next_delta = JUMP_TABLE_CHECK_BOUNDARY;
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
            memcpy(&instructions[instr_index].instruction_data.push_data[0], &evmone::zero_bytes, 32);
            memcpy(&instructions[instr_index].instruction_data.push_data[leading_zeroes], code + i + 1, push_size);
            i += push_size;
            next_delta = JUMP_TABLE_CHECK_BOUNDARY;
            break;
        }
        /**
        * TODO: figure out which is faster
        * Option 1: have singleton 'dup' and 'swap' opcodes, and use instruction_data to
        *           identify the stack indices to dup/swap
        * Option 2: have explicit 'dup' and 'swap' opcodes for each variant (e.g. dup1, ..., dup16)
        *
        * Option 1 requires an additional lookup into instruction_data per opcode execution,
        * Option 2 requires fetching more code, so there's a reduced chance that the required code
        *          is in the CPU cache (I think?).
        *          In addition, the CPU has more branches to predict when jumping to each opcode,
        *          but the rationale is that the program flow is simple enough
        *          for the CPU to predict ~100% of the time
        *          (N.B. how in the blazes can this be tested?)
        * I honestly have no idea which is faster, both benchmarks overlap each other.
        **/
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
            instructions[instr_index].instruction_data.number = static_cast<int64_t>(i);
            next_delta = JUMP_TABLE_CHECK_BOUNDARY;
            break;
        }
        case OP_STOP:
        case OP_JUMP:
        case OP_JUMPI:
        case OP_RETURN:
        case OP_REVERT:
        case OP_SELFDESTRUCT:
        {
            block = &instructions[instr_index + 1].block_data;
            block->gas_cost = 0;
            block->stack_max = 0;
            block->stack_req = 0;
            stack_diff = 0;
            next_delta = 0;
            break;
        }
        case OP_JUMPDEST:
        {
            /**
            * If this is a jump destination, we want to log it inside jumpdest_map.
            * This gives us an O(1) mapping from program counter -> relevant instruction.
            * This comes at the expense of using a sparse array,
            * so we use a lot of memory for this map (~200kb for a 24kb program),
            * and entries are less likely to be cached.
            * N.B. we actually map the program counter to the instruction that PRECEEDS
            * the actual instruction we want to jump to. This is because our
            * DISPATCH macro will increase state.next_instruction before jumping
            * We could write a special case for jump opcodes (so DISPATCH doesn't increase the ptr),
            * but I figured that if the access pattern into state.next_instruction was uniform,
            * the CPU would have an easier time of predicting the branch we're jumping to.
            * This is, however, 100% superstition, I have no idea how to measure pipeline stalls during eecution
            **/
            jumpdest_map[i] = &instructions[instr_index - 1];

            // we added this opcodes gas cost into the current basic block, undo that
            // TODO: cache this? Current code is a bit of a cludge to remove a conditional branch
            block->gas_cost -= metrics.gas_cost;

            // and point to the a new basic block
            block = &instructions[instr_index].block_data;
    
            // update the new basic block's gas cost with the cost of OP_JUMPDEST
            block->gas_cost = metrics.gas_cost;
            block->stack_max = 0;
            block->stack_req = 0;
            stack_diff = 0;
            delta = 0;
            next_delta = JUMP_TABLE_CHECK_BOUNDARY;
            break;
        }
        default:
        {
            next_delta = JUMP_TABLE_CHECK_BOUNDARY;
            break;
        }
        }

        instructions[instr_index].opcode_dest = jump_table[c + delta];
        delta = next_delta;
        next_delta = 0;
    }

    // We want to add an OP_STOP opcode to the end of our program, so that we always terminate
    instructions[instr_index].opcode_dest = jump_table[0];
    
    // For good measure, put an OP_STOP opcode in the two penultimate entries.
    // We will set state.next_instruction to code_size when we enter an error state
    instructions[code_size].opcode_dest = jump_table[0];
    instructions[code_size + 1].opcode_dest = jump_table[0];
}
}  // namespace evmone
