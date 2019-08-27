// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"
#include "opcodes_helpers.h"
#include <evmc/instructions.h>
#include <cassert>

namespace evmone
{
namespace
{
inline constexpr evmc_call_kind op2call_kind(uint8_t opcode) noexcept
{
    switch (opcode)
    {
    default:
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
    }
}

inline constexpr uint64_t load64be(const unsigned char* data) noexcept
{
    return uint64_t{data[7]} | (uint64_t{data[6]} << 8) | (uint64_t{data[5]} << 16) |
           (uint64_t{data[4]} << 24) | (uint64_t{data[3]} << 32) | (uint64_t{data[2]} << 40) |
           (uint64_t{data[1]} << 48) | (uint64_t{data[0]} << 56);
}
}  // namespace

code_analysis analyze(
    const exec_fn_table& fns, evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    code_analysis analysis;

    const auto max_instrs_size = code_size + 1;
    analysis.instrs.reserve(max_instrs_size);

    // This is 2x more than needed but using (code_size / 2 + 1) increases page-faults 1000x.
    const auto max_args_storage_size = code_size + 1;
    analysis.push_values.reserve(max_args_storage_size);

    const auto* instr_table = evmc_get_instruction_metrics_table(rev);

    block_info* block = nullptr;

    int block_stack_change = 0;
    int instr_index = 0;

    const auto code_end = code + code_size;
    for (auto code_pos = code; code_pos < code_end; ++instr_index)
    {
        // TODO: Loop in reverse order for easier GAS analysis.
        const auto opcode = *code_pos++;

        const bool jumpdest = opcode == OP_JUMPDEST;

        if (!block || jumpdest)
        {
            // Create BEGINBLOCK instruction which either replaces JUMPDEST or is injected
            // in case there is no JUMPDEST.
            auto& beginblock_instr = analysis.instrs.emplace_back(fns[OPX_BEGINBLOCK]);

            // Start new block.
            block = &beginblock_instr.arg.block;
            block_stack_change = 0;

            if (jumpdest)  // Add the jumpdest to the map.
            {
                analysis.jumpdest_offsets.emplace_back(static_cast<int16_t>(code_pos - code - 1));
                analysis.jumpdest_targets.emplace_back(static_cast<int16_t>(instr_index));
            }
            else  // Increase instruction count because additional BEGINBLOCK was injected.
                ++instr_index;
        }

        auto& instr = jumpdest ? analysis.instrs.back() : analysis.instrs.emplace_back(fns[opcode]);

        const auto metrics = instr_table[opcode];
        const auto instr_stack_req = metrics.num_stack_arguments;
        const auto instr_stack_change = metrics.num_stack_returned_items - instr_stack_req;

        // TODO: Define a block_analysis struct with regular ints for analysis.
        //       Compress it when block is closed.
        auto stack_req = instr_stack_req - block_stack_change;
        if (stack_req > std::numeric_limits<decltype(block->stack_req)>::max())
            stack_req = std::numeric_limits<decltype(block->stack_req)>::max();

        block->stack_req = std::max(block->stack_req, static_cast<int16_t>(stack_req));
        block_stack_change += instr_stack_change;
        block->stack_max_growth =
            static_cast<int16_t>(std::max(int{block->stack_max_growth}, block_stack_change));

        if (metrics.gas_cost > 0)  // can be -1 for undefined instruction
            block->gas_cost += metrics.gas_cost;

        switch (opcode)
        {
        case ANY_SMALL_PUSH:
        {
            const auto push_size = size_t(opcode - OP_PUSH1 + 1);
            const auto push_end = code_pos + push_size;

            uint8_t value_bytes[8]{};
            auto insert_pos = &value_bytes[sizeof(value_bytes) - push_size];

            // TODO: Consier the same endianness-specific loop as in ANY_LARGE_PUSH case.
            while (code_pos < push_end && code_pos < code_end)
                *insert_pos++ = *code_pos++;
            instr.arg.small_push_value = load64be(value_bytes);
            break;
        }

        case ANY_LARGE_PUSH:
        {
            const auto push_size = size_t(opcode - OP_PUSH1 + 1);
            const auto push_end = code_pos + push_size;

            auto& push_value = analysis.push_values.emplace_back();
            // TODO: Add as_bytes() helper to intx.
            const auto push_value_bytes = reinterpret_cast<uint8_t*>(intx::as_words(push_value));
            auto insert_pos = &push_value_bytes[push_size - 1];

            // Copy bytes to the deticated storage in the order to match native endianness.
            // The condition `code_pos < code_end` is to handle the edge case of PUSH being at
            // the end of the code with incomplete value bytes.
            // This condition can be replaced with single `push_end <= code_end` done once before
            // the loop. Then the push value will stay 0 but the value is not reachable
            // during the execution anyway.
            // This seems like a good micro-optimization but we were not able to show
            // this is faster, at least with GCC 8 (producing the best results at the time).
            // FIXME: Add support for big endian architectures.
            while (code_pos < push_end && code_pos < code_end)
                *insert_pos-- = *code_pos++;

            instr.arg.push_value = &push_value;
            break;
        }

        case ANY_DUP:
            // TODO: This is not needed, but we keep it
            //       otherwise compiler will not use the jumptable for switch implementation.
            instr.arg.p.number = opcode - OP_DUP1;
            break;

        case ANY_SWAP:
            // TODO: This is not needed, but we keep it
            //       otherwise compiler will not use the jumptable for switch implementation.
            instr.arg.p.number = opcode - OP_SWAP1 + 1;
            break;

        case OP_GAS:
            instr.arg.p.number = block->gas_cost;
            break;

        case OP_CALL:
        case OP_CALLCODE:
        case OP_DELEGATECALL:
        case OP_STATICCALL:
        case OP_CREATE:
        case OP_CREATE2:
            instr.arg.p.number = block->gas_cost;
            instr.arg.p.call_kind =
                op2call_kind(opcode == OP_STATICCALL ? uint8_t{OP_CALL} : opcode);
            break;

        case OP_PC:
            instr.arg.p.number = static_cast<int>(code_pos - code - 1);
            break;

        case OP_LOG0:
        case OP_LOG1:
        case OP_LOG2:
        case OP_LOG3:
        case OP_LOG4:
            // TODO: This is not needed, but we keep it
            //       otherwise compiler will not use the jumptable for switch implementation.
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

    // Make sure the push_values has not been reallocated. Otherwise iterators are invalid.
    assert(analysis.push_values.size() <= max_args_storage_size);

    return analysis;
}

}  // namespace evmone
