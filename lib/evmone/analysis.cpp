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
struct block_analysis
{
    int gas_cost = 0;

    int stack_req = 0;
    int stack_max_growth = 0;
    int stack_change = 0;

    size_t first_instruction_index = 0;

    explicit block_analysis(size_t index) noexcept : first_instruction_index{index} {}
};

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

    // Create first block.
    analysis.instrs.emplace_back(fns[OPX_BEGINBLOCK]);
    analysis.instrs.emplace_back(nullptr);
    auto block = block_analysis{analysis.instrs.size() - 1};

    const auto code_end = code + code_size;
    auto code_pos = code;

    while (code_pos != code_end)
    {
        const auto opcode = *code_pos++;

        const auto metrics = instr_table[opcode];
        const auto instr_stack_req = metrics.num_stack_arguments;
        const auto instr_stack_change = metrics.num_stack_returned_items - instr_stack_req;

        block.stack_req = std::max(block.stack_req, instr_stack_req - block.stack_change);
        block.stack_change += instr_stack_change;
        block.stack_max_growth = std::max(block.stack_max_growth, block.stack_change);

        if (metrics.gas_cost > 0)  // can be -1 for undefined instruction
            block.gas_cost += metrics.gas_cost;

        if (opcode == OP_JUMPDEST)
        {
            // The JUMPDEST is always the first instruction in the block.
            // We don't have to insert anything to the instruction table.
            analysis.jumpdest_offsets.emplace_back(static_cast<int16_t>(code_pos - code - 1));
            analysis.jumpdest_targets.emplace_back(
                static_cast<int16_t>(analysis.instrs.size() - 2));
        }
        else
            analysis.instrs.emplace_back(fns[opcode]);

        bool create_new_block = false;
        switch (opcode)
        {
        case OP_JUMP:
        case OP_JUMPI:
        case OP_STOP:
        case OP_RETURN:
        case OP_REVERT:
        case OP_SELFDESTRUCT:
            create_new_block = true;
            break;

        case ANY_SMALL_PUSH:
        {
            const auto push_size = size_t(opcode - OP_PUSH1 + 1);
            const auto push_end = code_pos + push_size;

            uint8_t value_bytes[8]{};
            auto insert_pos = &value_bytes[sizeof(value_bytes) - push_size];

            // TODO: Consier the same endianness-specific loop as in ANY_LARGE_PUSH case.
            while (code_pos < push_end && code_pos < code_end)
                *insert_pos++ = *code_pos++;

            analysis.instrs.emplace_back(nullptr).small_push_value = load64be(value_bytes);
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

            // FIXME: Check if using constructor (nullptr) for instr_info is optimal.
            analysis.instrs.emplace_back(nullptr).push_value = &push_value;
            break;
        }

        case OP_GAS:
            analysis.instrs.emplace_back(nullptr).p.number = static_cast<int>(block.gas_cost);
            break;

        case OP_CALL:
        case OP_CALLCODE:
        case OP_DELEGATECALL:
        case OP_STATICCALL:
        case OP_CREATE:
        case OP_CREATE2:
            analysis.instrs.emplace_back(nullptr).p.number = static_cast<int>(block.gas_cost);
            analysis.instrs.back().p.call_kind =
                op2call_kind(opcode == OP_STATICCALL ? uint8_t{OP_CALL} : opcode);
            break;

        case OP_PC:
            analysis.instrs.emplace_back(nullptr).p.number = static_cast<int>(code_pos - code - 1);
            break;
        }

        if (create_new_block || (code_pos != code_end && *code_pos == OP_JUMPDEST))
        {
            // Save current block.
            const auto stack_req = block.stack_req <= std::numeric_limits<int16_t>::max() ?
                                       static_cast<int16_t>(block.stack_req) :
                                       std::numeric_limits<int16_t>::max();
            const auto stack_max_growth = static_cast<int16_t>(block.stack_max_growth);
            analysis.instrs[block.first_instruction_index].block = {
                block.gas_cost, stack_req, stack_max_growth};

            // Create new block.
            analysis.instrs.emplace_back(fns[OPX_BEGINBLOCK]);
            analysis.instrs.emplace_back(nullptr);
            block = block_analysis{analysis.instrs.size() - 1};
        }
    }

    // Save current block.
    const auto stack_req = block.stack_req <= std::numeric_limits<int16_t>::max() ?
                               static_cast<int16_t>(block.stack_req) :
                               std::numeric_limits<int16_t>::max();
    const auto stack_max_growth = static_cast<int16_t>(block.stack_max_growth);
    analysis.instrs[block.first_instruction_index].block = {
        block.gas_cost, stack_req, stack_max_growth};

    // Make sure the last block is terminated.
    // TODO: This is not needed if the last instruction is a terminating one.
    analysis.instrs.emplace_back(fns[OP_STOP]);

    // FIXME: assert(analysis.instrs.size() <= max_instrs_size);

    // Make sure the push_values has not been reallocated. Otherwise iterators are invalid.
    assert(analysis.push_values.size() <= max_args_storage_size);

    return analysis;
}

}  // namespace evmone
