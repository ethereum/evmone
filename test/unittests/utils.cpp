// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "utils.hpp"

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>
#include <evmone/constants.hpp>
#include <evmone/execution.hpp>

#include <iomanip>
#include <iostream>


uint8_t map_label_to_instruction(const void** jump_table, const void* jump_label)
{
    for (size_t i = 0; i < evmone::JUMP_TABLE_SIZE; i++)
    {
        if (jump_table[i] == jump_label)
        {
            if (i >= evmone::JUMP_TABLE_CHECK_BOUNDARY)
            {
                return static_cast<uint8_t>(i - evmone::JUMP_TABLE_CHECK_BOUNDARY);
            }
        }
    }
    return -1;
}

bool is_block_header(const void** jump_table, const void* jump_label)
{
    for (size_t i = 0; i < evmone::JUMP_TABLE_SIZE; i++)
    {
        if (jump_table[i] == jump_label)
        {
            return i < evmone::JUMP_TABLE_CHECK_BOUNDARY;
        }
    }
    return false;
}

void dump_analysis(const evmone::instruction* instructions, size_t code_size, evmc_revision rev)
{
    using namespace evmone;

    auto names = evmc_get_instruction_names_table(EVMC_BYZANTIUM);
    auto metrics = evmc_get_instruction_metrics_table(EVMC_BYZANTIUM);

    const void** table = evmone::get_table(rev);
    for (size_t i = 0; i < code_size; ++i)
    {
        auto& instr = instructions[i];
        const void* jump_label = instr.opcode_dest;
        auto c = map_label_to_instruction(table, jump_label);
        // auto c = static_cast<uint8_t>((size_t)instr.fn);
        auto name = names[c];
        if (!name)
            name = "XX";

        bool contains_block = is_block_header(table, jump_label);
        if (contains_block)
        {
            block_info block = instr.block_data; // .blocks[size_t(instr.block_index)];

            std::cout << "┌ ";
            // auto offset = get_jumpdest_offset(i);
            // if (offset >= 0)
            //     std::cout << std::setw(2) << offset;
            // else
                std::cout << "  ";

            std::cout << " " << std::setw(10) << block.gas_cost << " " << block.stack_req << " "
                      << block.stack_max << " " << "\n";
        }

        std::cout << "│ " << std::setw(9) << std::left << name << std::setw(4) << std::right
                  << metrics[c].gas_cost;

        if (c >= OP_PUSH1 && c <= OP_PUSH32)
            std::cout << '\t' << to_hex(&instr.instruction_data.push_data[0], 32);

        std::cout << '\n';
    }
}
