// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <test/utils/utils.hpp>

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>

#include <iomanip>
#include <iostream>

void dump_analysis(const evmone::code_analysis& analysis)
{
    using namespace evmone;

    auto names = evmc_get_instruction_names_table(EVMC_BYZANTIUM);
    auto metrics = evmc_get_instruction_metrics_table(EVMC_BYZANTIUM);

    const block_info* block = nullptr;
    for (size_t i = 0; i < analysis.instrs.size(); ++i)
    {
        auto& instr = analysis.instrs[i];
        auto c = static_cast<uint8_t>((size_t)instr.fn);
        auto name = names[c];
        if (!name)
            name = "XX";


        if (instr.block_index >= 0)
        {
            block = &analysis.blocks[size_t(instr.block_index)];

            auto get_jumpdest_offset = [&analysis](size_t i) noexcept
            {
                // TODO: Replace with lower_bound().
                for (const auto& d : analysis.jumpdest_map)
                {
                    if (d.second == static_cast<int>(i))
                        return d.first;
                }
                return -1;
            };

            std::cout << "┌ ";
            auto offset = get_jumpdest_offset(i);
            if (offset >= 0)
                std::cout << std::setw(2) << offset;
            else
                std::cout << "  ";

            std::cout << " " << std::setw(10) << block->gas_cost << " " << block->stack_req << " "
                      << block->stack_max << " " << block->stack_diff << "\n";
        }

        std::cout << "│ " << std::setw(9) << std::left << name << std::setw(4) << std::right
                  << metrics[c].gas_cost;

        if (c >= OP_PUSH1 && c <= OP_PUSH32)
            std::cout << '\t' << to_hex({instr.arg.data, 32});

        std::cout << '\n';
    }
}
