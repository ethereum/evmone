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

        if (c == OPX_BEGINBLOCK)
        {
            block = &instr.arg.block;

            const auto get_jumpdest_offset = [&analysis](size_t index) noexcept
            {
                for (size_t t = 0; t < analysis.jumpdest_targets.size(); ++t)
                {
                    if (t == index)
                        return analysis.jumpdest_offsets[t];
                }
                return int16_t{-1};
            };

            std::cout << "┌ ";
            auto offset = get_jumpdest_offset(i);
            if (offset >= 0)
                std::cout << std::setw(2) << offset;
            else
                std::cout << "  ";

            std::cout << " " << std::setw(10) << block->gas_cost << " " << block->stack_req << " "
                      << block->stack_max_growth << "\n";
        }

        std::cout << "│ " << std::setw(9) << std::left << name << std::setw(4) << std::right
                  << metrics[c].gas_cost;

        if (c >= OP_PUSH1 && c <= OP_PUSH32)
            std::cout << '\t' << to_hex({instr.arg.data, 32});

        std::cout << '\n';
    }
}
