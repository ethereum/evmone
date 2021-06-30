// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instruction_traits.hpp"
#include <cassert>

namespace evmone::baseline
{
const InstructionTable& get_baseline_instruction_table(evmc_revision rev) noexcept
{
    static constexpr auto instruction_tables = []() noexcept {
        std::array<InstructionTable, EVMC_MAX_REVISION + 1> tables{};
        for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
        {
            auto& table = tables[r];
            for (size_t i = 0; i < table.size(); ++i)
            {
                auto& t = table[i];
                t.gas_cost = instr::gas_costs[r][i];  // Include instr::undefined in the table.
                t.stack_height_required = instr::traits[i].stack_height_required;

                // Because any instruction can increase stack height at most of 1,
                // stack overflow can only happen if stack height is already at the limit.
                assert(instr::traits[i].stack_height_change <= 1);
                t.can_overflow_stack = instr::traits[i].stack_height_change > 0;
            }
        }
        return tables;
    }();

    return instruction_tables[rev];
}
}  // namespace evmone::baseline
