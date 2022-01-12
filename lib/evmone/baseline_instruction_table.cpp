// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

namespace evmone::baseline
{
const CostTable& get_baseline_cost_table(evmc_revision rev) noexcept
{
    static constexpr auto cost_tables = []() noexcept {
        std::array<CostTable, EVMC_MAX_REVISION + 1> tables{};
        for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
        {
            auto& table = tables[r];
            for (size_t i = 0; i < table.size(); ++i)
            {
                table[i] = instr::gas_costs[r][i];  // Include instr::undefined in the table.
            }
        }
        return tables;
    }();

    return cost_tables[rev];
}
}  // namespace evmone::baseline
