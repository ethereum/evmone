// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

namespace evmone::baseline
{
namespace
{
consteval auto build_cost_tables(bool eof) noexcept
{
    std::array<CostTable, EVMC_MAX_REVISION + 1> tables{};
    for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        auto& table = tables[r];
        for (size_t op = 0; op < table.size(); ++op)
        {
            const auto& tr = instr::traits[op];
            const auto since = eof ? tr.eof_since : tr.since;
            table[op] = (since && r >= *since) ? instr::gas_costs[r][op] : instr::undefined;
        }
    }
    return tables;
}

constexpr auto LEGACY_COST_TABLES = build_cost_tables(false);
constexpr auto EOF_COST_TABLES = build_cost_tables(true);
}  // namespace

const CostTable& get_baseline_cost_table(evmc_revision rev, uint8_t eof_version) noexcept
{
    const auto& tables = (eof_version == 0) ? LEGACY_COST_TABLES : EOF_COST_TABLES;
    return tables[rev];
}
}  // namespace evmone::baseline
