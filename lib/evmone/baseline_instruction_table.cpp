// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instruction_traits.hpp"
#include <cassert>

namespace evmone
{
namespace
{
template <evmc_revision Rev>
constexpr InstructionTable create_instruction_table() noexcept
{
    InstructionTable table{};
    for (size_t i = 0; i < table.size(); ++i)
    {
        auto& t = table[i];
        const auto gas_cost = instr::gas_costs<Rev>[i];
        t.gas_cost = gas_cost;  // Include instr::undefined in the table.
        t.stack_height_required = instr::traits[i].stack_height_required;

        // Because any instruction can increase stack height at most of 1,
        // stack overflow can only happen if stack height is already at the limit.
        assert(instr::traits[i].stack_height_change <= 1);
        t.can_overflow_stack = instr::traits[i].stack_height_change > 0;
    }
    return table;
}

constexpr InstructionTable instruction_tables[] = {
    create_instruction_table<EVMC_FRONTIER>(),
    create_instruction_table<EVMC_HOMESTEAD>(),
    create_instruction_table<EVMC_TANGERINE_WHISTLE>(),
    create_instruction_table<EVMC_SPURIOUS_DRAGON>(),
    create_instruction_table<EVMC_BYZANTIUM>(),
    create_instruction_table<EVMC_CONSTANTINOPLE>(),
    create_instruction_table<EVMC_PETERSBURG>(),
    create_instruction_table<EVMC_ISTANBUL>(),
    create_instruction_table<EVMC_BERLIN>(),
    create_instruction_table<EVMC_LONDON>(),
};
static_assert(std::size(instruction_tables) == EVMC_MAX_REVISION + 1,
    "instruction table entry missing for an EVMC revision");
}  // namespace

const InstructionTable& get_baseline_instruction_table(evmc_revision rev) noexcept
{
    return instruction_tables[rev];
}
}  // namespace evmone
