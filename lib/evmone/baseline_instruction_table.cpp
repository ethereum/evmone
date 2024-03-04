// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

namespace evmone::baseline
{
namespace
{
constexpr auto common_cost_tables = []() noexcept {
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

constexpr auto legacy_cost_tables = []() noexcept {
    auto tables = common_cost_tables;
    tables[EVMC_PRAGUE][OP_RJUMP] = instr::undefined;
    tables[EVMC_PRAGUE][OP_RJUMPI] = instr::undefined;
    tables[EVMC_PRAGUE][OP_RJUMPV] = instr::undefined;
    tables[EVMC_PRAGUE][OP_CALLF] = instr::undefined;
    tables[EVMC_PRAGUE][OP_RETF] = instr::undefined;
    tables[EVMC_PRAGUE][OP_JUMPF] = instr::undefined;
    tables[EVMC_PRAGUE][OP_DATALOAD] = instr::undefined;
    tables[EVMC_PRAGUE][OP_DATALOADN] = instr::undefined;
    tables[EVMC_PRAGUE][OP_DATASIZE] = instr::undefined;
    tables[EVMC_PRAGUE][OP_DATACOPY] = instr::undefined;
    tables[EVMC_PRAGUE][OP_DUPN] = instr::undefined;
    tables[EVMC_PRAGUE][OP_SWAPN] = instr::undefined;
    tables[EVMC_PRAGUE][OP_RETURNDATALOAD] = instr::undefined;
    tables[EVMC_PRAGUE][OP_EOFCREATE] = instr::undefined;
    tables[EVMC_PRAGUE][OP_TXCREATE] = instr::undefined;
    tables[EVMC_PRAGUE][OP_RETURNCONTRACT] = instr::undefined;
    return tables;
}();

constexpr auto eof_cost_tables = []() noexcept {
    auto tables = common_cost_tables;
    tables[EVMC_PRAGUE][OP_JUMP] = instr::undefined;
    tables[EVMC_PRAGUE][OP_JUMPI] = instr::undefined;
    tables[EVMC_PRAGUE][OP_PC] = instr::undefined;
    tables[EVMC_PRAGUE][OP_CALLCODE] = instr::undefined;
    tables[EVMC_PRAGUE][OP_SELFDESTRUCT] = instr::undefined;
    tables[EVMC_PRAGUE][OP_CREATE] = instr::undefined;
    tables[EVMC_PRAGUE][OP_CREATE2] = instr::undefined;
    return tables;
}();

}  // namespace

const CostTable& get_baseline_cost_table(evmc_revision rev, uint8_t eof_version) noexcept
{
    const auto& tables = (eof_version == 0) ? legacy_cost_tables : eof_cost_tables;
    return tables[rev];
}
}  // namespace evmone::baseline
