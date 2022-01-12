// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/instructions.h>
#include <evmone/advanced_analysis.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

namespace
{
constexpr int unspecified = -1000000;

constexpr int get_revision_defined_in(size_t op) noexcept
{
    for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        if (evmone::instr::gas_costs[r][op] != evmone::instr::undefined)
            return static_cast<int>(r);
    }
    return unspecified;
}
}  // namespace

TEST(instructions, validate_since)
{
    for (size_t op = 0x00; op <= 0xff; ++op)
    {
        const auto since = evmone::instr::traits[op].since;
        const auto test_value = since.has_value() ? *since : unspecified;
        const auto expected = get_revision_defined_in(op);
        EXPECT_EQ(test_value, expected) << std::hex << op;
    }
}

TEST(instructions, compare_with_evmc_instruction_tables)
{
    for (int r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        const auto rev = static_cast<evmc_revision>(r);
        const auto& instr_tbl = evmone::instr::gas_costs[rev];
        const auto& evmone_tbl = evmone::advanced::get_op_table(rev);
        const auto* evmc_tbl = evmc_get_instruction_metrics_table(rev);

        for (size_t i = 0; i < evmone_tbl.size(); ++i)
        {
            const auto gas_cost = (instr_tbl[i] != evmone::instr::undefined) ? instr_tbl[i] : 0;
            const auto& metrics = evmone_tbl[i];
            const auto& ref_metrics = evmc_tbl[i];

            const auto case_descr = [rev](size_t opcode) {
                auto case_descr_str = std::ostringstream{};
                case_descr_str << "opcode " << to_name(evmc_opcode(opcode), rev);
                case_descr_str << " on revision " << rev;
                return case_descr_str.str();
            };

            EXPECT_EQ(gas_cost, ref_metrics.gas_cost) << case_descr(i);
            EXPECT_EQ(metrics.gas_cost, ref_metrics.gas_cost) << case_descr(i);
            EXPECT_EQ(metrics.stack_req, ref_metrics.stack_height_required) << case_descr(i);
            EXPECT_EQ(metrics.stack_change, ref_metrics.stack_height_change) << case_descr(i);
        }
    }
}

TEST(instructions, compare_undefined_instructions)
{
    for (int r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        const auto rev = static_cast<evmc_revision>(r);
        const auto& instr_tbl = evmone::instr::gas_costs[rev];
        const auto* evmc_names_tbl = evmc_get_instruction_names_table(rev);

        for (size_t i = 0; i < instr_tbl.size(); ++i)
            EXPECT_EQ(instr_tbl[i] == evmone::instr::undefined, evmc_names_tbl[i] == nullptr) << i;
    }
}

TEST(instructions, compare_with_evmc_instruction_names)
{
    const auto* evmc_tbl = evmc_get_instruction_names_table(EVMC_MAX_REVISION);
    for (size_t i = 0; i < evmone::instr::traits.size(); ++i)
    {
        EXPECT_STREQ(evmone::instr::traits[i].name, evmc_tbl[i]);
    }
}
