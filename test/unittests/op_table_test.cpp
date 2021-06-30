// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/instructions.h>
#include <evmone/analysis.hpp>
#include <evmone/instruction_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

TEST(op_table, compare_with_evmc_instruction_tables)
{
    for (int r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        const auto rev = static_cast<evmc_revision>(r);
        const auto& instr_tbl = evmone::instr::gas_costs[rev];
        const auto& evmone_tbl = evmone::get_op_table(rev);
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

TEST(op_table, compare_undefined_instructions)
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

TEST(op_table, compare_with_evmc_instruction_names)
{
    const auto* evmc_tbl = evmc_get_instruction_names_table(EVMC_MAX_REVISION);
    for (size_t i = 0; i < evmone::instr::traits.size(); ++i)
    {
        EXPECT_STREQ(evmone::instr::traits[i].name, evmc_tbl[i]);
    }
}
