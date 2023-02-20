// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/advanced_analysis.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

namespace
{
// Temporarily include EVMC instructions in an inline namespace so that evmc_opcode enum
// doesn't name clash with evmone::Opcode but the evmc_ functions are accessible.
#include <evmc/instructions.h>
}  // namespace

using namespace evmone;

namespace evmone::test
{
namespace
{
constexpr int unspecified = -1000000;

constexpr int get_revision_defined_in(size_t op) noexcept
{
    for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        if (instr::gas_costs[r][op] != instr::undefined)
            return static_cast<int>(r);
    }
    return unspecified;
}

constexpr bool is_terminating(Opcode op) noexcept
{
    switch (op)
    {
    case OP_STOP:
    case OP_RETURN:
    case OP_REVERT:
    case OP_INVALID:
    case OP_SELFDESTRUCT:
        return true;
    default:
        return false;
    }
}

template <Opcode Op>
constexpr void validate_traits_of() noexcept
{
    constexpr auto tr = instr::traits[Op];

    // immediate_size
    if constexpr (Op >= OP_PUSH1 && Op <= OP_PUSH32)
        static_assert(tr.immediate_size == Op - OP_PUSH1 + 1);
    else if constexpr (Op == OP_DUPN || Op == OP_SWAPN)
        static_assert(tr.immediate_size == 1);
    else
        static_assert(tr.immediate_size == 0);

    // is_terminating
    static_assert(tr.is_terminating == is_terminating(Op));
    static_assert(!tr.is_terminating || tr.immediate_size == 0,
        "terminating instructions must not have immediate bytes - this simplifies EOF validation");

    // since
    constexpr auto expected_rev = get_revision_defined_in(Op);
    static_assert(tr.since.has_value() ? *tr.since == expected_rev : expected_rev == unspecified);
}

template <std::size_t... Ops>
constexpr bool validate_traits(std::index_sequence<Ops...>)
{
    // Instantiate validate_traits_of for each opcode.
    // Validation errors are going to be reported via static_asserts.
    (validate_traits_of<static_cast<Opcode>(Ops)>(), ...);
    return true;
}
static_assert(validate_traits(std::make_index_sequence<256>{}));


// Check some cases for has_const_gas_cost().
static_assert(instr::has_const_gas_cost(OP_STOP));
static_assert(instr::has_const_gas_cost(OP_ADD));
static_assert(instr::has_const_gas_cost(OP_PUSH1));
static_assert(!instr::has_const_gas_cost(OP_SHL));
static_assert(!instr::has_const_gas_cost(OP_BALANCE));
static_assert(!instr::has_const_gas_cost(OP_SLOAD));
}  // namespace
}  // namespace evmone::test


TEST(instructions, compare_with_evmc_instruction_tables)
{
    for (int r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
    {
        const auto rev = static_cast<evmc_revision>(r);
        const auto& instr_tbl = instr::gas_costs[rev];
        const auto& evmone_tbl = advanced::get_op_table(rev);
        const auto* evmc_tbl = evmc_get_instruction_metrics_table(rev);

        for (size_t i = 0; i < evmone_tbl.size(); ++i)
        {
            // Skip DUPN and SWAPN for Cancun. They are not defined in evmc
            // TODO: Define DUPN and SWAPN in evmc
            if (r >= EVMC_CANCUN && (Opcode(i) == OP_DUPN || Opcode(i) == OP_SWAPN))
                continue;
            const auto gas_cost = (instr_tbl[i] != instr::undefined) ? instr_tbl[i] : 0;
            const auto& metrics = evmone_tbl[i];
            const auto& ref_metrics = evmc_tbl[i];

            const auto case_descr = [rev](size_t opcode) {
                auto case_descr_str = std::ostringstream{};
                case_descr_str << "opcode " << instr::traits[opcode].name;
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
        const auto& instr_tbl = instr::gas_costs[rev];
        const auto* evmc_names_tbl = evmc_get_instruction_names_table(rev);

        for (size_t i = 0; i < instr_tbl.size(); ++i)
        {
            // Skip DUPN and SWAPN. They are not defined in evmc
            // TODO: Define DUPN and SWAPN in evmc
            if (Opcode(i) == OP_DUPN || Opcode(i) == OP_SWAPN)
                continue;
            EXPECT_EQ(instr_tbl[i] == instr::undefined, evmc_names_tbl[i] == nullptr) << i;
        }
    }
}

TEST(instructions, compare_with_evmc_instruction_names)
{
    const auto* evmc_tbl = evmc_get_instruction_names_table(EVMC_MAX_REVISION);
    for (size_t i = 0; i < instr::traits.size(); ++i)
    {
        // Skip DUPN and SWAPN. They are not defined in evmc
        // TODO: Define DUPN and SWAPN in evmc
        if (Opcode(i) == OP_DUPN || Opcode(i) == OP_SWAPN)
            continue;
        EXPECT_STREQ(instr::traits[i].name, evmc_tbl[i]);
    }
}
