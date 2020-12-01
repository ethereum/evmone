// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/analysis.hpp>
#include <evmone/execution_state.hpp>
#include <gtest/gtest.h>
#include <type_traits>

static_assert(!std::is_default_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_move_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_copy_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_move_assignable<evmone::ExecutionState>::value);
static_assert(!std::is_copy_assignable<evmone::ExecutionState>::value);

static_assert(!std::is_default_constructible<evmone::execution_state>::value);
static_assert(!std::is_move_constructible<evmone::execution_state>::value);
static_assert(!std::is_copy_constructible<evmone::execution_state>::value);
static_assert(!std::is_move_assignable<evmone::execution_state>::value);
static_assert(!std::is_copy_assignable<evmone::execution_state>::value);

TEST(execution_state, construct)
{
    evmc_message msg{};
    msg.gas = -1;
    const evmc_host_interface host_interface{};
    const uint8_t code[]{0x0f};
    const evmone::ExecutionState st{
        msg, EVMC_MAX_REVISION, host_interface, nullptr, code, std::size(code)};

    EXPECT_EQ(st.gas_left, -1);
    EXPECT_EQ(st.stack.size(), 0);
    EXPECT_EQ(st.memory.size(), 0);
    EXPECT_EQ(st.msg, &msg);
    EXPECT_EQ(st.rev, EVMC_MAX_REVISION);
    EXPECT_EQ(st.return_data.size(), 0);
    EXPECT_EQ(st.code.data(), &code[0]);
    EXPECT_EQ(st.code.size(), std::size(code));
    EXPECT_EQ(st.status, EVMC_SUCCESS);
    EXPECT_EQ(st.output_offset, 0);
    EXPECT_EQ(st.output_size, 0);
}
