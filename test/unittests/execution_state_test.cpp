// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/analysis.hpp>
#include <evmone/execution_state.hpp>
#include <gtest/gtest.h>
#include <type_traits>

static_assert(std::is_default_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_move_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_copy_constructible<evmone::ExecutionState>::value);
static_assert(!std::is_move_assignable<evmone::ExecutionState>::value);
static_assert(!std::is_copy_assignable<evmone::ExecutionState>::value);

static_assert(std::is_default_constructible<evmone::execution_state>::value);
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

TEST(execution_state, default_construct)
{
    const evmone::ExecutionState st;

    EXPECT_EQ(st.gas_left, 0);
    EXPECT_EQ(st.stack.size(), 0);
    EXPECT_EQ(st.memory.size(), 0);
    EXPECT_EQ(st.msg, nullptr);
    EXPECT_EQ(st.rev, EVMC_FRONTIER);
    EXPECT_EQ(st.return_data.size(), 0);
    EXPECT_EQ(st.code.data(), nullptr);
    EXPECT_EQ(st.code.size(), 0);
    EXPECT_EQ(st.status, EVMC_SUCCESS);
    EXPECT_EQ(st.output_offset, 0);
    EXPECT_EQ(st.output_size, 0);
}

TEST(execution_state, default_construct_advanced)
{
    const evmone::execution_state st;

    EXPECT_EQ(st.gas_left, 0);
    EXPECT_EQ(st.stack.size(), 0);
    EXPECT_EQ(st.memory.size(), 0);
    EXPECT_EQ(st.msg, nullptr);
    EXPECT_EQ(st.rev, EVMC_FRONTIER);
    EXPECT_EQ(st.return_data.size(), 0);
    EXPECT_EQ(st.code.data(), nullptr);
    EXPECT_EQ(st.code.size(), 0);
    EXPECT_EQ(st.status, EVMC_SUCCESS);
    EXPECT_EQ(st.output_offset, 0);
    EXPECT_EQ(st.output_size, 0);

    EXPECT_EQ(st.current_block_cost, 0u);
    EXPECT_EQ(st.analysis, nullptr);
}

TEST(execution_state, stack_clear)
{
    evmone::evm_stack stack;

    stack.clear();
    EXPECT_EQ(stack.size(), 0);
    EXPECT_EQ(stack.top_item + 1, stack.storage);

    stack.push({});
    EXPECT_EQ(stack.size(), 1);
    EXPECT_EQ(stack.top_item, stack.storage);

    stack.clear();
    EXPECT_EQ(stack.size(), 0);
    EXPECT_EQ(stack.top_item + 1, stack.storage);

    stack.clear();
    EXPECT_EQ(stack.size(), 0);
    EXPECT_EQ(stack.top_item + 1, stack.storage);
}
