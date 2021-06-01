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

static_assert(std::is_default_constructible<evmone::AdvancedExecutionState>::value);
static_assert(!std::is_move_constructible<evmone::AdvancedExecutionState>::value);
static_assert(!std::is_copy_constructible<evmone::AdvancedExecutionState>::value);
static_assert(!std::is_move_assignable<evmone::AdvancedExecutionState>::value);
static_assert(!std::is_copy_assignable<evmone::AdvancedExecutionState>::value);

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
    const evmone::AdvancedExecutionState st;

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

TEST(execution_state, reset_advanced)
{
    const evmc_message msg{};
    const uint8_t code[]{0xff};
    evmone::AdvancedCodeAnalysis analysis;

    evmone::AdvancedExecutionState st;
    st.gas_left = 1;
    st.stack.push({});
    st.memory.resize(2);
    st.msg = &msg;
    st.rev = EVMC_BYZANTIUM;
    st.return_data.push_back('0');
    st.code = {code, std::size(code)};
    st.status = EVMC_FAILURE;
    st.output_offset = 3;
    st.output_size = 4;
    st.current_block_cost = 5;
    st.analysis = &analysis;

    EXPECT_EQ(st.gas_left, 1);
    EXPECT_EQ(st.stack.size(), 1);
    EXPECT_EQ(st.memory.size(), 2);
    EXPECT_EQ(st.msg, &msg);
    EXPECT_EQ(st.rev, EVMC_BYZANTIUM);
    EXPECT_EQ(st.return_data.size(), 1);
    EXPECT_EQ(st.code.data(), &code[0]);
    EXPECT_EQ(st.code.size(), 1);
    EXPECT_EQ(st.status, EVMC_FAILURE);
    EXPECT_EQ(st.output_offset, 3);
    EXPECT_EQ(st.output_size, 4u);
    EXPECT_EQ(st.current_block_cost, 5u);
    EXPECT_EQ(st.analysis, &analysis);

    {
        evmc_message msg2{};
        msg2.gas = 13;
        const evmc_host_interface host_interface2{};
        const uint8_t code2[]{0x80, 0x81};

        st.reset(msg2, EVMC_HOMESTEAD, host_interface2, nullptr, code2, std::size(code2));

        // TODO: We are not able to test HostContext with current API. It may require an execution
        //       test.
        EXPECT_EQ(st.gas_left, 13);
        EXPECT_EQ(st.stack.size(), 0);
        EXPECT_EQ(st.memory.size(), 0);
        EXPECT_EQ(st.msg, &msg2);
        EXPECT_EQ(st.rev, EVMC_HOMESTEAD);
        EXPECT_EQ(st.return_data.size(), 0);
        EXPECT_EQ(st.code.data(), &code2[0]);
        EXPECT_EQ(st.code.size(), 2);
        EXPECT_EQ(st.status, EVMC_SUCCESS);
        EXPECT_EQ(st.output_offset, 0);
        EXPECT_EQ(st.output_size, 0);
        EXPECT_EQ(st.current_block_cost, 0u);
        EXPECT_EQ(st.analysis, nullptr);
    }
}

TEST(execution_state, stack_clear)
{
    evmone::Stack stack;

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

TEST(execution_state, const_stack)
{
    evmone::Stack stack;
    stack.push(1);
    stack.push(2);

    const auto& cstack = stack;

    EXPECT_EQ(cstack[0], 2);
    EXPECT_EQ(cstack[1], 1);
}

TEST(execution_state, memory_view)
{
    evmone::Memory memory;
    memory.resize(3);

    evmone::bytes_view view{memory.data(), memory.size()};
    ASSERT_EQ(view.size(), 3);
    EXPECT_EQ(view[0], 0x00);
    EXPECT_EQ(view[1], 0x00);
    EXPECT_EQ(view[2], 0x00);

    memory[0] = 0xc0;
    memory[2] = 0xc2;
    ASSERT_EQ(view.size(), 3);
    EXPECT_EQ(view[0], 0xc0);
    EXPECT_EQ(view[1], 0x00);
    EXPECT_EQ(view[2], 0xc2);
}
