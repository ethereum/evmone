// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/state.hpp>
#include <test/state/system_contracts.hpp>
#include <test/utils/bytecode.hpp>

using namespace evmc::literals;
using namespace evmone::state;
using namespace evmone::test;

class state_system_call : public testing::Test
{
protected:
    evmc::VM vm{evmc_create_evmone()};
    State state;
};

TEST_F(state_system_call, non_existient)
{
    // Use MAX revision to invoke all activate system contracts.
    system_call(state, {}, EVMC_MAX_REVISION, vm);

    EXPECT_EQ(state.get_accounts().size(), 0) << "State must remain unchanged";
}

TEST_F(state_system_call, beacon_roots)
{
    const BlockInfo block{.number = 1, .parent_beacon_block_root = 0xbeac04004a54_bytes32};
    state.insert(
        BEACON_ROOTS_ADDRESS, {.code = sstore(OP_NUMBER, calldataload(0)) + sstore(0, OP_CALLER)});

    system_call(state, block, EVMC_CANCUN, vm);

    ASSERT_EQ(state.get_accounts().size(), 1);
    EXPECT_EQ(state.find(SYSTEM_ADDRESS), nullptr);
    EXPECT_EQ(state.get(BEACON_ROOTS_ADDRESS).nonce, 0);
    EXPECT_EQ(state.get(BEACON_ROOTS_ADDRESS).balance, 0);
    const auto& storage = state.get(BEACON_ROOTS_ADDRESS).storage;
    ASSERT_EQ(storage.size(), 2);
    EXPECT_EQ(storage.at(0x01_bytes32).current, block.parent_beacon_block_root);
    EXPECT_EQ(storage.at(0x00_bytes32).current, to_bytes32(SYSTEM_ADDRESS));
}
