// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/state.hpp>
#include <test/utils/bytecode.hpp>

using namespace evmc;
using namespace evmone::state;

TEST(state_system_call, non_existient)
{
    evmc::VM vm;
    State state;

    system_call(state, {}, EVMC_CANCUN, vm);

    EXPECT_EQ(state.get_accounts().size(), 0);
}

TEST(state_system_call, sstore_timestamp)
{
    static constexpr auto BeaconRootsAddress = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address;

    evmc::VM vm{evmc_create_evmone()};
    const BlockInfo block{.number = 1, .timestamp = 404};
    State state;
    state.insert(BeaconRootsAddress, {.code = sstore(OP_NUMBER, OP_TIMESTAMP)});

    system_call(state, block, EVMC_CANCUN, vm);

    ASSERT_EQ(state.get_accounts().size(), 1);
    EXPECT_EQ(state.get(BeaconRootsAddress).nonce, 0);
    EXPECT_EQ(state.get(BeaconRootsAddress).balance, 0);
    const auto& storage = state.get(BeaconRootsAddress).storage;
    ASSERT_EQ(storage.size(), 1);
    EXPECT_EQ(storage.at(0x01_bytes32).current, 404);
}
