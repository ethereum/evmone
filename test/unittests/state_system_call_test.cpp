// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/state.hpp>
#include <test/statetest/statetest.hpp>
#include <test/utils/bytecode.hpp>

using namespace evmc;
using namespace evmone::state;
using namespace evmone::test;

static evmone::MegaContext mega_ctx{.vm = evmc::VM{evmc_create_evmone()}};

TEST(state_system_call, non_existient)
{
    TestState state;

    const auto diff = system_call(mega_ctx, state, {}, EVMC_CANCUN);
    state.apply_diff(diff);

    EXPECT_EQ(state.size(), 0);
}

TEST(state_system_call, sstore_timestamp)
{
    static constexpr auto BeaconRootsAddress = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address;

    const BlockInfo block{.number = 1, .timestamp = 404};

    TestState state;
    state.insert(BeaconRootsAddress, {.code = sstore(OP_NUMBER, OP_TIMESTAMP)});

    const auto diff = system_call(mega_ctx, state, block, EVMC_CANCUN);
    state.apply_diff(diff);

    ASSERT_EQ(state.size(), 1);
    EXPECT_EQ(state[BeaconRootsAddress].nonce, 0);
    EXPECT_EQ(state[BeaconRootsAddress].balance, 0);
    const auto& storage = state[BeaconRootsAddress].storage;
    ASSERT_EQ(storage.size(), 1);
    EXPECT_EQ(storage.at(0x01_bytes32), 404);
}
