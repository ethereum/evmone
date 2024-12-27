// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/state.hpp>
#include <test/state/system_contracts.hpp>
#include <test/state/test_state.hpp>
#include <test/utils/bytecode.hpp>

using namespace evmc::literals;
using namespace evmone::state;
using namespace evmone::test;

class state_system_call : public testing::Test
{
protected:
    evmc::VM vm{evmc_create_evmone()};
    TestState state;
    TestBlockHashes block_hashes;
};

TEST_F(state_system_call, non_existient)
{
    // Use MAX revision to invoke all activate system contracts.
    system_call_block_start(state, {}, block_hashes, EVMC_MAX_REVISION, vm);
    EXPECT_EQ(state.size(), 0) << "State must remain unchanged";

    system_call_block_end(state, {}, block_hashes, EVMC_MAX_REVISION, vm);
    EXPECT_EQ(state.size(), 0) << "State must remain unchanged";
}

TEST_F(state_system_call, beacon_roots)
{
    const BlockInfo block{.number = 1, .parent_beacon_block_root = 0xbeac04004a54_bytes32};
    state.insert(
        BEACON_ROOTS_ADDRESS, {.code = sstore(OP_NUMBER, calldataload(0)) + sstore(0, OP_CALLER)});

    system_call_block_start(state, block, block_hashes, EVMC_CANCUN, vm);

    ASSERT_EQ(state.size(), 1);
    EXPECT_FALSE(state.contains(SYSTEM_ADDRESS));
    EXPECT_EQ(state.at(BEACON_ROOTS_ADDRESS).nonce, 0);
    EXPECT_EQ(state.at(BEACON_ROOTS_ADDRESS).balance, 0);
    const auto& storage = state.at(BEACON_ROOTS_ADDRESS).storage;
    ASSERT_EQ(storage.size(), 2);
    EXPECT_EQ(storage.at(0x01_bytes32), block.parent_beacon_block_root);
    EXPECT_EQ(storage.at(0x00_bytes32), to_bytes32(SYSTEM_ADDRESS));
}

TEST_F(state_system_call, history_storage)
{
    static constexpr auto NUMBER = 123456789;
    static constexpr auto PREV_BLOCKHASH = 0xbbbb_bytes32;
    const BlockInfo block{.number = NUMBER};
    block_hashes = {{NUMBER - 1, PREV_BLOCKHASH}};
    state.insert(HISTORY_STORAGE_ADDRESS,
        {.code = sstore(OP_NUMBER, calldataload(0)) + sstore(0, OP_CALLER)});

    system_call_block_start(state, block, block_hashes, EVMC_PRAGUE, vm);

    ASSERT_EQ(state.size(), 1);
    EXPECT_FALSE(state.contains(SYSTEM_ADDRESS));
    EXPECT_EQ(state.at(HISTORY_STORAGE_ADDRESS).nonce, 0);
    EXPECT_EQ(state.at(HISTORY_STORAGE_ADDRESS).balance, 0);
    const auto& storage = state.at(HISTORY_STORAGE_ADDRESS).storage;
    ASSERT_EQ(storage.size(), 2);
    EXPECT_EQ(storage.at(bytes32{NUMBER}), PREV_BLOCKHASH);
    EXPECT_EQ(storage.at(0x00_bytes32), to_bytes32(SYSTEM_ADDRESS));
}

TEST_F(state_system_call, withdrawal)
{
    static constexpr auto WITHDRAWAL_REQUEST = 0x0123456789_bytes32;
    const BlockInfo block{.number = 1};
    state.insert(WITHDRAWAL_REQUEST_ADDRESS,
        {.code = mstore(0, WITHDRAWAL_REQUEST) + sstore(1, 1) + ret(0, 32)});

    const auto requests = system_call_block_end(state, block, block_hashes, EVMC_PRAGUE, vm);

    ASSERT_EQ(state.size(), 1);
    EXPECT_FALSE(state.contains(SYSTEM_ADDRESS));
    EXPECT_EQ(state.at(WITHDRAWAL_REQUEST_ADDRESS).nonce, 0);
    EXPECT_EQ(state.at(WITHDRAWAL_REQUEST_ADDRESS).balance, 0);
    const auto& storage = state.at(WITHDRAWAL_REQUEST_ADDRESS).storage;
    ASSERT_EQ(storage.size(), 1);
    EXPECT_EQ(storage.at(0x01_bytes32), 0x01_bytes32);

    ASSERT_EQ(requests.size(), 2);
    EXPECT_EQ(requests[0].type(), Requests::Type::withdrawal);
    EXPECT_EQ(requests[0].data(), bytes(WITHDRAWAL_REQUEST));
    EXPECT_EQ(requests[1].type(), Requests::Type::consolidation);
    EXPECT_TRUE(requests[1].data().empty());
}

TEST_F(state_system_call, consolidation)
{
    static constexpr auto CONSOLIDATION_REQUEST = 0x0123456789_bytes32;
    const BlockInfo block{.number = 1};
    state.insert(CONSOLIDATION_REQUEST_ADDRESS,
        {.code = mstore(0, CONSOLIDATION_REQUEST) + sstore(1, 1) + ret(0, 32)});

    const auto requests = system_call_block_end(state, block, block_hashes, EVMC_PRAGUE, vm);

    ASSERT_EQ(state.size(), 1);
    EXPECT_FALSE(state.contains(SYSTEM_ADDRESS));
    EXPECT_EQ(state.at(CONSOLIDATION_REQUEST_ADDRESS).nonce, 0);
    EXPECT_EQ(state.at(CONSOLIDATION_REQUEST_ADDRESS).balance, 0);
    const auto& storage = state.at(CONSOLIDATION_REQUEST_ADDRESS).storage;
    ASSERT_EQ(storage.size(), 1);
    EXPECT_EQ(storage.at(0x01_bytes32), 0x01_bytes32);

    ASSERT_EQ(requests.size(), 2);
    EXPECT_EQ(requests[0].type(), Requests::Type::withdrawal);
    EXPECT_TRUE(requests[0].data().empty());
    EXPECT_EQ(requests[1].type(), Requests::Type::consolidation);
    EXPECT_EQ(requests[1].data(), bytes(CONSOLIDATION_REQUEST));
}
