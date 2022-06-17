// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/account.hpp>
#include <test/state/mpt.hpp>
#include <test/state/mpt_hash.hpp>

using namespace evmone;
using namespace evmone::state;
using namespace intx;

TEST(state_mpt_hash, empty)
{
    EXPECT_EQ(mpt_hash({}), emptyMPTHash);
}

TEST(state_mpt_hash, single_account_v1)
{
    // Expected value computed in go-ethereum.
    constexpr auto expected =
        0x084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e_bytes32;

    Account acc;
    acc.balance = 1_u256;
    const std::unordered_map<address, Account> accounts{{0x02_address, acc}};
    EXPECT_EQ(mpt_hash(accounts), expected);
}

TEST(state_mpt_hash, two_accounts)
{
    std::unordered_map<address, Account> accounts;
    EXPECT_EQ(mpt_hash(accounts), emptyMPTHash);

    accounts[0x00_address] = Account{};
    EXPECT_EQ(mpt_hash(accounts),
        0x0ce23f3c809de377b008a4a3ee94a0834aac8bec1f86e28ffe4fdb5a15b0c785_bytes32);

    Account acc2;
    acc2.nonce = 1;
    acc2.balance = -2_u256;
    acc2.code = {0x00};
    acc2.storage[0x01_bytes32] = {0xfe_bytes32};
    acc2.storage[0x02_bytes32] = {0xfd_bytes32};
    accounts[0x01_address] = acc2;
    EXPECT_EQ(mpt_hash(accounts),
        0xd3e845156fca75de99712281581304fbde104c0fc5a102b09288c07cdde0b666_bytes32);
}

TEST(state_mpt_hash, deleted_storage)
{
    Account acc;
    acc.storage[0x01_bytes32] = {};
    acc.storage[0x02_bytes32] = {0xfd_bytes32};
    acc.storage[0x03_bytes32] = {};
    const std::unordered_map<address, Account> accounts{{0x07_address, acc}};
    EXPECT_EQ(mpt_hash(accounts),
        0x4e7338c16731491e0fb5d1623f5265c17699c970c816bab71d4d717f6071414d_bytes32);
}
