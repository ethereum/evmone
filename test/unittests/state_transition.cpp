// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

namespace evmone::test
{
void state_transition::SetUp()
{
    pre.insert(tx.sender, {.nonce = 1, .balance = tx.gas_limit * tx.max_gas_price + tx.value + 1});

    // Default expectations.
    expect.post[Coinbase].exists = true;
    expect.post[tx.sender].exists = true;
}

void state_transition::TearDown()
{
    auto& state = pre;
    const auto res = evmone::state::transition(state, block, tx, rev, vm);
    ASSERT_TRUE(holds_alternative<TransactionReceipt>(res))
        << std::get<std::error_code>(res).message();
    const auto& receipt = std::get<TransactionReceipt>(res);
    evmone::state::finalize(state, rev, block.coinbase, 0, block.withdrawals);

    EXPECT_EQ(receipt.status, expect.status);
    if (expect.gas_used.has_value())
    {
        EXPECT_EQ(receipt.gas_used, *expect.gas_used);
    }

    for (const auto& [addr, expected_acc] : expect.post)
    {
        const auto acc = state.find(addr);
        if (!expected_acc.exists)
        {
            EXPECT_EQ(acc, nullptr) << "account " << addr << " should not exist";
        }
        else
        {
            ASSERT_NE(acc, nullptr) << "account " << addr << " should exist";
            if (expected_acc.nonce.has_value())
            {
                EXPECT_EQ(acc->nonce, *expected_acc.nonce) << "account " << addr;
            }
            if (expected_acc.balance.has_value())
            {
                EXPECT_EQ(acc->balance, *expected_acc.balance)
                    << to_string(acc->balance) << " vs " << to_string(*expected_acc.balance)
                    << " account " << addr;
            }
            if (expected_acc.code.has_value())
            {
                EXPECT_EQ(acc->code, *expected_acc.code) << "account " << addr;
            }
            for (const auto& [key, value] : expected_acc.storage)
            {
                EXPECT_EQ(acc->storage[key].current, value) << "account " << addr << " key " << key;
            }
            for (const auto& [key, value] : acc->storage)
            {
                // Find unexpected storage keys. This will also report entries with value 0.
                EXPECT_TRUE(expected_acc.storage.contains(key))
                    << "unexpected storage key " << key << "=" << value.current << " in " << addr;
            }
        }
    }

    for (const auto& [addr, _] : state.get_accounts())
    {
        EXPECT_TRUE(expect.post.contains(addr)) << "unexpected account " << addr;
    }
}
}  // namespace evmone::test
