// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/statetest/statetest.hpp>

using namespace evmone;

TEST(statetest_loader, load_empty_test)
{
    std::istringstream s{"{}"};
    EXPECT_THROW(test::load_state_test(s), std::invalid_argument);
}

TEST(statetest_loader, load_minimal_test)
{
    std::istringstream s{R"({
        "test": {
            "_info": {},
            "pre": {},
            "transaction": {
                "gasPrice": "",
                "sender": "",
                "to": "",
                "data": null,
                "gasLimit": "0",
                "value": null
            },
            "post": {},
            "env": {
                "currentNumber": "0",
                "currentTimestamp": "0",
                "currentGasLimit": "0",
                "currentCoinbase": ""
            }
        }
    })"};
    const test::StateTransitionTest st = test::load_state_test(s);
    // TODO: should add some comparison operator to State, BlockInfo, AccessList
    EXPECT_EQ(st.pre_state.get_accounts().size(), 0);
    EXPECT_EQ(st.block.number, 0);
    EXPECT_EQ(st.block.timestamp, 0);
    EXPECT_EQ(st.block.gas_limit, 0);
    EXPECT_EQ(st.block.coinbase, address{});
    EXPECT_EQ(st.block.prev_randao, bytes32{});
    EXPECT_EQ(st.block.base_fee, 0);
    EXPECT_EQ(st.multi_tx.kind, test::TestMultiTransaction::Kind::legacy);
    EXPECT_EQ(st.multi_tx.data, bytes{});
    EXPECT_EQ(st.multi_tx.gas_limit, 0);
    EXPECT_EQ(st.multi_tx.max_gas_price, 0);
    EXPECT_EQ(st.multi_tx.max_priority_gas_price, 0);
    EXPECT_EQ(st.multi_tx.sender, address{});
    EXPECT_EQ(st.multi_tx.to, std::nullopt);
    EXPECT_EQ(st.multi_tx.value, 0);
    EXPECT_EQ(st.multi_tx.access_list.size(), 0);
    EXPECT_EQ(st.multi_tx.chain_id, 0);
    EXPECT_EQ(st.multi_tx.nonce, 0);
    EXPECT_EQ(st.multi_tx.r, 0);
    EXPECT_EQ(st.multi_tx.s, 0);
    EXPECT_EQ(st.multi_tx.v, 0);
    EXPECT_EQ(st.multi_tx.access_lists.size(), 0);
    EXPECT_EQ(st.multi_tx.inputs.size(), 0);
    EXPECT_EQ(st.multi_tx.gas_limits.size(), 1);
    EXPECT_EQ(st.multi_tx.gas_limits[0], 0);
    EXPECT_EQ(st.multi_tx.values.size(), 0);
    EXPECT_EQ(st.cases.size(), 0);
    EXPECT_EQ(st.input_labels.size(), 0);
}
