// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/host.hpp>

using namespace evmc;
using namespace evmc::literals;
using namespace evmone::state;

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

TEST(state_transition, eof_invalid_initcode)
{
    const BlockInfo block{.gas_limit = 1'000'000};
    const Transaction tx{.gas_limit = block.gas_limit, .sender = 0x66_address, .to = 0xcc_address};

    auto code = eof1_bytecode(create() + push(0) + push(0) + OP_LOG1 + OP_STOP, 3);

    State state;
    state.insert(tx.sender, {3, 0});
    state.insert(*tx.to, {1, 0, {}, std::move(code)});

    evmc::VM vm{evmc_create_evmone()};
    const auto res = transition(state, block, tx, EVMC_CANCUN, vm);

    ASSERT_TRUE(holds_alternative<TransactionReceipt>(res))
        << std::get<std::error_code>(res).message();
    const auto& receipt = std::get<TransactionReceipt>(res);
    EXPECT_EQ(receipt.status, EVMC_SUCCESS);
    EXPECT_EQ(receipt.gas_used, 985960);
    EXPECT_EQ(receipt.logs.at(0).topics.at(0), 0x00_bytes32) << "CREATE must fail";

    EXPECT_EQ(state.get(tx.sender).nonce, 4);
    EXPECT_EQ(state.get(*tx.to).nonce, 2) << "CREATE caller's nonce must be bumped";
}
