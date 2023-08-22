// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, tx_non_existing_sender)
{
    tx.to = To;
    tx.max_gas_price = 0;
    tx.max_priority_gas_price = 0;
    tx.nonce = 0;
    block.base_fee = 0;
    pre.get_accounts().erase(Sender);

    rev = EVMC_BERLIN;

    expect.status = EVMC_SUCCESS;
    expect.post.at(Sender).nonce = 1;
    expect.post.at(Coinbase).exists = false;
}

TEST_F(state_transition, invalid_tx_non_existing_sender)
{
    tx.to = To;
    tx.max_gas_price = 1;
    tx.max_priority_gas_price = 1;
    tx.nonce = 0;
    block.base_fee = 1;
    pre.get_accounts().erase(Sender);

    rev = EVMC_BERLIN;

    expect.tx_error = INSUFFICIENT_FUNDS;
}
