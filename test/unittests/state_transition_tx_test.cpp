// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"
#include <test/utils/bytecode.hpp>

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, tx_legacy)
{
    rev = EVMC_ISTANBUL;
    tx.to = To;

    expect.post.at(Sender).nonce = pre.get(Sender).nonce + 1;
}

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

TEST_F(state_transition, blob_tx_insuficient_funds)
{
    tx.to = To;
    tx.gas_limit = 25000;
    tx.max_gas_price = 1;
    tx.max_priority_gas_price = 0;
    tx.nonce = 1;
    tx.type = Transaction::Type::blob;
    tx.blob_hashes.emplace_back(
        0x0100000000000000000000000000000000000000000000000000000000000000_bytes32);
    tx.max_blob_gas_price = 1;
    block.base_fee = 1;

    pre.get_accounts()[tx.sender].balance = 0x20000 + 25000;

    rev = EVMC_CANCUN;

    expect.post.at(Coinbase).exists = false;
    expect.status = EVMC_SUCCESS;
}

TEST_F(state_transition, empty_coinbase_fee_0_sd)
{
    rev = EVMC_SPURIOUS_DRAGON;

    block_reward = 0;
    block.base_fee = 0;
    tx.max_gas_price = 0;
    tx.max_priority_gas_price = 0;
    tx.to = To;
    pre.insert(Coinbase, {});
    expect.post[To].exists = false;
    expect.post[Coinbase].exists = false;
}

TEST_F(state_transition, empty_coinbase_fee_0_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;

    block_reward = 0;
    block.base_fee = 0;
    tx.max_gas_price = 0;
    tx.max_priority_gas_price = 0;
    tx.to = To;
    pre.insert(Coinbase, {});
    expect.post[To].exists = true;
    expect.post[Coinbase].balance = 0;
}

TEST_F(state_transition, access_list_storage)
{
    tx.to = To;
    tx.access_list = {{To, {0x01_bytes32}}};

    pre.insert(To,
        {.storage = {{0x01_bytes32, {0x01_bytes32, 0x01_bytes32}}}, .code = sstore(2, sload(1))});

    expect.post[To].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[To].storage[0x02_bytes32] = 0x01_bytes32;
    expect.gas_used = 47506;  // Without access list: 45206
}
