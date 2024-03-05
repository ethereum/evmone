// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, create2_factory)
{
    const auto factory_code =
        calldatacopy(0, 0, calldatasize()) + create2().input(0, calldatasize());
    const auto initcode = mstore8(0, push(0xFE)) + ret(0, 1);

    tx.to = To;
    tx.data = initcode;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    const auto create_address = compute_create2_address(*tx.to, {}, initcode);
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;  // CREATE caller's nonce must be bumped
    expect.post[create_address].code = bytes{0xFE};
}

TEST_F(state_transition, create_tx_empty)
{
    // The default transaction without "to" address is a create transaction.

    expect.post[compute_create_address(Sender, pre.get(Sender).nonce)] = {
        .nonce = 1, .code = bytes{}};

    // Example of checking the expected the post state MPT root hash.
    expect.state_hash = 0x8ae438f7a4a14dbc25410dfaa12e95e7b36f311ab904b4358c3b544e06df4c50_bytes32;
}

TEST_F(state_transition, create_tx)
{
    tx.data = mstore8(0, push(0xFE)) + ret(0, 1);

    const auto create_address = compute_create_address(Sender, pre.get(Sender).nonce);
    expect.post[create_address].code = bytes{0xFE};
}

TEST_F(state_transition, create2_max_nonce)
{
    tx.to = To;
    pre.insert(*tx.to, {.nonce = ~uint64_t{0}, .code = create2()});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // Nonce is unchanged.
}

TEST_F(state_transition, code_deployment_out_of_gas_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;  // 63/64 gas rule enabled
    block.base_fee = 0;
    const auto initcode = ret(0, 5000);  // create contract with a lot of zeros, deploy cost 1M

    tx.to = To;
    tx.gas_limit = 1000000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    expect.post[To].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, code_deployment_out_of_gas_f)
{
    rev = EVMC_FRONTIER;
    block.base_fee = 0;
    const auto initcode = ret(0, 1000);  // create contract with a lot of zeros

    tx.to = To;
    tx.gas_limit = 100000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    const auto created = compute_create_address(To, pre.get(To).nonce);
    expect.post[created].code = bytes{};  // code deployment failure creates empty account
    expect.post[created].nonce = 0;
    expect.post[To].storage[0x00_bytes32] = to_bytes32(created);  // address of created empty
}

TEST_F(state_transition, code_deployment_out_of_gas_storage_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;  // 63/64 gas rule enabled
    block.base_fee = 0;
    const auto initcode = sstore(0, 1)     // set storage
                          + ret(0, 5000);  // create contract with a lot of zeros

    tx.to = To;
    tx.gas_limit = 1000000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    expect.post[To].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, code_deployment_out_of_gas_storage_f)
{
    rev = EVMC_FRONTIER;
    block.base_fee = 0;
    const auto initcode = sstore(0, 1)     // set storage
                          + ret(0, 1000);  // create contract with a lot of zeros

    tx.to = To;
    tx.gas_limit = 100000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    expect.post[To].exists = true;
    const auto created = compute_create_address(To, pre.get(To).nonce);
    expect.post[created].code = bytes{};  // code deployment failure creates empty account
    expect.post[created].nonce = 0;
    expect.post[created].storage[0x00_bytes32] = 0x01_bytes32;  // storage stays
    expect.post[To].storage[0x00_bytes32] = to_bytes32(created);
    expect.gas_used = 93134;
}

TEST_F(state_transition, code_deployment_out_of_gas_refund_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;  // 63/64 gas rule enabled
    block.base_fee = 0;
    const auto initcode = sstore(0, 1)     // set storage
                          + sstore(0, 0)   // gas refund
                          + ret(0, 5000);  // create contract with a lot of zeros

    tx.to = To;
    tx.gas_limit = 1000000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    expect.post[To].storage[0x00_bytes32] = 0x00_bytes32;
    expect.gas_used = 990207;
}

TEST_F(state_transition, code_deployment_out_of_gas_refund_f)
{
    rev = EVMC_FRONTIER;
    block.base_fee = 0;
    const auto initcode = sstore(0, 1)     // set storage
                          + sstore(0, 0)   // gas refund
                          + ret(0, 1000);  // create contract with a lot of zeros

    tx.to = To;
    tx.gas_limit = 100000;
    pre.insert(To, {.code = mstore(0, push(initcode)) +
                            sstore(0, create().input(32 - initcode.size(), initcode.size()))});

    expect.post[To].exists = true;
    const auto created = compute_create_address(To, pre.get(To).nonce);
    expect.post[created].code = bytes{};  // code deployment failure creates empty account
    expect.post[created].nonce = 0;
    expect.post[created].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[To].storage[0x00_bytes32] = to_bytes32(created);
    expect.gas_used = 83140;
}
