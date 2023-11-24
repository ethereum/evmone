// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, create2_factory)
{
    static constexpr auto create_address = 0xfd8e7707356349027a32d71eabc7cb0cf9d7cbb4_address;

    const auto factory_code =
        calldatacopy(0, 0, calldatasize()) + create2().input(0, calldatasize());
    const auto initcode = mstore8(0, push(0xFE)) + ret(0, 1);

    tx.to = To;
    tx.data = initcode;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;  // CREATE caller's nonce must be bumped
    expect.post[create_address].code = bytes{0xFE};
}

TEST_F(state_transition, create_tx)
{
    static constexpr auto create_address = 0x3442a1dec1e72f337007125aa67221498cdd759d_address;

    tx.data = mstore8(0, push(0xFE)) + ret(0, 1);

    expect.post[create_address].code = bytes{0xFE};
}

TEST_F(state_transition, create2_max_nonce)
{
    // The address to be created by CREATE2 of the "To" sender and empty initcode.
    static constexpr auto create_address = 0x36fd63ce1cb5ee2993f19d1fae4e84d52f6f1595_address;

    tx.to = To;
    pre.insert(*tx.to, {.nonce = ~uint64_t{0}, .code = create2()});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // Nonce is unchanged.
    expect.post[create_address].exists = false;
}

TEST_F(state_transition, create_tx_with_eof_initcode)
{
    rev = EVMC_PRAGUE;

    const bytecode init_container = eof_bytecode(ret(0, 1));

    tx.data = init_container;

    expect.tx_error = EOF_CREATION_TRANSACTION;
}

TEST_F(state_transition, create_with_eof_initcode)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const bytecode init_container = eof_bytecode(ret(0, 1));
    const auto factory_code =
        mstore(0, push(init_container)) +
        // init_container will be left-padded in memory to 32 bytes
        sstore(0, create().input(32 - init_container.size(), init_container.size())) + sstore(1, 1);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, create2_with_eof_initcode)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const bytecode init_container = eof_bytecode(ret(0, 1));
    const auto factory_code =
        mstore(0, push(init_container)) +
        // init_container will be left-padded in memory to 32 bytes
        sstore(0, create2().input(32 - init_container.size(), init_container.size()).salt(0xff)) +
        sstore(1, 1);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, create_tx_deploying_eof)
{
    static constexpr auto create_address = 0x3442a1dec1e72f337007125aa67221498cdd759d_address;

    rev = EVMC_PRAGUE;

    const bytecode deploy_container = eof_bytecode(bytecode(OP_INVALID));
    const auto init_code = mstore(0, push(deploy_container)) +
                           // deploy_container will be left-padded in memory to 32 bytes
                           ret(32 - deploy_container.size(), deploy_container.size());

    tx.data = init_code;

    expect.status = EVMC_CONTRACT_VALIDATION_FAILURE;
    expect.post[Sender].nonce = pre.get(Sender).nonce + 1;
    expect.post[create_address].exists = false;
}

TEST_F(state_transition, create_deploying_eof)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const bytecode deploy_container = eof_bytecode(bytecode(OP_INVALID));
    const auto init_code = mstore(0, push(deploy_container)) +
                           // deploy_container will be left-padded in memory to 32 bytes
                           ret(32 - deploy_container.size(), deploy_container.size());

    const auto factory_code = mstore(0, push(init_code)) +
                              // init_code will be left-padded in memory to 32 bytes
                              sstore(0, create().input(32 - init_code.size(), init_code.size())) +
                              sstore(1, 1);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, create2_deploying_eof)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const bytecode deploy_container = eof_bytecode(bytecode(OP_INVALID));
    const auto init_code = mstore(0, push(deploy_container)) +
                           // deploy_container will be left-padded in memory to 32 bytes
                           ret(32 - deploy_container.size(), deploy_container.size());

    const auto factory_code =
        mstore(0, push(init_code)) +
        // init_code will be left-padded in memory to 32 bytes
        sstore(0, create2().input(32 - init_code.size(), init_code.size()).salt((0xff))) +
        sstore(1, 1);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}
