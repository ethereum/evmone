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

TEST_F(state_transition, create_tx_failure)
{
    static constexpr auto create_address = 0x3442a1dec1e72f337007125aa67221498cdd759d_address;

    tx.data = bytecode{} + OP_INVALID;

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[create_address].exists = false;
}

TEST_F(state_transition, create2_max_nonce)
{
    tx.to = To;
    pre.insert(*tx.to, {.nonce = ~uint64_t{0}, .code = create2()});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // Nonce is unchanged.
}

TEST_F(state_transition, create_tx_collision)
{
    static constexpr auto CREATED = 0x3442a1dec1e72f337007125aa67221498cdd759d_address;

    pre.insert(CREATED, {.nonce = 2});

    expect.status = EVMC_FAILURE;
    expect.post[CREATED].nonce = 2;
}

TEST_F(state_transition, create_collision)
{
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create()});
    pre.insert(CREATED, {.nonce = 2});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[CREATED].nonce = pre.get(CREATED).nonce;
}

TEST_F(state_transition, create_collision_revert)
{
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});
    pre.insert(CREATED, {.nonce = 2});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].nonce = pre.get(CREATED).nonce;
}

TEST_F(state_transition, create_prefunded_revert)
{
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});
    pre.insert(CREATED, {.balance = 2});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].nonce = pre.get(CREATED).nonce;
}

TEST_F(state_transition, create_revert)
{
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = false;
}

TEST_F(state_transition, create_revert_sd)
{
    rev = EVMC_SPURIOUS_DRAGON;
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = false;
}

TEST_F(state_transition, create_revert_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = false;
}

TEST_F(state_transition, create_collision_empty_revert)
{
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});
    pre.insert(CREATED, {});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = true;
}

TEST_F(state_transition, create_collision_empty_revert_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;
    static constexpr auto CREATED = 0x8bbc3514477d75ec797bbe4e19d7961660bb849c_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = create() + OP_INVALID});
    pre.insert(CREATED, {});

    expect.status = EVMC_INVALID_INSTRUCTION;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = true;
}

TEST_F(state_transition, touch_create_collision_empty_revert)
{
    static constexpr auto CREATED = 0x11f72042f0f1c9d8a1aeffc3680d0b41dd7769a7_address;
    static constexpr auto REVERT_PROXY = 0x94_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = call(CREATED) + call(REVERT_PROXY).gas(0xffff)});
    pre.insert(REVERT_PROXY, {.code = create() + OP_INVALID});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = false;
    expect.post[REVERT_PROXY].exists = true;
}

TEST_F(state_transition, touch_create_collision_empty_revert_tw)
{
    rev = EVMC_TANGERINE_WHISTLE;
    static constexpr auto CREATED = 0x11f72042f0f1c9d8a1aeffc3680d0b41dd7769a7_address;
    static constexpr auto REVERT_PROXY = 0x94_address;

    tx.to = To;
    pre.insert(*tx.to, {.code = call(CREATED) + call(REVERT_PROXY).gas(0xffff)});
    pre.insert(REVERT_PROXY, {.code = create() + OP_INVALID});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[CREATED].exists = true;
    expect.post[REVERT_PROXY].exists = true;
}

TEST_F(state_transition, created_code_hash)
{
    const auto CREATED = compute_create_address(To, pre[To].nonce);
    const auto runtime_code = bytes{0xc0};
    ASSERT_EQ(runtime_code.size(), 1);
    const auto initcode = mstore8(0, push(runtime_code)) + ret(0, runtime_code.size());
    tx.to = To;
    pre[To] = {.code = mstore(0, push(initcode)) +
                       create().input(32 - initcode.size(), initcode.size()) +
                       sstore(0, bytecode{OP_EXTCODEHASH})};

    expect.post[CREATED].code = runtime_code;
    expect.post[To].storage[0x00_bytes32] = keccak256(runtime_code);
}

TEST_F(state_transition, code_deployment_out_of_gas_h)
{
    rev = EVMC_HOMESTEAD;
    const auto initcode = ret(0, 1000);  // create contract will a lot of zeros.

    tx.to = To;
    tx.gas_limit = 100000;
    pre[To] = {.code = mstore(0, push(initcode)) +
                       sstore(0, create().input(32 - initcode.size(), initcode.size()))};

    expect.post[To].exists = true;
    expect.status = EVMC_OUT_OF_GAS;
}

TEST_F(state_transition, code_deployment_out_of_gas_f)
{
    rev = EVMC_FRONTIER;
    const auto CREATED = compute_create_address(To, pre[To].nonce);
    const auto initcode = ret(0, 100);  // create contract will a lot of zeros.

    tx.to = To;
    tx.gas_limit = 100000;
    pre[To] = {.code = mstore(0, push(initcode)) +
                       sstore(0, create().input(32 - initcode.size(), initcode.size()))};

    expect.post[To].exists = true;
    expect.post[CREATED].exists = true;
    bytes32 ccc{};
    std::copy(std::begin(CREATED.bytes), std::end(CREATED.bytes), &ccc.bytes[12]);
    expect.post[To].storage[0x00_bytes32] = ccc;
}
