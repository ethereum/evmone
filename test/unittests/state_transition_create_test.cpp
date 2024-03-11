// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

namespace
{
constexpr bytes32 Salt{0xff};
}

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
    block.base_fee = 0;
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
    block.base_fee = 0;
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
    block.base_fee = 0;
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
    block.base_fee = 0;
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
    const auto runtime_code = bytes{0xc0};
    ASSERT_EQ(runtime_code.size(), 1);
    const auto initcode = mstore8(0, push(runtime_code)) + ret(0, runtime_code.size());
    tx.to = To;
    pre.insert(To,
        {.code = mstore(0, push(initcode)) + create().input(32 - initcode.size(), initcode.size()) +
                 sstore(0, bytecode{OP_EXTCODEHASH})});

    const auto created = compute_create_address(To, pre.get(To).nonce);
    expect.post[created].code = runtime_code;
    expect.post[To].storage[0x00_bytes32] = keccak256(runtime_code);
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

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
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

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, create_tx_deploying_eof)
{
    rev = EVMC_PRAGUE;

    const bytecode deploy_container = eof_bytecode(bytecode(OP_INVALID));
    const auto init_code = mstore(0, push(deploy_container)) +
                           // deploy_container will be left-padded in memory to 32 bytes
                           ret(32 - deploy_container.size(), deploy_container.size());

    tx.data = init_code;

    expect.status = EVMC_CONTRACT_VALIDATION_FAILURE;
    expect.post[Sender].nonce = pre.get(Sender).nonce + 1;
    const auto create_address = compute_create_address(Sender, pre.get(Sender).nonce);
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

TEST_F(state_transition, eofcreate_empty_auxdata)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code = eofcreate().container(0).input(0, 0).salt(Salt) + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_auxdata_equal_to_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                              eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt) +
                              ret_top();
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    tx.data = aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_auxdata_longer_than_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data1 = "aabbccdd"_hex;
    const auto aux_data2 = "eeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data1.size());
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                              eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt) +
                              ret_top();
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    tx.data = aux_data1 + aux_data2;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data + aux_data1 + aux_data2);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_auxdata_shorter_than_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size() + 1);
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const auto init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    tx.data = aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_dataloadn_referring_to_auxdata)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = bytes(64, 0);
    const auto aux_data = bytes(32, 0);
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    // DATALOADN{64} - referring to data that will be appended as aux_data
    const auto deploy_code = bytecode(OP_DATALOADN) + "0040" + ret_top();
    const auto deploy_container = eof_bytecode(deploy_code, 2).data(deploy_data, deploy_data_size);

    const auto init_code = returncontract(0, 0, 32);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code =
        sstore(0, eofcreate().container(0).input(0, 0).salt(Salt)) + sstore(1, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof_bytecode(deploy_code, 2).data(deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_with_auxdata_and_subcontainer)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container = eof_bytecode(OP_INVALID)
                                      .container(eof_bytecode(OP_INVALID))
                                      .data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + sstore(1, 1) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    tx.data = aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof_bytecode(bytecode(OP_INVALID))
                                        .container(eof_bytecode(OP_INVALID))
                                        .data(deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_revert_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = revert(0, 0);
    const auto init_container = eof_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_revert_non_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = mstore8(0, 0xaa) + revert(0, 1);
    const auto init_container = eof_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, eofcreate_initcontainer_aborts)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_INVALID}};
    const auto init_container = eof_bytecode(init_code, 0);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_initcontainer_return)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{0xaa + ret_top()};
    const auto init_container = eof_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_initcontainer_stop)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_STOP}};
    const auto init_container = eof_bytecode(init_code, 0);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_deploy_container_max_size)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6000);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, eofcreate_deploy_container_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x6000 - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6001);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_appended_data_size_larger_than_64K)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto aux_data = bytes(std::numeric_limits<uint16_t>::max(), 0);
    const auto deploy_data = "aa"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    static constexpr bytes32 salt2{0xfe};
    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        // with aux data, final data size = 2**16
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) +
        // no aux_data - final data size = 1
        sstore(1, eofcreate().container(0).salt(salt2)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    tx.data = aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 2;  // 1 successful creation + 1 hard fail
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    const auto create_address = compute_eofcreate_address(*tx.to, salt2, init_container);
    expect.post[*tx.to].storage[0x01_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_deploy_container_with_aux_data_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6000);

    // 1 byte aux data
    const auto init_code = returncontract(0, 0, 1);
    const auto init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_nested_eofcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const bytecode init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code = sstore(0, eofcreate().container(1).salt(Salt)) + returncontract(0, 0, 0);
    const bytecode init_container =
        eof_bytecode(init_code, 4).container(deploy_container).container(init_container_nested);

    const auto factory_code = sstore(0, eofcreate().container(0).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 2;
    const auto create_address_nested =
        compute_eofcreate_address(create_address, Salt, init_container_nested);
    expect.post[create_address].storage[0x00_bytes32] = to_bytes32(create_address_nested);
    expect.post[create_address_nested].code = deploy_container_nested;
    expect.post[create_address_nested].nonce = 1;
}

TEST_F(state_transition, eofcreate_nested_eofcreate_revert)
{
    rev = EVMC_PRAGUE;

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const auto init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code = sstore(0, eofcreate().container(0).salt(Salt)) + revert(0, 0);
    const auto init_container = eof_bytecode(init_code, 4).container(init_container_nested);

    const auto factory_code = sstore(0, eofcreate().container(0).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_nested_txcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const bytecode init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code =
        sstore(0, txcreate().initcode(keccak256(init_container_nested)).salt(Salt)) +
        returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 5).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container_nested);

    const auto factory_code = sstore(0, eofcreate().container(0).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 2;
    const auto create_address_nested =
        compute_eofcreate_address(create_address, Salt, init_container_nested);
    expect.post[create_address].storage[0x00_bytes32] = to_bytes32(create_address_nested);
    expect.post[create_address_nested].code = deploy_container_nested;
    expect.post[create_address_nested].nonce = 1;
}

TEST_F(state_transition, eofcreate_caller_balance_too_low)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode{Opcode{OP_INVALID}}).data(deploy_data);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const auto init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt).value(10)) +
        sstore(1, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, eofcreate_not_enough_gas_for_initcode_charge)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    auto init_container = eof_bytecode(init_code, 2).container(deploy_container);
    // add max size data
    const auto init_data =
        bytes(std::numeric_limits<uint16_t>::max() - bytecode(init_container).size(), 0);
    init_container.data(init_data);
    EXPECT_EQ(bytecode(init_container).size(), std::numeric_limits<uint16_t>::max());

    const auto factory_code = sstore(0, eofcreate().container(0).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    // tx intrinsic cost + EOFCREATE cost + initcode charge - not enough for pushes before EOFCREATE
    tx.gas_limit = 21'000 + 32'000 + (std::numeric_limits<uint16_t>::max() + 31) / 32 * 6;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.status = EVMC_OUT_OF_GAS;

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_not_enough_gas_for_mem_expansion)
{
    rev = EVMC_PRAGUE;
    auto deploy_container = eof_bytecode(bytecode(OP_INVALID));
    // max size aux data
    const auto aux_data_size = static_cast<uint16_t>(
        std::numeric_limits<uint16_t>::max() - bytecode(deploy_container).size());
    deploy_container.data({}, aux_data_size);
    EXPECT_EQ(
        bytecode(deploy_container).size() + aux_data_size, std::numeric_limits<uint16_t>::max());

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto factory_code =
        sstore(0, eofcreate().container(0).input(0, aux_data_size).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    // tx intrinsic cost + EOFCREATE cost + initcode charge + mem expansion size = not enough for
    // pushes before EOFCREATE
    const auto initcode_size_words = (init_container.size() + 31) / 32;
    const auto aux_data_size_words = (aux_data_size + 31) / 32;
    tx.gas_limit = 21'000 + 32'000 + static_cast<uint16_t>(6 * initcode_size_words) +
                   3 * aux_data_size_words + aux_data_size_words * aux_data_size_words / 512;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.status = EVMC_OUT_OF_GAS;

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, returncontract_not_enough_gas_for_mem_expansion)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    auto deploy_container = eof_bytecode(bytecode(OP_INVALID));
    // max size aux data
    const auto aux_data_size = static_cast<uint16_t>(
        std::numeric_limits<uint16_t>::max() - bytecode(deploy_container).size());
    deploy_container.data({}, aux_data_size);
    EXPECT_EQ(
        bytecode(deploy_container).size() + aux_data_size, std::numeric_limits<uint16_t>::max());

    const auto init_code = returncontract(0, 0, aux_data_size);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code = eofcreate().container(0).salt(Salt) + OP_POP + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;
    // tx intrinsic cost + EOFCREATE cost + initcode charge + mem expansion size = not enough for
    // pushes before RETURNDATALOAD
    const auto initcode_size_words = (init_container.size() + 31) / 32;
    const auto aux_data_size_words = (aux_data_size + 31) / 32;
    tx.gas_limit = 21'000 + 32'000 + static_cast<uint16_t>(6 * initcode_size_words) +
                   3 * aux_data_size_words + aux_data_size_words * aux_data_size_words / 512;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, eofcreate_clears_returndata)
{
    static constexpr auto returning_address = 0x3000_address;

    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(OP_STOP);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code = sstore(0, call(returning_address).gas(0xffffff)) +
                              sstore(1, returndatasize()) +
                              sstore(2, eofcreate().container(0).salt(Salt)) +
                              sstore(3, returndatasize()) + sstore(4, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 7).container(init_container);

    const auto returning_code = ret(0, 10);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});
    pre.insert(returning_address, {.nonce = 1, .code = returning_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x01_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x0a_bytes32;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x02_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x03_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x04_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
    expect.post[returning_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_failure_after_eofcreate_success)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto deploy_container = eof_bytecode(OP_STOP);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    const auto factory_code = sstore(0, eofcreate().container(0).salt(Salt)) +
                              sstore(1, eofcreate().container(0).salt(Salt)) +  // address collision
                              sstore(2, returndatasize()) + sstore(3, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 2;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x02_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x03_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, eofcreate_call_created_contract)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;  // 3 bytes
    const auto static_aux_data =
        "aabbccdd00000000000000000000000000000000000000000000000000000000"_hex;  // 32 bytes
    const auto dynamic_aux_data = "eeff"_hex;                                    // 2 bytes
    const auto deploy_data_size =
        static_cast<uint16_t>(deploy_data.size() + static_aux_data.size());
    const auto deploy_code = rjumpv({6, 12}, calldataload(0)) +  // jump to one of 3 cases
                             35 + OP_DATALOAD + rjump(9) +       // read dynamic aux data
                             OP_DATALOADN + "0000" + rjump(3) +  // read pre_deploy_data_section
                             OP_DATALOADN + "0003" +             // read static aux data
                             ret_top();
    const auto deploy_container = eof_bytecode(deploy_code, 2).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    const auto create_address = compute_eofcreate_address(To, Salt, init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(Salt)) +
        mcopy(0, OP_CALLDATASIZE, 32) +  // zero out first 32-byte word of memory
        call(create_address).gas(0xffffff).input(0, 1) + OP_POP +  // calldata 0
        sstore(1, returndataload(0)) + mstore8(31, 1) +
        call(create_address).gas(0xffffff).input(0, 32) + OP_POP +  // calldata 1
        sstore(2, returndataload(0)) + mstore8(31, 2) +
        call(create_address).gas(0xffffff).input(0, 32) + OP_POP +  // calldata 2
        sstore(3, returndataload(0)) + sstore(4, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 7).container(init_container);

    tx.to = To;

    tx.data = static_aux_data + dynamic_aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] =
        0xabcdefaabbccdd00000000000000000000000000000000000000000000000000_bytes32;
    evmc::bytes32 static_aux_data_32;
    std::copy_n(static_aux_data.data(), static_aux_data.size(), &static_aux_data_32.bytes[0]);
    expect.post[*tx.to].storage[0x02_bytes32] = static_aux_data_32;
    evmc::bytes32 dynamic_aux_data_32;
    std::copy_n(dynamic_aux_data.data(), dynamic_aux_data.size(), &dynamic_aux_data_32.bytes[0]);
    expect.post[*tx.to].storage[0x03_bytes32] = dynamic_aux_data_32;
    expect.post[*tx.to].storage[0x04_bytes32] = 0x01_bytes32;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_empty_auxdata)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_auxdata_equal_to_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt) +
        ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    tx.data = aux_data;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_auxdata_longer_than_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data1 = "aabbccdd"_hex;
    const auto aux_data2 = "eeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data1.size());
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt) +
        ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    tx.data = aux_data1 + aux_data2;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data + aux_data1 + aux_data2);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_auxdata_shorter_than_declared)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size() + 1);
    const auto deploy_container =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt) +
        ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    tx.data = aux_data;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_dataloadn_referring_to_auxdata)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = bytes(64, 0);
    const auto aux_data = bytes(32, 0);
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    // DATALOADN{64} - referring to data that will be appended as aux_data
    const auto deploy_code = bytecode(OP_DATALOADN) + "0040" + ret_top();
    const auto deploy_container = eof_bytecode(deploy_code, 2).data(deploy_data, deploy_data_size);

    const auto init_code = returncontract(0, 0, 32);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        sstore(0, txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt)) +
        sstore(1, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof_bytecode(deploy_code, 2).data(deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_revert_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = revert(0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_revert_non_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = mstore8(0, 0xaa) + revert(0, 1);
    const bytecode init_container = eof_bytecode(init_code, 2);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, txcreate_initcontainer_aborts)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_INVALID}};
    const bytecode init_container = eof_bytecode(init_code, 0);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_initcontainer_return)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{0xaa + ret_top()};
    const bytecode init_container = eof_bytecode(init_code, 2);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_initcontainer_stop)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_STOP}};
    const bytecode init_container = eof_bytecode(init_code, 0);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_initcontainer_max_size)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container_no_data = eof_bytecode(init_code, 2).container(deploy_container);
    const auto data_size = 0xc000 - init_container_no_data.size();
    const bytecode init_container =
        eof_bytecode(init_code, 2).container(deploy_container).data(bytes(data_size, 0));
    EXPECT_EQ(init_container.size(), 0xc000);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_initcontainer_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container_no_data = eof_bytecode(init_code, 2).container(deploy_container);
    const auto data_size = 0xc001 - init_container_no_data.size();
    const bytecode init_container =
        eof_bytecode(init_code, 2).container(deploy_container).data(bytes(data_size, 0));
    EXPECT_EQ(init_container.size(), 0xc001);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.tx_error = INIT_CODE_SIZE_LIMIT_EXCEEDED;
}

TEST_F(state_transition, txcreate_too_many_initcontainers)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.assign(257, init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.tx_error = INIT_CODE_COUNT_LIMIT_EXCEEDED;
}

TEST_F(state_transition, initcode_transaction_before_prague)
{
    rev = EVMC_CANCUN;

    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.assign(257, init_container);

    tx.to = To;

    expect.tx_error = TX_TYPE_NOT_SUPPORTED;
}

TEST_F(state_transition, txcreate_deploy_container_max_size)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6000);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, txcreate_deploy_container_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x6000 - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6001);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_appended_data_size_larger_than_64K)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto aux_data = bytes(std::numeric_limits<uint16_t>::max(), 0);
    const auto deploy_data = "aa"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    static constexpr bytes32 salt2{0xfe};
    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        // with aux data, final data size = 2**16
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        // no aux_data - final data size = 1
        sstore(1, txcreate().initcode(keccak256(init_container)).salt(salt2)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    tx.data = aux_data;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 2;  // 1 successful creation + 1 hard fail
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    const auto create_address = compute_eofcreate_address(*tx.to, salt2, init_container);
    expect.post[*tx.to].storage[0x01_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_deploy_container_with_aux_data_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size =
        static_cast<int>(bytecode{eof_bytecode(Opcode{OP_INVALID})}.size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const bytecode deploy_container = eof_bytecode(deploy_code);
    EXPECT_EQ(deploy_container.size(), 0x6000);

    // 1 byte aux data
    const auto init_code = returncontract(0, 0, 1);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_nested_txcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const bytecode init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code =
        sstore(0, txcreate().initcode(keccak256(init_container_nested)).salt(Salt)) +
        returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 5).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);
    tx.initcodes.push_back(init_container_nested);

    const auto factory_code =
        sstore(0, txcreate().initcode(keccak256(init_container)).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 2;
    const auto create_address_nested =
        compute_eofcreate_address(create_address, Salt, init_container_nested);
    expect.post[create_address].storage[0x00_bytes32] = to_bytes32(create_address_nested);
    expect.post[create_address_nested].code = deploy_container_nested;
    expect.post[create_address_nested].nonce = 1;
}

TEST_F(state_transition, txcreate_nested_txcreate_revert)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const bytecode init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code =
        sstore(0, txcreate().initcode(keccak256(init_container_nested)).salt(Salt)) + revert(0, 0);
    const bytecode init_container = eof_bytecode(init_code, 5);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);
    tx.initcodes.push_back(init_container_nested);

    const auto factory_code =
        sstore(0, txcreate().initcode(keccak256(init_container)).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, txcreate_nested_eofcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested =
        eof_bytecode(bytecode(OP_INVALID)).data(deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const bytecode init_container_nested =
        eof_bytecode(init_code_nested, 2).container(deploy_container_nested);

    const auto init_code = sstore(0, eofcreate().container(1).salt(Salt)) + returncontract(0, 0, 0);
    const bytecode init_container =
        eof_bytecode(init_code, 4).container(deploy_container).container(init_container_nested);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        sstore(0, txcreate().initcode(keccak256(init_container)).salt(Salt)) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 2;
    const auto create_address_nested =
        compute_eofcreate_address(create_address, Salt, init_container_nested);
    expect.post[create_address].storage[0x00_bytes32] = to_bytes32(create_address_nested);
    expect.post[create_address_nested].code = deploy_container_nested;
    expect.post[create_address_nested].nonce = 1;
}

TEST_F(state_transition, txcreate_called_balance_too_low)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID)).data(deploy_data);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                              sstore(0, txcreate()
                                            .initcode(keccak256(init_container))
                                            .input(0, OP_CALLDATASIZE)
                                            .salt(Salt)
                                            .value(10)) +
                              sstore(1, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, txcreate_clears_returndata)
{
    static constexpr auto returning_address = 0x3000_address;

    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(OP_STOP);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code = sstore(0, call(returning_address).gas(0xffffff)) +
                              sstore(1, returndatasize()) +
                              sstore(2, txcreate().initcode(keccak256(init_container)).salt(Salt)) +
                              sstore(3, returndatasize()) + sstore(4, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 7);

    const auto returning_code = ret(0, 10);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});
    pre.insert(returning_address, {.nonce = 1, .code = returning_code});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x01_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x0a_bytes32;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x02_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x03_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x04_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
    expect.post[returning_address].nonce = 1;
}

TEST_F(state_transition, txcreate_failure_after_txcreate_success)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto deploy_container = eof_bytecode(OP_STOP);

    const auto init_code = returncontract(0, 0, 0);
    const bytecode init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        sstore(0, txcreate().initcode(keccak256(init_container)).salt(Salt)) +
        sstore(1, txcreate().initcode(keccak256(init_container)).salt(Salt)) +  // address collision
        sstore(2, returndatasize()) + sstore(3, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5).container(init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 2;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, init_container);
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x02_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x03_bytes32] = 0x01_bytes32;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, txcreate_invalid_initcode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytes init_container =
        eof_bytecode(init_code, 123).container(deploy_container);  // Invalid EOF

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    // TODO: extract this common code for a testing deployer contract
    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + OP_DUP1 + push(1) +
        OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55764;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_truncated_data_initcode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));

    const auto init_code = returncontract(0, 0, 0);
    const bytes init_container =
        eof_bytecode(init_code, 2).data("", 1).container(deploy_container);  // Truncated data

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    // TODO: extract this common code for a testing deployer contract
    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + OP_DUP1 + push(1) +
        OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55776;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_invalid_deploycode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(bytecode(OP_INVALID), 123);  // Invalid EOF

    const auto init_code = returncontract(0, 0, 0);
    const bytes init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + OP_DUP1 + push(1) +
        OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55776;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_missing_initcontainer)
{
    rev = EVMC_PRAGUE;
    tx.type = Transaction::Type::initcodes;

    const auto factory_code = txcreate().initcode(keccak256(bytecode())).input(0, 0).salt(Salt) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55236;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_light_failure_stack)
{
    rev = EVMC_PRAGUE;
    tx.type = Transaction::Type::initcodes;

    const auto factory_code =
        push(0x123) + txcreate().value(1).initcode(0x43_bytes32).input(2, 3).salt(Salt) + push(1) +
        OP_SSTORE +  // store result from TXCREATE
        push(2) +
        OP_SSTORE +  // store the preceding push value, nothing else should remain on stack
        ret(0);
    const auto factory_container = eof_bytecode(factory_code, 6);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // TXCREATE has pushed 0x0 on stack
    expect.post[*tx.to].storage[0x02_bytes32] =
        0x0123_bytes32;  // TXCREATE fails but has cleared its args first
}

TEST_F(state_transition, txcreate_missing_deploycontainer)
{
    rev = EVMC_PRAGUE;
    const auto init_code = returncontract(0, 0, 0);
    const bytes init_container = eof_bytecode(init_code, 2);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + OP_DUP1 + push(1) +
        OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55500;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_deploy_code_with_dataloadn_invalid)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = bytes(32, 0);
    // DATALOADN{64} - referring to offset out of bounds even after appending aux_data later
    const auto deploy_code = bytecode(OP_DATALOADN) + "0040" + ret_top();
    const auto aux_data = bytes(32, 0);
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container = eof_bytecode(deploy_code, 2).data(deploy_data, deploy_data_size);

    const auto init_code = returncontract(0, 0, 0);
    const bytes init_container = eof_bytecode(init_code, 2).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + OP_DUP1 + push(1) +
        OP_SSTORE + ret_top();
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 56048;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, txcreate_call_created_contract)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;  // 3 bytes
    const auto static_aux_data =
        "aabbccdd00000000000000000000000000000000000000000000000000000000"_hex;  // 32 bytes
    const auto dynamic_aux_data = "eeff"_hex;                                    // 2 bytes
    const auto deploy_data_size =
        static_cast<uint16_t>(deploy_data.size() + static_aux_data.size());
    const auto deploy_code = rjumpv({6, 12}, calldataload(0)) +  // jump to one of 3 cases
                             35 + OP_DATALOAD + rjump(9) +       // read dynamic aux data
                             OP_DATALOADN + "0000" + rjump(3) +  // read pre_deploy_data_section
                             OP_DATALOADN + "0003" +             // read static aux data
                             ret_top();
    const auto deploy_container = eof_bytecode(deploy_code, 2).data(deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const bytecode init_container = eof_bytecode(init_code, 3).container(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto create_address = compute_eofcreate_address(To, Salt, init_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0,
            txcreate().initcode(keccak256(init_container)).input(0, OP_CALLDATASIZE).salt(Salt)) +
        mcopy(0, OP_CALLDATASIZE, 32) +  // zero out first 32-byte word of memory
        call(create_address).gas(0xffffff).input(0, 1) + OP_POP +  // calldata 0
        sstore(1, returndataload(0)) + mstore8(31, 1) +
        call(create_address).gas(0xffffff).input(0, 32) + OP_POP +  // calldata 1
        sstore(2, returndataload(0)) + mstore8(31, 2) +
        call(create_address).gas(0xffffff).input(0, 32) + OP_POP +  // calldata 2
        sstore(3, returndataload(0)) + sstore(4, 1) + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 7).container(init_container);

    tx.to = To;

    tx.data = static_aux_data + dynamic_aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = to_bytes32(create_address);
    expect.post[*tx.to].storage[0x01_bytes32] =
        0xabcdefaabbccdd00000000000000000000000000000000000000000000000000_bytes32;
    evmc::bytes32 static_aux_data_32;
    std::copy_n(static_aux_data.data(), static_aux_data.size(), &static_aux_data_32.bytes[0]);
    expect.post[*tx.to].storage[0x02_bytes32] = static_aux_data_32;
    evmc::bytes32 dynamic_aux_data_32;
    std::copy_n(dynamic_aux_data.data(), dynamic_aux_data.size(), &dynamic_aux_data_32.bytes[0]);
    expect.post[*tx.to].storage[0x03_bytes32] = dynamic_aux_data_32;
    expect.post[*tx.to].storage[0x04_bytes32] = 0x01_bytes32;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, create_nested_in_txcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(OP_STOP);

    const auto init_code = bytecode{OP_DATASIZE} + OP_PUSH0 + OP_PUSH0 + OP_DATACOPY +
                           create().input(0, OP_DATASIZE) + returncontract(0, 0, 0);
    const bytes init_container =
        eof_bytecode(init_code, 3).container(deploy_container).data(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).salt(Salt) + push(1) + OP_SSTORE + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create2_nested_in_txcreate)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof_bytecode(OP_INVALID);

    const auto init_code = bytecode{OP_DATASIZE} + OP_PUSH0 + OP_PUSH0 + OP_DATACOPY +
                           create2().input(0, OP_DATASIZE).salt(Salt) + returncontract(0, 0, 0);
    const bytes init_container =
        eof_bytecode(init_code, 4).container(deploy_container).data(deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        txcreate().initcode(keccak256(init_container)).input(0, 0).salt(Salt) + push(1) +
        OP_SSTORE + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}
