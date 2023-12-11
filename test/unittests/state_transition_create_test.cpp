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

TEST_F(state_transition, create3_empty_auxdata)
{
    static constexpr auto create_address = 0x4fe3707830bc93c282c3702cfbdc048ad3762190_address;

    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data);

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    const auto factory_code = create3().container(0).input(0, 0).salt(0xff) + ret_top();
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, create3_non_empty_auxdata)
{
    static constexpr auto create_address = 0x58dddce25e22e1827156fea14c4a4dae2d5db179_address;


    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto aux_data = "aabbccddeeff"_hex;
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container =
        eof1_bytecode_truncated_data(bytecode(OP_INVALID), 0, deploy_data, deploy_data_size);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const auto init_container = eof1_bytecode_with_container(init_code, 3, {}, 0, deploy_container);

    const auto factory_code = calldatacopy(0, 0, OP_CALLDATASIZE) +
                              create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff) +
                              ret_top();
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;

    tx.data = aux_data;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, create3_dataloadn_referring_to_auxdata)
{
    static constexpr auto create_address = 0x89069eb18ad23e657a7e048e597a36b9097cf23d_address;

    rev = EVMC_PRAGUE;
    const auto deploy_data = bytes(64, 0);
    const auto aux_data = bytes(32, 0);
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    // DATALOADN{64} - referring to data that will be appended as cux_data
    const auto deploy_code = bytecode(OP_DATALOADN) + "0040" + ret_top();
    const auto deploy_container =
        eof1_bytecode_truncated_data(deploy_code, 2, deploy_data, deploy_data_size);

    const auto init_code = returncontract(0, 0, 32);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    const auto factory_code = create3().container(0).input(0, 0).salt(0xff) + ret_top();
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    const auto expected_container = eof1_bytecode(deploy_code, 2, deploy_data + aux_data);

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[create_address].code = expected_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, create3_revert_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = revert(0, 0);
    const auto init_container = eof1_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_revert_non_empty_returndata)
{
    rev = EVMC_PRAGUE;
    const auto init_code = mstore8(0, 0xaa) + revert(0, 1);
    const auto init_container = eof1_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) +
        sstore(1, OP_RETURNDATASIZE) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
}

TEST_F(state_transition, create3_initcontainer_aborts)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_INVALID}};
    const auto init_container = eof1_bytecode(init_code, 0);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_initcontainer_return)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{0xaa + ret_top()};
    const auto init_container = eof1_bytecode(init_code, 2);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_initcontainer_stop)
{
    rev = EVMC_PRAGUE;
    const auto init_code = bytecode{Opcode{OP_STOP}};
    const auto init_container = eof1_bytecode(init_code, 0);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_deploy_container_max_size)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    static constexpr auto create_address = 0xac84d697536dafc72ca38746bcfb59a3c6ad3928_address;

    const auto eof_header_size = static_cast<int>(eof1_bytecode({OP_INVALID}).size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const auto deploy_container = eof1_bytecode(deploy_code, 0);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    bytes32 create_address32{};
    std::copy_n(create_address.bytes, sizeof(create_address), &create_address32.bytes[12]);
    expect.post[*tx.to].storage[0x00_bytes32] = create_address32;
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, create3_deploy_container_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size = static_cast<int>(eof1_bytecode({OP_INVALID}).size() - 1);
    const auto deploy_code = (0x6000 - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const auto deploy_container = eof1_bytecode(deploy_code, 0);

    // no aux data
    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_deploy_container_with_aux_data_too_large)
{
    rev = EVMC_PRAGUE;
    block.gas_limit = 10'000'000;
    tx.gas_limit = block.gas_limit;
    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price + tx.value + 1;

    const auto eof_header_size = static_cast<int>(eof1_bytecode({OP_INVALID}).size() - 1);
    const auto deploy_code = (0x5fff - eof_header_size) * bytecode{Opcode{OP_JUMPDEST}} + OP_STOP;
    const auto deploy_container = eof1_bytecode(deploy_code, 0);

    // 1 byte aux data
    const auto init_code = returncontract(0, 0, 1);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_nested_create3)
{
    static constexpr auto create_address = 0xd886b500c2c58f75e1bd6fb64c05777c4b11b4f9_address;
    static constexpr auto create_address_nested =
        0x82d9c5bcce46288827c1e863d81913dfef699550_address;

    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data);

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const auto init_container_nested =
        eof1_bytecode_with_container(init_code_nested, 2, {}, 0, deploy_container_nested);

    const auto init_code = sstore(0, create3().container(1).salt(0xff)) + returncontract(0, 0, 0);
    const std::array embedded_conts = {deploy_container, init_container_nested};
    const auto init_container = eof1_bytecode_with_containers(init_code, 4, {}, 0, embedded_conts);

    const auto factory_code = sstore(0, create3().container(0).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0xd886b500c2c58f75e1bd6fb64c05777c4b11b4f9_bytes32;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 2;
    expect.post[create_address].storage[0x00_bytes32] =
        0x82d9c5bcce46288827c1e863d81913dfef699550_bytes32;
    expect.post[create_address_nested].code = deploy_container_nested;
    expect.post[create_address_nested].nonce = 1;
}

TEST_F(state_transition, create3_nested_create3_revert)
{
    rev = EVMC_PRAGUE;

    const auto deploy_data_nested = "ffffff"_hex;
    const auto deploy_container_nested = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data_nested);

    const auto init_code_nested = returncontract(0, 0, 0);
    const auto init_container_nested =
        eof1_bytecode_with_container(init_code_nested, 2, {}, 0, deploy_container_nested);

    const auto init_code = sstore(0, create3().container(0).salt(0xff)) + revert(0, 0);
    const auto init_container =
        eof1_bytecode_with_container(init_code, 4, {}, 0, init_container_nested);

    const auto factory_code = sstore(0, create3().container(0).salt(0xff)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;

    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create3_caller_balance_too_low)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof1_bytecode(bytecode{Opcode{OP_INVALID}}, 0, deploy_data);

    const auto init_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) + returncontract(0, 0, OP_CALLDATASIZE);
    const auto init_container = eof1_bytecode_with_container(init_code, 3, {}, 0, deploy_container);

    const auto factory_code =
        calldatacopy(0, 0, OP_CALLDATASIZE) +
        sstore(0, create3().container(0).input(0, OP_CALLDATASIZE).salt(0xff).value(10)) + OP_STOP;
    const auto factory_container =
        eof1_bytecode_with_container(factory_code, 4, {}, 0, init_container);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;
    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, create4_empty_auxdata)
{
    static constexpr auto create_address = 0x4fe3707830bc93c282c3702cfbdc048ad3762190_address;

    rev = EVMC_PRAGUE;
    const auto deploy_data = "abcdef"_hex;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 0, deploy_data);

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code =
        create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].nonce = 1;
}

TEST_F(state_transition, create4_invalid_initcode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 0);

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container =
        eof1_bytecode_with_container(init_code, 123, {}, 0, deploy_container);  // Invalid EOF

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    // TODO: extract this common code for a testing deployer contract
    const auto factory_code = create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55752;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, create4_truncated_data_initcode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 0);

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container =
        eof1_bytecode_with_container(init_code, 2, {}, 1, deploy_container);  // Truncated data

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    // TODO: extract this common code for a testing deployer contract
    const auto factory_code = create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55764;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, create4_invalid_deploycode)
{
    rev = EVMC_PRAGUE;
    const auto deploy_container = eof1_bytecode(bytecode(OP_INVALID), 123);  // Invalid EOF

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code = create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55764;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, create4_missing_initcontainer)
{
    rev = EVMC_PRAGUE;
    tx.type = Transaction::Type::initcodes;

    const auto factory_code = create4().initcode(keccak256(bytecode())).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55236;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, create4_light_failure_stack)
{
    rev = EVMC_PRAGUE;
    tx.type = Transaction::Type::initcodes;

    const auto factory_code =
        push(0x123) + create4().value(1).initcode(0x43_bytes32).input(2, 3).salt(0xff) + push(1) +
        OP_SSTORE +  // store result from create4
        push(2) +
        OP_SSTORE +  // store the preceding push value, nothing else should remain on stack
        ret(0);
    const auto factory_container = eof1_bytecode(factory_code, 6);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE4 has pushed 0x0 on stack
    expect.post[*tx.to].storage[0x02_bytes32] =
        0x0123_bytes32;  // CREATE4 fails but has cleared its args first
}

TEST_F(state_transition, create4_missing_deploycontainer)
{
    rev = EVMC_PRAGUE;
    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode(init_code, 2);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code = create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 55494;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}

TEST_F(state_transition, create4_deploy_code_with_dataloadn_invalid)
{
    rev = EVMC_PRAGUE;
    const auto deploy_data = bytes(32, 0);
    // DATALOADN{64} - referring to offset out of bounds even after appending aux_data later
    const auto deploy_code = bytecode(OP_DATALOADN) + "0040" + ret_top();
    const auto aux_data = bytes(32, 0);
    const auto deploy_data_size = static_cast<uint16_t>(deploy_data.size() + aux_data.size());
    const auto deploy_container =
        eof1_bytecode_truncated_data(deploy_code, 2, deploy_data, deploy_data_size);

    const auto init_code = returncontract(0, 0, 0);
    const auto init_container = eof1_bytecode_with_container(init_code, 2, {}, 0, deploy_container);

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(init_container);

    const auto factory_code = create4().initcode(keccak256(init_container)).input(0, 0).salt(0xff) +
                              OP_DUP1 + push(1) + OP_SSTORE + ret_top();
    const auto factory_container = eof1_bytecode(factory_code, 5);

    tx.to = To;
    pre.insert(*tx.to, {.nonce = 1, .code = factory_container});

    expect.gas_used = 56030;

    expect.post[tx.sender].nonce = pre.get(tx.sender).nonce + 1;
    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce;  // CREATE caller's nonce must not be bumped
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;  // CREATE must fail
}
