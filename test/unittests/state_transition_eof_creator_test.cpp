// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

namespace
{
constexpr bytes32 Salt{0xff};
const auto deploy_container = eof_bytecode(bytecode(OP_INVALID));
const bytecode simple_init_container =
    eof_bytecode(returncontract(0, 0, 0), 2).container(deploy_container);

const auto creator = bytecode(
    // EOF header
    "EF0001 010004 020001002c 040000 00"
    // Types section
    "00 80 0005"
    // Code section
    // Enough calldata or revert?
    // rjumpi(5, iszero(64 + calldatasize() + OP_LT)) + revert(0, 0)
    "6040 36 10 15 E10003 5F 5F FD"
    // Copy input data to memory
    // calldatacopy(0, 64, 64 + calldatasize() + OP_SUB)
    "6040 36 03 6040 5F 37"
    // TXCREATE with arguments
    // txcreate()
    // .initcode(calldataload(0))
    // .input(0, 64 + calldatasize() + OP_SUB)
    // .salt(calldataload(32))
    // .value(OP_CALLVALUE)
    "6040 36 03 5F 6020 35 34 5F 35 ED"
    // Creation successful or revert?
    // rjumpi(5, OP_DUP1) + revert(0, 0)
    "80 E10003 5F 5F FD"
    // RETURN new address
    // ret_top()
    "5F 52 6020 5F F3");

bytes creator_calldata(
    const bytecode& init_container, const bytes32 salt, const bytes& input = bytes{})
{
    return bytes(keccak256(init_container)) + bytes(salt) + input;
}
}  // namespace

TEST_F(state_transition, create_first)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, create_second)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(bytes{0xff});
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, create_255th)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    for (int i = 0; i < 255; ++i)
        tx.initcodes.push_back(bytes{0xff});
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, different_salt)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, bytes32{0xfe});
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address =
        compute_eofcreate_address(*tx.to, bytes32{0xfe}, simple_init_container);
    const auto other_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    // Sanity check
    ASSERT_NE(create_address, other_address);

    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, duplicate_container)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
}

TEST_F(state_transition, undefined_container_reverts)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(keccak256(bytecode()), Salt);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.status = EVMC_REVERT;
    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, not_enough_calldata_reverts)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(keccak256(bytecode()), Salt).substr(0, 63);
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.status = EVMC_REVERT;
    expect.post[*tx.to].exists = true;
}

TEST_F(state_transition, calldata_to_inputdata)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    const bytecode input_init_container =
        eof_bytecode(sstore(0, calldataload(0)) + returncontract(0, 0, 0), 2)
            .container(deploy_container);
    tx.initcodes.push_back(input_init_container);

    tx.to = To;
    tx.data = creator_calldata(input_init_container, Salt, bytes(bytes32{0xcc}));
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, input_init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].storage[0x00_bytes32] = 0xcc_bytes32;
}

TEST_F(state_transition, creator_returns_new_address)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    constexpr auto creator_address = 0x0c12ea1012_address;

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    pre.insert(*tx.to,
        {.nonce = 1,
            .storage = {{0x00_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(calldatacopy(0, 0, calldatasize()) +
                                     sstore(0, extdelegatecall(creator_address).input(0, 64)) +
                                     sstore(1, returndataload(0)) + OP_STOP,
                3)});
    pre.insert(creator_address, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[creator_address].exists = true;

    expect.post[*tx.to].storage[0x00_bytes32] = 0x00_bytes32;  // Success status code.
    expect.post[*tx.to].storage[0x01_bytes32] = to_bytes32(create_address);
}

TEST_F(state_transition, endowment)
{
    rev = EVMC_PRAGUE;

    tx.type = Transaction::Type::initcodes;
    tx.initcodes.push_back(simple_init_container);

    tx.to = To;
    tx.data = creator_calldata(simple_init_container, Salt);
    tx.value = 1;
    pre.insert(*tx.to, {.nonce = 1, .code = creator});

    expect.post[*tx.to].nonce = pre.get(*tx.to).nonce + 1;
    const auto create_address = compute_eofcreate_address(*tx.to, Salt, simple_init_container);
    expect.post[create_address].code = deploy_container;
    expect.post[create_address].balance = 1;
}
