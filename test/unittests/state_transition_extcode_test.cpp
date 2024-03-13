// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

constexpr auto target = 0xfffffffffffffffffffffffffffffffffffffffe_address;

TEST_F(state_transition, legacy_extcodesize_eof)
{
    pre.insert(target, {.code = eof_bytecode("FE")});

    rev = EVMC_PRAGUE;
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = bytecode(push(target) + sstore(1, OP_EXTCODESIZE)),
                       });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x02_bytes32;
    expect.post[target].exists = true;
}

TEST_F(state_transition, legacy_extcodehash_eof)
{
    pre.insert(target, {.code = eof_bytecode("FE")});

    rev = EVMC_PRAGUE;
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = bytecode(push(target) + sstore(1, OP_EXTCODEHASH)),
                       });
    expect.post[*tx.to].storage[0x01_bytes32] = keccak256(bytecode("EF00"));
    expect.post[target].exists = true;
}

TEST_F(state_transition, legacy_extcodecopy_eof)
{
    constexpr auto ones =
        0x1111111111111111111111111111111111111111111111111111111111111111_bytes32;
    pre.insert(target, {.code = eof_bytecode("FE")});

    rev = EVMC_PRAGUE;
    tx.to = To;
    pre.insert(*tx.to, {
                           .code = bytecode(mstore(0, ones) + push(20) + push0() + push0() +
                                            push(target) + OP_EXTCODECOPY + sstore(1, mload(0))),
                       });
    expect.post[*tx.to].storage[0x01_bytes32] =
        0xef00000000000000000000000000000000000000111111111111111111111111_bytes32;
    expect.post[target].exists = true;
}
