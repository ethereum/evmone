// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"

using namespace evmone::test;
using namespace intx;
using namespace evmc::literals;

TEST_P(evm, address_trunketed_bit_not_zero_balance)
{
    rev = EVMC_PRAGUE;

    execute(
        eof_bytecode(push(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256) +
                         OP_BALANCE + ret_top(),
            2));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(
        eof_bytecode(push(0x000000000000000000000001ffffffffffffffffffffffffffffffffffffffff_u256) +
                         OP_BALANCE + ret_top(),
            2));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(
        eof_bytecode(push(0x800000000000000000000000ffffffffffffffffffffffffffffffffffffffff_u256) +
                         OP_BALANCE + ret_top(),
            2));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(
        eof_bytecode(push(0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff_u256) +
                         OP_BALANCE + ret_top(),
            2));
    EXPECT_STATUS(EVMC_SUCCESS);

    execute(eof_bytecode(
        push(0xffffffffffffffffffffffffffffffffffffffff_address) + OP_BALANCE + ret_top(), 2));
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, address_trunketed_bit_not_zero_extcall)
{
    rev = EVMC_PRAGUE;

    if (evm::is_advanced())
        return;

    execute(eof_bytecode(
        push(0) + push(0) + push(0) +
            push(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256) +
            OP_EXTCALL + ret_top(),
        4));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(eof_bytecode(
        push(0) + push(0) + push(0) +
            push(0x000000000000000000000001ffffffffffffffffffffffffffffffffffffffff_u256) +
            OP_EXTCALL + ret_top(),
        4));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(eof_bytecode(
        push(0) + push(0) + push(0) +
            push(0x800000000000000000000000ffffffffffffffffffffffffffffffffffffffff_u256) +
            OP_EXTCALL + ret_top(),
        4));
    EXPECT_STATUS(EVMC_FAILURE);

    execute(eof_bytecode(
        push(0) + push(0) + push(0) +
            push(0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff_u256) +
            OP_EXTCALL + ret_top(),
        4));
    EXPECT_STATUS(EVMC_SUCCESS);

    execute(eof_bytecode(push(0) + push(0) + push(0) +
                             push(0xffffffffffffffffffffffffffffffffffffffff_address) + OP_EXTCALL +
                             ret_top(),
        4));
    EXPECT_STATUS(EVMC_SUCCESS);
}
