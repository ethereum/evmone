// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-7939 "CLZ instruction"
/// https://eips.ethereum.org/EIPS/eip-7939

#include "evm_fixture.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_P(evm, clz_pre_osaka)
{
    rev = EVMC_PRAGUE;
    const auto code = bytecode{OP_CLZ};

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, clz_zero)
{
    rev = EVMC_OSAKA;
    execute(push(0) + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(256);
}

TEST_P(evm, clz_one)
{
    rev = EVMC_OSAKA;
    execute(push(1) + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(255);
}

TEST_P(evm, clz_msb_set)
{
    rev = EVMC_OSAKA;
    // Test with MSB set (0x8000...0000)
    execute(push("0x8000000000000000000000000000000000000000000000000000000000000000") + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(0);
}

TEST_P(evm, clz_second_msb_set)
{
    rev = EVMC_OSAKA;
    // Test with second MSB set (0x4000...0000)
    execute(push("0x4000000000000000000000000000000000000000000000000000000000000000") + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(1);
}

TEST_P(evm, clz_bit_128_set)
{
    rev = EVMC_OSAKA;
    // Test with bit 128 set (0x0000...0001 followed by 16 zeros)
    execute(push("0x0000000000000000000000000000000100000000000000000000000000000000") + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(127);
}

TEST_P(evm, clz_bit_64_set)
{
    rev = EVMC_OSAKA;
    // Test with bit 64 set (0x0000...0000 followed by 0x10000...0000)
    execute(push("0x0000000000000000000000000000000000000000000000010000000000000000") + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(191);
}

TEST_P(evm, clz_bit_63_set)
{
    rev = EVMC_OSAKA;
    // Test with bit 63 set (0x0000...0000 followed by 0x8000...0000)
    execute(push("0x0000000000000000000000000000000000000000000000008000000000000000") + OP_CLZ + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 21);
    EXPECT_OUTPUT_INT(192);
}

TEST_P(evm, clz_stack_underflow)
{
    rev = EVMC_OSAKA;
    execute(OP_CLZ);
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);
}