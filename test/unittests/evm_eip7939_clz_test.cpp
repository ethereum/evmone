// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-7939 "Count leading zeros (CLZ) opcode"
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

TEST_P(evm, clz_gas)
{
    rev = EVMC_OSAKA;
    execute(bytecode{} + OP_PUSH0 + OP_CLZ);
    EXPECT_GAS_USED(EVMC_SUCCESS, 2 + 5);
}

TEST_P(evm, clz_osaka)
{
    rev = EVMC_OSAKA;
    const std::vector<std::pair<bytecode, intx::uint256>> cases{
        {0, 256},
        {1, 255},
        {0x8000000000000000000000000000000000000000000000000000000000000000_bytes32, 0},
        {0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32, 0},
        {0x4000000000000000000000000000000000000000000000000000000000000000_bytes32, 1},
        {0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32, 1},
        {0x0000000000000000000000000000000100000000000000000000000000000000_bytes32, 127},
        {0x0000000000000000000000000000000000000000000000010000000000000000_bytes32, 191},
        {0x0000000000000000000000000000000000000000000000008000000000000000_bytes32, 192},
    };
    for (const auto& [input, expected_output] : cases)
    {
        execute(clz(input) + ret_top());
        EXPECT_GAS_USED(EVMC_SUCCESS, 23);
        EXPECT_OUTPUT_INT(expected_output);
    }
}

TEST_P(evm, clz_stack_underflow)
{
    rev = EVMC_OSAKA;
    execute(OP_CLZ);
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);
}
