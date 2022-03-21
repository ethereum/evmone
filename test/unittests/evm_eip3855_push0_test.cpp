// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-3855 "PUSH0 instruction"
/// https://eips.ethereum.org/EIPS/eip-3855

#include "evm_fixture.hpp"

using namespace evmc::literals;
using evmone::test::evm;

TEST_P(evm, push0_pre_shanghai)
{
    rev = EVMC_PARIS;
    const auto code = bytecode{OP_PUSH0};

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, push0)
{
    rev = EVMC_SHANGHAI;
    execute(OP_PUSH0 + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 17);
    EXPECT_OUTPUT_INT(0);
}

TEST_P(evm, push0_return_empty)
{
    rev = EVMC_SHANGHAI;
    execute(bytecode{} + OP_PUSH0 + OP_PUSH0 + OP_RETURN);
    EXPECT_GAS_USED(EVMC_SUCCESS, 4);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, push0_full_stack)
{
    rev = EVMC_SHANGHAI;
    execute(1024 * bytecode{OP_PUSH0});
    EXPECT_GAS_USED(EVMC_SUCCESS, 1024 * 2);
}

TEST_P(evm, push0_stack_overflow)
{
    rev = EVMC_SHANGHAI;
    execute(1025 * bytecode{OP_PUSH0});
    EXPECT_STATUS(EVMC_STACK_OVERFLOW);
}
