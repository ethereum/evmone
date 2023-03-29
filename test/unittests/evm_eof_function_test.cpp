// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using evmone::test::evm;

TEST_P(evm, eof_function_example1)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code =
        "EF00 01 010008 020002 000f 0002 030000 00"
        "00000002 02010002"
        "6001 6008 b00001 " +
        ret_top() + "03b1";

    ASSERT_EQ((int)evmone::validate_eof(rev, code), (int)evmone::EOFValidationError{});

    execute(code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 32);
    EXPECT_OUTPUT_INT(7);
}

TEST_P(evm, eof_function_example2)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code =
        "ef0001 01000c 020003 003b 0017 001d 030000 00 00000004 01010003 01010004"
        "60043560003560e01c63c766526781145d001c63c6c2ea1781145d00065050600080fd50b00002600052602060"
        "00f350b0000160005260206000f3"
        "600181115d0004506001b160018103b0000181029050b1"
        "600281115d0004506001b160028103b0000260018203b00002019050b1"_hex;

    ASSERT_EQ((int)evmone::validate_eof(rev, code), (int)evmone::EOFValidationError{});

    // Call fac(5)
    const auto calldata_fac =
        "c76652670000000000000000000000000000000000000000000000000000000000000005"_hex;
    execute(bytecode{code}, calldata_fac);
    EXPECT_GAS_USED(EVMC_SUCCESS, 246);
    EXPECT_EQ(output, "0000000000000000000000000000000000000000000000000000000000000078"_hex);

    // Call fib(15)
    const auto calldata_fib =
        "c6c2ea17000000000000000000000000000000000000000000000000000000000000000f"_hex;
    execute(bytecode{code}, calldata_fib);
    EXPECT_GAS_USED(EVMC_SUCCESS, 44544);
    EXPECT_EQ(output, "0000000000000000000000000000000000000000000000000000000000000262"_hex);
}

TEST_P(evm, callf_stack_size_1024)
{
    // CALLF is not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code = bytecode{"ef0001 010008 020002 0BFF 0004 030000 00 000003FF 00000001"_hex} +
                      1023 * push(1) + OP_CALLF + bytecode{"0x0001"_hex} + 1021 * OP_POP +
                      OP_RETURN + push(1) + OP_POP + OP_RETF;

    ASSERT_EQ(evmone::validate_eof(rev, code), evmone::EOFValidationError::success);
    execute(bytecode{code});
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, callf_stack_overflow)
{
    // CALLF is not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code =
        bytecode{"ef0001 010008 020002 0BFF 0007 030000 00 000003FF 00000002"_hex} +  // EOF header
        1023 * push(1) + OP_CALLF + bytecode{"0x0001"_hex} + 1021 * OP_POP + OP_RETURN +
        2 * push(1) + 2 * OP_POP + OP_RETF;

    ASSERT_EQ(evmone::validate_eof(rev, code), evmone::EOFValidationError::success);
    execute(bytecode{code});
    EXPECT_STATUS(EVMC_STACK_OVERFLOW);
}

TEST_P(evm, callf_call_stack_size_1024)
{
    // CALLF is not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code = bytecode{"ef0001 010008 020002 0007 000e 030000 00 00000001 01000002"_hex} +
                      push(1023) + OP_CALLF + bytecode{"0x0001"_hex} + OP_STOP + OP_DUP1 +
                      OP_RJUMPI + bytecode{"0x0002"_hex} + OP_POP + OP_RETF + push(1) + OP_SWAP1 +
                      OP_SUB + OP_CALLF + bytecode{"0x0001"_hex} + OP_RETF;

    ASSERT_EQ(evmone::validate_eof(rev, code), evmone::EOFValidationError::success);
    execute(bytecode{code});
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, callf_call_stack_size_1025)
{
    // CALLF is not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    const auto code = bytecode{"ef0001 010008 020002 0007 000e 030000 00 00000001 01000002"_hex} +
                      push(1024) + OP_CALLF + bytecode{"0x0001"_hex} + OP_STOP + OP_DUP1 +
                      OP_RJUMPI + bytecode{"0x0002"_hex} + OP_POP + OP_RETF + push(1) + OP_SWAP1 +
                      OP_SUB + OP_CALLF + bytecode{"0x0001"_hex} + OP_RETF;

    ASSERT_EQ(evmone::validate_eof(rev, code), evmone::EOFValidationError::success);
    execute(bytecode{code});
    EXPECT_STATUS(EVMC_STACK_OVERFLOW);
}
