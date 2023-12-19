// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

using namespace evmone;

namespace
{
// Can be called as validate_eof(string_view hex, rev) or validate_eof(bytes_view cont, rev).
inline EOFValidationError validate_eof(
    const bytecode& container, evmc_revision rev = EVMC_PRAGUE) noexcept
{
    return evmone::validate_eof(rev, container);
}
}  // namespace

TEST(eof_stack_validation, non_constant_stack_height)
{
    // Final "OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights: 0, 2 or 1
    auto code = eof_bytecode(rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 + rjumpi(1, OP_PUSH0) +
                                 OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
        4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // Final "OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights: 1, 3 or 2
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 +
                            rjumpi(1, OP_PUSH0) + OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
        5);

    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // Final "OP_POP + OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights:
    // 0, 2 or 1. Stack underflow when height is 0.
    code = eof_bytecode(rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 + rjumpi(1, OP_PUSH0) + OP_POP +
                            OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
        4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);
}

TEST(eof_stack_validation, backwards_rjump)
{
    auto code = eof_bytecode(rjump(-3));
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    code = eof_bytecode(bytecode{OP_PUSH0} + OP_POP + rjump(-5), 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump backwards from different locations to the same target
    code = eof_bytecode(bytecode{OP_PUSH0} + OP_POP + rjumpi(3, 1) + rjump(-8) + rjump(-11), 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump backwards from different locations to the same target - stack height mismatch
    code = eof_bytecode(
        bytecode{OP_PUSH0} + OP_POP + rjumpi(3, 1) + rjump(-8) + OP_PUSH0 + rjump(-12), 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // infinite pushing loop
    code = eof_bytecode(bytecode{OP_PUSH0} + rjump(-4), 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // infinite popping loop
    code = eof_bytecode(bytecode{OP_PUSH0} + OP_POP + rjump(-4), 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
}

TEST(eof_stack_validation, backwards_rjump_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = bytecode{OP_PUSH0} + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    auto code = eof_bytecode(prolog + rjump(-3), 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    code = eof_bytecode(prolog + OP_PUSH0 + OP_POP + rjump(-5), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump backwards from different locations to the same target
    code = eof_bytecode(prolog + OP_PUSH0 + OP_POP + rjumpi(3, 1) + rjump(-8) + rjump(-11), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump backwards from different locations to the same target - stack height mismatch
    // 1st rjump: stack [1, 3]
    // 2nd rjump: stack [2, 4]
    // Jumping to [1, 3]
    code = eof_bytecode(
        prolog + OP_PUSH0 + OP_POP + rjumpi(3, 1) + rjump(-8) + OP_PUSH0 + rjump(-12), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // rjump backwards - max stack height mismatch
    // rjumpi: stack [1, 3]
    // push0:  stack [2, 4]
    // rjump:  stack [1, 4]
    // Jumping from [1, 4] to [1, 3]
    code = eof_bytecode(prolog + rjumpi(1, 0) + OP_PUSH0 + rjump(-7), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // rjump backwards - min stack height mismatch
    // rjumpi: stack [1, 3]
    // pop  :  stack [0, 2]
    // rjump:  stack [0, 3]
    // Jumping from [0, 3] to [1, 3]
    code = eof_bytecode(prolog + rjumpi(1, 0) + OP_POP + rjump(-7), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // infinite pushing loop
    code = eof_bytecode(prolog + bytecode{OP_PUSH0} + rjump(-4), 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // infinite popping loop
    code = eof_bytecode(prolog + bytecode{OP_PUSH0} + OP_POP + rjump(-4), 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
}

TEST(eof_stack_validation, forwards_rjump)
{
    auto code = eof_bytecode(rjump(0) + OP_STOP);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(3, 0) + rjump(1) + OP_NOT + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - equal stack
    code = eof_bytecode(
        bytecode{OP_PUSH0} + rjumpi(8, 0) + rjumpi(6, 0) + rjump(4) + rjump(1) + OP_NOT + OP_STOP,
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - different stack
    // rjump: [1, 1]
    // push0: [2, 2]
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(3, 0) + rjump(1) + OP_PUSH0 + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(8, 0) +  // [1, 1]
                            rjumpi(7, 0) +                   // [1, 1]
                            rjump(5) +                       // [1, 1]
                            OP_PUSH0 +                       // [2, 2]
                            rjump(1) +                       // [2, 2]
                            OP_NOT +                         // [1, 1]
                            OP_STOP,                         // [1, 2]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_stack_validation, forwards_rjump_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = bytecode{OP_PUSH0} + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    auto code = eof_bytecode(prolog + rjump(0) + OP_STOP, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 + rjumpi(3, 0) + rjump(1) + OP_NOT + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - equal stack
    code = eof_bytecode(
        prolog + OP_PUSH0 + rjumpi(8, 0) + rjumpi(6, 0) + rjump(4) + rjump(1) + OP_NOT + OP_STOP,
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - different stack
    code = eof_bytecode(prolog +            // [1, 3]
                            OP_PUSH0 +      // [2, 4]
                            rjumpi(3, 0) +  // [2, 4]
                            rjump(1) +      // [2, 4]
                            OP_PUSH0 +      // [3, 5]
                            OP_STOP,        // [2, 5]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - different stack
    code = eof_bytecode(prolog + rjumpi(8, 0) +  // [1, 3]
                            rjumpi(7, 0) +       // [1, 3]
                            rjump(5) +           // [1, 3]
                            OP_PUSH0 +           // [2, 4]
                            rjump(1) +           // [2, 4]
                            OP_NOT +             // [1, 3]
                            OP_STOP,             // [1, 4]
        4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_stack_validation, backwards_rjumpi)
{
    auto code = eof_bytecode(rjumpi(-5, 0) + OP_STOP, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    code = eof_bytecode(bytecode{OP_PUSH0} + OP_POP + rjumpi(-7, 0) + OP_STOP, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjumpi backwards from different locations to the same target
    code = eof_bytecode(bytecode{OP_PUSH0} + OP_POP + rjumpi(-7, 0) + rjumpi(-12, 0) + OP_STOP, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjumpi backwards from different locations to the same target - stack height mismatch
    code = eof_bytecode(
        bytecode{OP_PUSH0} + OP_POP + rjumpi(-7, 0) + OP_PUSH0 + rjumpi(-13, 0) + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // valid loop
    code = eof_bytecode(bytecode{OP_PUSH0} + push(1) + OP_ADD + rjumpi(-7, OP_DUP1) + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // pushing loop
    code = eof_bytecode(
        bytecode{OP_PUSH0} + push(1) + OP_ADD + OP_DUP1 + rjumpi(-8, OP_DUP1) + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // popping loop
    code = eof_bytecode(bytecode{OP_PUSH0} + OP_PUSH0 + OP_PUSH0 + rjumpi(-4, OP_POP) + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // rjump and rjumpi with the same target - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            OP_POP +          // [0, 0]
                            rjumpi(-1, 0) +   // [1, 1]
                            rjump(-6),        // [1, 1]
        1);

    // rjump and rjumpi with the same target - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            OP_POP +          // [0, 0]
                            rjumpi(-1, 0) +   // [0, 0]
                            OP_PUSH0 +        // [1, 1]
                            rjump(-6),        // [1, 1]
        1);
}

TEST(eof_stack_validation, backwards_rjumpi_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = bytecode{OP_PUSH0} + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    auto code = eof_bytecode(prolog + rjumpi(-5, 0) + OP_STOP, 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    code = eof_bytecode(prolog + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + OP_STOP, 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjumpi backwards from different locations to the same target
    code = eof_bytecode(prolog + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + rjumpi(-12, 0) + OP_STOP, 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjumpi backwards from different locations to the same target - stack height mismatch
    code = eof_bytecode(
        prolog + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + OP_PUSH0 + rjumpi(-13, 0) + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // valid loop
    code = eof_bytecode(prolog + OP_PUSH0 + push(1) + OP_ADD + rjumpi(-7, OP_DUP1) + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // pushing loop
    code = eof_bytecode(
        prolog + OP_PUSH0 + push(1) + OP_ADD + OP_DUP1 + rjumpi(-8, OP_DUP1) + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // popping loop
    code = eof_bytecode(prolog + OP_PUSH0 + OP_PUSH0 + OP_PUSH0 + rjumpi(-4, OP_POP) + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);

    // rjump and rjumpi with the same target - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [1, 1]
                            OP_POP +         // [0, 0]
                            rjumpi(-1, 0) +  // [1, 1]
                            rjump(-6),       // [1, 1]
        4);

    // rjump and rjumpi with the same target - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [1, 1]
                            OP_POP +         // [0, 0]
                            rjumpi(-1, 0) +  // [0, 0]
                            OP_PUSH0 +       // [1, 1]
                            rjump(-6),       // [1, 1]
        4);
}

TEST(eof_stack_validation, forwards_rjumpi)
{
    auto code = eof_bytecode(rjumpi(0, 1) + OP_STOP, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(1, 0) + OP_NOT + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(6, 0) + rjumpi(1, 0) + OP_NOT + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + fallthrough - different stack
    // rjumpi: [1, 1]
    // push0: [2, 2]
    code = eof_bytecode(bytecode{OP_PUSH0} + rjumpi(1, 0) + OP_PUSH0 + OP_STOP, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(7, 0) +    // [1, 1]
                            OP_PUSH0 +        // [2, 2]
                            rjumpi(1, 0) +    // [2, 2]
                            OP_NOT +          // [2, 2]
                            OP_STOP,          // [1, 2]
        3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // valid loop with a break
    code = eof_bytecode(bytecode{OP_PUSH0} +        // [1, 1]
                            push(1) +               // [2, 2]
                            OP_ADD +                // [1, 1]
                            OP_DUP1 +               // [2, 2]
                            push(10) +              // [3, 3]
                            rjumpi(4, OP_GT) +      // [1, 1]
                            rjumpi(-14, OP_DUP1) +  // [1, 1]
                            OP_STOP,                // [1, 1]
        3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // valid loop with a break - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +        // [1, 1]
                            push(1) +               // [2, 2]
                            OP_ADD +                // [1, 1]
                            OP_DUP1 +               // [2, 2]
                            push(10) +              // [3, 3]
                            rjumpi(5, OP_GT) +      // [1, 1]
                            OP_PUSH0 +              // [2, 2]
                            rjumpi(-13, OP_DUP1) +  // [2, 2]
                            OP_STOP,                // [1, 2]
        3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with push - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(4, 0) +    // [1, 1]
                            OP_PUSH0 +        // [2, 2]
                            rjump(1) +        // [2, 2]
                            OP_PUSH0 +        // [2, 2]
                            OP_STOP,          // [2, 2]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with push - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(4, 0) +    // [1, 1]
                            OP_PUSH0 +        // [2, 2]
                            rjump(1) +        // [2, 2]
                            OP_NOT +          // [1, 1]
                            OP_STOP,          // [1, 2]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with pop - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(4, 0) +    // [1, 1]
                            OP_POP +          // [0, 0]
                            rjump(1) +        // [0, 0]
                            OP_POP +          // [0, 0]
                            OP_STOP,          // [0, 0]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with pop - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(4, 0) +    // [1, 1]
                            OP_POP +          // [0, 0]
                            rjump(1) +        // [0, 0]
                            OP_NOT +          // [1, 1]
                            OP_STOP,          // [0, 1]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump and rjumpi with the same target - equal stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(3, 0) +    // [1, 1]
                            rjump(0) +        // [1, 1]
                            OP_STOP,          // [1, 1]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    code = eof_bytecode(bytecode{OP_PUSH0} +  // [1, 1]
                            rjumpi(4, 0) +    // [1, 1]
                            OP_PUSH0 +        // [2, 2]
                            rjump(0) +        // [2, 2]
                            OP_STOP,          // [1, 2]
        2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_stack_validation, forwards_rjumpi_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = bytecode{OP_PUSH0} + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    auto code = eof_bytecode(prolog + rjumpi(0, 1) + OP_STOP, 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 + rjumpi(1, 0) + OP_NOT + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 + rjumpi(6, 0) + rjumpi(1, 0) + OP_NOT + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + fallthrough - different stack
    // rjumpi: [4, 4]
    // push0: [5, 5]
    code = eof_bytecode(prolog + OP_PUSH0 + rjumpi(1, 0) + OP_PUSH0 + OP_STOP, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(7, 0) +   // [2, 4]
                            OP_PUSH0 +       // [3, 5]
                            rjumpi(1, 0) +   // [3, 5]
                            OP_NOT +         // [3, 5]
                            OP_STOP,         // [2, 5]
        6);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // valid loop with a break
    code = eof_bytecode(prolog + OP_PUSH0 +         // [2, 4]
                            push(1) +               // [3, 5]
                            OP_ADD +                // [2, 4]
                            OP_DUP1 +               // [3, 5]
                            push(10) +              // [4, 6]
                            rjumpi(4, OP_GT) +      // [2, 4]
                            rjumpi(-14, OP_DUP1) +  // [2, 4]
                            OP_STOP,                // [2, 4]
        6);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // valid loop with a break - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +         // [2, 4]
                            push(1) +               // [3, 5]
                            OP_ADD +                // [2, 4]
                            OP_DUP1 +               // [3, 5]
                            push(10) +              // [4, 6]
                            rjumpi(5, OP_GT) +      // [2, 4]
                            OP_PUSH0 +              // [3, 5]
                            rjumpi(-13, OP_DUP1) +  // [3, 5]
                            OP_STOP,                // [2, 5]
        6);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with push - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(4, 0) +   // [2, 4]
                            OP_PUSH0 +       // [3, 5]
                            rjump(1) +       // [3, 5]
                            OP_PUSH0 +       // [3, 5]
                            OP_STOP,         // [3, 5]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with push - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(4, 0) +   // [2, 4]
                            OP_PUSH0 +       // [3, 5]
                            rjump(1) +       // [3, 5]
                            OP_NOT +         // [2, 4]
                            OP_STOP,         // [2, 5]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with pop - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(4, 0) +   // [2, 4]
                            OP_POP +         // [1, 3]
                            rjump(1) +       // [1, 3]
                            OP_POP +         // [1, 3]
                            OP_STOP,         // [1, 3]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // if-then-else with pop - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(4, 0) +   // [2, 4]
                            OP_POP +         // [1, 3]
                            rjump(1) +       // [1, 3]
                            OP_NOT +         // [2, 4]
                            OP_STOP,         // [1, 4]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump and rjumpi with the same target - equal stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(3, 0) +   // [2, 4]
                            rjump(0) +       // [2, 4]
                            OP_STOP,         // [2, 4]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    code = eof_bytecode(prolog + OP_PUSH0 +  // [2, 4]
                            rjumpi(4, 0) +   // [2, 4]
                            OP_PUSH0 +       // [3, 5]
                            rjump(0) +       // [3, 5]
                            OP_STOP,         // [2, 5]
        5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_stack_validation, underflow)
{
    auto code = eof_bytecode(bytecode{OP_ADD} + OP_STOP, 0);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // CALLF underflow
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1).code(push0() + OP_RETF, 1, 2, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to returning function
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
               .code(bytecode{OP_JUMPF} + "0002", 0, 2, 0)
               .code(push0() + OP_RETF, 1, 2, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to non-returning function
    code = eof_bytecode(bytecode{OP_JUMPF} + "0001", 0).code(revert(0, 0), 1, 0x80, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // RETF underflow
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2).code(push0() + OP_RETF, 0, 2, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);
}

TEST(eof_stack_validation, underflow_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = push0() + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    // LOG2 underflow - [1, 3] stack - neither min nor max enough for 4 inputs
    auto code = eof_bytecode(prolog + OP_LOG2 + OP_STOP, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // ADD underflow - [1, 3] stack - only max enough for 5 inputs
    code = eof_bytecode(prolog + OP_ADD + OP_STOP, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // CALLF underflow - [1, 3] stack - neither min nor max enough for 5 inputs
    code = eof_bytecode(prolog + OP_CALLF + "0001" + OP_STOP, 4).code(push0() + OP_RETF, 4, 5, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // CALLF underflow - [1, 3] stack - only max enough for 3 inputs
    code = eof_bytecode(prolog + OP_CALLF + "0001" + OP_STOP, 4).code(push0() + OP_RETF, 3, 4, 4);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to returning function - neither min nor max enough for 5 inputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
               .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
               .code(bytecode{OP_POP} + OP_POP + OP_RETF, 5, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to returning function - only max enough for 3 inputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
               .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
               .code(bytecode{OP_RETF}, 3, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to non-returning function - [1, 3] stack - neither min nor max enough for 5 inputs
    code = eof_bytecode(prolog + OP_JUMPF + "0001", 0).code(revert(0, 0), 5, 0x80, 7);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF to non-returning function - [1, 3] stack - only max enough for 3 inputs
    code = eof_bytecode(prolog + OP_JUMPF + "0001", 0).code(revert(0, 0), 3, 0x80, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack - neither min nor max enough for 5 outputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 5).code(prolog + OP_RETF, 0, 5, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack - only max enough for 3 outputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3).code(prolog + OP_RETF, 0, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);
}

TEST(eof_stack_validation, retf_variable_stack)
{
    // RETF in variable stack segment is not allowed and always fails with one of two errors

    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = push0() + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    // RETF from [1, 3] stack returning 5 outputs
    auto code =
        eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 5).code(prolog + OP_RETF, 0, 5, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack returning 3 outputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3).code(prolog + OP_RETF, 0, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack returning 1 output
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1).code(prolog + OP_RETF, 0, 1, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_higher_than_outputs_required);

    // RETF from [1, 3] returning 0 outputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 0).code(prolog + OP_RETF, 0, 0, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_higher_than_outputs_required);
}

TEST(eof_stack_validation, jumpf_to_returning_variable_stack)
{
    // JUMPF to returning function in variable stack segment is not allowed and always fails with
    // one of two errors

    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = push0() + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    // JUMPF from [1, 3] stack to function with 5 inputs
    auto code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
                    .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
                    .code(push0() + OP_RETF, 5, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 3 inputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
               .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
               .code(bytecode{OP_RETF}, 3, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 1 inputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
               .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
               .code(push0() + push0() + OP_RETF, 1, 3, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_higher_than_outputs_required);

    // JUMPF from [1, 3] stack to function with 0 inputs
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 3)
               .code(prolog + OP_JUMPF + "0002", 0, 3, 3)
               .code(push0() + push0() + push0() + OP_RETF, 0, 3, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_higher_than_outputs_required);
}

TEST(eof_stack_validation, jumpf_to_nonreturning_variable_stack)
{
    // code prologue that creates a segment starting with possible stack heights 1 and 3
    const auto prolog = push0() + rjumpi(2, 0) + OP_PUSH0 + OP_PUSH0;

    // JUMPF from [1, 3] stack to non-returning function with 5 inputs
    auto code = eof_bytecode(prolog + OP_JUMPF + "0001", 3).code(Opcode{OP_INVALID}, 5, 0x80, 5);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to non-returning function with 3 inputs
    code = eof_bytecode(prolog + OP_JUMPF + "0001", 3).code(Opcode{OP_INVALID}, 3, 0x80, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // Extra items on stack are allowed for JUMPF to non-returning

    // JUMPF from [1, 3] stack to non-returning function with 1 inputs
    code = eof_bytecode(prolog + OP_JUMPF + "0001", 3).code(Opcode{OP_INVALID}, 1, 0x80, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // JUMPF from [1, 3] stack to non-returning function with 0 inputs
    code = eof_bytecode(prolog + OP_JUMPF + "0001", 3).code(Opcode{OP_INVALID}, 0, 0x80, 0);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}
