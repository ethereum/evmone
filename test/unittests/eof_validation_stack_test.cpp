// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <evmone/eof.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

using namespace evmone;
using namespace evmone::test;

namespace
{
// code prologue that creates a segment starting with possible stack heights 1 and 3
const auto varstack = push0() + rjumpi(2, 0) + push0() + push0();
}  // namespace

TEST_F(eof_validation, unreachable_instructions)
{
    add_test_case(
        eof_bytecode(bytecode{OP_STOP} + OP_STOP), EOFValidationError::unreachable_instructions);

    add_test_case(
        eof_bytecode(rjump(1) + OP_STOP + OP_STOP), EOFValidationError::unreachable_instructions);

    // STOP reachable only via backwards jump - invalid
    add_test_case(
        eof_bytecode(rjump(1) + OP_STOP + rjump(-4)), EOFValidationError::unreachable_instructions);
}

TEST_F(eof_validation, no_terminating_instruction)
{
    add_test_case(eof_bytecode(push0()), EOFValidationError::no_terminating_instruction);

    add_test_case(eof_bytecode(add(1, 2)), EOFValidationError::no_terminating_instruction);

    add_test_case(eof_bytecode(rjumpi(-5, 1)), EOFValidationError::no_terminating_instruction);
}

TEST_F(eof_validation, non_constant_stack_height)
{
    // Final "OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights: 0, 2 or 1
    add_test_case(eof_bytecode(rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 + rjumpi(1, OP_PUSH0) +
                                   OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
                      4),
        EOFValidationError::success);

    // Final "OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights: 1, 3 or 2
    add_test_case(eof_bytecode(push0() + rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 +
                                   rjumpi(1, OP_PUSH0) + OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
                      5),
        EOFValidationError::success);

    // Final "OP_POP + OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT" can be reached with stack heights:
    // 0, 2 or 1. Stack underflow when height is 0.
    add_test_case(eof_bytecode(rjumpi(7, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 + rjumpi(1, OP_PUSH0) +
                                   OP_POP + OP_POP + OP_PUSH0 + OP_PUSH0 + OP_REVERT,
                      4),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, stack_range_maximally_broad)
{
    // Construct series of RJUMPIs all targeting final STOP.
    // Stack range at STOP is [0, 1023]
    bytecode code = OP_STOP;
    int16_t offset = 1;
    for (auto i = 0; i < 1023; ++i)
    {
        code = rjumpi(offset, OP_PUSH0) + OP_PUSH0 + code;
        offset += 5;
    }

    add_test_case(eof_bytecode(code, 1023), EOFValidationError::success, "valid_1023_rjumpis");

    code = rjumpi(offset, OP_PUSH0) + OP_PUSH0 + code;
    add_test_case(eof_bytecode(code, 1023), EOFValidationError::invalid_max_stack_height,
        "invalid_1024_rjumpis");
}

TEST_F(eof_validation, backwards_rjump)
{
    add_test_case(eof_bytecode(rjump(-3)), EOFValidationError::success);

    add_test_case(eof_bytecode(push0() + OP_POP + rjump(-5), 1), EOFValidationError::success);

    // rjump backwards from different locations to the same target
    add_test_case(eof_bytecode(push0() + OP_POP + rjumpi(3, 1) + rjump(-8) + rjump(-11), 1),
        EOFValidationError::success);

    // rjump backwards from different locations to the same target - stack height mismatch
    add_test_case(
        eof_bytecode(push0() + OP_POP + rjumpi(3, 1) + rjump(-8) + OP_PUSH0 + rjump(-12), 1),
        EOFValidationError::stack_height_mismatch);

    // infinite pushing loop
    add_test_case(eof_bytecode(push0() + rjump(-4), 1), EOFValidationError::stack_height_mismatch);

    // infinite popping loop
    add_test_case(
        eof_bytecode(push0() + OP_POP + rjump(-4), 1), EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, backwards_rjump_variable_stack)
{
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + OP_POP + rjump(-5), 4), EOFValidationError::success);

    // rjump backwards from different locations to the same target
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + OP_POP + rjumpi(3, 1) + rjump(-8) + rjump(-11), 4),
        EOFValidationError::success);

    // rjump backwards from different locations to the same target - stack height mismatch
    // 1st rjump: stack [1, 3]
    // 2nd rjump: stack [2, 4]
    // Jumping to [1, 3]
    add_test_case(
        eof_bytecode(
            varstack + OP_PUSH0 + OP_POP + rjumpi(3, 1) + rjump(-8) + OP_PUSH0 + rjump(-12), 4),
        EOFValidationError::stack_height_mismatch);

    // rjump backwards - max stack height mismatch
    // rjumpi: stack [1, 3]
    // push0:  stack [2, 4]
    // rjump:  stack [1, 4]
    // Jumping from [1, 4] to [1, 3]
    add_test_case(eof_bytecode(varstack + rjumpi(1, 0) + OP_PUSH0 + rjump(-7), 4),
        EOFValidationError::stack_height_mismatch);

    // rjump backwards - min stack height mismatch
    // rjumpi: stack [1, 3]
    // pop  :  stack [0, 2]
    // rjump:  stack [0, 3]
    // Jumping from [0, 3] to [1, 3]
    add_test_case(eof_bytecode(varstack + rjumpi(1, 0) + OP_POP + rjump(-7), 4),
        EOFValidationError::stack_height_mismatch);

    // infinite pushing loop
    add_test_case(
        eof_bytecode(varstack + push0() + rjump(-4), 4), EOFValidationError::stack_height_mismatch);

    // infinite popping loop
    add_test_case(eof_bytecode(varstack + push0() + OP_POP + rjump(-4), 3),
        EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, forwards_rjump)
{
    // forwards rjump + fallthrough - equal stack
    add_test_case(eof_bytecode(push0() + rjumpi(3, 0) + rjump(1) + OP_NOT + OP_STOP, 2),
        EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - equal stack
    add_test_case(
        eof_bytecode(
            push0() + rjumpi(8, 0) + rjumpi(6, 0) + rjump(4) + rjump(1) + OP_NOT + OP_STOP, 2),
        EOFValidationError::success);

    // forwards rjump + fallthrough - different stack
    // rjump: [1, 1]
    // push0: [2, 2]
    add_test_case(eof_bytecode(push0() + rjumpi(3, 0) + rjump(1) + OP_PUSH0 + OP_STOP, 2),
        EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - different stack
    add_test_case(eof_bytecode(push0() + rjumpi(8, 0) +  // [1, 1]
                                   rjumpi(7, 0) +        // [1, 1]
                                   rjump(5) +            // [1, 1]
                                   OP_PUSH0 +            // [2, 2]
                                   rjump(1) +            // [2, 2]
                                   OP_NOT +              // [1, 1]
                                   OP_STOP,              // [1, 2]
                      2),
        EOFValidationError::success);
}

TEST_F(eof_validation, forwards_rjump_variable_stack)
{
    add_test_case(eof_bytecode(varstack + rjump(0) + OP_STOP, 3), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 + rjumpi(3, 0) + rjump(1) + OP_NOT + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 + rjumpi(8, 0) + rjumpi(6, 0) + rjump(4) +
                                   rjump(1) + OP_NOT + OP_STOP,
                      5),
        EOFValidationError::success);

    // forwards rjump + fallthrough - different stack
    add_test_case(eof_bytecode(varstack +          // [1, 3]
                                   OP_PUSH0 +      // [2, 4]
                                   rjumpi(3, 0) +  // [2, 4]
                                   rjump(1) +      // [2, 4]
                                   OP_PUSH0 +      // [3, 5]
                                   OP_STOP,        // [2, 5]
                      5),
        EOFValidationError::success);

    // forwards rjump + forwards rjump + fallthrough - different stack
    add_test_case(eof_bytecode(varstack + rjumpi(8, 0) +  // [1, 3]
                                   rjumpi(7, 0) +         // [1, 3]
                                   rjump(5) +             // [1, 3]
                                   OP_PUSH0 +             // [2, 4]
                                   rjump(1) +             // [2, 4]
                                   OP_NOT +               // [1, 3]
                                   OP_STOP,               // [1, 4]
                      4),
        EOFValidationError::success);
}

TEST_F(eof_validation, backwards_rjumpi)
{
    add_test_case(
        eof_bytecode(push0() + OP_POP + rjumpi(-7, 0) + OP_STOP, 1), EOFValidationError::success);

    // rjumpi backwards from different locations to the same target
    add_test_case(eof_bytecode(push0() + OP_POP + rjumpi(-7, 0) + rjumpi(-12, 0) + OP_STOP, 1),
        EOFValidationError::success);

    // rjumpi backwards from different locations to the same target - stack height mismatch
    add_test_case(
        eof_bytecode(push0() + OP_POP + rjumpi(-7, 0) + OP_PUSH0 + rjumpi(-13, 0) + OP_STOP, 2),
        EOFValidationError::stack_height_mismatch);

    // valid loop
    add_test_case(eof_bytecode(push0() + push(1) + OP_ADD + rjumpi(-7, OP_DUP1) + OP_STOP, 2),
        EOFValidationError::success);

    // pushing loop
    add_test_case(
        eof_bytecode(push0() + push(1) + OP_ADD + OP_DUP1 + rjumpi(-8, OP_DUP1) + OP_STOP, 2),
        EOFValidationError::stack_height_mismatch);

    // popping loop
    add_test_case(eof_bytecode(push0() + OP_PUSH0 + OP_PUSH0 + rjumpi(-4, OP_POP) + OP_STOP, 2),
        EOFValidationError::stack_height_mismatch);

    // rjump and rjumpi with the same target - equal stack
    add_test_case(eof_bytecode(push0() +            // [1, 1]
                                   OP_POP +         // [0, 0]
                                   rjumpi(-7, 0) +  // [1, 1]
                                   rjump(-10),      // [1, 1]
                      1),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    add_test_case(eof_bytecode(push0() +            // [1, 1]
                                   OP_POP +         // [0, 0]
                                   rjumpi(-7, 0) +  // [0, 0]
                                   OP_PUSH0 +       // [1, 1]
                                   rjump(-11),      // [1, 1]
                      1),
        EOFValidationError::stack_height_mismatch);

    // rjumpi backwards - only max stack height mismatch
    add_test_case(eof_bytecode(OP_PUSH0 +            // [1, 1]
                                   rjumpi(1, 0) +    // [1, 1]
                                   OP_PUSH0 +        // [2, 2]
                                   rjumpi(-11, 0) +  // [1, 2]
                                   OP_STOP,          // [1, 2]
                      3),
        EOFValidationError::stack_height_mismatch);

    // rjumpi backwards - only min stack height mismatch
    add_test_case(eof_bytecode(OP_PUSH0 + OP_PUSH0 +  // [2, 2]
                                   rjumpi(1, 0) +     // [2, 2]
                                   OP_POP +           // [1, 1]
                                   rjumpi(-11, 0) +   // [1, 2]
                                   OP_STOP,           // [1, 2]
                      3),
        EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, backwards_rjumpi_variable_stack)
{
    add_test_case(eof_bytecode(varstack + rjumpi(-5, 0) + OP_STOP, 4), EOFValidationError::success);

    add_test_case(eof_bytecode(varstack + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + OP_STOP, 4),
        EOFValidationError::success);

    // rjumpi backwards from different locations to the same target
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + rjumpi(-12, 0) + OP_STOP, 4),
        EOFValidationError::success);

    // rjumpi backwards from different locations to the same target - stack height mismatch
    add_test_case(
        eof_bytecode(
            varstack + OP_PUSH0 + OP_POP + rjumpi(-7, 0) + OP_PUSH0 + rjumpi(-13, 0) + OP_STOP, 5),
        EOFValidationError::stack_height_mismatch);

    // valid loop
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + push(1) + OP_ADD + rjumpi(-7, OP_DUP1) + OP_STOP, 5),
        EOFValidationError::success);

    // pushing loop
    add_test_case(
        eof_bytecode(
            varstack + OP_PUSH0 + push(1) + OP_ADD + OP_DUP1 + rjumpi(-8, OP_DUP1) + OP_STOP, 5),
        EOFValidationError::stack_height_mismatch);

    // popping loop
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + OP_PUSH0 + OP_PUSH0 + rjumpi(-4, OP_POP) + OP_STOP, 5),
        EOFValidationError::stack_height_mismatch);

    // rjump and rjumpi with the same target - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjumpi(-7, 0) +    // [1, 3]
                                   rjump(-10),        // [1, 3]
                      4),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjumpi(-7, 0) +    // [1, 3]
                                   OP_PUSH0 +         // [2, 4]
                                   rjump(-11),        // [2, 4]
                      4),
        EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, forwards_rjumpi)
{
    add_test_case(eof_bytecode(rjumpi(0, 1) + OP_STOP, 1), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    add_test_case(
        eof_bytecode(push0() + rjumpi(1, 0) + OP_NOT + OP_STOP, 2), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - equal stack
    add_test_case(eof_bytecode(push0() + rjumpi(6, 0) + rjumpi(1, 0) + OP_NOT + OP_STOP, 2),
        EOFValidationError::success);

    // forwards rjumpi + fallthrough - different stack
    // rjumpi: [1, 1]
    // push0: [2, 2]
    add_test_case(
        eof_bytecode(push0() + rjumpi(1, 0) + OP_PUSH0 + OP_STOP, 2), EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - different stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(7, 0) +  // [1, 1]
                                   OP_PUSH0 +      // [2, 2]
                                   rjumpi(1, 0) +  // [2, 2]
                                   OP_NOT +        // [2, 2]
                                   OP_STOP,        // [1, 2]
                      3),
        EOFValidationError::success);

    // valid loop with a break
    add_test_case(eof_bytecode(push0() +                   // [1, 1]
                                   push(1) +               // [2, 2]
                                   OP_ADD +                // [1, 1]
                                   OP_DUP1 +               // [2, 2]
                                   push(10) +              // [3, 3]
                                   rjumpi(4, OP_GT) +      // [1, 1]
                                   rjumpi(-14, OP_DUP1) +  // [1, 1]
                                   OP_STOP,                // [1, 1]
                      3),
        EOFValidationError::success);

    // valid loop with a break - different stack
    add_test_case(eof_bytecode(push0() +                   // [1, 1]
                                   push(1) +               // [2, 2]
                                   OP_ADD +                // [1, 1]
                                   OP_DUP1 +               // [2, 2]
                                   push(10) +              // [3, 3]
                                   rjumpi(5, OP_GT) +      // [1, 1]
                                   OP_PUSH0 +              // [2, 2]
                                   rjumpi(-13, OP_DUP1) +  // [2, 2]
                                   OP_STOP,                // [1, 2]
                      3),
        EOFValidationError::success);

    // if-then-else with push - equal stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(4, 0) +  // [1, 1]
                                   OP_PUSH0 +      // [2, 2]
                                   rjump(1) +      // [2, 2]
                                   OP_PUSH0 +      // [2, 2]
                                   OP_STOP,        // [2, 2]
                      2),
        EOFValidationError::success);

    // if-then-else with push - different stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(4, 0) +  // [1, 1]
                                   OP_PUSH0 +      // [2, 2]
                                   rjump(1) +      // [2, 2]
                                   OP_NOT +        // [1, 1]
                                   OP_STOP,        // [1, 2]
                      2),
        EOFValidationError::success);

    // if-then-else with pop - equal stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(4, 0) +  // [1, 1]
                                   OP_POP +        // [0, 0]
                                   rjump(1) +      // [0, 0]
                                   OP_POP +        // [0, 0]
                                   OP_STOP,        // [0, 0]
                      2),
        EOFValidationError::success);

    // if-then-else with pop - different stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(4, 0) +  // [1, 1]
                                   OP_POP +        // [0, 0]
                                   rjump(1) +      // [0, 0]
                                   OP_NOT +        // [1, 1]
                                   OP_STOP,        // [0, 1]
                      2),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - equal stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(3, 0) +  // [1, 1]
                                   rjump(0) +      // [1, 1]
                                   OP_STOP,        // [1, 1]
                      2),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    add_test_case(eof_bytecode(push0() +           // [1, 1]
                                   rjumpi(4, 0) +  // [1, 1]
                                   OP_PUSH0 +      // [2, 2]
                                   rjump(0) +      // [2, 2]
                                   OP_STOP,        // [1, 2]
                      2),
        EOFValidationError::success);
}

TEST_F(eof_validation, forwards_rjumpi_variable_stack)
{
    add_test_case(eof_bytecode(varstack + rjumpi(0, 1) + OP_STOP, 4), EOFValidationError::success);

    // forwards rjump + fallthrough - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 + rjumpi(1, 0) + OP_NOT + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - equal stack
    add_test_case(
        eof_bytecode(varstack + OP_PUSH0 + rjumpi(6, 0) + rjumpi(1, 0) + OP_NOT + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjumpi + fallthrough - different stack
    // rjumpi: [4, 4]
    // push0: [5, 5]
    add_test_case(eof_bytecode(varstack + OP_PUSH0 + rjumpi(1, 0) + OP_PUSH0 + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjumpi + forwards rjumpi + fallthrough - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(7, 0) +     // [2, 4]
                                   OP_PUSH0 +         // [3, 5]
                                   rjumpi(1, 0) +     // [3, 5]
                                   OP_NOT +           // [3, 5]
                                   OP_STOP,           // [2, 5]
                      6),
        EOFValidationError::success);

    // valid loop with a break
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +       // [2, 4]
                                   push(1) +               // [3, 5]
                                   OP_ADD +                // [2, 4]
                                   OP_DUP1 +               // [3, 5]
                                   push(10) +              // [4, 6]
                                   rjumpi(4, OP_GT) +      // [2, 4]
                                   rjumpi(-14, OP_DUP1) +  // [2, 4]
                                   OP_STOP,                // [2, 4]
                      6),
        EOFValidationError::success);

    // valid loop with a break - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +       // [2, 4]
                                   push(1) +               // [3, 5]
                                   OP_ADD +                // [2, 4]
                                   OP_DUP1 +               // [3, 5]
                                   push(10) +              // [4, 6]
                                   rjumpi(5, OP_GT) +      // [2, 4]
                                   OP_PUSH0 +              // [3, 5]
                                   rjumpi(-13, OP_DUP1) +  // [3, 5]
                                   OP_STOP,                // [2, 5]
                      6),
        EOFValidationError::success);

    // if-then-else with push - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(4, 0) +     // [2, 4]
                                   OP_PUSH0 +         // [3, 5]
                                   rjump(1) +         // [3, 5]
                                   OP_PUSH0 +         // [3, 5]
                                   OP_STOP,           // [3, 5]
                      5),
        EOFValidationError::success);

    // if-then-else with push - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(4, 0) +     // [2, 4]
                                   OP_PUSH0 +         // [3, 5]
                                   rjump(1) +         // [3, 5]
                                   OP_NOT +           // [2, 4]
                                   OP_STOP,           // [2, 5]
                      5),
        EOFValidationError::success);

    // if-then-else with pop - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(4, 0) +     // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjump(1) +         // [1, 3]
                                   OP_POP +           // [1, 3]
                                   OP_STOP,           // [1, 3]
                      5),
        EOFValidationError::success);

    // if-then-else with pop - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(4, 0) +     // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjump(1) +         // [1, 3]
                                   OP_NOT +           // [2, 4]
                                   OP_STOP,           // [1, 4]
                      5),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - equal stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(3, 0) +     // [2, 4]
                                   rjump(0) +         // [2, 4]
                                   OP_STOP,           // [2, 4]
                      5),
        EOFValidationError::success);

    // rjump and rjumpi with the same target - different stack
    add_test_case(eof_bytecode(varstack + OP_PUSH0 +  // [2, 4]
                                   rjumpi(4, 0) +     // [2, 4]
                                   OP_PUSH0 +         // [3, 5]
                                   rjump(0) +         // [3, 5]
                                   OP_STOP,           // [2, 5]
                      5),
        EOFValidationError::success);
}

TEST_F(eof_validation, backwards_rjumpv)
{
    add_test_case(eof_bytecode(rjumpv({-6}, 0) + OP_STOP, 1), EOFValidationError::success);

    add_test_case(
        eof_bytecode(push0() + OP_POP + rjumpv({-8}, 0) + OP_STOP, 1), EOFValidationError::success);

    // rjumpv backwards from different locations to the same target
    add_test_case(eof_bytecode(push0() + OP_POP + rjumpv({-8}, 0) + rjumpv({-14}, 0) + OP_STOP, 1),
        EOFValidationError::success);

    // rjumpv backwards from different locations to the same target - stack height mismatch
    add_test_case(
        eof_bytecode(push0() + OP_POP + rjumpv({-8}, 0) + push0() + rjumpv({-15}, 0) + OP_STOP, 2),
        EOFValidationError::stack_height_mismatch);

    // rjump and rjumpv with the same target - equal stack
    add_test_case(eof_bytecode(push0() +              // [1, 1]
                                   OP_POP +           // [0, 0]
                                   rjumpv({-8}, 0) +  // [0, 0]
                                   rjump(-11),        // [0, 0]
                      1),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - different stack
    add_test_case(eof_bytecode(push0() +              // [1, 1]
                                   OP_POP +           // [0, 0]
                                   rjumpv({-8}, 0) +  // [0, 0]
                                   OP_PUSH0 +         // [1, 1]
                                   rjump(-12),        // [1, 1]
                      1),
        EOFValidationError::stack_height_mismatch);

    // rjumpv backwards - only max stack height mismatch
    add_test_case(eof_bytecode(push0() +               // [1, 1]
                                   rjumpi(1, 0) +      // [1, 1]
                                   OP_PUSH0 +          // [2, 2]
                                   rjumpv({-12}, 0) +  // [1, 2]
                                   OP_STOP,            // [1, 2]
                      3),
        EOFValidationError::stack_height_mismatch);

    // rjumpv backwards - only min stack height mismatch
    add_test_case(eof_bytecode(OP_PUSH0 + OP_PUSH0 +   // [2, 2]
                                   rjumpi(1, 0) +      // [2, 2]
                                   OP_POP +            // [1, 1]
                                   rjumpv({-12}, 0) +  // [1, 2]
                                   OP_STOP,            // [1, 2]
                      3),
        EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, backwards_rjumpv_variable_stack)
{
    add_test_case(
        eof_bytecode(varstack + rjumpv({-6}, 0) + OP_STOP, 4), EOFValidationError::success);

    add_test_case(eof_bytecode(varstack + push0() + OP_POP + rjumpv({-8}, 0) + OP_STOP, 4),
        EOFValidationError::success);

    // rjumpv backwards from different locations to the same target
    add_test_case(
        eof_bytecode(varstack + push0() + OP_POP + rjumpv({-8}, 0) + rjumpv({-14}, 0) + OP_STOP, 4),
        EOFValidationError::success);

    // rjumpv backwards from different locations to the same target - stack height mismatch
    add_test_case(eof_bytecode(varstack + push0() + OP_POP + rjumpv({-8}, 0) + push0() +
                                   rjumpv({-15}, 0) + OP_STOP,
                      5),
        EOFValidationError::stack_height_mismatch);

    // rjump and rjumpv with the same target - equal stack
    add_test_case(eof_bytecode(varstack + push0() +   // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjumpv({-8}, 0) +  // [1, 3]
                                   rjump(-11),        // [1, 3]
                      4),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - different stack
    add_test_case(eof_bytecode(varstack + push0() +   // [2, 4]
                                   OP_POP +           // [1, 3]
                                   rjumpv({-8}, 0) +  // [1, 3]
                                   OP_PUSH0 +         // [2, 4]
                                   rjump(-12),        // [2, 4]
                      4),
        EOFValidationError::stack_height_mismatch);

    // rjumpv backwards - only max stack height mismatch
    add_test_case(eof_bytecode(varstack + push0() +    // [2, 4]
                                   rjumpi(1, 0) +      // [2, 4]
                                   OP_PUSH0 +          // [3, 5]
                                   rjumpv({-12}, 0) +  // [2, 5]
                                   OP_STOP,            // [2, 5]
                      5),
        EOFValidationError::stack_height_mismatch);

    // rjumpv backwards - only min stack height mismatch
    add_test_case(eof_bytecode(varstack + OP_PUSH0 + OP_PUSH0 +  // [3, 5]
                                   rjumpi(1, 0) +                // [3, 5]
                                   OP_POP +                      // [2, 4]
                                   rjumpv({-12}, 0) +            // [2, 5]
                                   OP_STOP,                      // [2, 5]
                      5),
        EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, forwards_rjumpv)
{
    add_test_case(eof_bytecode(rjumpv({0}, 1) + OP_STOP, 1), EOFValidationError::success);

    // forwards rjumpv + fallthrough - equal stack
    add_test_case(
        eof_bytecode(push0() + rjumpv({1}, 0) + OP_NOT + OP_STOP, 2), EOFValidationError::success);

    // forwards rjumpv 2 cases + fallthrough - equal stack
    add_test_case(
        eof_bytecode(push0() + rjumpv({2, 3}, 0) + OP_PUSH0 + OP_POP + OP_NOT + OP_STOP, 2),
        EOFValidationError::success);

    // forwards rjumpv + fallthrough - different stack
    add_test_case(eof_bytecode(push0() +             // [1, 1]
                                   rjumpv({1}, 0) +  // [1, 1]
                                   OP_PUSH0 +        // [2, 2]
                                   OP_STOP,          // [1, 2]
                      2),
        EOFValidationError::success);

    // forwards rjumpv 2 cases + fallthrough - different stack
    add_test_case(eof_bytecode(push0() +                // [1, 1]
                                   rjumpv({1, 2}, 0) +  // [1, 1]
                                   OP_PUSH0 +           // [2, 2]
                                   OP_PUSH0 +           // [2, 3]
                                   OP_NOT +             // [1, 3]
                                   OP_STOP,             // [1, 2]
                      3),
        EOFValidationError::success);

    // switch - equal stack
    add_test_case(eof_bytecode(push0() + rjumpv({5, 10}, 0) +  // [1, 1]
                                   push(1) + rjump(7) +        // [2, 2]
                                   push(2) + rjump(2) +        // [2, 2]
                                   push(3) +                   // [2, 2]
                                   OP_STOP,                    // [2, 2]
                      2),
        EOFValidationError::success);

    // switch with pushes - different stack
    add_test_case(eof_bytecode(push0() + rjumpv({4, 9}, 0) +       // [1, 1]
                                   push0() + rjump(8) +            // [2, 2]
                                   push0() + push0() + rjump(3) +  // [3, 3]
                                   push0() + push0() + push0() +   // [4, 4]
                                   OP_STOP,                        // [1, 4]
                      4),
        EOFValidationError::success);


    // switch with pops - different stack
    add_test_case(eof_bytecode(4 * push0() + rjumpv({4, 9}, 0) +  // [4, 4]
                                   OP_POP + rjump(8) +            // [3, 3]
                                   OP_POP + OP_POP + rjump(3) +   // [2, 2]
                                   OP_POP + OP_POP + OP_POP +     // [1, 1]
                                   OP_STOP,                       // [1, 4]
                      5),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - equal stack
    add_test_case(eof_bytecode(push0() +             // [1, 1]
                                   rjumpv({3}, 0) +  // [1, 1]
                                   rjump(0) +        // [1, 1]
                                   OP_STOP,          // [1, 1]
                      2),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - different stack
    add_test_case(eof_bytecode(push0() +             // [1, 1]
                                   rjumpv({4}, 0) +  // [1, 1]
                                   OP_PUSH0 +        // [2, 2]
                                   rjump(0) +        // [2, 2]
                                   OP_STOP,          // [1, 2]
                      2),
        EOFValidationError::success);
}

TEST_F(eof_validation, forwards_rjumpv_variable_stack)
{
    add_test_case(
        eof_bytecode(varstack + rjumpv({0}, 1) + OP_STOP, 4), EOFValidationError::success);

    // forwards rjumpv + fallthrough - equal stack
    add_test_case(eof_bytecode(varstack + push0() + rjumpv({1}, 0) + OP_NOT + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjumpv 2 cases + fallthrough - equal stack
    add_test_case(
        eof_bytecode(
            varstack + push0() + rjumpv({2, 3}, 0) + OP_PUSH0 + OP_POP + OP_NOT + OP_STOP, 5),
        EOFValidationError::success);

    // forwards rjumpv + fallthrough - different stack
    add_test_case(eof_bytecode(varstack + push0() +  // [2, 4]
                                   rjumpv({1}, 0) +  // [2, 4]
                                   OP_PUSH0 +        // [3, 5]
                                   OP_STOP,          // [2, 5]
                      5),
        EOFValidationError::success);

    // forwards rjumpv 2 cases + fallthrough - different stack
    add_test_case(eof_bytecode(varstack + push0() +     // [2, 4]
                                   rjumpv({1, 2}, 0) +  // [2, 4]
                                   OP_PUSH0 +           // [3, 5]
                                   OP_PUSH0 +           // [2, 6]
                                   OP_NOT +             // [2, 6]
                                   OP_STOP,             // [2, 6]
                      6),
        EOFValidationError::success);

    // switch - equal stack
    add_test_case(eof_bytecode(varstack + push0() + rjumpv({5, 10}, 0) +  // [2, 4]
                                   push(1) + rjump(7) +                   // [3, 5]
                                   push(2) + rjump(2) +                   // [3, 5]
                                   push(3) +                              // [3, 5]
                                   OP_STOP,                               // [3, 5]
                      5),
        EOFValidationError::success);

    // switch with pushes - different stack
    add_test_case(eof_bytecode(varstack + push0() + rjumpv({4, 9}, 0) +  // [2, 4]
                                   push0() + rjump(8) +                  // [3, 5]
                                   push0() + push0() + rjump(3) +        // [4, 6]
                                   push0() + push0() + push0() +         // [5, 7]
                                   OP_STOP,                              // [3, 7]
                      7),
        EOFValidationError::success);


    // switch with pops - different stack
    add_test_case(eof_bytecode(varstack + 4 * push0() + rjumpv({4, 9}, 0) +  // [5, 7]
                                   OP_POP + rjump(8) +                       // [4, 6]
                                   OP_POP + OP_POP + rjump(3) +              // [3, 5]
                                   OP_POP + OP_POP + OP_POP +                // [2, 4]
                                   OP_STOP,                                  // [2, 6]
                      8),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - equal stack
    add_test_case(eof_bytecode(varstack + push0() +  // [2, 4]
                                   rjumpv({3}, 0) +  // [2, 4]
                                   rjump(0) +        // [2, 4]
                                   OP_STOP,          // [2, 4]
                      5),
        EOFValidationError::success);

    // rjump and rjumpv with the same target - different stack
    add_test_case(eof_bytecode(varstack + push0() +  // [2, 4]
                                   rjumpv({4}, 0) +  // [2, 4]
                                   OP_PUSH0 +        // [3, 5]
                                   rjump(0) +        // [3, 5]
                                   OP_STOP,          // [2, 5]
                      5),
        EOFValidationError::success);
}

TEST_F(eof_validation, self_referencing_jumps)
{
    // rjumpf from stack 0 to stack 0
    add_test_case(eof_bytecode(rjump(-3)), EOFValidationError::success, "rjump");

    // rjumpi from stack 0 to stack 1
    add_test_case(
        eof_bytecode(rjumpi(-3, 0) + OP_STOP), EOFValidationError::stack_height_mismatch, "rjumpi");

    // rjumpv from stack 0 to stack 1
    add_test_case(eof_bytecode(rjumpv({-4}, 0) + OP_STOP),
        EOFValidationError::stack_height_mismatch, "rjumpv");
}

TEST_F(eof_validation, self_referencing_jumps_variable_stack)
{
    // rjumpf from stack [1, 3] to stack [1, 3]
    add_test_case(eof_bytecode(varstack + rjump(-3), 3), EOFValidationError::success, "rjump");

    // rjumpi from stack [1, 3] to stack [2, 4]
    add_test_case(eof_bytecode(varstack + rjumpi(-3, 0) + OP_STOP, 4),
        EOFValidationError::stack_height_mismatch, "rjumpi");

    // rjumpv from stack [1, 3] to stack [2, 4]
    add_test_case(eof_bytecode(varstack + rjumpv({-4}, 0) + OP_STOP, 4),
        EOFValidationError::stack_height_mismatch, "rjumpv");
}

TEST_F(eof_validation, underflow)
{
    add_test_case(eof_bytecode(bytecode{OP_ADD} + OP_STOP, 0), EOFValidationError::stack_underflow);

    // CALLF underflow
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 1).code(push0() + OP_RETF, 1, 2, 2),
        EOFValidationError::stack_underflow);

    // JUMPF to returning function
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(jumpf(2), 0, 2, 0)
                      .code(push0() + OP_RETF, 1, 2, 2),
        EOFValidationError::stack_underflow);

    // JUMPF to non-returning function
    add_test_case(eof_bytecode(jumpf(1), 0).code(revert(0, 0), 1, 0x80, 3),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, underflow_variable_stack)
{
    // LOG2 underflow - [1, 3] stack - neither min nor max enough for 4 inputs
    add_test_case(
        eof_bytecode(varstack + OP_LOG2 + OP_STOP, 3), EOFValidationError::stack_underflow);

    // ADD underflow - [1, 3] stack - only max enough for 5 inputs
    add_test_case(
        eof_bytecode(varstack + OP_ADD + OP_STOP, 3), EOFValidationError::stack_underflow);

    // CALLF underflow - [1, 3] stack - neither min nor max enough for 5 inputs
    add_test_case(eof_bytecode(varstack + callf(1) + OP_STOP, 4).code(push0() + OP_RETF, 4, 5, 5),
        EOFValidationError::stack_underflow);

    // CALLF underflow - [1, 3] stack - only max enough for 3 inputs
    add_test_case(eof_bytecode(varstack + callf(1) + OP_STOP, 4).code(push0() + OP_RETF, 3, 4, 4),
        EOFValidationError::stack_underflow);

    // JUMPF to returning function - neither min nor max enough for 5 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(varstack + jumpf(2), 0, 3, 3)
                      .code(bytecode{OP_POP} + OP_POP + OP_RETF, 5, 3, 3),
        EOFValidationError::stack_underflow);

    // JUMPF to non-returning function - [1, 3] stack - neither min nor max enough for 5 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 0).code(revert(0, 0), 5, 0x80, 7),
        EOFValidationError::stack_underflow);

    // JUMPF to non-returning function - [1, 3] stack - only max enough for 3 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 0).code(revert(0, 0), 3, 0x80, 5),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, callf_stack_validation)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 1)
                      .code(push0() + push0() + callf(2) + OP_RETF, 0, 1, 2)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::success);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 1)
                      .code(push0() + push0() + push0() + callf(2) + OP_RETF, 0, 1, 3)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::stack_higher_than_outputs_required);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 1)
                      .code(push0() + callf(2) + OP_RETF, 0, 1, 1)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, callf_stack_overflow)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP)
                      .code(512 * push(1) + callf(1) + 512 * OP_POP + OP_RETF, 0, 0, 512),
        EOFValidationError::success);

    add_test_case(eof_bytecode(callf(1) + OP_STOP)
                      .code(513 * push(1) + callf(1) + 513 * OP_POP + OP_RETF, 0, 0, 513),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(callf(1) + OP_STOP)
                      .code(1023 * push(1) + callf(1) + 1023 * OP_POP + OP_RETF, 0, 0, 1023),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(callf(1) + OP_STOP)
                      .code(1023 * push(1) + callf(2) + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
                      .code(push0() + OP_POP + OP_RETF, 0, 0, 1),
        EOFValidationError::success);

    add_test_case(eof_bytecode(callf(1) + OP_STOP)
                      .code(1023 * push(1) + callf(2) + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
                      .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 0, 0, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, callf_stack_overflow_variable_stack)
{
    add_test_case(eof_bytecode(varstack + 509 * push(1) + callf(1) + OP_STOP, 512)
                      .code(512 * push(1) + 512 * OP_POP + OP_RETF, 0, 0, 512),
        EOFValidationError::success);

    // CALLF from [510, 512] stack to function with 515 max stack - both min and max stack overflow
    add_test_case(eof_bytecode(varstack + 509 * push(1) + callf(1) + OP_STOP, 512)
                      .code(515 * push(1) + 515 * OP_POP + OP_RETF, 0, 0, 515),
        EOFValidationError::stack_overflow);

    // CALLF from [510, 512] stack to function with 514 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 509 * push(1) + callf(1) + OP_STOP, 512)
                      .code(514 * push(1) + 514 * OP_POP + OP_RETF, 0, 0, 514),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to function with 1 max stack
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + OP_POP + OP_RETF, 0, 0, 1),
        EOFValidationError::success);

    // CALLF from [1021, 1023] stack to function with 5 max stack - both min and  max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(5 * push0() + 5 * OP_POP + OP_RETF, 0, 0, 5),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to function with 2 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 0, 0, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, callf_with_inputs_stack_overflow)
{
    add_test_case(eof_bytecode(1023 * push(1) + callf(1) + 1019 * OP_POP + OP_RETURN, 1023)
                      .code(bytecode{OP_POP} + OP_POP + OP_RETF, 2, 0, 2),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + callf(1) + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push(1) + OP_POP + OP_RETF, 3, 3, 4),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + callf(1) + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + push0() + OP_RETF, 3, 5, 5),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1023 * push(1) + callf(1) + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 3, 3, 5),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1024 * push(1) + callf(1) + 1020 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 3),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(1023 * push(1) + callf(1) + 1020 * OP_POP + OP_RETURN, 1023)
            .code(push0() + push0() + OP_POP + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 4),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, callf_with_inputs_stack_overflow_variable_stack)
{
    // CALLF from [1021, 1023] stack to function with 2 inputs and 2 max stack
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(bytecode{OP_POP} + OP_POP + OP_RETF, 2, 0, 2),
        EOFValidationError::success);

    // CALLF from [1021, 1023] stack to function with 3 inputs and 4 max stack
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push(1) + OP_POP + OP_RETF, 3, 3, 4),
        EOFValidationError::success);

    // CALLF from [1021, 1023] stack to 3 inputs and 7 outputs - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(4 * push0() + OP_RETF, 3, 7, 7),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to 3 inputs and 5 outputs - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + push0() + OP_RETF, 3, 5, 5),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to 3 inputs and 7 max stack - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(4 * push0() + OP_POP + OP_POP + OP_RETF, 3, 3, 7),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to 3 inputs and 5 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 3, 3, 5),
        EOFValidationError::stack_overflow);

    // CALLF from [1022, 1024] stack to 2 inputs and 5 max stack - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1021 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(3 * push0() + 5 * OP_POP + OP_RETF, 2, 0, 5),
        EOFValidationError::stack_overflow);

    // CALLF from [1022, 1024] stack to 2 inputs and 3 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1021 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 3),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to 2 inputs and 6 max stack - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(4 * push0() + 6 * OP_POP + OP_RETF, 2, 0, 6),
        EOFValidationError::stack_overflow);

    // CALLF from [1021, 1023] stack to 2 inputs and 4 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push(1) + callf(1) + OP_STOP, 1023)
                      .code(push0() + push0() + 4 * OP_POP + OP_RETF, 2, 0, 4),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, retf_stack_validation)
{
    // 2 outputs, RETF has 2 values on stack
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2).code(push0() + push0() + OP_RETF, 0, 2, 2),
        EOFValidationError::success);

    // 2 outputs, RETF has 1 value on stack
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2).code(push0() + OP_RETF, 0, 2, 1),
        EOFValidationError::stack_underflow);

    // 2 outputs, RETF has 3 values on stack
    add_test_case(
        eof_bytecode(callf(1) + OP_STOP, 2).code(push0() + push0() + push0() + OP_RETF, 0, 2, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // RETF in a helper (reached via different paths)
    add_test_case(
        eof_bytecode(push0() + callf(1) + OP_STOP, 2)
            .code(rjumpi(7, {}) + push(1) + push(1) + rjump(2) + push0() + push0() + OP_RETF, 1, 2,
                2),
        EOFValidationError::success);
}

TEST_F(eof_validation, retf_variable_stack)
{
    // RETF in variable stack segment is not allowed and always fails with one of two errors

    // RETF from [1, 3] stack returning 5 outputs
    auto code = eof_bytecode(callf(1) + OP_STOP, 5).code(varstack + OP_RETF, 0, 5, 3);
    add_test_case(code, EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack returning 3 outputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3).code(varstack + OP_RETF, 0, 3, 3),
        EOFValidationError::stack_underflow);

    // RETF from [1, 3] stack returning 1 output
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 1).code(varstack + OP_RETF, 0, 1, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // RETF from [1, 3] returning 0 outputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 0).code(varstack + OP_RETF, 0, 0, 3),
        EOFValidationError::stack_higher_than_outputs_required);
}

TEST_F(eof_validation, jumpf_to_returning)
{
    // JUMPF into a function with the same number of outputs as current one

    // 0 inputs target
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(jumpf(2), 0, 2, 0)
                      .code(push0() + push0() + OP_RETF, 0, 2, 2),
        EOFValidationError::success);

    // 0 inputs target - extra items on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + jumpf(2), 0, 2, 2)
                      .code(push0() + push0() + OP_RETF, 0, 2, 2),
        EOFValidationError::stack_higher_than_outputs_required);

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + jumpf(2), 0, 2, 3)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + push0() + jumpf(2), 0, 2, 4)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + jumpf(2), 0, 2, 2)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::stack_underflow);

    // JUMPF into a function with fewer outputs than current one

    // (0, 2) --JUMPF--> (0, 1): 0 inputs + 1 output = 1 item required

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + jumpf(2), 0, 2, 1)
                      .code(push0() + OP_RETF, 0, 1, 1),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + jumpf(2), 0, 2, 3)
                      .code(push0() + OP_RETF, 0, 1, 1),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(jumpf(2), 0, 2, 0)
                      .code(push0() + OP_RETF, 0, 1, 1),
        EOFValidationError::stack_underflow);

    // (0, 2) --JUMPF--> (3, 1): 3 inputs + 1 output = 4 items required

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + push0() + jumpf(2), 0, 2, 4)
                      .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + push0() + push0() + jumpf(2), 0, 2, 5)
                      .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(push0() + push0() + push0() + jumpf(2), 0, 2, 3)
                      .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, jumpf_to_returning_variable_stack)
{
    // JUMPF to returning function in variable stack segment is not allowed and always fails with
    // one of two errors

    // JUMPF into a function with the same number of outputs as current one

    // JUMPF from [1, 3] stack to function with 5 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(varstack + jumpf(2), 0, 3, 3)
                      .code(push0() + OP_RETF, 5, 3, 3),
        EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 3 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(varstack + jumpf(2), 0, 3, 3)
                      .code(bytecode{OP_RETF}, 3, 3, 3),
        EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 1 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(varstack + jumpf(2), 0, 3, 3)
                      .code(push0() + push0() + OP_RETF, 1, 3, 5),
        EOFValidationError::stack_higher_than_outputs_required);

    // JUMPF from [1, 3] stack to function with 0 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(varstack + jumpf(2), 0, 3, 3)
                      .code(push0() + push0() + push0() + OP_RETF, 0, 3, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // JUMPF into a function with fewer outputs than current one

    // JUMPF from [1, 3] stack to function with 5 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(varstack + jumpf(2), 0, 2, 3)
                      .code(4 * OP_POP + OP_RETF, 5, 1, 5),
        EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 3 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(varstack + jumpf(2), 0, 2, 3)
                      .code(bytecode{OP_POP} + OP_POP + bytecode{OP_RETF}, 3, 1, 3),
        EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to function with 1 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(varstack + jumpf(2), 0, 2, 3)
                      .code(OP_RETF, 1, 1, 1),
        EOFValidationError::stack_higher_than_outputs_required);

    // JUMPF from [1, 3] stack to function with 0 inputs
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 2)
                      .code(varstack + jumpf(2), 0, 2, 3)
                      .code(push0() + OP_RETF, 0, 1, 1),
        EOFValidationError::stack_higher_than_outputs_required);
}

TEST_F(eof_validation, jumpf_to_nonreturning)
{
    // Target has 0 inputs

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(push0() + push0() + jumpf(1), 2).code(OP_STOP, 0, 0x80, 0),
        EOFValidationError::success);

    // Target has 3 inputs

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(3 * OP_PUSH0 + jumpf(1), 3).code(OP_STOP, 3, 0x80, 3),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(4 * OP_PUSH0 + jumpf(1), 4).code(OP_STOP, 3, 0x80, 3),
        EOFValidationError::success);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(2 * OP_PUSH0 + jumpf(1), 2).code(OP_STOP, 3, 0x80, 3),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, jumpf_to_nonreturning_variable_stack)
{
    // JUMPF from [1, 3] stack to non-returning function with 5 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 3).code(Opcode{OP_INVALID}, 5, 0x80, 5),
        EOFValidationError::stack_underflow);

    // JUMPF from [1, 3] stack to non-returning function with 3 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 3).code(Opcode{OP_INVALID}, 3, 0x80, 3),
        EOFValidationError::stack_underflow);

    // Extra items on stack are allowed for JUMPF to non-returning

    // JUMPF from [1, 3] stack to non-returning function with 1 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 3).code(Opcode{OP_INVALID}, 1, 0x80, 1),
        EOFValidationError::success);

    // JUMPF from [1, 3] stack to non-returning function with 0 inputs
    add_test_case(eof_bytecode(varstack + jumpf(1), 3).code(Opcode{OP_INVALID}, 0, 0x80, 0),
        EOFValidationError::success);
}

TEST_F(eof_validation, jumpf_stack_overflow)
{
    add_test_case(eof_bytecode(512 * push(1) + jumpf(0), 512), EOFValidationError::success);

    add_test_case(eof_bytecode(513 * push(1) + jumpf(0), 513), EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(1023 * push(1) + jumpf(0), 1023), EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1023 * push(1) + jumpf(1), 1023).code(push0() + OP_STOP, 0, 0x80, 1),
        EOFValidationError::success);

    add_test_case(
        eof_bytecode(1023 * push(1) + jumpf(1), 1023).code(push0() + push0() + OP_STOP, 0, 0x80, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, jumpf_stack_overflow_variable_stack)
{
    add_test_case(
        eof_bytecode(varstack + 509 * OP_PUSH0 + jumpf(0), 512), EOFValidationError::success);

    // JUMPF from [510, 512] stack to function with 515 max stack - both min and max stack overflow
    add_test_case(eof_bytecode(varstack + 509 * OP_PUSH0 + jumpf(1), 512)
                      .code(515 * OP_PUSH0 + OP_STOP, 0, 0x80, 515),
        EOFValidationError::stack_overflow);

    // JUMPF from [510, 512] stack to function with 514 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 509 * OP_PUSH0 + jumpf(1), 512)
                      .code(514 * OP_PUSH0 + OP_STOP, 0, 0x80, 514),
        EOFValidationError::stack_overflow);

    // JUMPF from [1021, 1023] stack to function with 1 max stack
    add_test_case(eof_bytecode(varstack + 1020 * OP_PUSH0 + jumpf(1), 1023)
                      .code(push0() + OP_STOP, 0, 0x80, 1),
        EOFValidationError::success);

    // JUMPF from [1021, 1023] stack to function with 5 max stack - both min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * OP_PUSH0 + jumpf(1), 1023)
                      .code(5 * push0() + OP_STOP, 0, 0x80, 5),
        EOFValidationError::stack_overflow);

    // JUMPF from [1021, 1023] stack to function with 2 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * OP_PUSH0 + jumpf(1), 1023)
                      .code(push0() + push0() + OP_STOP, 0, 0x80, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, jumpf_with_inputs_stack_overflow)
{
    add_test_case(eof_bytecode(1023 * push0() + jumpf(1), 1023).code(push0() + OP_STOP, 2, 0x80, 3),
        EOFValidationError::success);

    add_test_case(
        eof_bytecode(1023 * push0() + jumpf(1), 1023).code(push0() + push0() + OP_STOP, 2, 0x80, 4),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1024 * push0() + jumpf(1), 1023).code(push0() + OP_STOP, 2, 0x80, 3),
        EOFValidationError::stack_overflow);
}


TEST_F(eof_validation, jumpf_with_inputs_stack_overflow_variable_stack)
{
    // JUMPF from [1021, 1023] stack to 2 inputs and 3 max stack
    add_test_case(eof_bytecode(varstack + 1020 * push0() + jumpf(1), 1023)
                      .code(push0() + OP_STOP, 2, 0x80, 3),
        EOFValidationError::success);

    // JUMPF from [1021, 1023] stack to 2 inputs and 6 max stack - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push0() + jumpf(1), 1023)
                      .code(4 * push0() + OP_STOP, 2, 0x80, 6),
        EOFValidationError::stack_overflow);

    // JUMPF from [1021, 1023] stack to 2 inputs and 4 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1020 * push0() + jumpf(1), 1023)
                      .code(push0() + push0() + OP_STOP, 2, 0x80, 4),
        EOFValidationError::stack_overflow);

    // JUMPF from [1022, 1024] stack to 2 inputs and 5 max stack - min and max stack overflow
    add_test_case(eof_bytecode(varstack + 1021 * push0() + jumpf(1), 1023)
                      .code(3 * push0() + OP_STOP, 2, 0x80, 5),
        EOFValidationError::stack_overflow);

    // JUMPF from [1022, 1024] stack to 2 inputs and 3 max stack - only max stack overflow
    add_test_case(eof_bytecode(varstack + 1021 * push0() + jumpf(1), 1023)
                      .code(push0() + OP_STOP, 2, 0x80, 3),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, dupn_stack_validation)
{
    const auto pushes = 20 * push(1);
    add_test_case(eof_bytecode(pushes + OP_DUPN + "00" + OP_STOP, 21), EOFValidationError::success);
    add_test_case(eof_bytecode(pushes + OP_DUPN + "13" + OP_STOP, 21), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_DUPN + "14" + OP_STOP, 21), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_DUPN + "d0" + OP_STOP, 21), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_DUPN + "fe" + OP_STOP, 21), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_DUPN + "ff" + OP_STOP, 21), EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, swapn_stack_validation)
{
    const auto pushes = 20 * push(1);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "00" + OP_STOP, 20), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "12" + OP_STOP, 20), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "13" + OP_STOP, 20), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "d0" + OP_STOP, 20), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "fe" + OP_STOP, 20), EOFValidationError::stack_underflow);
    add_test_case(
        eof_bytecode(pushes + OP_SWAPN + "ff" + OP_STOP, 20), EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, exchange_stack_validation)
{
    const auto pushes = 10 * push(1);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "00" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "10" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "01" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "20" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "02" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "70" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "07" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "11" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "34" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "43" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "16" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "61" + OP_STOP, 10), EOFValidationError::success);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "80" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "08" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "71" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "17" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "44" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "53" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "35" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "ee" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "ef" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "fe" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
    add_test_case(eof_bytecode(pushes + OP_EXCHANGE + "ff" + OP_STOP, 10),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, exchange_deep_stack_validation)
{
    const auto pushes = 33 * push(1);
    add_test_case(
        eof_bytecode(pushes + OP_EXCHANGE + "ff" + OP_STOP, 33), EOFValidationError::success);
}

TEST_F(eof_validation, exchange_empty_stack_validation)
{
    add_test_case(eof_bytecode(bytecode(OP_EXCHANGE) + "00" + OP_STOP, 0),
        EOFValidationError::stack_underflow);
}
