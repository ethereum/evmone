// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <evmone/eof.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;
using namespace evmone::test;

TEST_F(eof_validation, callf_stack_validation)
{
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                      .code(push0() + push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 2)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::success);

    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                      .code(push0() + push0() + push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 3)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::stack_higher_than_outputs_required);

    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                      .code(push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 1)
                      .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, callf_stack_overflow)
{
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                      .code(512 * push(1) + OP_CALLF + "0001" + 512 * OP_POP + OP_RETF, 0, 0, 512),
        EOFValidationError::success);

    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                      .code(513 * push(1) + OP_CALLF + "0001" + 513 * OP_POP + OP_RETF, 0, 0, 513),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
            .code(1023 * push(1) + OP_CALLF + "0001" + 1023 * OP_POP + OP_RETF, 0, 0, 1023),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
            .code(1023 * push(1) + OP_CALLF + "0002" + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
            .code(push0() + OP_POP + OP_RETF, 0, 0, 1),
        EOFValidationError::success);

    add_test_case(
        eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
            .code(1023 * push(1) + OP_CALLF + "0002" + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
            .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 0, 0, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, callf_with_inputs_stack_overflow)
{
    add_test_case(eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1019 * OP_POP + OP_RETURN, 1023)
                      .code(bytecode{OP_POP} + OP_POP + OP_RETF, 2, 0, 2),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push(1) + OP_POP + OP_RETF, 3, 3, 4),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + push0() + OP_RETF, 3, 5, 5),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 3, 3, 5),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1024 * push(1) + OP_CALLF + "0001" + 1020 * OP_POP + OP_RETURN, 1023)
                      .code(push0() + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 3),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1020 * OP_POP + OP_RETURN, 1023)
            .code(push0() + push0() + OP_POP + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 4),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, retf_stack_validation)
{
    // 2 outputs, RETF has 2 values on stack
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
                      .code(push0() + push0() + OP_RETF, 0, 2, 2),
        EOFValidationError::success);

    // 2 outputs, RETF has 1 value on stack
    add_test_case(
        eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2).code(push0() + OP_RETF, 0, 2, 1),
        EOFValidationError::stack_underflow);

    // 2 outputs, RETF has 3 values on stack
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
                      .code(push0() + push0() + push0() + OP_RETF, 0, 2, 3),
        EOFValidationError::stack_higher_than_outputs_required);
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
