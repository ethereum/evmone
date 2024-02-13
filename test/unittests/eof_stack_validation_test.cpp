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

TEST_F(eof_validation, jumpf_to_returning)
{
    // JUMPF into a function with the same number of outputs as current one

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
                      .code(push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 3)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(eof_bytecode(bytecode{OP_STOP})
                      .code(push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 4)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(bytecode{OP_STOP})
                      .code(push0() + push0() + OP_JUMPF + "0002", 0, 2, 2)
                      .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3),
        EOFValidationError::stack_underflow);

    // JUMPF into a function with fewer outputs than current one
    // (0, 2) --JUMPF--> (3, 1): 3 inputs + 1 output = 4 items required

    // Exactly required inputs on stack at JUMPF
    add_test_case(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
                      .code(push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 4)
                      .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case(
        eof_bytecode(bytecode{OP_STOP})
            .code(push0() + push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 5)
            .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    add_test_case(eof_bytecode(bytecode{OP_STOP})
                      .code(push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 3)
                      .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3),
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, jumpf_to_nonreturning)
{
    // Exactly required inputs on stack at JUMPF
    add_test_case("EF0001 010008 02000200060001 040000 00 0080000303800003 5F5F5FE50001 00",
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    add_test_case("EF0001 010008 02000200070001 040000 00 0080000403800003 5F5F5F5FE50001 00",
        EOFValidationError::success);

    // Not enough inputs on stack at JUMPF
    add_test_case("EF0001 010008 02000200050001 040000 00 0080000203800003 5F5FE50001 00",
        EOFValidationError::stack_underflow);
}

TEST_F(eof_validation, jumpf_stack_overflow)
{
    add_test_case(eof_bytecode(512 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 512),
        EOFValidationError::success);

    add_test_case(eof_bytecode(513 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 513),
        EOFValidationError::stack_overflow);

    add_test_case(eof_bytecode(1023 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 1023),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(1023 * push(1) + OP_JUMPF + "0001", 1023).code(push0() + OP_STOP, 0, 0x80, 1),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + OP_JUMPF + "0001", 1023)
                      .code(push0() + push0() + OP_STOP, 0, 0x80, 2),
        EOFValidationError::stack_overflow);
}

TEST_F(eof_validation, jumpf_with_inputs_stack_overflow)
{
    add_test_case(
        eof_bytecode(1023 * push0() + OP_JUMPF + "0001", 1023).code(push0() + OP_STOP, 2, 0x80, 3),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push0() + OP_JUMPF + "0001", 1023)
                      .code(push0() + push0() + OP_STOP, 2, 0x80, 4),
        EOFValidationError::stack_overflow);

    add_test_case(
        eof_bytecode(1024 * push0() + OP_JUMPF + "0001", 1023).code(push0() + OP_STOP, 2, 0x80, 3),
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
