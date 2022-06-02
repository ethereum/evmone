// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, eof1_execution)
{
    const auto code = eof1_bytecode(OP_STOP);

    rev = EVMC_PARIS;
    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    rev = EVMC_SHANGHAI;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, eof1_execution_with_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains ret(0, 1)
    const auto code = eof1_bytecode(mstore8(0, 1) + OP_STOP, ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, eof1_pc)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(OP_PC + mstore8(0) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);

    code = eof1_bytecode(4 * bytecode{OP_JUMPDEST} + OP_PC + mstore8(0) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 4);
}

TEST_P(evm, eof1_jump_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code =
        eof1_bytecode(jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jumpi_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jump_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jump(4) + OP_STOP, OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_jumpi_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jumpi(6, 1) + OP_STOP, OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_push_byte_in_header)
{
    rev = EVMC_SHANGHAI;
    // data section is 0x65 bytes long, so header contains 0x65 (PUSH6) byte,
    // but it must not affect jumpdest analysis (OP_JUMPDEST stays valid)
    auto code = eof1_bytecode(
        jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), bytes(0x65, '\0'));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 16);

    code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 23);
}

TEST_P(evm, eof1_codecopy_full)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{19} + 0 + 0 + OP_CODECOPY + ret(0, 19));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000c006013600060003960136000f3"_hex);

    code = eof1_bytecode(bytecode{26} + 0 + 0 + OP_CODECOPY + ret(0, 26), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000c02000400601a6000600039601a6000f3deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_header)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{7} + 0 + 0 + OP_CODECOPY + ret(0, 7));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "ef000101000c00"_hex);

    code = eof1_bytecode(bytecode{10} + 0 + 0 + OP_CODECOPY + ret(0, 10), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "ef000101000c02000400"_hex);
}

TEST_P(evm, eof1_codecopy_code)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{12} + 7 + 0 + OP_CODECOPY + ret(0, 12));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c6007600039600c6000f3"_hex);

    code = eof1_bytecode(bytecode{12} + 10 + 0 + OP_CODECOPY + ret(0, 12), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c600a600039600c6000f3"_hex);
}

TEST_P(evm, eof1_codecopy_data)
{
    rev = EVMC_SHANGHAI;

    const auto code = eof1_bytecode(bytecode{4} + 22 + 0 + OP_CODECOPY + ret(0, 4), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_out_of_bounds)
{
    // 4 bytes out of container bounds - result is implicitly 0-padded
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{23} + 0 + 0 + OP_CODECOPY + ret(0, 23));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000c006017600060003960176000f300000000"_hex);

    code = eof1_bytecode(bytecode{30} + 0 + 0 + OP_CODECOPY + ret(0, 30), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000c02000400601e6000600039601e6000f3deadbeef00000000"_hex);
}
