// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, eof1_execution)
{
    const auto code = eof1_bytecode(OP_STOP);

    rev = EVMC_LONDON;
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
    auto code = eof1_bytecode(mstore8(0, 1), ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);
    EXPECT_EQ(result.output_size, 0);

    // data section contains ret(0, 1)
    code = eof1_bytecode(mstore8(0, 1) + OP_STOP, ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, eof1_pc)
{
    rev = EVMC_SHANGHAI;
    const auto code = eof1_bytecode(OP_PC + mstore8(0) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 8);
}

TEST_P(evm, eof1_jump_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jump(12) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code =
        eof1_bytecode(jump(15) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jumpi_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jumpi(14, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        jumpi(17, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jump_into_header)
{
    rev = EVMC_SHANGHAI;
    // data section is of size 0x5b = OP_JUMPDEST
    const auto code = eof1_bytecode(jump(9), 0x5b * bytecode{0});

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_jumpi_into_header)
{
    rev = EVMC_SHANGHAI;
    // data section is of size 0x5b = OP_JUMPDEST
    const auto code = eof1_bytecode(jumpi(9, 1), 0x5b * bytecode{0});

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_jump_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jump(15), OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_jumpi_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jumpi(17, 1), OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 17);

    code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 24);
}

TEST_P(evm, eof1_codecopy_full)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{20} + 0 + 0 + OP_CODECOPY + ret(0, 20));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        from_hex("efcafe0101000c006014600060003960146000f3"));

    code = eof1_bytecode(bytecode{27} + 0 + 0 + OP_CODECOPY + ret(0, 27), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        from_hex("efcafe0101000c02000400601b6000600039601b6000f3deadbeef"));
}

TEST_P(evm, eof1_codecopy_header)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{8} + 0 + 0 + OP_CODECOPY + ret(0, 8));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), from_hex("efcafe0101000c00"));

    code = eof1_bytecode(bytecode{11} + 0 + 0 + OP_CODECOPY + ret(0, 11), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), from_hex("efcafe0101000c02000400"));
}

TEST_P(evm, eof1_codecopy_code)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{12} + 8 + 0 + OP_CODECOPY + ret(0, 12));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), from_hex("600c6008600039600c6000f3"));

    code = eof1_bytecode(bytecode{12} + 11 + 0 + OP_CODECOPY + ret(0, 12), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), from_hex("600c600b600039600c6000f3"));
}

TEST_P(evm, eof1_codecopy_data)
{
    rev = EVMC_SHANGHAI;

    const auto code = eof1_bytecode(bytecode{4} + 23 + 0 + OP_CODECOPY + ret(0, 4), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), from_hex("deadbeef"));
}

TEST_P(evm, eof2_rjump)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof2_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_backward)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code =
        eof2_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_0_offset)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjump(0) + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjumpi)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(
        rjumpi(10, calldataload(0)) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1));

    // RJUMPI condition is true
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // RJUMPI condition is false
    execute(code, "00");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);
}

TEST_P(evm, eof2_rjumpi_backwards)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) +
                              rjumpi(-16, calldataload(0)) + mstore8(0, 2) + ret(0, 1));

    // RJUMPI condition is true
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // RJUMPI condition is false
    execute(code, "00");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);
}

TEST_P(evm, eof2_rjumpi_0_offset)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjumpi(0, calldataload(0)) + mstore8(0, 1) + ret(0, 1));

    // RJUMPI condition is true
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);

    // RJUMPI condition is false
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
}

TEST_P(evm, eof2_rjumptable)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjump(10) + mstore8(0, 1) + ret(0, 1) +
                                  rjumptable(0, calldataload(0)) + mstore8(0, 2) + ret(0, 1) +
                                  mstore8(0, 3) + ret(0, 1) + mstore8(0, 4) + ret(0, 1),
        {}, {{20, 10, 0, -16}});

    // index = 0 (offset = 20)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 4);

    // index = 1 (offset = 10)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 3);

    // index = 2 (offset = 0)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000002");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);

    // index = 3 (offset = -16)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000003");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // index = 4 (out of table bounds)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000004");
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof2_rjumptable_multiple_tables)
{
    rev = EVMC_SHANGHAI;
    auto code = eof2_bytecode(rjumptable(0, calldataload(0)) + mstore8(0, 1) + ret(0, 1) +
                                  rjumptable(1, calldataload(32)) + mstore8(0, 2) + ret(0, 1) +
                                  mstore8(0, 3) + ret(0, 1) + mstore8(0, 4) + ret(0, 1),
        {}, {{10, 0}, {0, 10, 20}});

    // 1st jump: table 0 index = 0 (offset = 10)
    // 2st jump: table 1 index = 0 (offset = 0)
    execute(code,
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);

    // 1st jump: table 0 index = 0 (offset = 10)
    // 2st jump: table 1 index = 1 (offset = 10)
    execute(code,
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 3);

    // 1st jump: table 0 index = 0 (offset = 10)
    // 2st jump: table 1 index = 2 (offset = 20)
    execute(code,
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000002");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 4);

    // 1st jump: table 0 index = 1 (offset = 0)
    execute(code, "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, relative_jumps_undefined_in_legacy)
{
    rev = EVMC_SHANGHAI;
    auto code = rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    code = rjumpi(10, 1) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    code = rjumptable(0, 0) + mstore8(0, 1) + ret(0, 1) + mstore8(0, 2) + ret(0, 1) +
           mstore8(0, 3) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}
