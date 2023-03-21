// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using evmone::test::evm;


TEST_P(evm, eof1_rjump)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjumpi(3, 0) + rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        rjumpi(3, 0) + rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1), 2, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_rjump_backward)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjump(10) + mstore8(0, 1) + ret(0, 1) + rjump(-13), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(rjump(10) + mstore8(0, 1) + ret(0, 1) + rjump(-13), 2, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_rjump_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjump(0) + mstore8(0, 1) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_rjumpi)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(
        rjumpi(10, calldataload(0)) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1), 2);

    // RJUMPI condition is true
    execute(code, "01"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // RJUMPI condition is false
    execute(code, "00"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);
}

TEST_P(evm, eof1_rjumpi_backwards)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjump(10) + mstore8(0, 1) + ret(0, 1) + rjumpi(-16, calldataload(0)) +
                                  mstore8(0, 2) + ret(0, 1),
        2);

    // RJUMPI condition is true
    execute(code, "01"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // RJUMPI condition is false
    execute(code, "00"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 2);
}

TEST_P(evm, eof1_rjumpi_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjumpi(0, calldataload(0)) + mstore8(0, 1) + ret(0, 1), 2);

    // RJUMPI condition is true
    execute(code, "01"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    // RJUMPI condition is false
    execute(code, "00"_hex);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_rjumpv_single_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjumpv({3}, 0) + OP_JUMPDEST + OP_JUMPDEST + OP_STOP + 20 + 40 + 0 +
                                  OP_CODECOPY + ret(0, 20),
        3, "ef000101000402000100010300000000000000fe");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 20);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000402000100010300000000000000fe"_hex);
}

TEST_P(evm, eof1_rjumpv_multiple_offsets)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(rjump(12) + 10 + 68 + 0 + OP_CODECOPY + ret(0, 10) +
                                  rjumpv({12, -22, 0}, 1) + 10 + 78 + 0 + OP_CODECOPY + ret(0, 10) +
                                  20 + 68 + 0 + OP_CODECOPY + ret(0, 20),
        3, "ef000101000402000100010300000000000000fe");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 10);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "ef000101000402000100"_hex);

    auto& rjumpv_cond = code[35];

    rjumpv_cond = 2;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 10);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "010300000000000000fe"_hex);

    rjumpv_cond = 0;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 20);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef000101000402000100010300000000000000fe"_hex);

    rjumpv_cond = 12;  // case >= count, same behaviour as for case == 2
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 10);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "010300000000000000fe"_hex);
}

TEST_P(evm, eof1_rjumpv_long_jumps)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_CANCUN;
    auto code =
        rjump(0x7fff - 3 - 5) + (0x7fff - 3 - 2 - 8 - 5) * bytecode{OP_JUMPDEST} + 7 + ret_top();

    code += rjumpv({-0x7FFF, 0x7FFF - 8 - 2 - 8}, 0) +
            (0x7fff - 8 - 2 - 8) * bytecode{OP_JUMPDEST} + 5 + ret_top();

    code = eof1_bytecode(code, 2);
    auto& rjumpv_cond = code[0x7fff - 3 - 5 + 3 + 1 + 19];

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_OUTPUT_INT(7);

    rjumpv_cond = 1;

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_OUTPUT_INT(5);
}

TEST_P(evm, rjumps_undefined_in_legacy)
{
    rev = EVMC_CANCUN;
    auto code = rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    code = rjumpi(10, 1) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}
