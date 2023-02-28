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
    auto code = eof1_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1), "deadbeef");

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
    auto code =
        eof1_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13) + OP_STOP);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13) + OP_STOP, "deadbeef");

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
    auto code = eof1_bytecode(rjump(0) + mstore8(0, 1) + ret(0, 1));

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
        rjumpi(10, calldataload(0)) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1));

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
    auto code = eof1_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) +
                              rjumpi(-16, calldataload(0)) + mstore8(0, 2) + ret(0, 1));

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
    auto code = eof1_bytecode(rjumpi(0, calldataload(0)) + mstore8(0, 1) + ret(0, 1));

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
