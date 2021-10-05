// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, eof2_rjump)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code = rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_backward)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code = rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code = rjump(0) + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjumpi)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code =
        rjumpi(10, calldataload(0)) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1);

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
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code = rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) +
                              rjumpi(-16, calldataload(0)) + mstore8(0, 2) + ret(0, 1);

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
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_CANCUN;
    auto code = rjumpi(0, calldataload(0)) + mstore8(0, 1) + ret(0, 1);

    // RJUMPI condition is true
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);

    // RJUMPI condition is false
    execute(code, "01");
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
}
