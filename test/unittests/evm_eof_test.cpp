// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using evmone::test::evm;

TEST_P(evm, eof1_execution)
{
    const auto code = eof1_bytecode(OP_STOP);

    rev = EVMC_SHANGHAI;
    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    rev = EVMC_CANCUN;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, eof1_execution_with_data_section)
{
    rev = EVMC_CANCUN;
    // data section contains ret(0, 1)
    const auto code = eof1_bytecode(mstore8(0, 1) + OP_STOP, 2, ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 28);

    code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), 2, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 32);
}

TEST_P(evm, eof1_codecopy_full)
{
    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(bytecode{31} + 0 + 0 + OP_CODECOPY + ret(0, 31), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c0300000000000003601f6000600039601f6000f3"_hex);

    code = eof1_bytecode(bytecode{35} + 0 + 0 + OP_CODECOPY + ret(0, 35), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c03000400000000036023600060003960236000f3deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_header)
{
    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(bytecode{15} + 0 + 0 + OP_CODECOPY + ret(0, 15), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), "ef0001010004020001000c03000000"_hex);

    code = eof1_bytecode(bytecode{15} + 0 + 0 + OP_CODECOPY + ret(0, 15), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), "ef0001010004020001000c03000400"_hex);
}

TEST_P(evm, eof1_codecopy_code)
{
    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(bytecode{12} + 19 + 0 + OP_CODECOPY + ret(0, 12), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c6013600039600c6000f3"_hex);

    code = eof1_bytecode(bytecode{12} + 19 + 0 + OP_CODECOPY + ret(0, 12), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "600c6013600039600c6000f3"_hex);
}

TEST_P(evm, eof1_codecopy_data)
{
    rev = EVMC_CANCUN;

    const auto code = eof1_bytecode(bytecode{4} + 31 + 0 + OP_CODECOPY + ret(0, 4), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_out_of_bounds)
{
    // 4 bytes out of container bounds - result is implicitly 0-padded
    rev = EVMC_CANCUN;
    auto code = eof1_bytecode(bytecode{35} + 0 + 0 + OP_CODECOPY + ret(0, 35), 3);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c03000000000000036023600060003960236000f300000000"_hex);

    code = eof1_bytecode(bytecode{39} + 0 + 0 + OP_CODECOPY + ret(0, 39), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        "ef0001010004020001000c03000400000000036027600060003960276000f3deadbeef00000000"_hex);
}

TEST_P(evm, eof_data_only_contract)
{
    rev = EVMC_CANCUN;
    auto code = "EF0001 010004 020001 0001 03daaa 00 00000000 FE"_hex;
    const auto data_size_ptr = &code[code.find(0xda)];

    intx::be::unsafe::store(data_size_ptr, uint16_t{0});
    execute(code);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);

    intx::be::unsafe::store(data_size_ptr, uint16_t{1});
    execute(code + "aa"_hex);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);

    intx::be::unsafe::store(data_size_ptr, uint16_t{256});
    execute(code + bytes(256, 0x01));
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);
}
