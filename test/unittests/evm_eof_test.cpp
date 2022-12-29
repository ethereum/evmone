// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using evmone::test::evm;
using namespace evmc::literals;

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
    const auto code = eof1_bytecode(mstore8(0, 1) + OP_STOP, 2, ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, DISABLED_eof1_pc)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(OP_PC + mstore8(0) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);

    code = eof1_bytecode(4 * bytecode{OP_JUMPDEST} + OP_PC + mstore8(0) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 4);
}

TEST_P(evm, DISABLED_eof1_jump_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, DISABLED_eof1_jumpi_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), 2, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, DISABLED_eof1_jump_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jump(4) + OP_STOP, 1, OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, DISABLED_eof1_jumpi_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code =
        eof1_bytecode(jumpi(6, 1) + OP_STOP, 2, OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, DISABLED_eof1_push_byte_in_header)
{
    rev = EVMC_SHANGHAI;
    // data section is 0x65 bytes long, so header contains 0x65 (PUSH6) byte,
    // but it must not affect jumpdest analysis (OP_JUMPDEST stays valid)
    auto code = eof1_bytecode(
        jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), 2, bytes(0x65, '\0'));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_SHANGHAI;
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
    rev = EVMC_SHANGHAI;
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
    rev = EVMC_SHANGHAI;
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
    rev = EVMC_SHANGHAI;
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
    rev = EVMC_SHANGHAI;

    const auto code = eof1_bytecode(bytecode{4} + 31 + 0 + OP_CODECOPY + ret(0, 4), 3, "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), "deadbeef"_hex);
}

TEST_P(evm, eof1_codecopy_out_of_bounds)
{
    // 4 bytes out of container bounds - result is implicitly 0-padded
    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof2_rjump)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof2_rjump_backward)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof2_rjump_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(rjump(0) + mstore8(0, 1) + ret(0, 1), 2);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjumpi)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof2_rjumpi_backwards)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof2_rjumpi_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

    rev = EVMC_SHANGHAI;
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

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, relative_jumps_undefined_in_legacy)
{
    rev = EVMC_SHANGHAI;
    auto code = rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    code = rjumpi(10, 1) + mstore8(0, 2) + ret(0, 1) + mstore8(0, 1) + ret(0, 1);

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, eof_function_example1)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
    const auto code =
        "EF00 01 010008 020002 000f 0002 00"
        "00000002 02010002"
        "6001 6008 b00001 " +
        ret_top() + "03b1";

    ASSERT_EQ((int)evmone::validate_eof(rev, code), (int)evmone::EOFValidationError{});

    execute(code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 32);
    EXPECT_OUTPUT_INT(7);
}

TEST_P(evm, eof_function_example2)
{
    // Relative jumps are not implemented in Advanced.
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
    const auto code =
        "ef0001 01000c 020003 003b 0017 001d 00 00000004 01010003 01010004"
        "60043560003560e01c63c766526781145d001c63c6c2ea1781145d00065050600080fd50b00002600052602060"
        "00f350b0000160005260206000f3"
        "600181115d0004506001b160018103b0000181029050b1"
        "600281115d0004506001b160028103b0000260018203b00002019050b1"_hex;

    ASSERT_EQ((int)evmone::validate_eof(rev, code), (int)evmone::EOFValidationError{});

    // Call fac(5)
    const auto calldata_fac =
        "c76652670000000000000000000000000000000000000000000000000000000000000005"_hex;
    execute(bytecode{code}, calldata_fac);
    EXPECT_GAS_USED(EVMC_SUCCESS, 246);
    EXPECT_EQ(output, "0000000000000000000000000000000000000000000000000000000000000078"_hex);

    // Call fib(15)
    const auto calldata_fib =
        "c6c2ea17000000000000000000000000000000000000000000000000000000000000000f"_hex;
    execute(bytecode{code}, calldata_fib);
    EXPECT_GAS_USED(EVMC_SUCCESS, 44544);
    EXPECT_EQ(output, "0000000000000000000000000000000000000000000000000000000000000262"_hex);
}


TEST_P(evm, eof_data_only_contract)
{
    if (is_advanced())
        return;

    rev = EVMC_SHANGHAI;
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

TEST_P(evm, eof_creates_valid_eof_contract_only)
{
    rev = EVMC_SHANGHAI;
    host.call_result.create_address = 0x02_address;
    {
        // invalid eof contract (push1 truncated)
        auto new_contract = "EF0001 010004 0200010001 030000 00 00000000 60";
        auto code =
            eof1_bytecode(bytecode{20} + 41 + 0 + OP_CODECOPY + 20 + 0 + 0 + OP_CREATE + ret_top(),
                3, new_contract);

        execute(code);
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_OUTPUT_INT(0);
    }

    {
        // valid eof contract
        auto new_contract = "EF0001 010004 0200010001 030000 00 00000000 FE";
        auto code =
            eof1_bytecode(bytecode{20} + 41 + 0 + OP_CODECOPY + 20 + 0 + 0 + OP_CREATE + ret_top(),
                3, new_contract);

        execute(code);
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_OUTPUT_INT(2);
    }

    {
        // non-eof contract
        auto new_contract = "FE";
        auto code =
            eof1_bytecode(bytecode{1} + 34 + 0 + OP_CODECOPY + 1 + 0 + 0 + OP_CREATE + ret_top(), 3,
                new_contract);

        execute(code);
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_OUTPUT_INT(0);
    }

    {
        // empty contract
        auto code = eof1_bytecode(
            bytecode{0} + 34 + 0 + OP_CODECOPY + 0 + 0 + 0 + OP_CREATE + ret_top(), 3);

        execute(code);
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_OUTPUT_INT(0);
    }
}
