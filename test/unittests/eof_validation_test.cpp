// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <evmone/constants.hpp>
#include <evmone/eof.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;
using namespace evmone::test;

TEST_F(eof_validation, before_activation)
{
    ASSERT_EQ(
        evmone::validate_eof(EVMC_CANCUN, ContainerKind::runtime, bytes(eof_bytecode(OP_STOP))),
        EOFValidationError::eof_version_unknown);
}

TEST_F(eof_validation, validate_empty_code)
{
    add_test_case("", EOFValidationError::invalid_prefix);
}

TEST_F(eof_validation, validate_EOF_prefix)
{
    add_test_case("00", EOFValidationError::invalid_prefix);
    add_test_case("FE", EOFValidationError::invalid_prefix);
    add_test_case("EF", EOFValidationError::invalid_prefix);

    add_test_case("EF0101", EOFValidationError::invalid_prefix);
    add_test_case("EFEF01", EOFValidationError::invalid_prefix);
    add_test_case("EFFF01", EOFValidationError::invalid_prefix);

    add_test_case("EF00", EOFValidationError::eof_version_unknown);

    add_test_case("EF0001", EOFValidationError::section_headers_not_terminated);

    add_test_case("EFFF 01 010004 0200010003 040004 00 00800000 600000 AABBCCDD",
        EOFValidationError::invalid_prefix, "valid_except_magic");
}

TEST_F(eof_validation, validate_EOF_version)
{
    add_test_case("EF0002", EOFValidationError::eof_version_unknown);
    add_test_case("EF00FF", EOFValidationError::eof_version_unknown);

    add_test_case("EF0000 010004 0200010003 040004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_00");
    add_test_case("EF0002 010004 0200010003 040004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_02");
    add_test_case("EF00FF 010004 0200010003 040004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_FF");
}

TEST_F(eof_validation, minimal_valid_EOF1_code)
{
    add_test_case(eof_bytecode(OP_INVALID), EOFValidationError::success);
}

TEST_F(eof_validation, minimal_valid_EOF1_code_with_data)
{
    add_test_case(eof_bytecode(OP_INVALID).data("DA"), EOFValidationError::success);
}

TEST_F(eof_validation, minimal_valid_EOF1_multiple_code_sections)
{
    add_test_case("EF0001 010008 02000200010001 00  00800000 00800000  FE FE",
        EOFValidationError::data_section_missing, "no_data_section");
    add_test_case(eof_bytecode(jumpf(1)).code(OP_INVALID, 0, 0x80, 0).data("DA"),
        EOFValidationError::success, "with_data_section");

    add_test_case(eof_bytecode(OP_PUSH0 + callf(1) + OP_STOP, 1)
                      .code(OP_POP + callf(2) + OP_POP + OP_RETF, 1, 0, 1)
                      .code(dup1(OP_ADDRESS) + callf(3) + OP_POP + OP_POP + OP_RETF, 0, 1, 3)
                      .code(bytecode{OP_DUP1} + OP_RETF, 2, 3, 3),
        EOFValidationError::success, "non_void_input_output");
}

TEST_F(eof_validation, minimal_valid_EOF1_multiple_container_sections)
{
    add_test_case("EF0001 010004 0200010001 0300010001 0300010001 040000 00 00800000 00 00 00",
        EOFValidationError::data_section_missing, "no_data_section");
}

TEST_F(eof_validation, EOF1_types_section_missing)
{
    add_test_case("EF0001 00", EOFValidationError::type_section_missing);
    add_test_case("EF0001 0200010001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 0200010001 030001 00 FE DA", EOFValidationError::type_section_missing);
    add_test_case("EF0001 0200010001 040001 00 FE DA", EOFValidationError::type_section_missing);
    add_test_case("EF0001 02000200010001 00 FE FE", EOFValidationError::type_section_missing);
}

TEST_F(eof_validation, EOF1_types_section_0_size)
{
    add_test_case("EF0001 010000 0200010001 040000 00 FE", EOFValidationError::zero_section_size);
    add_test_case(
        "EF0001 010000 0200010001 040001 00 FE DA", EOFValidationError::zero_section_size);
}

TEST_F(eof_validation, EOF1_code_section_missing)
{
    add_test_case("EF0001 010004 00", EOFValidationError::code_section_missing);
    add_test_case("EF0001 010004 040001 00 00800000 DA", EOFValidationError::code_section_missing);
}

TEST_F(eof_validation, EOF1_code_section_0_size)
{
    add_test_case("EF0001 010004 020000 00", EOFValidationError::zero_section_size);
    add_test_case("EF0001 010004 020000 040001 00 DA", EOFValidationError::zero_section_size);
}

TEST_F(eof_validation, EOF1_data_section_before_code_section)
{
    add_test_case("EF0001 010004 030001 0200010001 00 00800000 AA FE",
        EOFValidationError::code_section_missing);
}

TEST_F(eof_validation, EOF1_data_section_before_types_section)
{
    add_test_case("EF0001 040001 010004 0200010001 00 AA 00800000 FE",
        EOFValidationError::type_section_missing);
}

TEST_F(eof_validation, EOF1_multiple_data_sections)
{
    add_test_case("EF0001 010004 0200010001 040001 040001 00 00800000 FE DA DA",
        EOFValidationError::header_terminator_missing);
}

TEST_F(eof_validation, EOF1_unknown_section)
{
    add_test_case("EF0001 050001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 FF0001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 010004 0200010001 050001 00 00800000 FE 00",
        EOFValidationError::data_section_missing);
    add_test_case("EF0001 010004 0200010001 FF0001 00 00800000 FE 00",
        EOFValidationError::data_section_missing);
    add_test_case("EF0001 010004 0200010001 040001 050001 00 00800000 FE AA 00",
        EOFValidationError::header_terminator_missing);
    add_test_case("EF0001 010004 0200010001 040001 FF0001 00 00800000 FE AA 00",
        EOFValidationError::header_terminator_missing);
}

TEST_F(eof_validation, EOF1_incomplete_section_size)
{
    // TODO: section_headers_not_terminated should rather be incomplete_section_size
    //  in these examples.
    add_test_case("EF0001 0100", EOFValidationError::incomplete_section_size);
    add_test_case("EF0001 010004 0200", EOFValidationError::incomplete_section_number);
    add_test_case("EF0001 010004 02000100", EOFValidationError::incomplete_section_size);
    add_test_case("EF0001 010004 0200010001", EOFValidationError::section_headers_not_terminated);
    add_test_case(
        "EF0001 010004 0200010001 04", EOFValidationError::section_headers_not_terminated);
    add_test_case("EF0001 010004 0200010001 0400", EOFValidationError::incomplete_section_size);
}

TEST_F(eof_validation, EOF1_header_not_terminated)
{
    add_test_case("EF0001 01", EOFValidationError::section_headers_not_terminated);
    add_test_case("EF0001 010004", EOFValidationError::section_headers_not_terminated);
    add_test_case("EF0001 010004 FE", EOFValidationError::code_section_missing);
    add_test_case("EF0001 010004 02", EOFValidationError::incomplete_section_number);
    add_test_case("EF0001 010004 020001", EOFValidationError::section_headers_not_terminated);
    add_test_case(
        "EF0001 010004 0200010001 040001", EOFValidationError::section_headers_not_terminated);
    add_test_case(
        "EF0001 010004 0200010001 040001 FE AA", EOFValidationError::header_terminator_missing);
}

TEST_F(eof_validation, EOF1_truncated_section)
{
    add_test_case(
        "EF0001 010004 0200010002 040000 00", EOFValidationError::invalid_section_bodies_size);
    add_test_case("EF0001 010004 0200010002 040000 00 008000",
        EOFValidationError::invalid_section_bodies_size);
    add_test_case("EF0001 010004 0200010002 040000 00 00800000 FE",
        EOFValidationError::invalid_section_bodies_size);

    // Data section may not be truncated in toplevel container
    add_test_case(
        eof_bytecode(OP_INVALID).data("", 2), EOFValidationError::toplevel_container_truncated);
    add_test_case(
        eof_bytecode(OP_INVALID).data("aa", 2), EOFValidationError::toplevel_container_truncated);
}

TEST_F(eof_validation, EOF1_code_section_offset)
{
    const auto eof = eof_bytecode(jumpf(1)).code(OP_INVALID, 0, 0x80, 0).data("00000000");
    add_test_case(eof, EOFValidationError::success);

    const auto header = read_valid_eof1_header(bytecode(eof));
    ASSERT_EQ(header.code_sizes.size(), 2);
    EXPECT_EQ(header.code_sizes[0], 3);
    EXPECT_EQ(header.code_sizes[1], 1);
    ASSERT_EQ(header.code_offsets.size(), 2);
    EXPECT_EQ(header.code_offsets[0], 25);
    EXPECT_EQ(header.code_offsets[1], 28);
}

TEST_F(eof_validation, EOF1_trailing_bytes_in_subcontainer)
{
    add_test_case(
        eof_bytecode(eofcreate() + OP_STOP, 4).container(eof_bytecode(OP_INVALID) + "DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4)
                      .container(eof_bytecode(OP_INVALID).data("aabb") + "DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
}

TEST_F(eof_validation, EOF1_trailing_bytes_top_level)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 FE DEADBEEF",
        EOFValidationError::invalid_section_bodies_size);
    add_test_case("EF0001 010004 0200010001 040002 00 00800000 FE AABB DEADBEEF",
        EOFValidationError::invalid_section_bodies_size);
}

TEST_F(eof_validation, EOF1_multiple_type_sections)
{
    add_test_case("EF0001 010004 010004 02000200010001 00 00800000 00800000 FE FE",
        EOFValidationError::code_section_missing);

    // Section order is must be (Types, Code+, Data)
    add_test_case("EF0001 030002 010001 010001 040002 00 0000 FE FE 0000",
        EOFValidationError::type_section_missing);
}

TEST_F(eof_validation, EOF1_type_section_not_first)
{
    add_test_case(
        "EF0001 0200010001 010004 00 FE 00800000", EOFValidationError::type_section_missing);

    add_test_case(
        "EF0001 02000200010001 010004 00 FE FE 00800000", EOFValidationError::type_section_missing);

    add_test_case("EF0001 0200010001 010004 040003 00 FE 00800000 AABBCC",
        EOFValidationError::type_section_missing);

    add_test_case("EF0001 0200010001 040003 010004 00 FE AABBCC 00800000",
        EOFValidationError::type_section_missing);
}

TEST_F(eof_validation, EOF1_invalid_type_section_size)
{
    add_test_case(
        "EF0001 010001 0200010001 040000 00 00 FE", EOFValidationError::invalid_type_section_size);
    add_test_case("EF0001 010002 0200010001 040000 00 0080 FE",
        EOFValidationError::invalid_type_section_size);
    add_test_case("EF0001 010008 0200010001 040000 00 0080000000000000 FE",
        EOFValidationError::invalid_type_section_size);

    add_test_case("EF0001 010008 020003000100010001 040000 00 0080000000800000 FE FE FE",
        EOFValidationError::invalid_type_section_size);
    add_test_case(
        "EF0001 010010 020003000100010001 040000 00 00800000008000000080000000800000 FE FE FE",
        EOFValidationError::invalid_type_section_size);
}

TEST_F(eof_validation, EOF1_invalid_section_0_type)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00000000 00",
        EOFValidationError::invalid_first_section_type);
    add_test_case("EF0001 010004 0200010003 040000 00 00010000 60005C",
        EOFValidationError::invalid_first_section_type);
    add_test_case("EF0001 010004 0200010001 040000 00 01800000 FE",
        EOFValidationError::invalid_first_section_type);
    add_test_case("EF0001 010004 0200010003 040000 00 02030000 60005C",
        EOFValidationError::invalid_first_section_type);
}

TEST_F(eof_validation, EOF1_too_many_code_sections)
{
    auto eof_code_sections_1023 = eof_bytecode(jumpf(1));
    for (int i = 1; i < 1022; ++i)
        eof_code_sections_1023 =
            eof_code_sections_1023.code(jumpf(static_cast<uint16_t>(i + 1)), 0, 0x80, 0);

    auto eof_code_sections_1024 = eof_code_sections_1023;
    eof_code_sections_1023 = eof_code_sections_1023.code(OP_STOP, 0, 0x80, 0);
    eof_code_sections_1024 = eof_code_sections_1024.code(jumpf(1023), 0, 0x80, 0);

    auto eof_code_sections_1025 = eof_code_sections_1024;
    eof_code_sections_1024 = eof_code_sections_1024.code(OP_STOP, 0, 0x80, 0);
    eof_code_sections_1025 =
        eof_code_sections_1025.code(jumpf(1024), 0, 0x80, 0).code(OP_STOP, 0, 0x80, 0);

    add_test_case(eof_code_sections_1023, EOFValidationError::success, "valid_1023");
    add_test_case(eof_code_sections_1024, EOFValidationError::success, "valid_1024");
    add_test_case(
        eof_code_sections_1025, EOFValidationError::too_many_code_sections, "invalid_1025");
}

TEST_F(eof_validation, EOF1_undefined_opcodes)
{
    const auto& gas_table = evmone::instr::gas_costs[EVMC_OSAKA];

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        // PUSH*, DUPN, SWAPN, RJUMP*, CALLF, JUMPF, EOFCREATE, RETRUNCONTRACT  require immediate
        // argument to be valid, checked in a separate test.
        if ((opcode >= OP_PUSH1 && opcode <= OP_PUSH32) || opcode == OP_DUPN ||
            opcode == OP_SWAPN || opcode == OP_EXCHANGE || opcode == OP_RJUMP ||
            opcode == OP_RJUMPI || opcode == OP_CALLF || opcode == OP_RJUMPV ||
            opcode == OP_DATALOADN || opcode == OP_JUMPF || opcode == OP_EOFCREATE ||
            opcode == OP_RETURNCODE)
            continue;
        // These opcodes are deprecated since Osaka.
        // gas_cost table current implementation does not allow to undef instructions.
        if (opcode == OP_JUMP || opcode == OP_JUMPI || opcode == OP_PC || opcode == OP_CALLCODE ||
            opcode == OP_SELFDESTRUCT || opcode == OP_CALL || opcode == OP_STATICCALL ||
            opcode == OP_DELEGATECALL || opcode == OP_CREATE || opcode == OP_CREATE2 ||
            opcode == OP_CODESIZE || opcode == OP_CODECOPY || opcode == OP_EXTCODESIZE ||
            opcode == OP_EXTCODECOPY || opcode == OP_EXTCODEHASH || opcode == OP_GAS)
            continue;

        const auto expected = (gas_table[opcode] == evmone::instr::undefined ?
                                   EOFValidationError::undefined_instruction :
                                   EOFValidationError::success);

        if (opcode == OP_RETF)
        {
            // RETF can be tested in 2nd code section.
            add_test_case(eof_bytecode(callf(1) + OP_STOP).code(OP_RETF, 0, 0, 0), expected);
        }
        else
        {
            auto op_stack_change = instr::traits[opcode].stack_height_change;
            auto code = push(1) + 16 * OP_DUP1 + Opcode{static_cast<uint8_t>(opcode)};
            if (!instr::traits[opcode].is_terminating)
                code += bytecode{OP_STOP};
            add_test_case(
                eof_bytecode(code, static_cast<uint16_t>(std::max(17, 17 + op_stack_change))),
                expected);
        }
    }

    add_test_case(eof_bytecode(OP_INVALID), EOFValidationError::success);
}

TEST_F(eof_validation, EOF1_truncated_push)
{
    for (uint8_t opcode = OP_PUSH1; opcode <= OP_PUSH32; ++opcode)
    {
        const auto required_bytes = static_cast<size_t>(opcode) - OP_PUSH1 + 1;
        for (size_t i = 0; i < required_bytes; ++i)
        {
            auto eof_header = "EF0001 010004 0200010001 040000 00 00800000"_hex;
            auto& code_size_byte = eof_header[10];
            const bytes code{opcode + bytes(i, 0)};
            code_size_byte = static_cast<uint8_t>(code.size());
            const auto container = eof_header + code;

            add_test_case(container, EOFValidationError::truncated_instruction);
        }

        const auto container = eof_bytecode(opcode + bytes(required_bytes, 0) + OP_STOP,
            static_cast<uint8_t>(instr::traits[opcode].stack_height_change));

        add_test_case(container, EOFValidationError::success);
    }
}

TEST_F(eof_validation, EOF1_valid_rjump)
{
    // offset = 0
    add_test_case(eof_bytecode(rjump(0) + OP_STOP), EOFValidationError::success, "offset_zero");

    // offset = 3
    add_test_case(
        eof_bytecode(
            rjumpi(5, OP_PUSH0) + OP_PUSH0 + OP_PUSH0 + rjump(3) + OP_PUSH0 + push(1) + OP_STOP, 2),
        EOFValidationError::success, "offset_positive");

    // offset = -4
    add_test_case(
        eof_bytecode(OP_JUMPDEST + rjump(-4)), EOFValidationError::success, "offset_negative");
}

TEST_F(eof_validation, EOF1_valid_rjumpi)
{
    // offset = 0
    add_test_case(
        eof_bytecode(rjumpi(0, 0) + OP_STOP, 1), EOFValidationError::success, "offset_zero");

    // offset = 3
    add_test_case(eof_bytecode(rjumpi(3, 0) + OP_JUMPDEST + OP_JUMPDEST + OP_JUMPDEST + OP_STOP, 1),
        EOFValidationError::success, "offset_positive");

    // offset = -5
    add_test_case(
        eof_bytecode(rjumpi(-5, 0) + OP_STOP, 1), EOFValidationError::success, "offset_negative");
}

TEST_F(eof_validation, EOF1_valid_rjumpv)
{
    // table = [0] case = 0
    add_test_case(eof_bytecode(rjumpv({0}, 0) + push(1) + OP_STOP, 1), EOFValidationError::success,
        "single_entry_case_0");

    // table = [0,3] case = 0
    add_test_case(eof_bytecode(rjumpv({0, 3}, 0) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::success, "two_entries_case_0");

    // table = [0,3] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::success, "two_entries_case_2");

    // table = [0,3,-10] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, -10}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::success, "three_entries_case_2");
}

TEST_F(eof_validation, EOF1_rjump_truncated)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 E0",
        EOFValidationError::truncated_instruction);

    add_test_case("EF0001 010004 0200010002 040000 00 00800000 E000",
        EOFValidationError::truncated_instruction);
}

TEST_F(eof_validation, EOF1_rjumpi_truncated)
{
    add_test_case("EF0001 010004 0200010003 040000 00 00800000 6000E1",
        EOFValidationError::truncated_instruction);

    add_test_case("EF0001 010004 0200010004 040000 00 00800000 6000E100",
        EOFValidationError::truncated_instruction);
}

TEST_F(eof_validation, EOF1_rjumpv_truncated)
{
    // table = [0] case = 0
    add_test_case("EF0001 010004 0200010005 040000 00 00800000 6000E20000",
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 0
    add_test_case("EF0001 010004 0200010007 040000 00 00800000 6000E201000000",
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 2
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6002E2010000",
        EOFValidationError::truncated_instruction);

    // table = [0,3,-10] case = 2
    add_test_case("EF0001 010004 0200010009 040000 00 00800000 6002E20200000003FF",
        EOFValidationError::truncated_instruction);
}

TEST_F(eof_validation, EOF1_rjump_invalid_destination)
{
    // Into header (offset = -5)
    add_test_case(eof_bytecode(rjump(-5) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -13)
    add_test_case(
        eof_bytecode(rjump(-13) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    add_test_case(eof_bytecode(rjump(2) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    add_test_case(eof_bytecode(rjump(1) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To the same RJUMP immediate (offset = -1)
    add_test_case(eof_bytecode(rjump(-1) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    add_test_case(
        eof_bytecode(push(0) + rjump(-4) + OP_STOP), EOFValidationError::invalid_rjump_destination);

    // To EOFCREATE immediate
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(rjump(9) + 0 + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0} + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::invalid_rjump_destination);

    // To RETURNCODE immediate
    add_test_case(eof_bytecode(rjump(5) + 0 + 0 + OP_RETURNCODE + Opcode{0}, 2).container(embedded),
        ContainerKind::initcode, EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_rjumpi_invalid_destination)
{
    // Into header (offset = -7)
    add_test_case(
        eof_bytecode(rjumpi(-7, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -15)
    add_test_case(
        eof_bytecode(rjumpi(-15, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    add_test_case(
        eof_bytecode(rjumpi(2, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    add_test_case(
        eof_bytecode(rjumpi(1, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To the same RJUMPI immediate (offset = -1)
    add_test_case(
        eof_bytecode(rjumpi(-1, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    add_test_case(
        eof_bytecode(rjumpi(-4, 0) + OP_STOP, 1), EOFValidationError::invalid_rjump_destination);

    // To EOFCREATE immediate
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(
            rjumpi(9, 0) + 0 + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0} + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::invalid_rjump_destination);

    // To RETURNCODE immediate
    add_test_case(
        eof_bytecode(rjumpi(5, 0) + 0 + 0 + OP_RETURNCODE + Opcode{0}, 2).container(embedded),
        ContainerKind::initcode, EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_rjumpv_invalid_destination)
{
    // table = [-23] case = 0
    add_test_case(eof_bytecode(rjumpv({-23}, 0) + push(1) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [-8] case = 0
    add_test_case(eof_bytecode(rjumpv({-8}, 0) + push(1) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [-1] case = 0
    add_test_case(eof_bytecode(rjumpv({-1}, 0) + push(1) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [3] case = 0
    add_test_case(eof_bytecode(rjumpv({3}, 0) + push(1) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [4] case = 0
    add_test_case(eof_bytecode(rjumpv({4}, 0) + push(1) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);


    // table = [0,3,-27] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, -27}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-12] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, -12}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-1] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, -1}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,6] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, 6}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,7] case = 2
    add_test_case(eof_bytecode(rjumpv({0, 3, 7}, 2) + push(1) + OP_STOP + push(2) + OP_STOP, 1),
        EOFValidationError::invalid_rjump_destination);

    // To EOFCREATE immediate
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(
            rjumpv({9}, 0) + 0 + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0} + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::invalid_rjump_destination);

    // To RETURNCODE immediate
    add_test_case(
        eof_bytecode(rjumpv({5}, 0) + 0 + 0 + OP_RETURNCODE + Opcode{0}, 2).container(embedded),
        ContainerKind::initcode, EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_section_order)
{
    // 01 02 04
    add_test_case("EF0001 010004 0200010006 040002 00 00800001 6000E0000000 AABB",
        EOFValidationError::success);

    // 01 04 02
    add_test_case("EF0001 010004 040002 0200010006 00 00800000 AABB 6000E0000000",
        EOFValidationError::code_section_missing);

    // 02 01 04
    add_test_case("EF0001 0200010006 010004 040002 00 6000E0000000 00800000 AABB",
        EOFValidationError::type_section_missing);

    // 02 04 01
    add_test_case("EF0001 0200010006 040002 010004 00 6000E0000000 AABB 00800000",
        EOFValidationError::type_section_missing);

    // 04 01 02
    add_test_case("EF0001 040002 010004 0200010006 00 AABB 00800000 6000E0000000",
        EOFValidationError::type_section_missing);

    // 04 02 01
    add_test_case("EF0001 040002 0200010006 010004 00 AABB 6000E0000000 00800000",
        EOFValidationError::type_section_missing);

    // 01 02 03 04
    add_test_case(
        "EF0001 010004 0200010007 0300010014 040002 00 00800004 5F5F5F5FEC0000 "
        "EF000101000402000100010400000000800000FE AABB",
        EOFValidationError::success);

    // 03 01 02 04
    add_test_case(
        "EF0001 0300010014 010004 0200010007 040002 00 EF000101000402000100010400000000800000FE "
        "00800004 5F5F5F5FEC0000 AABB",
        EOFValidationError::type_section_missing);

    // 01 03 02 04
    add_test_case(
        "EF0001 010004 0300010014 0200010007 040002 00 00800004 "
        "EF000101000402000100010400000000800000FE 5F5F5F5FEC0000 AABB",
        EOFValidationError::code_section_missing);

    // 01 02 04 03
    add_test_case(
        "EF0001 010004 0200010007 040002 0300010014 00 00800004 5F5F5F5FEC0000 AABB "
        "EF000101000402000100010400000000800000FE",
        EOFValidationError::header_terminator_missing);
}

TEST_F(eof_validation, deprecated_instructions)
{
    for (auto op : {OP_CALLCODE, OP_SELFDESTRUCT, OP_JUMP, OP_JUMPI, OP_PC, OP_CALL, OP_STATICCALL,
             OP_DELEGATECALL, OP_CREATE, OP_CREATE2, OP_CODESIZE, OP_CODECOPY, OP_EXTCODESIZE,
             OP_EXTCODECOPY, OP_EXTCODEHASH, OP_GAS})
        add_test_case(eof_bytecode(op), EOFValidationError::undefined_instruction);
}

TEST_F(eof_validation, max_arguments_count)
{
    add_test_case(
        eof_bytecode(127 * push0() + callf(1) + OP_STOP, 127).code(OP_RETF, 127, 127, 127),
        EOFValidationError::success);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 0).code(OP_RETF, 128, 128, 128),
        EOFValidationError::inputs_outputs_num_above_limit);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 127).code(127 * push(1) + OP_RETF, 0, 127, 127),
        EOFValidationError::success);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 129).code(129 * push(1) + OP_RETF, 0, 129, 129),
        EOFValidationError::inputs_outputs_num_above_limit);

    add_test_case(eof_bytecode(127 * push0() + callf(1) + OP_STOP, 127)
                      .code(127 * OP_POP + OP_RETF, 127, 0, 127),
        EOFValidationError::success);

    add_test_case(eof_bytecode(128 * push(1) + callf(1) + OP_STOP, 128)
                      .code(128 * OP_POP + OP_RETF, 128, 0, 128),
        EOFValidationError::inputs_outputs_num_above_limit);
}

TEST_F(eof_validation, max_stack_height)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 0)
                      .code(0x3FF * push(1) + 0x3FF * OP_POP + OP_RETF, 0, 0, 1023),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1023 * push(1) + 1023 * OP_POP + callf(1) + OP_STOP, 1023)
                      .code(OP_RETF, 0, 0, 0),
        EOFValidationError::success);

    add_test_case(eof_bytecode(1024 * push(1) + OP_STOP, 1024),
        EOFValidationError::max_stack_height_above_limit);

    add_test_case(eof_bytecode(0x400 * push(1) + callf(1) + 0x400 * OP_POP + OP_STOP, 1024)
                      .code(OP_RETF, 0, 0, 0),
        EOFValidationError::max_stack_height_above_limit);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 0)
                      .code(0x400 * push(1) + 0x400 * OP_POP + OP_RETF, 0, 0, 1023),
        EOFValidationError::invalid_max_stack_height);

    add_test_case(eof_bytecode(1024 * push(1) + callf(1) + 1024 * OP_POP + OP_STOP, 1023)
                      .code(OP_RETF, 0, 0, 0),
        EOFValidationError::invalid_max_stack_height);

    add_test_case(eof_bytecode(rjumpi(2, 0) + 1 + OP_STOP, 1), EOFValidationError::success);

    add_test_case(
        eof_bytecode(rjumpi(-3, 0) + OP_STOP, 1), EOFValidationError::stack_height_mismatch);

    add_test_case(
        eof_bytecode(rjumpv({-4}, 0) + OP_STOP, 1), EOFValidationError::stack_height_mismatch);
}

TEST_F(eof_validation, EOF1_callf_truncated)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 E3",
        EOFValidationError::truncated_instruction);

    add_test_case("EF0001 010004 0200010002 040000 00 00800000 E300",
        EOFValidationError::truncated_instruction);
}

TEST_F(eof_validation, callf_invalid_code_section_index)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP), EOFValidationError::invalid_code_section_index);
}

TEST_F(eof_validation, incomplete_section_size)
{
    add_test_case("ef0001 010100 02003f 0100", EOFValidationError::incomplete_section_size);
}

TEST_F(eof_validation, data_section_missing)
{
    add_test_case(
        "ef0001 010004 0200010001 00 00800000 fe", EOFValidationError::data_section_missing);
}

TEST_F(eof_validation, multiple_code_sections_headers)
{
    add_test_case(
        "0xef0001 010008 020001 0004 020001 0005 040000 00 00800000 045c0000 00405c00 00002e0005",
        EOFValidationError::data_section_missing);
}

TEST_F(eof_validation, EOF1_dataloadn_truncated)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 D1",
        EOFValidationError::truncated_instruction);

    add_test_case("EF0001 010004 0200010002 040000 00 00800000 D100",
        EOFValidationError::truncated_instruction);
}

TEST_F(eof_validation, dataloadn)
{
    // DATALOADN{0}
    add_test_case(eof_bytecode(dataloadn(0) + OP_POP + OP_STOP, 1)
                      .data("0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::success);

    // DATALOADN{1}
    add_test_case(eof_bytecode(dataloadn(1) + OP_POP + OP_STOP, 1)
                      .data("000000000000000011111111111111112222222222222222333333333333333344"),
        EOFValidationError::success);

    // DATALOADN{32}
    add_test_case(eof_bytecode(dataloadn(32) + OP_POP + OP_STOP, 1)
                      .data("0000000000000000111111111111111122222222222222223333333333333333"
                            "0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::success);

    // DATALOADN{0} - no data section
    add_test_case(eof_bytecode(dataloadn(0) + OP_POP + OP_STOP, 1),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{1} - out of data section bounds
    add_test_case(eof_bytecode(dataloadn(1) + OP_POP + OP_STOP, 1).data("00"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - out of data section bounds
    add_test_case(eof_bytecode(dataloadn(32) + OP_POP + OP_STOP, 1)
                      .data("0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{uint16_max} - out of data section bounds
    add_test_case(eof_bytecode(dataloadn(0xffff) + OP_POP + OP_STOP, 1)
                      .data("0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - truncated word
    add_test_case(eof_bytecode(dataloadn(32) + OP_POP + OP_STOP, 1)
                      .data("0000000000000000111111111111111122222222222222223333333333333333 "
                            "00000000000000001111111111111111222222222222222233333333333333"),
        EOFValidationError::invalid_dataloadn_index);
}

TEST_F(eof_validation, non_returning_status)
{
    // Non-returning with no JUMPF and no RETF
    add_test_case(eof_bytecode(OP_STOP), EOFValidationError::success);
    // Non-returning with JUMPF
    add_test_case(eof_bytecode(jumpf(1)).code(OP_STOP, 0, 0x80, 0), EOFValidationError::success);

    // Returning with RETF
    add_test_case(
        eof_bytecode(callf(1) + OP_STOP).code(OP_RETF, 0, 0, 0), EOFValidationError::success);
    // Returning with JUMPF
    add_test_case(eof_bytecode(callf(1) + OP_STOP).code(jumpf(2), 0, 0, 0).code(OP_RETF, 0, 0, 0),
        EOFValidationError::success);
    // Returning with JUMPF to returning and RETF
    add_test_case(eof_bytecode(OP_PUSH0 + callf(1) + OP_STOP, 1)
                      .code(bytecode{OP_RJUMPI} + "0001" + OP_RETF + jumpf(2), 1, 0, 1)
                      .code(OP_RETF, 0, 0, 0),
        EOFValidationError::success);
    // Returning with JUMPF to non-returning and RETF
    add_test_case(eof_bytecode(OP_PUSH0 + callf(1) + OP_STOP, 1)
                      .code(bytecode{OP_RJUMPI} + "0001" + OP_RETF + jumpf(0), 1, 0, 1),
        EOFValidationError::success);

    // Invalid with RETF
    add_test_case(eof_bytecode(jumpf(1)).code(OP_RETF, 0, 0x80, 0),
        EOFValidationError::invalid_non_returning_flag);
    add_test_case(eof_bytecode(OP_RETF), EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning
    add_test_case(eof_bytecode(jumpf(1)).code(jumpf(2), 0, 0x80, 0).code(OP_RETF, 0, 0, 0),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning
    add_test_case(eof_bytecode(jumpf(1)).code(jumpf(0), 0, 0, 0),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning and RETF
    add_test_case(eof_bytecode(OP_PUSH0 + jumpf(1), 1)
                      .code(bytecode{OP_RJUMPI} + "0001" + OP_RETF + jumpf(2), 1, 0x80, 1)
                      .code(OP_RETF, 0, 0, 0),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning and RETF
    add_test_case(eof_bytecode(OP_PUSH0 + jumpf(1), 1)
                      .code(bytecode{OP_RJUMPI} + "0001" + OP_RETF + jumpf(0), 1, 0x80, 1),
        EOFValidationError::invalid_non_returning_flag);

    // Circular JUMPF: can be both returning and non-returning
    add_test_case(eof_bytecode(jumpf(1)).code(jumpf(2), 0, 0x80, 0).code(jumpf(1), 0, 0x80, 0),
        EOFValidationError::success);
    add_test_case(eof_bytecode(callf(1) + OP_STOP).code(jumpf(2), 0, 0, 0).code(jumpf(1), 0, 0, 0),
        EOFValidationError::success);
}

TEST_F(eof_validation, callf_into_nonreturning)
{
    // function 0: (0, non-returning) : CALLF{1} STOP
    // function 2: (1, non-returning) : STOP
    add_test_case(eof_bytecode(callf(1) + OP_STOP).code(OP_STOP, 0, 0x80, 0),
        EOFValidationError::callf_to_non_returning_function);
}

TEST_F(eof_validation, jumpf_equal_outputs)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 3)
                      .code(jumpf(2), 0, 3, 0)
                      .code(3 * OP_PUSH0 + OP_RETF, 0, 3, 3),
        EOFValidationError::success);
}

TEST_F(eof_validation, jumpf_compatible_outputs)
{
    add_test_case(eof_bytecode(callf(1) + OP_STOP, 5)
                      .code(2 * OP_PUSH0 + jumpf(2), 0, 5, 2)
                      .code(3 * OP_PUSH0 + OP_RETF, 0, 3, 3),
        EOFValidationError::success);
}

TEST_F(eof_validation, jumpf_incompatible_outputs)
{
    const auto code = eof_bytecode(callf(1) + OP_STOP, 3)
                          .code(jumpf(2), 0, 3, 0)
                          .code(5 * OP_PUSH0 + OP_RETF, 0, 5, 3);

    add_test_case(code, EOFValidationError::jumpf_destination_incompatible_outputs);
}

TEST_F(eof_validation, unreachable_code_sections)
{
    add_test_case(eof_bytecode(OP_INVALID).code(OP_INVALID, 0, 0x80, 0),
        EOFValidationError::unreachable_code_sections);

    add_test_case(eof_bytecode(callf(1) + OP_STOP, 0)
                      .code(bytecode{"5B"} + OP_RETF, 0, 0, 0)
                      .code(bytecode{"FE"}, 0, 0x80, 0),
        EOFValidationError::unreachable_code_sections);


    add_test_case(eof_bytecode(callf(2) + OP_STOP, 0)
                      .code(bytecode{"FE"}, 0, 0x80, 0)
                      .code(bytecode{"5B"} + OP_RETF, 0, 0, 0),
        EOFValidationError::unreachable_code_sections);

    add_test_case(eof_bytecode(callf(3) + OP_STOP, 0)
                      .code(bytecode{"FE"}, 0, 0x80, 0)
                      .code(bytecode{"5B"} + OP_RETF, 0, 0, 0)
                      .code(callf(2) + OP_RETF, 0, 0, 0),
        EOFValidationError::unreachable_code_sections);

    add_test_case(eof_bytecode(jumpf(0)).code(jumpf(1), 0, 0x80, 0),
        EOFValidationError::unreachable_code_sections);

    add_test_case(eof_bytecode(jumpf(1))
                      .code(bytecode{OP_STOP}, 0, 0x80, 0)
                      .code(bytecode{"5B"} + OP_RETF, 0, 0, 0),
        EOFValidationError::unreachable_code_sections);

    {
        auto code_sections_256_err_001 = eof_bytecode(jumpf(1)).code(jumpf(1), 0, 0x80, 0);
        auto code_sections_256_err_254 = eof_bytecode(jumpf(1)).code(jumpf(2), 0, 0x80, 0);
        for (int i = 2; i < 254; ++i)
        {
            code_sections_256_err_001.code(jumpf(static_cast<uint16_t>(i + 1)), 0, 0x80, 0);
            code_sections_256_err_254.code(jumpf(static_cast<uint16_t>(i + 1)), 0, 0x80, 0);
        }

        code_sections_256_err_001.code(jumpf(255), 0, 0x80, 0)
            .code(3 * bytecode{"5B"} + OP_STOP, 0, 0x80, 0);
        code_sections_256_err_254.code(jumpf(254), 0, 0x80, 0)
            .code(3 * bytecode{"5B"} + OP_STOP, 0, 0x80, 0);

        // Code Section 1 calls itself instead of code section 2, leaving code section 2 unreachable
        add_test_case(code_sections_256_err_001, EOFValidationError::unreachable_code_sections);

        // Code Section 254 calls itself instead of code section 255, leaving code section 255
        // unreachable
        add_test_case(code_sections_256_err_254, EOFValidationError::unreachable_code_sections);

        // Code Section 0 calls section 1, which calls itself, leaving section
        // 2 unreachable
        add_test_case(eof_bytecode(jumpf(1)).code(jumpf(1), 0, 0x80, 0).code(jumpf(2), 0, 0x80, 0),
            EOFValidationError::unreachable_code_sections);

        // Code Section 0 calls section 1, which calls section 2, section 3 and
        // 4 call each other but are not reachable from section 0
        add_test_case(eof_bytecode(jumpf(1))
                          .code(jumpf(2), 0, 0x80, 0)
                          .code(OP_INVALID, 0, 0x80, 0)
                          .code(jumpf(4), 0, 0x80, 0)
                          .code(jumpf(3), 0, 0x80, 0),
            EOFValidationError::unreachable_code_sections);
    }
}

TEST_F(eof_validation, EOF1_embedded_container)
{
    // no data section
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(eofcreate() + OP_STOP, 4).container(embedded), EOFValidationError::success);

    // no data section in container, but anticipated aux_data
    // data section is allowed to be truncated in runtime subcontainer
    add_test_case(
        eof_bytecode(returncode(0, 0, 2), 2).container(eof_bytecode(OP_INVALID).data("", 2)),
        ContainerKind::initcode, EOFValidationError::success);

    // data section is allowed to be partially truncated in runtime subcontainer
    add_test_case(
        eof_bytecode(returncode(0, 0, 1), 2).container(eof_bytecode(OP_INVALID).data("aa", 2)),
        ContainerKind::initcode, EOFValidationError::success);

    // with data section
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4).container(embedded).data("AABB", 2),
        EOFValidationError::success);

    // garbage in container section - not allowed
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4).container("aabbccddeeff"),
        EOFValidationError::invalid_prefix);

    // multiple container sections
    add_test_case(eof_bytecode(eofcreate() + OP_POP + eofcreate().container(1) + OP_STOP, 4)
                      .container(embedded)
                      .container(eof_bytecode(revert(0, 0), 2)),
        EOFValidationError::success);

    // Max number (256) of container sections
    bytecode code;
    for (auto i = 0; i < 256; ++i)
        code += eofcreate().container(static_cast<uint8_t>(i)) + OP_POP;
    code += bytecode{OP_STOP};
    auto container = eof_bytecode(code, 4);
    const auto subcontainer = eof_bytecode(OP_INVALID);
    for (auto i = 0; i < 256; ++i)
        container.container(subcontainer);
    add_test_case(container, EOFValidationError::success);
}

TEST_F(eof_validation, EOF1_embedded_container_invalid)
{
    // Truncated container header
    add_test_case("EF0001 010004 0200010006 03", EOFValidationError::incomplete_section_number);
    add_test_case("EF0001 010004 0200010006 0300", EOFValidationError::incomplete_section_number);
    add_test_case(
        "EF0001 010004 0200010006 030001", EOFValidationError::section_headers_not_terminated);
    add_test_case("EF0001 010004 0200010006 03000100", EOFValidationError::incomplete_section_size);
    add_test_case(
        "EF0001 010004 0200010006 0300010014", EOFValidationError::section_headers_not_terminated);

    // Zero container sections
    add_test_case("EF0001 010004 0200010006 030000 040000 00 00800001 6000E1000000",
        EOFValidationError::zero_section_size);

    // Container section with 0 size
    add_test_case("EF0001 010004 0200010006 0300010000 040000 00 00800001 6000E1000000",
        EOFValidationError::zero_section_size);

    // Container body missing
    add_test_case("EF0001 010004 0200010006 0300010014 040000 00 00800001 6000E1000000",
        EOFValidationError::invalid_section_bodies_size);

    // Too many container sections
    auto code = eof_bytecode(rjumpi(0, 0) + OP_STOP, 1);
    for (auto i = 0; i < 257; ++i)
        code = code.container(OP_STOP);
    add_test_case(code, EOFValidationError::too_many_container_sections);
}

TEST_F(eof_validation, EOF1_eofcreate_valid)
{
    // initcontainer_index = 0
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(
            eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(0xff) + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::success);

    // initcontainer_index = 0, 1
    add_test_case(
        eof_bytecode(eofcreate().container(0).input(0, OP_CALLDATASIZE).salt(0xff) + OP_POP +
                         eofcreate().container(1).input(0, OP_CALLDATASIZE).salt(0xfe) + OP_POP +
                         OP_STOP,
            4)
            .container(embedded)
            .container(embedded),
        EOFValidationError::success);

    // initcontainer_index  0..255
    bytecode code;
    for (auto i = 0; i < 256; ++i)
        code += eofcreate().container(static_cast<uint8_t>(i)).input(0, OP_CALLDATASIZE) + OP_POP;
    code += bytecode{OP_STOP};
    auto cont = eof_bytecode(code, 4);
    for (auto i = 0; i < 256; ++i)
        cont.container(embedded);
    add_test_case(cont, EOFValidationError::success);
}

TEST_F(eof_validation, EOF1_eofcreate_invalid)
{
    // truncated immediate
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(eof_bytecode(bytecode(0) + 0xff + 0 + 0 + OP_EOFCREATE, 4).container(embedded),
        EOFValidationError::truncated_instruction);

    // last instruction
    add_test_case(
        eof_bytecode(bytecode(0) + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0}, 4).container(embedded),
        EOFValidationError::no_terminating_instruction);

    // referring to non-existent container section
    add_test_case(
        eof_bytecode(bytecode(0) + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{1} + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::invalid_container_section_index);
    add_test_case(
        eof_bytecode(bytecode(0) + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0xff} + OP_POP + OP_STOP, 4)
            .container(embedded),
        EOFValidationError::invalid_container_section_index);

    // referring to container with truncated data
    const auto embedded_truncated_data = eof_bytecode(OP_INVALID).data("aabb"_hex, 3);
    add_test_case(
        eof_bytecode(bytecode(0) + 0xff + 0 + 0 + OP_EOFCREATE + Opcode{0} + OP_POP + OP_STOP, 4)
            .container(embedded_truncated_data),
        EOFValidationError::eofcreate_with_truncated_container);
}

TEST_F(eof_validation, EOF1_returncode_valid)
{
    // deploy_container_index = 0
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(eof_bytecode(returncode(0, 0, 0), 2).container(embedded), ContainerKind::initcode,
        EOFValidationError::success);

    // deploy_container_index = 0 from eofcreate
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4)
                      .container(eof_bytecode(returncode(0, 0, 0), 2).container(embedded)),
        EOFValidationError::success);

    // deploy_container_index = 0, 1
    add_test_case(eof_bytecode(rjumpi(6, 0) + returncode(0, 0, 0) + returncode(1, 0, 0), 2)
                      .container(embedded)
                      .container(embedded),
        ContainerKind::initcode, EOFValidationError::success);

    // deploy_container_index = 0..255
    bytecode code;
    for (auto i = 0; i < 256; ++i)
        code += rjumpi(6, 0) + returncode(static_cast<uint8_t>(i), 0, 0);
    code += revert(0, 0);
    auto cont = eof_bytecode(code, 2);
    for (auto i = 0; i < 256; ++i)
        cont.container(embedded);
    add_test_case(cont, ContainerKind::initcode, EOFValidationError::success);
}

TEST_F(eof_validation, EOF1_returncode_invalid)
{
    // truncated immediate
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(eof_bytecode(bytecode(0) + 0 + OP_RETURNCODE, 4).container(embedded),
        ContainerKind::initcode, EOFValidationError::truncated_instruction);

    // referring to non-existent container section
    add_test_case(eof_bytecode(bytecode(0) + 0 + OP_RETURNCODE + Opcode{1}, 4).container(embedded),
        ContainerKind::initcode, EOFValidationError::invalid_container_section_index);
    add_test_case(
        eof_bytecode(bytecode(0) + 0 + OP_RETURNCODE + Opcode{0xff}, 4).container(embedded),
        ContainerKind::initcode, EOFValidationError::invalid_container_section_index);

    // Unreachable code after RETURNCODE
    add_test_case(eof_bytecode(bytecode(0) + 0 + OP_RETURNCODE + Opcode{0} + revert(0, 0), 2)
                      .container(embedded),
        ContainerKind::initcode, EOFValidationError::unreachable_instructions);
}

TEST_F(eof_validation, EOF1_unreferenced_subcontainer_invalid)
{
    const auto embedded = eof_bytecode(bytecode{OP_INVALID});
    add_test_case(
        eof_bytecode(OP_STOP).container(embedded), EOFValidationError::unreferenced_subcontainer);
}

TEST_F(eof_validation, EOF1_subcontainer_containing_unreachable_code_sections)
{
    const auto embedded_1 = eof_bytecode(OP_INVALID).code(OP_INVALID, 0, 0x80, 0);
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4).container(embedded_1),
        EOFValidationError::unreachable_code_sections);

    const auto embedded_2 = eof_bytecode(jumpf(1))
                                .code(jumpf(2), 0, 0x80, 0)
                                .code(OP_INVALID, 0, 0x80, 0)
                                .code(jumpf(4), 0, 0x80, 0)
                                .code(jumpf(3), 0, 0x80, 0);
    add_test_case(eof_bytecode(eofcreate() + OP_STOP, 4).container(embedded_2),
        EOFValidationError::unreachable_code_sections);
}

TEST_F(eof_validation, max_nested_containers_eofcreate)
{
    bytecode code{};
    bytecode nextcode = eof_bytecode(OP_INVALID);
    while (nextcode.size() <= MAX_INITCODE_SIZE)
    {
        code = nextcode;
        nextcode = eof_bytecode(4 * push0() + OP_EOFCREATE + Opcode{0} + OP_INVALID, 4)
                       .container(nextcode);
    }
    add_test_case(code, EOFValidationError::success);
}

TEST_F(eof_validation, max_nested_containers_eofcreate_returncode)
{
    bytecode code{};
    bytecode nextcode = eof_bytecode(OP_INVALID);
    while (nextcode.size() <= MAX_INITCODE_SIZE)
    {
        code = nextcode;

        const bytecode initcode =
            eof_bytecode(push0() + push0() + OP_RETURNCODE + Opcode{0}, 2).container(nextcode);
        if (initcode.size() >= std::numeric_limits<uint16_t>::max())
            break;
        nextcode = eof_bytecode(4 * push0() + OP_EOFCREATE + Opcode{0} + OP_INVALID, 4)
                       .container(initcode);
    }
    add_test_case(code, EOFValidationError::success);
}

// Summary of validity of combinations of referencing instructions with instructions inside
// referenced containers.
// Rows are instructions referencing subcontainers or rules for top-level container.
// Columns are instructions inside referenced subcontainer.
//
// |                              | STOP   | RETURN | REVERT | RETURNCODE |
// | ---------------------------- | ------ | ------ | ------ | -------------- |
// | top-level initcode           | -      | -      | +      | +              |
// | EOFCREATE                    | -      | -      | +      | +              |
// | TXCREATE                     | -      | -      | +      | +              |
// | top-level runtime            | +      | +      | +      | -              |
// | RETURNCODE               | +      | +      | +      | -              |
// | EOFCREATE and RETURNCODE | -      | -      | +      | -              |

TEST_F(eof_validation, initcode_container_stop)
{
    const auto initcode = bytecode{OP_STOP};
    const auto initcontainer = eof_bytecode(initcode, 0);

    add_test_case(
        initcontainer, ContainerKind::initcode, EOFValidationError::incompatible_container_kind);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::incompatible_container_kind);
}

TEST_F(eof_validation, initcode_container_return)
{
    const auto initcode = ret(0, 0);
    const auto initcontainer = eof_bytecode(initcode, 2);

    add_test_case(
        initcontainer, ContainerKind::initcode, EOFValidationError::incompatible_container_kind);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::incompatible_container_kind);
}

TEST_F(eof_validation, initcode_container_revert)
{
    const auto initcode = revert(0, 0);
    const auto initcontainer = eof_bytecode(initcode, 2);

    add_test_case(initcontainer, ContainerKind::initcode, EOFValidationError::success);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::success);
}

TEST_F(eof_validation, runtime_container_stop)
{
    const auto runtime_container = eof_bytecode(OP_STOP);

    add_test_case(runtime_container, ContainerKind::runtime, EOFValidationError::success);

    const auto initcontainer = eof_bytecode(returncode(0, 0, 0), 2).container(runtime_container);

    add_test_case(initcontainer, ContainerKind::initcode, EOFValidationError::success);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::success);
}

TEST_F(eof_validation, runtime_container_return)
{
    const auto runtime_container = eof_bytecode(ret(0, 0), 2);

    add_test_case(runtime_container, ContainerKind::runtime, EOFValidationError::success);

    const auto initcontainer = eof_bytecode(returncode(0, 0, 0), 2).container(runtime_container);

    add_test_case(initcontainer, ContainerKind::initcode, EOFValidationError::success);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::success);
}

TEST_F(eof_validation, runtime_container_revert)
{
    const auto runtime_container = eof_bytecode(revert(0, 0), 2);

    add_test_case(runtime_container, ContainerKind::runtime, EOFValidationError::success);

    const auto initcontainer = eof_bytecode(returncode(0, 0, 0), 2).container(runtime_container);

    add_test_case(initcontainer, ContainerKind::initcode, EOFValidationError::success);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::success);
}

TEST_F(eof_validation, runtime_container_returncode)
{
    const auto runtime_container =
        eof_bytecode(returncode(0, 0, 0), 2).container(eof_bytecode(OP_INVALID));

    add_test_case(
        runtime_container, ContainerKind::runtime, EOFValidationError::incompatible_container_kind);

    const auto initcontainer = eof_bytecode(returncode(0, 0, 0), 2).container(runtime_container);

    add_test_case(
        initcontainer, ContainerKind::initcode, EOFValidationError::incompatible_container_kind);

    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::incompatible_container_kind);
}

TEST_F(eof_validation, eofcreate_stop_and_returncode)
{
    const auto runtime_container = eof_bytecode(OP_INVALID);
    const auto initcode = rjumpi(1, 0) + OP_STOP + returncode(0, 0, 0);
    const auto initcontainer = eof_bytecode(initcode, 2).container(runtime_container);
    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::incompatible_container_kind);
}

TEST_F(eof_validation, eofcreate_return_and_returncode)
{
    const auto runtime_container = eof_bytecode(OP_INVALID);
    const auto initcode = rjumpi(5, 0) + ret(0, 0) + returncode(0, 0, 0);
    const auto initcontainer = eof_bytecode(initcode, 2).container(runtime_container);
    const auto factory_code = eofcreate() + OP_STOP;
    const auto factory_container = eof_bytecode(factory_code, 4).container(initcontainer);

    add_test_case(factory_container, EOFValidationError::incompatible_container_kind);
}

TEST_F(eof_validation, eofcreate_and_returncode_targeting_same_container)
{
    const auto runtime_container = eof_bytecode(OP_INVALID);
    const auto initcode = eofcreate() + returncode(0, 0, 0);
    const auto initcontainer = eof_bytecode(initcode, 4).container(runtime_container);

    add_test_case(
        initcontainer, ContainerKind::initcode, EOFValidationError::ambiguous_container_kind);

    const auto initcode2 = eofcreate() + eofcreate().container(1) + returncode(1, 0, 0);
    const auto initcontainer2 =
        eof_bytecode(initcode, 4).container(runtime_container).container(runtime_container);

    add_test_case(
        initcontainer2, ContainerKind::initcode, EOFValidationError::ambiguous_container_kind);
}
