// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <evmone/eof.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;
using namespace evmone::test;

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

    add_test_case("EFFF 01 010004 0200010003 030004 00 00800000 600000 AABBCCDD",
        EOFValidationError::invalid_prefix, "valid_except_magic");
}

TEST_F(eof_validation, validate_EOF_version)
{
    add_test_case("EF0002", EOFValidationError::eof_version_unknown);
    add_test_case("EF00FF", EOFValidationError::eof_version_unknown);

    add_test_case("EF0000 010004 0200010003 020004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_00");
    add_test_case("EF0002 010004 0200010003 020004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_02");
    add_test_case("EF00FF 010004 0200010003 020004 00 00800000 600000 AABBCCDD",
        EOFValidationError::eof_version_unknown, "valid_except_version_FF");
}

TEST_F(eof_validation, minimal_valid_EOF1_code)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 FE", EOFValidationError::success);
}

TEST_F(eof_validation, minimal_valid_EOF1_code_with_data)
{
    add_test_case("EF0001 010004 0200010001 040001 00 00800000 FE DA", EOFValidationError::success);
}

TEST_F(eof_validation, minimal_valid_EOF1_multiple_code_sections)
{
    add_test_case("EF0001 010008 02000200010001 00  00800000 00800000  FE FE",
        EOFValidationError::data_section_missing, "no_data_section");
    add_test_case("EF0001 010008 02000200030001 040001 00  00800000 00800000 E50001 FE DA",
        EOFValidationError::success, "with_data_section");

    add_test_case(
        "EF0001 010010 0200040005000600080002 040000 00 "
        "00800001 01000001 00010003 02030003"
        "5FE3000100 50E3000250E4 3080E300035050E4 80E4",
        EOFValidationError::success, "non_void_input_output");
}

TEST_F(eof_validation, EOF1_types_section_missing)
{
    add_test_case("EF0001 0200010001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 0200010001 040001 00 FE DA", EOFValidationError::type_section_missing);
}

TEST_F(eof_validation, EOF1_types_section_0_size)
{
    add_test_case("EF0001 010000 0200010001 00 FE", EOFValidationError::zero_section_size);
    add_test_case(
        "EF0001 010000 0200010001 040001 00 FE DA", EOFValidationError::zero_section_size);
}

TEST_F(eof_validation, EOF1_type_section_missing)
{
    add_test_case("EF0001 0200010001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 0200010001 030001 00 FE DA", EOFValidationError::type_section_missing);
    add_test_case("EF0001 00", EOFValidationError::type_section_missing);
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

TEST_F(eof_validation, EOF1_data_section_0_size)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 FE", EOFValidationError::success);
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

    add_test_case("EF0001 01", EOFValidationError::section_headers_not_terminated);
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
    add_test_case("EF0001 010004 0200", EOFValidationError::incomplete_section_number);
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
    add_test_case("EF0001 010004 0200010001 040002 00 00800000 FE",
        EOFValidationError::invalid_section_bodies_size);
    add_test_case("EF0001 010004 0200010001 040002 00 00800000 FE AA",
        EOFValidationError::invalid_section_bodies_size);
}

TEST_F(eof_validation, EOF1_code_section_offset)
{
    const auto eof =
        "EF0001 010008 02000200030001 040004 00 00800000 00800000 E50001 FE 00000000"_hex;
    add_test_case(eof, EOFValidationError::success);

    const auto header = read_valid_eof1_header(eof);
    ASSERT_EQ(header.code_sizes.size(), 2);
    EXPECT_EQ(header.code_sizes[0], 3);
    EXPECT_EQ(header.code_sizes[1], 1);
    ASSERT_EQ(header.code_offsets.size(), 2);
    EXPECT_EQ(header.code_offsets[0], 25);
    EXPECT_EQ(header.code_offsets[1], 28);
}

TEST_F(eof_validation, EOF1_trailing_bytes)
{
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 FE DEADBEEF",
        EOFValidationError::invalid_section_bodies_size);
    add_test_case("EF0001 010004 0200010001 040002 00 00800000 FE AABB DEADBEEF",
        EOFValidationError::invalid_section_bodies_size);
}

TEST_F(eof_validation, EOF1_no_type_section)
{
    add_test_case("EF0001 0200010001 00 FE", EOFValidationError::type_section_missing);
    add_test_case("EF0001 02000200010001 00 FE FE", EOFValidationError::type_section_missing);
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
    std::string cs_calling_next;
    for (int i = 0; i < 1023; ++i)
        cs_calling_next += "E5" + hex(big_endian(static_cast<uint16_t>(i + 1)));

    const std::string code_sections_1024 = cs_calling_next + "5B5B00";
    const std::string code_sections_1025 = cs_calling_next + "E504005B5B00";

    add_test_case("EF0001 011000" + bytecode{"020400"} + 0x400 * bytecode{"0003"} + "040000 00" +
                      0x400 * bytecode{"00800000"} + code_sections_1024,
        EOFValidationError::success, "valid");

    add_test_case("EF0001 011002" + bytecode{"020401"} + 0x401 * bytecode{"0001"} + "040000 00" +
                      0x401 * bytecode{"00800000"} + code_sections_1025,
        EOFValidationError::too_many_code_sections, "invalid");
}

TEST_F(eof_validation, EOF1_undefined_opcodes)
{
    const auto& gas_table = evmone::instr::gas_costs[EVMC_PRAGUE];

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        // PUSH*, DUPN, SWAPN, RJUMP*, CALLF, JUMPF require immediate argument to be valid,
        // checked in a separate test.
        if ((opcode >= OP_PUSH1 && opcode <= OP_PUSH32) || opcode == OP_DUPN ||
            opcode == OP_SWAPN || opcode == OP_EXCHANGE || opcode == OP_RJUMP ||
            opcode == OP_RJUMPI || opcode == OP_CALLF || opcode == OP_RJUMPV ||
            opcode == OP_DATALOADN || opcode == OP_JUMPF)
            continue;
        // These opcodes are deprecated since Prague.
        // gas_cost table current implementation does not allow to undef instructions.
        if (opcode == OP_JUMP || opcode == OP_JUMPI || opcode == OP_PC || opcode == OP_CALLCODE ||
            opcode == OP_SELFDESTRUCT || opcode == OP_CALL || opcode == OP_STATICCALL ||
            opcode == OP_DELEGATECALL || opcode == OP_CREATE || opcode == OP_CREATE2 ||
            opcode == OP_CODESIZE || opcode == OP_CODECOPY || opcode == OP_EXTCODESIZE ||
            opcode == OP_EXTCODECOPY || opcode == OP_EXTCODEHASH || opcode == OP_GAS)
            continue;

        auto cont =
            "EF0001 010004 0200010014 040000 00 00800000 6001"
            "80808080808080808080808080808080 "
            ""_hex;

        if (opcode == OP_RETF)
        {
            // RETF can be tested in 2nd code section.
            cont =
                "EF0001 010008 02000200040001 040000 00 00800000 00000000 E3000100 "_hex + OP_RETF;
        }
        else
        {
            cont += static_cast<uint8_t>(opcode);
            if (!instr::traits[opcode].is_terminating)
                cont += "00"_hex;
            else
                cont[10] = 0x13;

            auto op_stack_change = instr::traits[opcode].stack_height_change;
            cont[18] = static_cast<uint8_t>(op_stack_change <= 0 ? 17 : 17 + op_stack_change);
        }

        const auto expected = (gas_table[opcode] == evmone::instr::undefined ?
                                   EOFValidationError::undefined_instruction :
                                   EOFValidationError::success);
        add_test_case(cont, expected);
    }

    add_test_case("EF0001 010004 0200010001 040000 00 00800000 FE", EOFValidationError::success);
}

TEST_F(eof_validation, EOF1_truncated_push)
{
    auto eof_header = "EF0001 010004 0200010001 040000 00 00800000"_hex;
    auto& code_size_byte = eof_header[10];
    for (uint8_t opcode = OP_PUSH1; opcode <= OP_PUSH32; ++opcode)
    {
        const auto required_bytes = static_cast<size_t>(opcode) - OP_PUSH1 + 1;
        for (size_t i = 0; i < required_bytes; ++i)
        {
            const bytes code{opcode + bytes(i, 0)};
            code_size_byte = static_cast<uint8_t>(code.size());
            const auto container = eof_header + code;

            add_test_case(container, EOFValidationError::truncated_instruction);
        }

        const bytes code{opcode + bytes(required_bytes, 0) + uint8_t{OP_STOP}};
        code_size_byte = static_cast<uint8_t>(code.size());

        eof_header[18] = static_cast<uint8_t>(instr::traits[opcode].stack_height_change);

        const auto container = eof_header + code;

        add_test_case(container, EOFValidationError::success);
    }
}

TEST_F(eof_validation, EOF1_valid_rjump)
{
    // offset = 0
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0000000",
        EOFValidationError::success, "offset_zero");

    // offset = 3
    add_test_case("EF0001 010004 020001000D 040000 00 00800002 5FE100055F5FE000035F600100",
        EOFValidationError::success, "offset_positive");

    // offset = -4
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 5BE0FFFC",
        EOFValidationError::success, "offset_negative");
}

TEST_F(eof_validation, EOF1_valid_rjumpi)
{
    // offset = 0
    add_test_case("EF0001 010004 0200010006 040000 00 00800001 6000E1000000",
        EOFValidationError::success, "offset_zero");

    // offset = 3
    add_test_case("EF0001 010004 0200010009 040000 00 00800001 6000E100035B5B5B00",
        EOFValidationError::success, "offset_positive");

    // offset = -5
    add_test_case("EF0001 010004 0200010006 040000 00 00800001 6000E1FFFB00",
        EOFValidationError::success, "offset_negative");
}

TEST_F(eof_validation, EOF1_valid_rjumpv)
{
    // table = [0] case = 0
    add_test_case("EF0001 010004 0200010009 040000 00 00800001 6000E2000000600100",
        EOFValidationError::success, "single_entry_case_0");

    // table = [0,3] case = 0
    add_test_case("EF0001 010004 020001000E 040000 00 00800001 6000E20100000003600100600200",
        EOFValidationError::success, "two_entries_case_0");

    // table = [0,3] case = 2
    add_test_case("EF0001 010004 020001000E 040000 00 00800001 6002E20100000003600100600200",
        EOFValidationError::success, "two_entries_case_2");

    // table = [0,3,-10] case = 2
    add_test_case("EF0001 010004 0200010010 040000 00 00800001 6002E20200000003FFF6600100600200",
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
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0FFFB00",
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -13)
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0FFF300",
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0000200",
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0000100",
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMP immediate (offset = -1)
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E0FFFF00",
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E0FFFC00",
        EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_rjumpi_invalid_destination)
{
    // Into header (offset = -7)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1FFF900",
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -15)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1FFF100",
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1000200",
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1000100",
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMPI immediate (offset = -1)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1FFFF00",
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    add_test_case("EF0001 010004 0200010006 040000 00 00800000 6000E1FFFC00",
        EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_rjumpv_invalid_destination)
{
    // table = [-23] case = 0
    add_test_case("EF0001 010004 0200010008 040000 00 00800000 6000E200FFE96001",
        EOFValidationError::invalid_rjump_destination);

    // table = [-8] case = 0
    add_test_case("EF0001 010004 0200010008 040000 00 00800000 6000E200FFF86001",
        EOFValidationError::invalid_rjump_destination);

    // table = [-1] case = 0
    add_test_case("EF0001 010004 0200010008 040000 00 00800000 6000E200FFFF6001",
        EOFValidationError::invalid_rjump_destination);

    // table = [2] case = 0
    add_test_case("EF0001 010004 0200010008 040000 00 00800000 6000E20000026001",
        EOFValidationError::invalid_rjump_destination);

    // table = [3] case = 0
    add_test_case("EF0001 010004 0200010008 040000 00 00800000 6000E20000036001",
        EOFValidationError::invalid_rjump_destination);


    // table = [0,3,-27] case = 2
    add_test_case("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFE56001006002",
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-12] case = 2
    add_test_case("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFF46001006002",
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-1] case = 2
    add_test_case("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFFF6001006002",
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,5] case = 2
    add_test_case("EF0001 010004 020001000F 040000 00 00800000 6002E2020000000300056001006002",
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,6] case = 2
    add_test_case("EF0001 010004 020001000F 040000 00 00800000 6002E2020000000300066001006002",
        EOFValidationError::invalid_rjump_destination);
}

TEST_F(eof_validation, EOF1_section_order)
{
    // 01 02 03
    add_test_case("EF0001 010004 0200010006 040002 00 00800001 6000E0000000 AABB",
        EOFValidationError::success);

    // 01 03 02
    add_test_case("EF0001 010004 040002 0200010006 00 00800000 AABB 6000E0000000",
        EOFValidationError::code_section_missing);

    // 02 01 03
    add_test_case("EF0001 0200010006 010004 040002 00 6000E0000000 00800000 AABB",
        EOFValidationError::type_section_missing);

    // 02 03 01
    add_test_case("EF0001 0200010006 040002 010004 00 6000E0000000 AABB 00800000",
        EOFValidationError::type_section_missing);

    // 03 01 02
    add_test_case("EF0001 040002 010004 0200010006 00 AABB 00800000 6000E0000000",
        EOFValidationError::type_section_missing);

    // 03 02 01
    add_test_case("EF0001 040002 0200010006 010004 00 AABB 6000E0000000 00800000",
        EOFValidationError::type_section_missing);
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
    add_test_case("EF0001 010008 02000200830001 040000 00 0080007F 7F7F007F" +
                      127 * bytecode{"5F"} + "E3000100 E4",
        EOFValidationError::success);

    add_test_case("EF0001 010008 02000200010001 040000 00 00800000 80800080 00 E4",
        EOFValidationError::inputs_outputs_num_above_limit);

    add_test_case("EF0001 010008 020002000400FF 040000 00 0080007F 007F007F E3000100" +
                      127 * bytecode{1} + OP_RETF,
        EOFValidationError::success);


    add_test_case(bytecode{"EF0001 010008 02000200010101 040000 00 00800000 00810081"} + OP_STOP +
                      128 * bytecode{1} + OP_RETF,
        EOFValidationError::inputs_outputs_num_above_limit);

    add_test_case("EF0001 010008 02000200830080 040000 00 0080007F 7F00007F" +
                      127 * bytecode{"5F"} + "E3000100" + 127 * OP_POP + OP_RETF,
        EOFValidationError::success);

    add_test_case(bytecode{"EF0001 010008 02000200010081 040000 00 00800000 80000080"} + OP_STOP +
                      128 * OP_POP + OP_RETF,
        EOFValidationError::inputs_outputs_num_above_limit);
}

TEST_F(eof_validation, max_stack_height)
{
    add_test_case("EF0001 010008 02000200040BFE 040000 00 00800000 000003FF E3000100" +
                      0x3FF * bytecode{1} + 0x3FF * OP_POP + OP_RETF,
        EOFValidationError::success);

    add_test_case("EF0001 010008 0200020C010001 040000 00 008003FF 00000000" + 0x3FF * bytecode{1} +
                      0x3FF * OP_POP + "E3000100" + OP_RETF,
        EOFValidationError::success);

    add_test_case(bytecode{"EF0001 010008 02000200010C01 040000 00 00800000 00000400"} + OP_STOP +
                      0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF,
        EOFValidationError::max_stack_height_above_limit);

    add_test_case("EF0001 010008 0200020C010001 040000 00 00800400 00000000" + 0x400 * bytecode{1} +
                      0x400 * OP_POP + OP_STOP + OP_RETF,
        EOFValidationError::max_stack_height_above_limit);

    add_test_case(bytecode{"EF0001 010008 02000200010C01 040000 00 00800000 000003FF"} + OP_STOP +
                      0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF,
        EOFValidationError::invalid_max_stack_height);

    add_test_case("EF0001 010008 0200020C010001 040000 00 008003FF 00000000" + 0x400 * bytecode{1} +
                      0x400 * OP_POP + OP_STOP + OP_RETF,
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
    add_test_case("EF0001 010004 0200010004 040000 00 00800000 E3000100",
        EOFValidationError::invalid_code_section_index);
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

TEST_F(eof_validation, many_code_sections_1023)
{
    std::string code_sections_1023;
    for (auto i = 0; i < 1022; ++i)
        code_sections_1023 += "E5" + hex(big_endian(static_cast<uint16_t>(i + 1)));
    code_sections_1023 += "5B5B00";

    const auto code = "EF0001 010FFC 0203FF " + 1023 * bytecode{"0003"} + "040000 00" +
                      1023 * bytecode{"00800000"} + code_sections_1023;

    add_test_case(code, EOFValidationError::success);
}

TEST_F(eof_validation, many_code_sections_1024)
{
    std::string code_sections_1024;
    for (auto i = 0; i < 1023; ++i)
        code_sections_1024 += "E5" + hex(big_endian(static_cast<uint16_t>(i + 1)));
    code_sections_1024 += "5B5B00";

    const auto code = "EF0001 011000 020400 " + 1024 * bytecode{"0003"} + "040000 00" +
                      1024 * bytecode{"00800000"} + code_sections_1024;

    add_test_case(code, EOFValidationError::success);
}

TEST_F(eof_validation, too_many_code_sections)
{
    add_test_case("ef0001 011004 020401" + 1025 * bytecode{"0001"} + "040000 00" +
                      1025 * bytecode{"00800000"} + bytecode{bytes(1025, OP_STOP)},
        EOFValidationError::too_many_code_sections);
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
    add_test_case(
        "EF0001 010004 0200010005 040020 00 00800001 D100005000 "
        "0000000000000000111111111111111122222222222222223333333333333333",
        EOFValidationError::success);

    // DATALOADN{1}
    add_test_case(
        "EF0001 010004 0200010005 040021 00 00800001 D100015000"
        "000000000000000011111111111111112222222222222222333333333333333344",
        EOFValidationError::success);

    // DATALOADN{32}
    add_test_case(
        "EF0001 010004 0200010005 040040 00 00800001 D100205000"
        "0000000000000000111111111111111122222222222222223333333333333333"
        "0000000000000000111111111111111122222222222222223333333333333333",
        EOFValidationError::success);

    // DATALOADN{0} - no data section
    add_test_case("EF0001 010004 0200010005 040000 00 00800001 D100005000",
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{1} - out of data section bounds
    add_test_case("EF0001 010004 0200010005 040001 00 00800001 D100015000 00",
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - out of data section bounds
    add_test_case(
        "EF0001 010004 0200010005 040020 00 00800001 D100205000 "
        "0000000000000000111111111111111122222222222222223333333333333333",
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{uint16_max} - out of data section bounds
    add_test_case(
        "EF0001 010004 0200010005 040020 00 00800001 D1ffff5000"
        "0000000000000000111111111111111122222222222222223333333333333333",
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - truncated word
    add_test_case(
        "EF0001 010004 0200010005 04003F 00 00800001 D100205000"
        "0000000000000000111111111111111122222222222222223333333333333333"
        "00000000000000001111111111111111222222222222222233333333333333",
        EOFValidationError::invalid_dataloadn_index);
}

TEST_F(eof_validation, non_returning_status)
{
    // Non-returning with no JUMPF and no RETF
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 00", EOFValidationError::success);
    // Non-returning with JUMPF
    add_test_case("EF0001 010008 02000200030001 040000 00 0080000000800000 E50001 00",
        EOFValidationError::success);

    // Returning with RETF
    add_test_case("EF0001 010008 02000200040001 040000 00 0080000000000000 E3000100 E4",
        EOFValidationError::success);
    // Returning with JUMPF
    add_test_case(
        "EF0001 01000c 020003000400030001 040000 00 008000000000000000000000 E3000100 E50002 E4",
        EOFValidationError::success);
    // Returning with JUMPF to returning and RETF
    add_test_case(
        "EF0001 01000C 020003000500070001 040000 00 008000010100000100000000 5FE3000100 "
        "E10001E4E50002 E4",
        EOFValidationError::success);
    // Returning with JUMPF to non-returning and RETF
    add_test_case(
        "EF0001 010008 02000200050007 040000 00 0080000101000001 5FE3000100 E10001E4E50000",
        EOFValidationError::success);

    // Invalid with RETF
    add_test_case("EF0001 010008 02000200010001 040000 00 0080000000800000 00 E4",
        EOFValidationError::invalid_non_returning_flag);
    add_test_case("EF0001 010004 0200010001 040000 00 00800000 E4",
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning
    add_test_case(
        "EF0001 01000c 020003000100030001 040000 00 008000000080000000000000 00 E50002 E4",
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning
    add_test_case("EF0001 010008 02000200010003 040000 00 0080000000000000 00 E50000",
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning and RETF
    add_test_case(
        "EF0001 01000C 020003000100070001 040000 00 008000000180000100000000 00 E10001E4E50002 E4",
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning and RETF
    add_test_case("EF0001 010008 02000200010007 040000 00 0080000001800001 00 E10001E4E50000",
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
    add_test_case(
        "EF0001 010008 02000200040001 040000 00 00800000 00800000 "
        "E3000100 00",
        EOFValidationError::callf_to_non_returning_function);
}

TEST_F(eof_validation, jumpf_equal_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0003 0004 040000 00 00800003 00030000 00030003"_hex} +
        OP_CALLF + "0001" + OP_STOP + OP_JUMPF + "0002" + 3 * OP_PUSH0 + OP_RETF;

    add_test_case(code, EOFValidationError::success);
}

TEST_F(eof_validation, jumpf_compatible_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0005 0004 040000 00 00800005 00050002 00030003"_hex} +
        OP_CALLF + "0001" + OP_STOP + 2 * OP_PUSH0 + OP_JUMPF + "0002" + 3 * OP_PUSH0 + OP_RETF;

    add_test_case(code, EOFValidationError::success);
}

TEST_F(eof_validation, jumpf_incompatible_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0005 0004 040000 00 00800003 00030002 00050003"_hex} +
        OP_CALLF + "0001" + OP_STOP + OP_JUMPF + "0002" + 5 * OP_PUSH0 + OP_RETF;

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
    }
}
