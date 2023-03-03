// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <evmone/instructions_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;

namespace
{
// Can be called as validate_eof(string_view hex, rev) or validate_eof(bytes_view cont, rev).
inline EOFValidationError validate_eof(
    const bytecode& container, evmc_revision rev = EVMC_CANCUN) noexcept
{
    return evmone::validate_eof(rev, container);
}
}  // namespace

TEST(eof_validation, get_error_message)
{
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::success), "success");
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::invalid_prefix), "invalid_prefix");
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::impossible), "impossible");
    EXPECT_EQ(evmone::get_error_message(static_cast<EOFValidationError>(-1)), "<unknown>");
}

TEST(eof_validation, validate_empty_code)
{
    EXPECT_EQ(validate_eof(""), EOFValidationError::invalid_prefix);
}

TEST(eof_validation, validate_EOF_prefix)
{
    EXPECT_EQ(validate_eof("00"), EOFValidationError::invalid_prefix);
    EXPECT_EQ(validate_eof("FE"), EOFValidationError::invalid_prefix);
    EXPECT_EQ(validate_eof("EF"), EOFValidationError::invalid_prefix);

    EXPECT_EQ(validate_eof("EF0101"), EOFValidationError::invalid_prefix);
    EXPECT_EQ(validate_eof("EFEF01"), EOFValidationError::invalid_prefix);
    EXPECT_EQ(validate_eof("EFFF01"), EOFValidationError::invalid_prefix);

    EXPECT_EQ(validate_eof("EF00"), EOFValidationError::eof_version_unknown);

    EXPECT_EQ(validate_eof("EF0001"), EOFValidationError::section_headers_not_terminated);

    // valid except for magic
    EXPECT_EQ(validate_eof("EFFF 01 010004 0200010003 030004 00 00000000 600000 AABBCCDD"),
        EOFValidationError::invalid_prefix);
}

TEST(eof_validation, validate_EOF_version)
{
    EXPECT_EQ(validate_eof("EF0002"), EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF"), EOFValidationError::eof_version_unknown);

    // valid except version
    EXPECT_EQ(validate_eof("EF0000 010004 0200010003 020004 00 00000000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF0002 010004 0200010003 020004 00 00000000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF 010004 0200010003 020004 00 00000000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, valid_EOF1_code_pre_shanghai)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 00 00000000 FE", EVMC_PARIS),
        EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, minimal_valid_EOF1_code)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030000 00 00000000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, minimal_valid_EOF1_code_with_data)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001 00 00000000 FE DA"),
        EOFValidationError::success);
}

TEST(eof_validation, minimal_valid_EOF1_multiple_code_sections)
{
    // no data section
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 00  00000000 00000000  FE FE"),
        EOFValidationError::data_section_missing);
    // with data section
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 030001 00  00000000 00000000  FE FE DA"),
        EOFValidationError::success);

    // non-void input and output types
    EXPECT_EQ(validate_eof("EF0001 010010 0200040001000200020002 030000 00 "
                           "00000000 01000001 00010001 02030003"
                           "FE 5000 3000 8000"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_types_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 0200010001 030001 00 FE DA"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_types_section_0_size)
{
    EXPECT_EQ(
        validate_eof("EF0001 010000 0200010001 00 FE"), EOFValidationError::zero_section_size);
    EXPECT_EQ(validate_eof("EF0001 010000 0200010001 030001 00 FE DA"),
        EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_type_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 00"), EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_code_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 010004 00"), EOFValidationError::code_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 030001 00 00000000 DA"),
        EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_code_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010004 020000 00"), EOFValidationError::zero_section_size);
    EXPECT_EQ(
        validate_eof("EF0001 010004 020000 030001 00 DA"), EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_data_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030000 00 00000000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_data_section_before_code_section)
{
    EXPECT_EQ(validate_eof("EF0001 010004 030001 0200010001 00 00000000 AA FE"),
        EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_data_section_before_types_section)
{
    EXPECT_EQ(validate_eof("EF0001 030001 010004 0200010001 00 AA 00000000 FE"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_multiple_data_sections)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001 030001 00 00000000 FE DA DA"),
        EOFValidationError::header_terminator_missing);
}

TEST(eof_validation, EOF1_unknown_section)
{
    EXPECT_EQ(validate_eof("EF0001 040001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 FF0001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 00 00000000 FE 00"),
        EOFValidationError::data_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 FF0001 00 00000000 FE 00"),
        EOFValidationError::data_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001 040001 00 00000000 FE AA 00"),
        EOFValidationError::header_terminator_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001 FF0001 00 00000000 FE AA 00"),
        EOFValidationError::header_terminator_missing);
}

TEST(eof_validation, EOF1_incomplete_section_size)
{
    // TODO: section_headers_not_terminated should rather be incomplete_section_size
    //  in these examples.

    EXPECT_EQ(validate_eof("EF0001 01"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 0100"), EOFValidationError::incomplete_section_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200"), EOFValidationError::incomplete_section_number);
    EXPECT_EQ(validate_eof("EF0001 010004 02000100"), EOFValidationError::incomplete_section_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001"),
        EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 03"),
        EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(
        validate_eof("EF0001 010004 0200010001 0300"), EOFValidationError::incomplete_section_size);
}

TEST(eof_validation, EOF1_header_not_terminated)
{
    EXPECT_EQ(validate_eof("EF0001 01"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004 FE"), EOFValidationError::code_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 02"), EOFValidationError::incomplete_section_number);
    EXPECT_EQ(validate_eof("EF0001 010004 0200"), EOFValidationError::incomplete_section_number);
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001"),
        EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030001 FE AA"),
        EOFValidationError::header_terminator_missing);
}

TEST(eof_validation, EOF1_truncated_section)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 030000 00"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 030000 00 000000"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 030000 00 00000000 FE"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030002 00 00000000 FE"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030002 00 00000000 FE AA"),
        EOFValidationError::invalid_section_bodies_size);
}

TEST(eof_validation, EOF1_code_section_offset)
{
    const auto eof =
        "EF0001 010008 02000200030001 030004 00 00000001 00000000 6001fe fe 0000 0000"_hex;
    ASSERT_EQ(validate_eof(EVMC_CANCUN, eof), EOFValidationError::success);

    const auto header = read_valid_eof1_header(eof);
    ASSERT_EQ(header.code_sizes.size(), 2);
    EXPECT_EQ(header.code_sizes[0], 3);
    EXPECT_EQ(header.code_sizes[1], 1);
    ASSERT_EQ(header.code_offsets.size(), 2);
    EXPECT_EQ(header.code_offsets[0], 25);
    EXPECT_EQ(header.code_offsets[1], 28);
}

TEST(eof_validation, EOF1_trailing_bytes)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030000 00 00000000 FE DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030002 00 00000000 FE AABB DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
}

TEST(eof_validation, EOF1_no_type_section)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(
        validate_eof("EF0001 02000200010001 00 FE FE"), EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_multiple_type_sections)
{
    EXPECT_EQ(validate_eof("EF0001 010004 010004 02000200010001 00 00000000 00000000 FE FE"),
        EOFValidationError::code_section_missing);

    // Section order is must be (Types, Code+, Data)
    EXPECT_EQ(validate_eof("EF0001 030002 010001 010001 030002 00 0000 FE FE 0000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_type_section_not_first)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 010004 00 FE 00000000"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 02000200010001 010004 00 FE FE 00000000"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 0200010001 010004 030003 00 FE 00000000 AABBCC"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 0200010001 030003 010004 00 FE AABBCC 00000000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_invalid_type_section_size)
{
    EXPECT_EQ(validate_eof("EF0001 010001 0200010001 030000 00 00 FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(validate_eof("EF0001 010002 0200010001 030000 00 0000 FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(validate_eof("EF0001 010008 0200010001 030000 00 0000000000000000 FE"),
        EOFValidationError::invalid_type_section_size);

    EXPECT_EQ(validate_eof("EF0001 010008 020003000100010001 030000 00 0000000000000000 FE FE FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(
        validate_eof(
            "EF0001 010010 020003000100010001 030000 00 00000000000000000000000000000000 FE FE FE"),
        EOFValidationError::invalid_type_section_size);
}

TEST(eof_validation, EOF1_invalid_section_0_type)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 030000 00 00010000 60005C"),
        EOFValidationError::invalid_first_section_type);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 030000 00 01000000 5000"),
        EOFValidationError::invalid_first_section_type);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 030000 00 02030000 60005C"),
        EOFValidationError::invalid_first_section_type);
}

TEST(eof_validation, EOF1_too_many_code_sections)
{
    const auto valid = "EF0001 011000" + bytecode{"020400"} + 0x400 * bytecode{"0001"} +
                       "030000 00" + 0x400 * bytecode{"00000000"} + 0x400 * bytecode{"FE"};
    EXPECT_EQ(validate_eof(valid), EOFValidationError::success);

    const auto invalid = "EF0001 011002" + bytecode{"020401"} + 0x401 * bytecode{"0001"} +
                         "030000 00" + 0x401 * bytecode{"00000000"} + 0x401 * bytecode{"FE"};
    EXPECT_EQ(validate_eof(invalid), EOFValidationError::too_many_code_sections);
}

TEST(eof_validation, EOF1_undefined_opcodes)
{
    const auto& gas_table = evmone::instr::gas_costs[EVMC_CANCUN];

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        // PUSH*, DUPN, SWAPN, RJUMP*, CALLF require immediate argument to be valid,
        // checked in a separate test.
        if ((opcode >= OP_PUSH1 && opcode <= OP_PUSH32) || opcode == OP_DUPN ||
            opcode == OP_SWAPN || opcode == OP_RJUMP || opcode == OP_RJUMPI ||
            opcode == OP_RJUMPV || opcode == OP_CALLF)
            continue;
        // These opcodes are deprecated since Cancun.
        // gas_cost table current implementation does not allow to undef instructions.
        if (opcode == OP_JUMP || opcode == OP_JUMPI || opcode == OP_PC || opcode == OP_CALLCODE ||
            opcode == OP_SELFDESTRUCT)
            continue;

        auto cont =
            "EF0001 010004 0200010014 030000 00 00000000 6001"
            "80808080808080808080808080808080 "
            ""_hex;

        if (opcode == OP_RETF)
        {
            cont += "5050505050505050505050505050505050"_hex;
            cont += static_cast<uint8_t>(opcode);
            cont[10] = 0x24;
        }
        else
        {
            cont += static_cast<uint8_t>(opcode);
            if (!instr::traits[opcode].is_terminating)
                cont += "00"_hex;
            else
                cont[10] = 0x13;
        }

        auto op_stack_change = instr::traits[opcode].stack_height_change;
        cont[18] = static_cast<uint8_t>(op_stack_change <= 0 ? 17 : 17 + op_stack_change);

        const auto expected = (gas_table[opcode] == evmone::instr::undefined ?
                                   EOFValidationError::undefined_instruction :
                                   EOFValidationError::success);
        auto result = validate_eof(cont);
        EXPECT_EQ(result, expected) << hex(cont);
    }

    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030000 00 00000000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_truncated_push)
{
    auto eof_header = "EF0001 010004 0200010001 030000 00 00000000"_hex;
    auto& code_size_byte = eof_header[10];
    for (uint8_t opcode = OP_PUSH1; opcode <= OP_PUSH32; ++opcode)
    {
        const auto required_bytes = static_cast<size_t>(opcode) - OP_PUSH1 + 1;
        for (size_t i = 0; i < required_bytes; ++i)
        {
            const bytes code{opcode + bytes(i, 0)};
            code_size_byte = static_cast<uint8_t>(code.size());
            const auto container = eof_header + code;

            EXPECT_EQ(validate_eof(container), EOFValidationError::truncated_instruction)
                << hex(container);
        }

        const bytes code{opcode + bytes(required_bytes, 0) + uint8_t{OP_STOP}};
        code_size_byte = static_cast<uint8_t>(code.size());

        eof_header[18] = static_cast<uint8_t>(instr::traits[opcode].stack_height_change);

        const auto container = eof_header + code;

        EXPECT_EQ(validate_eof(container), EOFValidationError::success) << hex(container);
    }
}

TEST(eof_validation, EOF1_valid_rjump)
{
    // offset = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5C000000"),
        EOFValidationError::success);

    // offset = 3
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 030000 00 00000001 5C00036001005CFFFA"),
        EOFValidationError::success);

    // offset = -4
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5B5CFFFC"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_valid_rjumpi)
{
    // offset = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000001 60005D000000"),
        EOFValidationError::success);

    // offset = 3
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 030000 00 00000001 60005D00035B5B5B00"),
        EOFValidationError::success);

    // offset = -5
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000001 60005DFFFB00"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_valid_rjumpv)
{
    // table = [0] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 030000 00 00000001 60005E010000600100"),
        EOFValidationError::success);

    // table = [0,3] case = 0
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000E 030000 00 00000001 60005E0200000003600100600200"),
        EOFValidationError::success);

    // table = [0,3] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000E 030000 00 00000001 60025E0200000003600100600200"),
        EOFValidationError::success);

    // table = [0,3,-10] case = 2
    EXPECT_EQ(validate_eof(
                  "EF0001 010004 0200010010 030000 00 00000001 60025E0300000003FFF6600100600200"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_rjump_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 030000 00 00000000 5C"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 030000 00 00000000 5C00"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjumpi_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 030000 00 00000000 60005D"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 60005D00"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjumpv_truncated)
{
    // table = [0] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 030000 00 00000000 60005E0100"),
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010007 030000 00 00000000 60005E02000000"),
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 2
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60025E020000"),
        EOFValidationError::truncated_instruction);

    // table = [0,3,-10] case = 2
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 030000 00 00000000 60025E0300000003FF"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjumpv_0_count)
{
    auto code = eof1_bytecode(rjumpv({}, 0) + OP_STOP, 1);

    EXPECT_EQ(validate_eof(code), EOFValidationError::invalid_rjumpv_count);
}

TEST(eof_validation, EOF1_rjump_invalid_destination)
{
    // Into header (offset = -5)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5CFFFB00"),
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -13)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5CFFF300"),
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5C000200"),
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5C000100"),
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMP immediate (offset = -1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 5CFFFF00"),
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005CFFFC00"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_rjumpi_invalid_destination)
{
    // Into header (offset = -7)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005DFFF900"),
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -15)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005DFFF100"),
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005D000200"),
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005D000100"),
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMPI immediate (offset = -1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005DFFFF00"),
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030000 00 00000000 60005DFFFC00"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_rjumpv_invalid_destination)
{
    // table = [-23] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 030000 00 00000000 60005E01FFE96001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [-8] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 030000 00 00000000 60005E01FFF86001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [-1] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 030000 00 00000000 60005E01FFFF6001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [2] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 030000 00 00000000 60005E0100026001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [3] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 030000 00 00000000 60005E0100036001"),
        EOFValidationError::invalid_rjump_destination);


    // table = [0,3,-27] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 030000 00 00000000 60025E0300000003FFE56001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-12] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 030000 00 00000000 60025E0300000003FFF46001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-1] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 030000 00 00000000 60025E0300000003FFFF6001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,5] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 030000 00 00000000 60025E030000000300056001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,6] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 030000 00 00000000 60025E030000000300066001006002"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_section_order)
{
    // 01 02 03
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 030002 00 00000001 60005D000000 AABB"),
        EOFValidationError::success);

    // 01 03 02
    EXPECT_EQ(validate_eof("EF0001 010004 030002 0200010006 00 00000000 AABB 60005D000000"),
        EOFValidationError::code_section_missing);

    // 02 01 03
    EXPECT_EQ(validate_eof("EF0001 0200010006 010004 030002 00 60005D000000 00000000 AABB"),
        EOFValidationError::type_section_missing);

    // 02 03 01
    EXPECT_EQ(validate_eof("EF0001 0200010006 030002 010004 00 60005D000000 AABB 00000000"),
        EOFValidationError::type_section_missing);

    // 03 01 02
    EXPECT_EQ(validate_eof("EF0001 030002 010004 0200010006 00 AABB 00000000 60005D000000"),
        EOFValidationError::type_section_missing);

    // 03 02 01
    EXPECT_EQ(validate_eof("EF0001 030002 0200010006 010004 00 AABB 60005D000000 00000000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, deprecated_instructions)
{
    for (auto op : {OP_CALLCODE, OP_SELFDESTRUCT, OP_JUMP, OP_JUMPI, OP_PC})
    {
        EXPECT_EQ(validate_eof(eof1_bytecode(op)), EOFValidationError::undefined_instruction);
    }
}

TEST(eof_valication, max_arguments_count)
{
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 030000 00 00000000 7F7F007F B1 B1"),
        EOFValidationError::success);

    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 030000 00 00000000 80800080 B1 B1"),
        EOFValidationError::inputs_outputs_num_above_limit);

    {
        auto code = "EF0001 010008 020002000100FF 030000 00 00000000 007F007F B1" +
                    127 * bytecode{1} + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = "EF0001 010008 02000200010101 030000 00 00000000 00800080 B1" +
                    128 * bytecode{1} + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::inputs_outputs_num_above_limit);
    }

    {
        auto code =
            "EF0001 010008 02000200010080 030000 00 00000000 7F00007F B1" + 127 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code =
            "EF0001 010008 02000200010081 030000 00 00000000 80000080 B1" + 128 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::inputs_outputs_num_above_limit);
    }
}

TEST(eof_valication, max_stack_heigh)
{
    {
        auto code = "EF0001 010008 02000200010BFE 030000 00 00000000 000003FF B1" +
                    0x3FF * bytecode{1} + 0x3FF * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = "EF0001 010008 0200020BFE0001 030000 00 000003FF 00000000" +
                    0x3FF * bytecode{1} + 0x3FF * OP_POP + OP_RETF + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = "EF0001 010008 02000200010C01 030000 00 00000000 00000400 B1" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::max_stack_height_above_limit);
    }

    {
        auto code = "EF0001 010008 0200020C010001 030000 00 00000400 00000000" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::max_stack_height_above_limit);
    }

    {
        auto code = "EF0001 010008 02000200010C01 030000 00 00000000 000003FF B1" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::invalid_max_stack_height);
    }

    {
        auto code = "EF0001 010008 0200020C010001 030000 00 000003FF 00000000" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::invalid_max_stack_height);
    }

    {
        auto code = eof1_bytecode(rjumpi(2, 0) + 1 + OP_RETF, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }

    {
        auto code = eof1_bytecode(rjumpi(-3, 0) + OP_RETF, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }

    {
        auto code = eof1_bytecode(rjumpv({-4}, 0) + OP_RETF, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }
}

TEST(eof_validation, callf_invalid_code_section_index)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 030000 00 00000000 b0000100"),
        EOFValidationError::invalid_code_section_index);
}

TEST(eof_validation, incomplete_section_size)
{
    EXPECT_EQ(
        validate_eof("ef0001 010100 02003f 0100"), EOFValidationError::incomplete_section_size);
}

TEST(eof_validation, data_section_missing)
{
    EXPECT_EQ(validate_eof("ef0001 010004 0200010001 00 00000000 fe"),
        EOFValidationError::data_section_missing);
}

TEST(eof_validation, multiple_code_sections_headers)
{
    EXPECT_EQ(validate_eof("0xef0001 010008 020001 0004 020001 0005 030000 00 00040000 045c0000 "
                           "00405c00 00002e0005"),
        EOFValidationError::data_section_missing);
}

TEST(eof_validation, many_code_sections_1023)
{
    auto code =
        "0xef0001010ffc0203ff0001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010300000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000";
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, many_code_sections_1024)
{
    auto code =
        "0xef00010110000204000001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001030000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000";
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, too_many_code_sections)
{
    auto code =
        "0xef00010110040204010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000100010001000100010001"
        "000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100"
        "010001000100010001000100010001000100010001000100010001000100010001000103000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_EQ(validate_eof(code), EOFValidationError::too_many_code_sections);
}
