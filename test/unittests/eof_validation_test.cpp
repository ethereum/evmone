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
    const bytecode& container, evmc_revision rev = EVMC_PRAGUE) noexcept
{
    return evmone::validate_eof(rev, container);
}
}  // namespace

TEST(eof_validation, get_error_message)
{
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::success), "success");
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::invalid_prefix), "invalid_prefix");
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::stack_overflow), "stack_overflow");
    EXPECT_EQ(evmone::get_error_message(EOFValidationError::impossible), "impossible");

    // NOLINTNEXTLINE(*.EnumCastOutOfRange)
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
    EXPECT_EQ(validate_eof("EFFF 01 010004 0200010003 030004 00 00800000 600000 AABBCCDD"),
        EOFValidationError::invalid_prefix);
}

TEST(eof_validation, validate_EOF_version)
{
    EXPECT_EQ(validate_eof("EF0002"), EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF"), EOFValidationError::eof_version_unknown);

    // valid except version
    EXPECT_EQ(validate_eof("EF0000 010004 0200010003 020004 00 00800000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF0002 010004 0200010003 020004 00 00800000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF 010004 0200010003 020004 00 00800000 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, valid_EOF1_code_pre_shanghai)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 00 00800000 FE", EVMC_PARIS),
        EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, minimal_valid_EOF1_code)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, minimal_valid_EOF1_code_with_data)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 00 00800000 FE DA"),
        EOFValidationError::success);
}

TEST(eof_validation, minimal_valid_EOF1_multiple_code_sections)
{
    // no data section
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 00  00800000 00800000  FE FE"),
        EOFValidationError::data_section_missing);
    // with data section
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 040001 00  00800000 00800000  FE FE DA"),
        EOFValidationError::success);

    // non-void input and output types
    EXPECT_EQ(validate_eof("EF0001 010010 0200040001000200020002 040000 00 "
                           "00800000 01800001 00010001 02030003"
                           "FE 5000 30e4 80e4"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_types_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 0200010001 040001 00 FE DA"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_types_section_0_size)
{
    EXPECT_EQ(
        validate_eof("EF0001 010000 0200010001 00 FE"), EOFValidationError::zero_section_size);
    EXPECT_EQ(validate_eof("EF0001 010000 0200010001 040001 00 FE DA"),
        EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_type_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 0200010001 030001 00 FE DA"),
        EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 00"), EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_code_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 010004 00"), EOFValidationError::code_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 040001 00 00800000 DA"),
        EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_code_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010004 020000 00"), EOFValidationError::zero_section_size);
    EXPECT_EQ(
        validate_eof("EF0001 010004 020000 040001 00 DA"), EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_data_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_data_section_before_code_section)
{
    EXPECT_EQ(validate_eof("EF0001 010004 030001 0200010001 00 00800000 AA FE"),
        EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_data_section_before_types_section)
{
    EXPECT_EQ(validate_eof("EF0001 040001 010004 0200010001 00 AA 00800000 FE"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_multiple_data_sections)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 040001 00 00800000 FE DA DA"),
        EOFValidationError::header_terminator_missing);
}

TEST(eof_validation, EOF1_unknown_section)
{
    EXPECT_EQ(validate_eof("EF0001 050001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 FF0001 00 FE"), EOFValidationError::type_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 050001 00 00800000 FE 00"),
        EOFValidationError::data_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 FF0001 00 00800000 FE 00"),
        EOFValidationError::data_section_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 050001 00 00800000 FE AA 00"),
        EOFValidationError::header_terminator_missing);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 FF0001 00 00800000 FE AA 00"),
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
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 04"),
        EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(
        validate_eof("EF0001 010004 0200010001 0400"), EOFValidationError::incomplete_section_size);
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
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001"),
        EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040001 FE AA"),
        EOFValidationError::header_terminator_missing);
}

TEST(eof_validation, EOF1_truncated_section)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00 008000"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00 00800000 FE"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040002 00 00800000 FE"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040002 00 00800000 FE AA"),
        EOFValidationError::invalid_section_bodies_size);
}

TEST(eof_validation, EOF1_code_section_offset)
{
    const auto eof =
        "EF0001 010008 02000200030001 040004 00 00800001 00800000 6001fe fe 0000 0000"_hex;
    ASSERT_EQ(validate_eof(EVMC_PRAGUE, eof), EOFValidationError::success);

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
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 FE DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040002 00 00800000 FE AABB DEADBEEF"),
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
    EXPECT_EQ(validate_eof("EF0001 010004 010004 02000200010001 00 00800000 00800000 FE FE"),
        EOFValidationError::code_section_missing);

    // Section order is must be (Types, Code+, Data)
    EXPECT_EQ(validate_eof("EF0001 030002 010001 010001 040002 00 0000 FE FE 0000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_type_section_not_first)
{
    EXPECT_EQ(validate_eof("EF0001 0200010001 010004 00 FE 00800000"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 02000200010001 010004 00 FE FE 00800000"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 0200010001 010004 040003 00 FE 00800000 AABBCC"),
        EOFValidationError::type_section_missing);

    EXPECT_EQ(validate_eof("EF0001 0200010001 040003 010004 00 FE AABBCC 00800000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, EOF1_invalid_type_section_size)
{
    EXPECT_EQ(validate_eof("EF0001 010001 0200010001 040000 00 00 FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(validate_eof("EF0001 010002 0200010001 040000 00 0080 FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(validate_eof("EF0001 010008 0200010001 040000 00 0080000000000000 FE"),
        EOFValidationError::invalid_type_section_size);

    EXPECT_EQ(validate_eof("EF0001 010008 020003000100010001 040000 00 0080000000800000 FE FE FE"),
        EOFValidationError::invalid_type_section_size);
    EXPECT_EQ(
        validate_eof(
            "EF0001 010010 020003000100010001 040000 00 00800000008000000080000000800000 FE FE FE"),
        EOFValidationError::invalid_type_section_size);
}

TEST(eof_validation, EOF1_invalid_section_0_type)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00000000 00"),
        EOFValidationError::invalid_first_section_type);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 040000 00 00010000 60005C"),
        EOFValidationError::invalid_first_section_type);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 01800000 FE"),
        EOFValidationError::invalid_first_section_type);
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 040000 00 02030000 60005C"),
        EOFValidationError::invalid_first_section_type);
}

TEST(eof_validation, EOF1_too_many_code_sections)
{
    const auto valid = "EF0001 011000" + bytecode{"020400"} + 0x400 * bytecode{"0001"} +
                       "040000 00" + 0x400 * bytecode{"00800000"} + 0x400 * bytecode{"FE"};
    EXPECT_EQ(validate_eof(valid), EOFValidationError::success);

    const auto invalid = "EF0001 011002" + bytecode{"020401"} + 0x401 * bytecode{"0001"} +
                         "040000 00" + 0x401 * bytecode{"00800000"} + 0x401 * bytecode{"FE"};
    EXPECT_EQ(validate_eof(invalid), EOFValidationError::too_many_code_sections);
}

TEST(eof_validation, EOF1_undefined_opcodes)
{
    const auto& gas_table = evmone::instr::gas_costs[EVMC_PRAGUE];

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        // PUSH*, DUPN, SWAPN, RJUMP*, CALLF, JUMPF, ***MODX require immediate argument to be valid,
        // checked in a separate test.
        if ((opcode >= OP_PUSH1 && opcode <= OP_PUSH32) || opcode == OP_DUPN ||
            opcode == OP_SWAPN || opcode == OP_RJUMP || opcode == OP_RJUMPI || opcode == OP_CALLF ||
            opcode == OP_RJUMPV || opcode == OP_DATALOADN || opcode == OP_JUMPF ||
            opcode == OP_ADDMODX || opcode == OP_SUBMODX || opcode == OP_MULMODX)
            continue;
        // These opcodes are deprecated since Prague.
        // gas_cost table current implementation does not allow to undef instructions.
        if (opcode == OP_JUMP || opcode == OP_JUMPI || opcode == OP_PC || opcode == OP_CALLCODE ||
            opcode == OP_SELFDESTRUCT)
            continue;

        auto cont =
            "EF0001 010004 0200010014 040000 00 00800000 6001"
            "80808080808080808080808080808080 "
            ""_hex;

        if (opcode == OP_RETF)
        {
            // RETF can be tested in 2nd code section.
            cont = "EF0001 010008 02000200010001 040000 00 00800000 00000000 00"_hex + OP_RETF;
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
        auto result = validate_eof(cont);
        EXPECT_EQ(result, expected) << hex(cont);
    }

    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 FE"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_truncated_push)
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
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0000000"),
        EOFValidationError::success);

    // offset = 3
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 040000 00 00800001 E00003600100E0FFFA"),
        EOFValidationError::success);

    // offset = -4
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 5BE0FFFC"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_valid_rjumpi)
{
    // offset = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800001 6000E1000000"),
        EOFValidationError::success);

    // offset = 3
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 040000 00 00800001 6000E100035B5B5B00"),
        EOFValidationError::success);

    // offset = -5
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800001 6000E1FFFB00"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_valid_rjumpv)
{
    // table = [0] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 040000 00 00800001 6000E2000000600100"),
        EOFValidationError::success);

    // table = [0,3] case = 0
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000E 040000 00 00800001 6000E20100000003600100600200"),
        EOFValidationError::success);

    // table = [0,3] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000E 040000 00 00800001 6002E20100000003600100600200"),
        EOFValidationError::success);

    // table = [0,3,-10] case = 2
    EXPECT_EQ(validate_eof(
                  "EF0001 010004 0200010010 040000 00 00800001 6002E20200000003FFF6600100600200"),
        EOFValidationError::success);
}

TEST(eof_validation, EOF1_rjump_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 E0"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00 00800000 E000"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjumpi_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010003 040000 00 00800000 6000E1"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 6000E100"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjumpv_truncated)
{
    // table = [0] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040000 00 00800000 6000E20000"),
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010007 040000 00 00800000 6000E201000000"),
        EOFValidationError::truncated_instruction);

    // table = [0,3] case = 2
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6002E2010000"),
        EOFValidationError::truncated_instruction);

    // table = [0,3,-10] case = 2
    EXPECT_EQ(validate_eof("EF0001 010004 0200010009 040000 00 00800000 6002E20200000003FF"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, EOF1_rjump_invalid_destination)
{
    // Into header (offset = -5)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0FFFB00"),
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -13)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0FFF300"),
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0000200"),
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0000100"),
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMP immediate (offset = -1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E0FFFF00"),
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E0FFFC00"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_rjumpi_invalid_destination)
{
    // Into header (offset = -7)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1FFF900"),
        EOFValidationError::invalid_rjump_destination);

    // To before code begin (offset = -15)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1FFF100"),
        EOFValidationError::invalid_rjump_destination);

    // To after code end (offset = 2)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1000200"),
        EOFValidationError::invalid_rjump_destination);

    // To code end (offset = 1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1000100"),
        EOFValidationError::invalid_rjump_destination);

    // To the same RJUMPI immediate (offset = -1)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1FFFF00"),
        EOFValidationError::invalid_rjump_destination);

    // To PUSH immediate (offset = -4)
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040000 00 00800000 6000E1FFFC00"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_rjumpv_invalid_destination)
{
    // table = [-23] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 040000 00 00800000 6000E200FFE96001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [-8] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 040000 00 00800000 6000E200FFF86001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [-1] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 040000 00 00800000 6000E200FFFF6001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [2] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 040000 00 00800000 6000E20000026001"),
        EOFValidationError::invalid_rjump_destination);

    // table = [3] case = 0
    EXPECT_EQ(validate_eof("EF0001 010004 0200010008 040000 00 00800000 6000E20000036001"),
        EOFValidationError::invalid_rjump_destination);


    // table = [0,3,-27] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFE56001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-12] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFF46001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,-1] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 040000 00 00800000 6002E20200000003FFFF6001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,5] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 040000 00 00800000 6002E2020000000300056001006002"),
        EOFValidationError::invalid_rjump_destination);

    // table = [0,3,6] case = 2
    EXPECT_EQ(
        validate_eof("EF0001 010004 020001000F 040000 00 00800000 6002E2020000000300066001006002"),
        EOFValidationError::invalid_rjump_destination);
}

TEST(eof_validation, EOF1_section_order)
{
    // 01 02 03
    EXPECT_EQ(validate_eof("EF0001 010004 0200010006 040002 00 00800001 6000E0000000 AABB"),
        EOFValidationError::success);

    // 01 03 02
    EXPECT_EQ(validate_eof("EF0001 010004 040002 0200010006 00 00800000 AABB 6000E0000000"),
        EOFValidationError::code_section_missing);

    // 02 01 03
    EXPECT_EQ(validate_eof("EF0001 0200010006 010004 040002 00 6000E0000000 00800000 AABB"),
        EOFValidationError::type_section_missing);

    // 02 03 01
    EXPECT_EQ(validate_eof("EF0001 0200010006 040002 010004 00 6000E0000000 AABB 00800000"),
        EOFValidationError::type_section_missing);

    // 03 01 02
    EXPECT_EQ(validate_eof("EF0001 040002 010004 0200010006 00 AABB 00800000 6000E0000000"),
        EOFValidationError::type_section_missing);

    // 03 02 01
    EXPECT_EQ(validate_eof("EF0001 040002 0200010006 010004 00 AABB 6000E0000000 00800000"),
        EOFValidationError::type_section_missing);
}

TEST(eof_validation, deprecated_instructions)
{
    for (auto op : {OP_CALLCODE, OP_SELFDESTRUCT, OP_JUMP, OP_JUMPI, OP_PC})
    {
        EXPECT_EQ(validate_eof(eof_bytecode(op)), EOFValidationError::undefined_instruction);
    }
}

TEST(eof_validation, max_arguments_count)
{
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 040000 00 00800000 7F7F007F 00 E4"),
        EOFValidationError::success);

    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 040000 00 00800000 80800080 00 E4"),
        EOFValidationError::inputs_outputs_num_above_limit);

    {
        auto code = bytecode{"EF0001 010008 020002000100FF 040000 00 00800000 007F007F"} + OP_STOP +
                    127 * bytecode{1} + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = bytecode{"EF0001 010008 02000200010101 040000 00 00800000 00810081"} + OP_STOP +
                    128 * bytecode{1} + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::inputs_outputs_num_above_limit);
    }

    {
        auto code = bytecode{"EF0001 010008 02000200010080 040000 00 00800000 7F00007F"} + OP_STOP +
                    127 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = bytecode{"EF0001 010008 02000200010081 040000 00 00800000 80000080"} + OP_STOP +
                    128 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::inputs_outputs_num_above_limit);
    }
}

TEST(eof_validation, max_stack_height)
{
    {
        auto code = bytecode{"EF0001 010008 02000200010BFE 040000 00 00800000 000003FF"} + OP_STOP +
                    0x3FF * bytecode{1} + 0x3FF * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = "EF0001 010008 0200020BFE0001 040000 00 008003FF 00000000" +
                    0x3FF * bytecode{1} + 0x3FF * OP_POP + OP_STOP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        auto code = bytecode{"EF0001 010008 02000200010C01 040000 00 00800000 00000400"} + OP_STOP +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::max_stack_height_above_limit);
    }

    {
        auto code = "EF0001 010008 0200020C010001 040000 00 00800400 00000000" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_STOP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::max_stack_height_above_limit);
    }

    {
        auto code = bytecode{"EF0001 010008 02000200010C01 040000 00 00800000 000003FF"} + OP_STOP +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::invalid_max_stack_height);
    }

    {
        auto code = "EF0001 010008 0200020C010001 040000 00 008003FF 00000000" +
                    0x400 * bytecode{1} + 0x400 * OP_POP + OP_STOP + OP_RETF;

        EXPECT_EQ(validate_eof(code), EOFValidationError::invalid_max_stack_height);
    }

    {
        auto code = eof_bytecode(rjumpi(2, 0) + 1 + OP_STOP, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }

    {
        auto code = eof_bytecode(rjumpi(-3, 0) + OP_STOP, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }

    {
        auto code = eof_bytecode(rjumpv({-4}, 0) + OP_STOP, 1);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_height_mismatch);
    }
}

TEST(eof_validation, EOF1_callf_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 E3"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00 00800000 E300"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, callf_invalid_code_section_index)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010004 040000 00 00800000 E3000100"),
        EOFValidationError::invalid_code_section_index);
}

TEST(eof_validation, callf_stack_overflow)
{
    {
        const auto code =
            eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                .code(512 * push(1) + OP_CALLF + "0001" + 512 * OP_POP + OP_RETF, 0, 0, 512);
        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code =
            eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                .code(513 * push(1) + OP_CALLF + "0001" + 513 * OP_POP + OP_RETF, 0, 0, 513);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code =
            eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                .code(1023 * push(1) + OP_CALLF + "0001" + 1023 * OP_POP + OP_RETF, 0, 0, 1023);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code =
            eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                .code(1023 * push(1) + OP_CALLF + "0002" + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
                .code(push0() + OP_POP + OP_RETF, 0, 0, 1);
        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code =
            eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP)
                .code(1023 * push(1) + OP_CALLF + "0002" + 1023 * OP_POP + OP_RETF, 0, 0, 1023)
                .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 0, 0, 2);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }
}

TEST(eof_validation, callf_with_inputs_stack_overflow)
{
    {
        const auto code =
            eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1019 * OP_POP + OP_RETURN, 1023)
                .code(bytecode{OP_POP} + OP_POP + OP_RETF, 2, 0, 2);

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code =
            eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                .code(push(1) + OP_POP + OP_RETF, 3, 3, 4);

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code =
            eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                .code(push0() + push0() + OP_RETF, 3, 5, 5);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code =
            eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1021 * OP_POP + OP_RETURN, 1023)
                .code(push0() + push0() + OP_POP + OP_POP + OP_RETF, 3, 3, 5);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code =
            eof_bytecode(1024 * push(1) + OP_CALLF + "0001" + 1020 * OP_POP + OP_RETURN, 1023)
                .code(push0() + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 3);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code =
            eof_bytecode(1023 * push(1) + OP_CALLF + "0001" + 1020 * OP_POP + OP_RETURN, 1023)
                .code(push0() + push0() + OP_POP + OP_POP + OP_POP + OP_POP + OP_RETF, 2, 0, 4);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }
}

TEST(eof_validation, incomplete_section_size)
{
    EXPECT_EQ(
        validate_eof("ef0001 010100 02003f 0100"), EOFValidationError::incomplete_section_size);
}

TEST(eof_validation, data_section_missing)
{
    EXPECT_EQ(validate_eof("ef0001 010004 0200010001 00 00800000 fe"),
        EOFValidationError::data_section_missing);
}

TEST(eof_validation, multiple_code_sections_headers)
{
    EXPECT_EQ(validate_eof("0xef0001 010008 020001 0004 020001 0005 040000 00 00800000 045c0000 "
                           "00405c00 00002e0005"),
        EOFValidationError::data_section_missing);
}

TEST(eof_validation, many_code_sections_1023)
{
    auto code = bytecode{"ef0001 010ffc 0203ff"} + 1023 * bytecode{"0001"} + "040000 00" +
                1023 * bytecode{"00800000"} + bytecode{bytes(1023, OP_STOP)};
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, many_code_sections_1024)
{
    auto code = bytecode{"ef0001 011000 020400"} + 1024 * bytecode{"0001"} + "040000 00" +
                1024 * bytecode{"00800000"} + bytecode{bytes(1024, OP_STOP)};
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, too_many_code_sections)
{
    auto code = bytecode{"ef0001 011004 020401"} + 1025 * bytecode{"0001"} + "040000 00" +
                1025 * bytecode{"00800000"} + bytecode{bytes(1025, OP_STOP)};
    EXPECT_EQ(validate_eof(code), EOFValidationError::too_many_code_sections);
}

TEST(eof_validation, EOF1_dataloadn_truncated)
{
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 E9"),
        EOFValidationError::truncated_instruction);

    EXPECT_EQ(validate_eof("EF0001 010004 0200010002 040000 00 00800000 E900"),
        EOFValidationError::truncated_instruction);
}

TEST(eof_validation, dataloadn)
{
    // DATALOADN{0}
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040020 00 00800001 E900005000"
                           "0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::success);

    // DATALOADN{1}
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040021 00 00800001 E900015000"
                           "000000000000000011111111111111112222222222222222333333333333333344"),
        EOFValidationError::success);

    // DATALOADN{32}
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040040 00 00800001 E900205000"
                           "0000000000000000111111111111111122222222222222223333333333333333"
                           "0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::success);

    // DATALOADN{0} - no data section
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040000 00 00800001 E900005000"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{1} - out of data section bounds
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040001 00 00800001 E900015000"
                           "00"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - out of data section bounds
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040020 00 00800001 E900205000"
                           "0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{uint16_max} - out of data section bounds
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 040020 00 00800001 E9ffff5000"
                           "0000000000000000111111111111111122222222222222223333333333333333"),
        EOFValidationError::invalid_dataloadn_index);

    // DATALOADN{32} - truncated word
    EXPECT_EQ(validate_eof("EF0001 010004 0200010005 04003F 00 00800001 E900205000"
                           "0000000000000000111111111111111122222222222222223333333333333333"
                           "00000000000000001111111111111111222222222222222233333333333333"),
        EOFValidationError::invalid_dataloadn_index);
}

TEST(eof_validation, callf_stack_validation)
{
    EXPECT_EQ(validate_eof(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                               .code(push0() + push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 2)
                               .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2)),
        EOFValidationError::success);

    EXPECT_EQ(
        validate_eof(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                         .code(push0() + push0() + push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 3)
                         .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2)),
        EOFValidationError::stack_higher_than_outputs_required);

    EXPECT_EQ(validate_eof(eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 1)
                               .code(push0() + OP_CALLF + "0002" + OP_RETF, 0, 1, 1)
                               .code(bytecode(OP_POP) + OP_RETF, 2, 1, 2)),
        EOFValidationError::stack_underflow);
}

TEST(eof_validation, retf_stack_validation)
{
    // 2 outputs, RETF has 2 values on stack
    auto code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
                    .code(push0() + push0() + OP_RETF, 0, 2, 2);
    EXPECT_EQ(validate_eof(code), EOFValidationError::success);

    // 2 outputs, RETF has 1 value on stack
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2).code(push0() + OP_RETF, 0, 2, 1);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_underflow);

    // 2 outputs, RETF has 3 values on stack
    code = eof_bytecode(bytecode{OP_CALLF} + "0001" + OP_STOP, 2)
               .code(push0() + push0() + push0() + OP_RETF, 0, 2, 3);
    EXPECT_EQ(validate_eof(code), EOFValidationError::stack_higher_than_outputs_required);
}

TEST(eof_validation, non_returning_status)
{
    // Non-returning with no JUMPF and no RETF
    EXPECT_EQ(validate_eof("EF0001 010004 0200010001 040000 00 00800000 00"),
        EOFValidationError::success);
    // Non-returning with JUMPF
    EXPECT_EQ(validate_eof("EF0001 010008 02000200030001 040000 00 0080000000800000 E50001 00"),
        EOFValidationError::success);

    // Returning with RETF
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 040000 00 0080000000000000 00 E4"),
        EOFValidationError::success);
    // Returning with JUMPF
    EXPECT_EQ(
        validate_eof(
            "EF0001 01000c 020003000100030001 040000 00 008000000000000000000000 00 E50002 E4"),
        EOFValidationError::success);
    // Returning with JUMPF to returning and RETF
    EXPECT_EQ(validate_eof("EF0001 01000C 020003000100070001 040000 00 008000000100000100000000 00 "
                           "E10001E4E50002 E4"),
        EOFValidationError::success);
    // Returning with JUMPF to non-returning and RETF
    EXPECT_EQ(
        validate_eof("EF0001 010008 02000200010007 040000 00 0080000001000001 00 E10001E4E50000"),
        EOFValidationError::success);

    // Invalid with RETF
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010001 040000 00 0080000000800000 00 E4"),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning
    EXPECT_EQ(
        validate_eof(
            "EF0001 01000c 020003000100030001 040000 00 008000000080000000000000 00 E50002 E4"),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning
    EXPECT_EQ(validate_eof("EF0001 010008 02000200010003 040000 00 0080000000000000 00 E50000"),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to returning and RETF
    EXPECT_EQ(validate_eof("EF0001 01000C 020003000100070001 040000 00 008000000180000100000000 00 "
                           "E10001E4E50002 E4"),
        EOFValidationError::invalid_non_returning_flag);
    // Invalid with JUMPF to non-returning and RETF
    EXPECT_EQ(
        validate_eof("EF0001 010008 02000200010007 040000 00 0080000001800001 00 E10001E4E50000"),
        EOFValidationError::invalid_non_returning_flag);
}

TEST(eof_validation, callf_into_nonreturning)
{
    // function 0: (0, non-returning) : CALLF{1} STOP
    // function 2: (1, non-returning) : STOP
    EXPECT_EQ(validate_eof("EF0001 010008 02000200040001 040000 00 00800000 00800000 "
                           "E3000100 00"),
        EOFValidationError::callf_to_non_returning_function);
}

TEST(eof_validation, jumpf_equal_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0003 0004 040000 00 00800003 00030000 00030003"_hex} +
        OP_CALLF + "0001" + OP_STOP + OP_JUMPF + "0002" + 3 * OP_PUSH0 + OP_RETF;

    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, jumpf_compatible_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0005 0004 040000 00 00800005 00050002 00030003"_hex} +
        OP_CALLF + "0001" + OP_STOP + 2 * OP_PUSH0 + OP_JUMPF + "0002" + 3 * OP_PUSH0 + OP_RETF;

    EXPECT_EQ(validate_eof(code), EOFValidationError::success);
}

TEST(eof_validation, jumpf_incompatible_outputs)
{
    const auto code =
        bytecode{"ef0001 01000c 020003 0004 0005 0004 040000 00 00800003 00030002 00050003"_hex} +
        OP_CALLF + "0001" + OP_STOP + OP_JUMPF + "0002" + 5 * OP_PUSH0 + OP_RETF;

    EXPECT_EQ(validate_eof(code), EOFValidationError::jumpf_destination_incompatible_outputs);
}

TEST(eof_validation, jumpf_into_nonreturning_stack_validation)
{
    // Exactly required inputs on stack at JUMPF
    EXPECT_EQ(
        validate_eof("EF0001 010008 02000200060001 040000 00 0080000303800003 5F5F5FE50001 00"),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    EXPECT_EQ(
        validate_eof("EF0001 010008 02000200070001 040000 00 0080000403800003 5F5F5F5FE50001 00"),
        EOFValidationError::success);

    // Not enough inputs on stack at JUMPF
    EXPECT_EQ(validate_eof("EF0001 010008 02000200050001 040000 00 0080000203800003 5F5FE50001 00"),
        EOFValidationError::stack_underflow);
}

TEST(eof_validation, jumpf_into_returning_stack_validation)
{
    // JUMPF into a function with the same number of outputs as current one

    // Exactly required inputs on stack at JUMPF
    EXPECT_EQ(validate_eof(eof_bytecode(bytecode{OP_STOP})
                               .code(push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 3)
                               .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3)),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    EXPECT_EQ(
        validate_eof(eof_bytecode(bytecode{OP_STOP})
                         .code(push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 4)
                         .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3)),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    EXPECT_EQ(validate_eof(eof_bytecode(bytecode{OP_STOP})
                               .code(push0() + push0() + OP_JUMPF + "0002", 0, 2, 2)
                               .code(bytecode(OP_POP) + OP_RETF, 3, 2, 3)),
        EOFValidationError::stack_underflow);

    // JUMPF into a function with fewer outputs than current one
    // (0, 2) --JUMPF--> (3, 1): 3 inputs + 1 output = 4 items required

    // Exactly required inputs on stack at JUMPF
    EXPECT_EQ(
        validate_eof(eof_bytecode(bytecode{OP_STOP})
                         .code(push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 4)
                         .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3)),
        EOFValidationError::success);

    // Extra items on stack at JUMPF
    EXPECT_EQ(
        validate_eof(
            eof_bytecode(bytecode{OP_STOP})
                .code(push0() + push0() + push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 5)
                .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3)),
        EOFValidationError::stack_higher_than_outputs_required);

    // Not enough inputs on stack at JUMPF
    EXPECT_EQ(validate_eof(eof_bytecode(bytecode{OP_STOP})
                               .code(push0() + push0() + push0() + OP_JUMPF + "0002", 0, 2, 3)
                               .code(bytecode(OP_POP) + OP_POP + OP_RETF, 3, 1, 3)),
        EOFValidationError::stack_underflow);
}

TEST(eof_validation, jumpf_stack_overflow)
{
    {
        const auto code = eof_bytecode(512 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 512);
        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code = eof_bytecode(513 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 513);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code = eof_bytecode(1023 * push(1) + OP_JUMPF + bytecode{"0x0000"_hex}, 1023);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code = eof_bytecode(1023 * push(1) + OP_JUMPF + "0001", 1023)
                              .code(push0() + OP_STOP, 0, 0x80, 1);
        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code = eof_bytecode(1023 * push(1) + OP_JUMPF + "0001", 1023)
                              .code(push0() + push0() + OP_STOP, 0, 0x80, 2);
        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }
}

TEST(eof_validation, jumpf_with_inputs_stack_overflow)
{
    {
        const auto code = eof_bytecode(1023 * push0() + OP_JUMPF + "0001", 1023)
                              .code(push0() + OP_STOP, 2, 0x80, 3);

        EXPECT_EQ(validate_eof(code), EOFValidationError::success);
    }

    {
        const auto code = eof_bytecode(1023 * push0() + OP_JUMPF + "0001", 1023)
                              .code(push0() + push0() + OP_STOP, 2, 0x80, 4);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }

    {
        const auto code = eof_bytecode(1024 * push0() + OP_JUMPF + "0001", 1023)
                              .code(push0() + OP_STOP, 2, 0x80, 3);

        EXPECT_EQ(validate_eof(code), EOFValidationError::stack_overflow);
    }
}
