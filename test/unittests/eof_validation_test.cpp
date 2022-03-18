// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

namespace
{
inline EOFValidationError validate_eof(
    std::string_view code_hex, evmc_revision rev = EVMC_SHANGHAI) noexcept
{
    return ::validate_eof(rev, from_hex(code_hex));
}
}  // namespace

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
    EXPECT_EQ(validate_eof("EFFF01 010003 020004 00 600000 AABBCCDD"),
        EOFValidationError::invalid_prefix);
}

TEST(eof_validation, validate_EOF_version)
{
    EXPECT_EQ(validate_eof("EF0002"), EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF"), EOFValidationError::eof_version_unknown);

    // valid except version
    EXPECT_EQ(validate_eof("EF00000 10003 020004 00 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00020 10003 020004 00 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF0 10003 020004 00 600000 AABBCCDD"),
        EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, valid_EOF1_code_pre_shanghai)
{
    EXPECT_EQ(
        validate_eof("EF0001 010001 00 FE", EVMC_PARIS), EOFValidationError::eof_version_unknown);
}

TEST(eof_validation, minimal_valid_EOF1_code)
{
    EXPECT_EQ(validate_eof("EF0001 010001 00 FE"), EOFValidationError::success);
}

TEST(eof_validation, minimal_valid_EOF1_code_with_data)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020001 00 FE DA"), EOFValidationError::success);
}

TEST(eof_validation, EOF1_code_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 00"), EOFValidationError::code_section_missing);
    EXPECT_EQ(validate_eof("EF0001 020001 DA"), EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_code_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010000 00"), EOFValidationError::zero_section_size);
    EXPECT_EQ(validate_eof("EF0001 010000 020001 00 DA"), EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_data_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020000 00 FE"), EOFValidationError::zero_section_size);
}

TEST(eof_validation, EOF1_multiple_code_sections)
{
    EXPECT_EQ(
        validate_eof("EF0001 010001 010001 00 FE FE"), EOFValidationError::multiple_code_sections);
    EXPECT_EQ(validate_eof("EF0001 010001 010001 020001 00 FE FE DA"),
        EOFValidationError::multiple_code_sections);
}

TEST(eof_validation, EOF1_data_section_before_code_section)
{
    EXPECT_EQ(
        validate_eof("EF0001 020001 010001 00 AA FE"), EOFValidationError::code_section_missing);
}

TEST(eof_validation, EOF1_multiple_data_sections)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020001 020001 00 FE DA DA"),
        EOFValidationError::multiple_data_sections);
}

TEST(eof_validation, EOF1_unknown_section)
{
    EXPECT_EQ(validate_eof("EF0001 030001 00 FE"), EOFValidationError::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 FF0001 00 FE"), EOFValidationError::unknown_section_id);
    EXPECT_EQ(
        validate_eof("EF0001 010001 030001 00 FE 00"), EOFValidationError::unknown_section_id);
    EXPECT_EQ(
        validate_eof("EF0001 010001 FF0001 00 FE 00"), EOFValidationError::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 030001 00 FE AA 00"),
        EOFValidationError::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 FF0001 00 FE AA 00"),
        EOFValidationError::unknown_section_id);
}

TEST(eof_validation, EOF1_incomplete_section_size)
{
    EXPECT_EQ(validate_eof("EF0001 0100"), EOFValidationError::incomplete_section_size);
    EXPECT_EQ(validate_eof("EF0001 010001 0200"), EOFValidationError::incomplete_section_size);
}

TEST(eof_validation, EOF1_header_not_terminated)
{
    EXPECT_EQ(validate_eof("EF0001 01"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001 FE"), EOFValidationError::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 010001 02"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(
        validate_eof("EF0001 010001 020001"), EOFValidationError::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 FE AA"), EOFValidationError::unknown_section_id);
}

TEST(eof_validation, EOF1_truncated_section)
{
    EXPECT_EQ(validate_eof("EF0001 010002 00"), EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010002 00 FE"), EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE AA"),
        EOFValidationError::invalid_section_bodies_size);
}

TEST(eof_validation, EOF1_trailing_bytes)
{
    EXPECT_EQ(validate_eof("EF0001 010001 00 FE DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE AABB DEADBEEF"),
        EOFValidationError::invalid_section_bodies_size);
}
