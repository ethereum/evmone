// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

TEST(eof, is_eof_container)
{
    EXPECT_FALSE(is_eof_container(""_hex));
    EXPECT_FALSE(is_eof_container("EF"_hex));
    EXPECT_FALSE(is_eof_container("EF01"_hex));
    EXPECT_FALSE(is_eof_container("EF02"_hex));
    EXPECT_FALSE(is_eof_container("EFFF"_hex));
    EXPECT_FALSE(is_eof_container("00"_hex));
    EXPECT_FALSE(is_eof_container("FE"_hex));

    EXPECT_TRUE(is_eof_container("EF00"_hex));
    EXPECT_TRUE(is_eof_container("EF00 01 010004 0200010001 00 00000000 00"_hex));
    EXPECT_TRUE(is_eof_container("EF00 01 010004 0200010001 030004 00 00000000 00 AABBCCDD"_hex));
    EXPECT_TRUE(is_eof_container("EF00 02 ABCFEF"_hex));
}

TEST(eof, read_valid_eof1_header)
{
    struct TestCase
    {
        std::string code;
        uint16_t types_size;
        uint16_t data_size;
        std::vector<uint16_t> code_sizes;
    };
    std::string nops_255;
    for (int i = 0; i < 255; ++i)
        nops_255 += "5B";

    const TestCase test_cases[] = {{"EF00 01 010004 0200010001 030000 00 00000000 00", 4, 0, {1}},
        {"EF00 01 010004 0200010006 030000 00 00000002 600160005500", 4, 0, {6}},
        {"EF00 01 010004 0200010001 030001 00 00000000 00 AA", 4, 1, {1}},
        {"EF00 01 010004 0200010006 030004 00 00000002 600160005500 AABBCCDD", 4, 4, {6}},
        {"EF00 01 010004 0200010100 031000 00 00000000" + nops_255 + "00" + std::string(8192, 'F'),
            4, 4096, {256}}};

    for (const auto& test_case : test_cases)
    {
        const auto code = from_spaced_hex(test_case.code).value();
        EXPECT_EQ(validate_eof(EVMC_CANCUN, code), EOFValidationError::success) << test_case.code;

        const auto header = read_valid_eof1_header(code);
        EXPECT_EQ(header.code_sizes, test_case.code_sizes) << test_case.code;
        EXPECT_EQ(header.data_size, test_case.data_size) << test_case.code;
        EXPECT_EQ(header.types.size() * 4, test_case.types_size) << test_case.code;
    }
}
