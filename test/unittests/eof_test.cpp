// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

TEST(eof, code_begin)
{
    EOF1Header header1{1, 0};
    EXPECT_EQ(header1.code_begin(), 7);

    EOF1Header header2{10, 0};
    EXPECT_EQ(header2.code_begin(), 7);

    EOF1Header header3{1, 1};
    EXPECT_EQ(header3.code_begin(), 10);

    EOF1Header header4{1, 10};
    EXPECT_EQ(header4.code_begin(), 10);
}

TEST(eof, is_eof_code)
{
    EXPECT_FALSE(is_eof_code(""_hex));
    EXPECT_FALSE(is_eof_code("EF"_hex));
    EXPECT_FALSE(is_eof_code("EF01"_hex));
    EXPECT_FALSE(is_eof_code("EF02"_hex));
    EXPECT_FALSE(is_eof_code("EFFF"_hex));
    EXPECT_FALSE(is_eof_code("00"_hex));
    EXPECT_FALSE(is_eof_code("FE"_hex));

    EXPECT_TRUE(is_eof_code("EF00"_hex));
    EXPECT_TRUE(is_eof_code("EF00 01 010001 00 00"_hex));
    EXPECT_TRUE(is_eof_code("EF00 01 010001 020004 00 00 AABBCCDD"_hex));
    EXPECT_TRUE(is_eof_code("EF00 02 ABCFEF"_hex));
}

TEST(eof, read_valid_eof1_header)
{
    struct TestCase
    {
        std::string code;
        uint16_t code_size;
        uint16_t data_size;
    };
    const TestCase test_cases[] = {
        {"EF00 01 010001 00 00", 1, 0},
        {"EF00 01 010006 00 600160005500", 6, 0},
        {"EF00 01 010001 020001 00 00 00 AA", 1, 1},
        {"EF00 01 010006 020004 00 600160005500 AABBCCDD", 6, 4},
        {"EF00 01 010100 021000 00" + std::string(256, '0') + std::string(4096, 'F'), 256, 4096},
    };

    for (const auto& test_case : test_cases)
    {
        const auto code = from_spaced_hex(test_case.code).value();
        const auto header = read_valid_eof1_header(bytes_view(code).begin());
        EXPECT_EQ(header.code_size, test_case.code_size) << test_case.code;
        EXPECT_EQ(header.data_size, test_case.data_size) << test_case.code;
    }
}
