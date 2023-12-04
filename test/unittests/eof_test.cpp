// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>
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
        std::vector<uint16_t> container_sizes;
    };
    std::string nops_255;
    for (int i = 0; i < 255; ++i)
        nops_255 += "5B";

    std::string section_size_1_256;
    for (int i = 0; i < 256; ++i)
        section_size_1_256 += "0001";

    std::string section_types_256;
    for (int i = 0; i < 256; ++i)
        section_types_256 += "00800000";

    const TestCase test_cases[] = {
        {"EF00 01 010004 0200010001 040000 00 00800000 00", 4, 0, {1}, {}},
        {"EF00 01 010004 0200010006 040000 00 00800002 600160005500", 4, 0, {6}, {}},
        {"EF00 01 010004 0200010001 040001 00 00800000 00 AA", 4, 1, {1}, {}},
        {"EF00 01 010004 0200010006 040004 00 00800002 600160005500 AABBCCDD", 4, 4, {6}, {}},
        {"EF00 01 01000C 020003000100020003 040000 00 008000000080000000800000 00 5B00 5B5B00", 12,
            0, {1, 2, 3}, {}},
        {"EF00 01 01000C 020003000100020003 040004 00 008000000080000000800000 00 5B00 5B5B00 "
         "FFFFFFFF",
            12, 4, {1, 2, 3}, {}},
        {"EF00 01 010004 0200010100 041000 00 00800000" + nops_255 + "00" + std::string(8192, 'F'),
            4, 4096, {256}, {}},
        {"EF00 01 010400 020100" + section_size_1_256 + " 041000 00 " + section_types_256 +
                std::string(512, '0') + std::string(8192, 'F'),
            4 * 256, 4096, std::vector<uint16_t>(256, 1), {}},
        //        {"EF00 01 010004 0200010001 0300010001 040000 00 00800000 00 00", 4, 0, {1}, {1}},
        //        {"EF00 01 010004 0200010001 0300010002 040003 00 00800000 00 0000 000000", 4, 3,
        //        {1}, {2}},
        //        {"EF00 01 010004 0200010001 030003000100020003 040000 00 00800000 00 aa bbbb
        //        cccccc", 4, 0,
        //            {1}, {1, 2, 3}},
        //        {"EF00 01 010004 0200010001 030003000100020003 040003 00 00800000 00 aa bbbb
        //        cccccc ddeeff",
        //            4, 3, {1}, {1, 2, 3}},
        //        {"EF00 01 01000C 020003000100010001 030003000100020003 040003 00
        //        008000000080000000800000 "
        //         "00 00 00 aa bbbb cccccc ddeeff",
        //            12, 3, {1, 1, 1}, {1, 2, 3}},
        // TODO fix for non-returning sections
        //        {"EF00 01 010004 0200010001 0300010100 040000 00 00000000 00 " + std::string(512,
        //        'F'), 4,
        //            0, {1}, {256}},
        //        {"EF00 01 010004 0200010001 030100" + section_size_1_256 + "040000 00 00000000 00
        //        " +
        //                std::string(512, 'F'),
        //            4, 0, {1}, std::vector<uint16_t>(256, 1)},
    };

    for (const auto& test_case : test_cases)
    {
        const auto code = from_spaced_hex(test_case.code).value();
        EXPECT_EQ(validate_eof(EVMC_PRAGUE, code), EOFValidationError::success) << test_case.code;

        const auto header = read_valid_eof1_header(code);
        EXPECT_EQ(header.code_sizes, test_case.code_sizes) << test_case.code;
        EXPECT_EQ(header.data_size, test_case.data_size) << test_case.code;
        EXPECT_EQ(header.types.size() * 4, test_case.types_size) << test_case.code;
        EXPECT_EQ(header.container_sizes, test_case.container_sizes) << test_case.code;
    }
}
