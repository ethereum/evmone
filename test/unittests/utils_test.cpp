// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

TEST(utils, to_hex)
{
    auto data = bytes{0x0, 0x1, 0xa, 0xf, 0x1f, 0xa0, 0xff, 0xf0};
    EXPECT_EQ(to_hex(data), "00010a0f1fa0fff0");
}

TEST(utils, from_hex_empty)
{
    EXPECT_TRUE(from_hex({}).empty());
}

TEST(utils, from_hex_odd_input_length)
{
    EXPECT_THROW(from_hex("0"), std::length_error);
}

TEST(utils, from_hex_capital_letters)
{
    EXPECT_EQ(from_hex("ABCDEF"), (bytes{0xab, 0xcd, 0xef}));
}

TEST(utils, from_hex_invalid_encoding)
{
    EXPECT_THROW(from_hex({"\0\0", 2}), std::out_of_range);
}
