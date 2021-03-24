// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

TEST(utils, from_hexx)
{
    EXPECT_EQ(hex(from_hexx("")), "");

    EXPECT_EQ(hex(from_hexx("(0xca)")), "");
    EXPECT_EQ(hex(from_hexx("(1xca)")), "ca");
    EXPECT_EQ(hex(from_hexx("(5xca)")), "cacacacaca");

    EXPECT_EQ(hex(from_hexx("01(0x3a)02")), "0102");
    EXPECT_EQ(hex(from_hexx("01(1x3a)02")), "013a02");
    EXPECT_EQ(hex(from_hexx("01(2x3a)02")), "013a3a02");

    EXPECT_EQ(hex(from_hexx("01(2x333)02(2x4444)03")), "01333333024444444403");
    EXPECT_EQ(hex(from_hexx("01(4x333)02(4x4)03")), "0133333333333302444403");

    EXPECT_EQ(hex(from_hexx("00")), "00");
}
