// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "test/experimental/opcode_manip.hpp"
#include "test/utils/bytecode.hpp"
#include <gtest/gtest.h>

using namespace evmone::experimental;

TEST(opcode_manip, find_first_push)
{
    struct TestCase
    {
        bytecode code;
        int expected;
    };

    static TestCase test_cases[]{
        {"0000000000000000", -1},
        {"6000000000000000", 0},
        {"0060000000000000", 1},
        {"0000600000000000", 2},
        {"0000006000000000", 3},
        {"0000000060000000", 4},
        {"0000000000600000", 5},
        {"0000000000006000", 6},
        {"0000000000000060", 7},
        {"6100000000000000", 0},
        {"0061000000000000", 1},
        {"0000610000000000", 2},
        {"0000006100000000", 3},
        {"0000000061000000", 4},
        {"0000000000610000", 5},
        {"0000000000006100", 6},
        {"0000000000000061", 7},
        {"7f00000000000000", 0},
        {"007f000000000000", 1},
        {"00007f0000000000", 2},
        {"0000007f00000000", 3},
        {"000000007f000000", 4},
        {"00000000007f0000", 5},
        {"0000000000007f00", 6},
        {"000000000000007f", 7},
        {"7000000000000000", 0},
        {"0070000000000000", 1},
        {"0000700000000000", 2},
        {"0000007000000000", 3},
        {"0000000070000000", 4},
        {"0000000000700000", 5},
        {"0000000000007000", 6},
        {"0000000000000070", 7},
        {"6060606060606060", 0},
        {"0060606060606060", 1},
        {"0000606060606060", 2},
        {"0000006060606060", 3},
        {"0000000060606060", 4},
        {"0000000000606060", 5},
        {"0000000000006060", 6},
        {"0000000000000060", 7},
        {"e000000000000000", -1},
        {"0000e00000000000", -1},
        {"000000e0e0e0e0e0", -1},
    };

    for (const auto& [code, expected] : test_cases)
    {
        EXPECT_EQ(find_first_push(code.data()), expected);
        EXPECT_EQ(find_first_push_opt1(code.data()), expected);
        EXPECT_EQ(find_first_push_opt2(code.data()), expected);
        EXPECT_EQ(find_first_push_opt3(code.data()), expected);
    }
}
