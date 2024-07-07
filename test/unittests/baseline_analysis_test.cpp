// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/baseline.hpp>
#include <gtest/gtest.h>
#include <test/utils/bytecode.hpp>

using namespace evmone::test;

TEST(baseline_analysis, legacy)
{
    const auto code = push(1) + ret_top();
    const auto analysis = evmone::baseline::analyze(code, false);

    EXPECT_EQ(analysis.eof_header().version, 0);
    EXPECT_EQ(analysis.executable_code(), code);
    EXPECT_EQ(analysis.raw_code(), code);
    EXPECT_NE(analysis.raw_code().data(), code.data()) << "copy should be made";
}

TEST(baseline_analysis, eof1)
{
    const auto code = push(1) + ret_top();
    const bytecode container = eof_bytecode(code, 2).data("da4a");
    const auto analysis = evmone::baseline::analyze(container, true);

    EXPECT_EQ(analysis.eof_header().version, 1);
    EXPECT_EQ(analysis.eof_header().code_sizes.size(), 1);
    EXPECT_EQ(analysis.eof_header().data_size, 2);
    EXPECT_EQ(analysis.executable_code(), code);
    EXPECT_EQ(analysis.raw_code(), container);
    EXPECT_EQ(analysis.raw_code().data(), container.data()) << "copy should not be made";
}
