// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmmax/evmmax.hpp>
#include <gtest/gtest.h>

TEST(evmmax, setup_invalid)
{
    const auto s = evmmax::setup({}, 0);
    EXPECT_EQ(s, nullptr);
}

