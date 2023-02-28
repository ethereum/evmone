// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <evmmax/evmmax.hpp>
#include <gtest/gtest.h>

const auto BLS12384ModBytes =
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"_hex;

TEST(evmmax, setup_bls12_384)
{
    const auto s = evmmax::setup(BLS12384ModBytes, 0);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->num_elems, 0);
    EXPECT_EQ(s->mod_inv, 0x89f3fffcfffcfffd);
}
