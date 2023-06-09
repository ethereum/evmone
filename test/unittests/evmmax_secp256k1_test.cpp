// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <evmmax/secp256k1.hpp>
#include <gtest/gtest.h>

using namespace evmmax::secp256k1;

TEST(evmmax, secp256k1_inv_1)
{
    const evmmax::ModArith s{Secp256K1Mod};

    for (const auto& t :
        {1_u256, 0x6e140df17432311190232a91a38daed3ee9ed7f038645dd0278da7ca6e497de_u256,
            Secp256K1Mod - 1})
    {
        const auto a = s.to_mont(t);
        const auto a_inv = inv(s, a);
        const auto p = s.mul(a, a_inv);
        EXPECT_EQ(s.from_mont(p), 1);
    }
}
