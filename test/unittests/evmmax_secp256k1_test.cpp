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

TEST(evmmax, secp256k1_sqrt)
{
    const evmmax::ModArith s{Secp256K1Mod};

    for (const auto& t :
        {1_u256, 0x6e140df17432311190232a91a38daed3ee9ed7f038645dd0278da7ca6e497de_u256,
            0xf3b9accc43dc8919ba3b4f1e14c8f7c72e7c4c013a404e9fd35e9c9a5b7b228_u256,
            0x3db99f8c1e729de4c9a283e8714b9f6bc3ef22ac5fd70daaa88b73dcf52ebe9_u256,
            0x37ec7e48f17a78e38d7b3c77d15be8c4a8e6bae83971fdec3b25f861be4b7da_u256,
            0x5b1a739f853ba7e4c6a2f3e91c7b2f7c87d4c0d98ba2fde82a79f3e5d8b76b9_u256,
            0x69187a3b9c5de9e4783a29df87b6f8c5d3a2b6d98c5d7ea1b28f7e5d9a7b6b8_u256,
            0x7a98763a85df9e7c6a28d9f7b6f8d5c3a2b7c6d98c5d7e9a1b2f7d6e5a9b7b6_u256,
            0x8b87953a75ef8d7b5a27c8e7a6f7d4b2a1b6c5d87b5c6d89a0b1e6d4a8a6b5_u256,
            0x9c76942a65df7c6a4a16b7d6a5f6c3a0b0c4b5c76a4b5c78a9f6d3c4a7a5b4_u256,
            0xad65931a55cf6b594915a6c5a4f5b2a9f0b3a4b6593a4b6789e5c2b39694a3_u256,
            0xbe54820a45bf5a48381495b494e4a1f8e9a293b548394a5678d4b1a28583a2_u256,
            Secp256K1Mod - 1})
    {
        const auto a = s.to_mont(t);
        const auto a2 = s.mul(a, a);
        const auto a2_sqrt = sqrt(s, a2);
        ASSERT_TRUE(a2_sqrt.has_value()) << to_string(t);
        EXPECT_TRUE(a2_sqrt == a || a2_sqrt == s.sub(0, a)) << to_string(t);
    }
}
