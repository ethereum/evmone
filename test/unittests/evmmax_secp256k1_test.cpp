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

TEST(evmmax, secp256k1_calculate_y)
{
    const evmmax::ModArith s{Secp256K1Mod};

    struct TestCase
    {
        uint256 x;
        uint256 y_even;
        uint256 y_odd;
    };

    const TestCase test_cases[] = {
        {1_u256, 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee_u256,
            0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441_u256},
        {0xb697546bfbc062d06df1d25a26e4fadfe2f2a48109c349bf65d2b01182f3aa60_u256,
            0xd02714d31d0c08c38037400d232886863b473a37adba9823ea44ae50028a5bea_u256,
            0x2fd8eb2ce2f3f73c7fc8bff2dcd77979c4b8c5c8524567dc15bb51aefd75a045_u256},
        {0x18f4057699e2d9679421de8f4e11d7df9fa4b9e7cb841ea48aed75f1567b9731_u256,
            0x6db5b7ecd8e226c06f538d15173267bf1e78acc02bb856e83b3d6daec6a68144_u256,
            0x924a4813271dd93f90ac72eae8cd9840e187533fd447a917c4c2925039597aeb_u256}};

    for (const auto& t : test_cases)
    {
        const auto x = s.to_mont(t.x);

        const auto y_even = sec256k1_calculate_y(s, x, false);
        ASSERT_TRUE(y_even.has_value());
        EXPECT_EQ(s.from_mont(*y_even), t.y_even);

        const auto y_odd = sec256k1_calculate_y(s, x, true);
        ASSERT_TRUE(y_odd.has_value());
        EXPECT_EQ(s.from_mont(*y_odd), t.y_odd);
    }
}

TEST(evmmax, secp256k1_calculate_y_invalid)
{
    const evmmax::ModArith s{Secp256K1Mod};

    for (const auto& t :
        {0x207ea538f1835f6de40c793fc23d22b14da5a80015a0fecddf56f146b21d7949_u256, Secp256K1Mod - 1})
    {
        const auto x = s.to_mont(t);

        const auto y_even = sec256k1_calculate_y(s, x, false);
        ASSERT_FALSE(y_even.has_value());

        const auto y_odd = sec256k1_calculate_y(s, x, true);
        ASSERT_FALSE(y_odd.has_value());
    }
}
