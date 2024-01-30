// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include "evmone_precompiles/bn254.hpp"
#include "evmone_precompiles/utils.hpp"
#include <gtest/gtest.h>

using namespace evmmax::bn254;
using namespace intx;

TEST(evmmax, bee_inv_bn254)
{
    const evmmax::ModArith<uint256> m{evmmax::bn254::FieldPrime};

    const auto a =
        m.to_mont(0x6e140df17432311190232a91a38daed3ee9ed7f038645dd0278da7ca6e497de_u256);
    const auto R2 = 0x6D89F71CAB8351F47AB1EFF0A417FF6B5E71911D44501FBF32CFC5B538AFA89_u256;

    const auto a_inv = evmmax::utils::bee_inverse(a, FieldPrime, R2);
    const auto p = m.mul(a, a_inv);
    EXPECT_EQ(m.from_mont(p), 1);
}

TEST(evmmax, bee_inv_bn254_no_mont)
{
    const evmmax::ModArith<uint256> m{evmmax::bn254::FieldPrime};

    const auto a = 0x6e140df17432311190232a91a38daed3ee9ed7f038645dd0278da7ca6e497de_u256;

    const auto a_inv = evmmax::utils::ee_inverse(a, FieldPrime);
    const auto p = m.mul(m.to_mont(a), m.to_mont(a_inv));
    EXPECT_EQ(m.from_mont(p), 1);
}

TEST(evmmax, bee_inv_mont_simple)
{
    const evmmax::ModArith<uint256> m{11};

    const auto a = m.to_mont(2_u256);
    const auto R2 = 4_u256;

    const auto a_inv = evmmax::utils::bee_inverse(a, uint256{11}, R2);
    const auto p = m.mul(a, a_inv);
    EXPECT_EQ(m.from_mont(p), 1);
}

TEST(evmmax, bee_inv)
{
    EXPECT_EQ(evmmax::utils::ee_inverse(uint256{5}, uint256{23}), 14);
    EXPECT_EQ(evmmax::utils::ee_inverse(uint256{3}, uint256{11}), 4);
    EXPECT_EQ(evmmax::utils::ee_inverse(uint256{2}, FieldPrime), (FieldPrime + 1) / 2);
}

TEST(evmmax, calc_lambda)
{
    const evmmax::ModArith<uint256> m{evmmax::bn254::Order};

    const auto sqrt_p_3 =
        m.to_mont(8815841940592487684786734430012312169832938914291687956923_u256);

    EXPECT_EQ(m.mul(sqrt_p_3, sqrt_p_3), m.to_mont(evmmax::bn254::Order - 3));

    // const auto R2 = 0x6D89F71CAB8351F47AB1EFF0A417FF6B5E71911D44501FBF32CFC5B538AFA89_u256;
    const auto _2_inv = evmmax::utils::bee_inverse(uint256{2}, Order);
    EXPECT_EQ(m.mul(m.to_mont(_2_inv), m.to_mont(2)), m.to_mont(1));
    const auto _minus_1 = m.sub(uint256{0}, m.to_mont(uint256{1}));

    const auto lambda_1 = m.mul(m.add(_minus_1, sqrt_p_3), m.to_mont(_2_inv));
    const auto lambda_2 = m.mul(m.sub(_minus_1, sqrt_p_3), m.to_mont(_2_inv));

    // lambda_1 == 0xb3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd
    // lambda_2 == 0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48

    EXPECT_EQ(m.add(m.add(m.mul(lambda_1, lambda_1), lambda_1), m.to_mont(uint256{1})), 0);
    EXPECT_EQ(m.add(m.add(m.mul(lambda_2, lambda_2), lambda_2), m.to_mont(uint256{1})), 0);

    std::cout << "lambda1 = " + hex(m.from_mont(lambda_1)) << std::endl;
    std::cout << "lambda2 = " + hex(m.from_mont(lambda_2)) << std::endl;
}

TEST(evmmax, calc_lambda_inv)
{
    const evmmax::ModArith<uint256> m{evmmax::bn254::Order};
    {
        const auto lambda_1 = 0xb3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd_u256;

        const auto a_inv = evmmax::utils::ee_inverse(lambda_1, Order);

        const auto p = m.mul(m.to_mont(lambda_1), m.to_mont(a_inv));
        EXPECT_EQ(m.from_mont(p), 1);
    }
    {
        const auto lambda_2 =
            0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48_u256;

        const auto a_inv = evmmax::utils::ee_inverse(lambda_2, Order);

        const auto p = m.mul(m.to_mont(lambda_2), m.to_mont(a_inv));
        EXPECT_EQ(m.from_mont(p), 1);
    }
}

TEST(evmmax, scalar_decomp_vectors_test)
{
    const evmmax::ModArith<uint256> m{evmmax::bn254::Order};

    // v1 should be (s_(m+1), -t_(m+1)). We don't use signed int so we leave it as (s_(m+1),
    // t_(m+1)) (9931322734385697762, 147946756881789319000765030803803410729) ->
    // (9931322734385697762, -147946756881789319000765030803803410729) (second value is negative!)
    // m + 1
    const uint256 v1[2] = {9931322734385697763_u256, 147946756881789319000765030803803410728_u256};
    // (147946756881789319010696353538189108491, -9931322734385697762) ->
    // (147946756881789319010696353538189108491, 9931322734385697762) (both values are positive)
    // m
    const uint256 v2[2] = {147946756881789319010696353538189108491_u256, 9931322734385697763_u256};

    // const auto field_prime_sqrt = 147946756881789319005730692170996259610_u256;

    //    EXPECT_TRUE(v1[0] < v2[0]);
    //    EXPECT_TRUE(v1[1] > v2[1]);
    //    EXPECT_TRUE(v1[0] < field_prime_sqrt);
    //    EXPECT_TRUE(v2[0] >= field_prime_sqrt);

    const uint256 v1_m[2] = {m.to_mont(v1[0]), m.to_mont(v1[1])};
    const uint256 v2_m[2] = {m.to_mont(v2[0]), m.to_mont(v2[1])};

    const auto lambda_1 = m.to_mont(0xb3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd_u256);

    EXPECT_EQ(m.sub(v1_m[0], m.mul(lambda_1, v1_m[1])), 0);  // y is neg so we `sub` instead od
                                                             // `add`
    EXPECT_EQ(m.add(v2_m[0], m.mul(lambda_1, v2_m[1])), 0);
}

//TEST(evmmax, scalar_decoposition)
//{
//    static const uint256 test_cases[6] = {0x59e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe_u256,
//        7, (FieldPrime + 1) / 2, (FieldPrime - 127), (FieldPrime - 2), FieldPrime / 2};
//
//    static const auto lambda = 0x59e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe_u512;
//
//    for (const auto& k : test_cases)
//    {
//        const auto [k1, k2] = decompose(k);
//        EXPECT_EQ((k1 + (k2 * lambda)) % FieldPrime, k);
//    }
//}

//TEST(evmmax, bn254_endomorphism)
//{
//    const evmmax::ModArith<uint256> m{evmmax::bn254::FieldPrime};
//
//    const auto beta = m.to_mont((FieldPrime / 3) + 1);
//
//    EXPECT_EQ(m.add(beta, m.add(beta, beta)), m.to_mont(1));
//}
