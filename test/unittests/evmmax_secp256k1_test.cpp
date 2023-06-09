// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <evmone_precompiles/secp256k1.hpp>
#include <gtest/gtest.h>

using namespace evmmax::secp256k1;

TEST(secp256k1, field_inv)
{
    const evmmax::ModArith m{FieldPrime};

    for (const auto& t : {
             1_u256,
             0x6e140df17432311190232a91a38daed3ee9ed7f038645dd0278da7ca6e497de_u256,
             FieldPrime - 1,
         })
    {
        ASSERT_LT(t, FieldPrime);
        const auto a = m.to_mont(t);
        const auto a_inv = field_inv(m, a);
        const auto p = m.mul(a, a_inv);
        EXPECT_EQ(m.from_mont(p), 1);
    }
}
