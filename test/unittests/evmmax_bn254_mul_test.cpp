// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <evmmax/bn254.hpp>
#include <gtest/gtest.h>

using namespace evmmax::bn254;

struct TestCaseMul
{
    bytes input;
    bytes expected_output;

    TestCaseMul(bytes i, bytes o) : input{std::move(i)}, expected_output{std::move(o)}
    {
        input.resize(96);
        expected_output.resize(64);
    }
};

static const TestCaseMul
    test_cases
        [] =
            {
                {"0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003"_hex, "1f4d1d80177b1377743d1901f70d7389be7f7a35a35bfd234a8aaee615b88c49018683193ae021a2f8920fed186cde5d9b1365116865281ccf884c1f28b1df8f"_hex}
            };

TEST(evmmax, bn254_mul_validate_inputs)
{
    const evmmax::ModArith s{BN254Mod};

    for (const auto& t : test_cases)
    {
        ASSERT_EQ(t.input.size(), 96);
        ASSERT_EQ(t.expected_output.size(), 64);

        const Point a{
            be::unsafe::load<uint256>(&t.input[0]), be::unsafe::load<uint256>(&t.input[32])};
        const Point e{be::unsafe::load<uint256>(&t.expected_output[0]),
            be::unsafe::load<uint256>(&t.expected_output[32])};

        EXPECT_TRUE(validate(a));
        EXPECT_TRUE(validate(e));
    }
}

TEST(evmmax, bn254_pt_mul)
{
    const evmmax::ModArith s{BN254Mod};

    for (const auto& t : test_cases)
    {
        const Point p{
            be::unsafe::load<uint256>(&t.input[0]), be::unsafe::load<uint256>(&t.input[32])};
        const auto d{be::unsafe::load<uint256>(&t.input[64])};
        const Point e{be::unsafe::load<uint256>(&t.expected_output[0]),
            be::unsafe::load<uint256>(&t.expected_output[32])};

        EXPECT_EQ(bn254_mul(p, d), e);
    }
}

