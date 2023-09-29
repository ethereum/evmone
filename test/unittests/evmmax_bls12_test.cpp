// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include "evmone_precompiles/bls12.hpp"
#include <gtest/gtest.h>

using namespace evmmax::bls12;
using namespace intx;

TEST(evmmax, bls12_inv)
{
    const BLS12ModArith s;

    const auto _5_mont = s.to_mont(5);
    const auto _5_inv_mont = s.inv(_5_mont);

    const auto m = s.mul(_5_mont, _5_inv_mont);

    EXPECT_EQ(m, s.one_mont());
}

struct TestCaseBLS12
{
    bytes input;
    bytes expected_output;

    TestCaseBLS12(bytes i, bytes o) : input{std::move(i)}, expected_output{std::move(o)}
    {
        input.resize(256);
        expected_output.resize(128);
    }
};

static const TestCaseBLS12 test_cases[] = {
    {"0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f560000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee000000000000000000000000000000000001101098f5c39893765766af4512a0c74e1bb89bc7e6fdf14e3e7337d257cc0f94658179d83320b99f31ff94cd2bac0000000000000000000000000000000003e1a9f9f44ca2cdab4f43a1a3ee3470fdf90b2fc228eb3b709fcd72f014838ac82a6d797aeefed9a0804b22ed1ce8f7"_hex,
        "000000000000000000000000000000001466e1373ae4a7e7ba885c5f0c3ccfa48cdb50661646ac6b779952f466ac9fc92730dcaed9be831cd1f8c4fefffd5209000000000000000000000000000000000c1fb750d2285d4ca0378e1e8cdbf6044151867c34a711b73ae818aee6dbe9e886f53d7928cc6ed9c851e0422f609b11"_hex}};

TEST(evmmax, bls12_validate_inputs)
{
    const evmmax::ModArith s{BLS12Mod};

    for (const auto& t : test_cases)
    {
        ASSERT_EQ(t.input.size(), 256);
        ASSERT_EQ(t.expected_output.size(), 128);

        const Point a{
            be::unsafe::load<uint384>(&t.input[16]), be::unsafe::load<uint384>(&t.input[64 + 16])};
        const Point b{be::unsafe::load<uint384>(&t.input[128 + 16]),
            be::unsafe::load<uint384>(&t.input[192 + 16])};
        const Point e{be::unsafe::load<uint384>(&t.expected_output[16]),
            be::unsafe::load<uint384>(&t.expected_output[64 + 16])};

        EXPECT_TRUE(validate(a));
        EXPECT_TRUE(validate(b));
        EXPECT_TRUE(validate(e));
    }
}

TEST(evmmax, bls12_pt_add)
{
    const evmmax::ModArith s{BLS12Mod};

    for (const auto& t : test_cases)
    {
        const Point a{
            be::unsafe::load<uint384>(&t.input[16]), be::unsafe::load<uint384>(&t.input[64 + 16])};
        const Point b{be::unsafe::load<uint384>(&t.input[128 + 16]),
            be::unsafe::load<uint384>(&t.input[192 + 16])};
        const Point e{be::unsafe::load<uint384>(&t.expected_output[16]),
            be::unsafe::load<uint384>(&t.expected_output[64 + 16])};

        EXPECT_EQ(bls12_add(a, b), e);
    }
}
