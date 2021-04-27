// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "test/experimental/jumpdest_analysis.hpp"
#include "test/utils/bytecode.hpp"
#include <evmone/analysis.hpp>
#include <evmone/baseline.hpp>
#include <gtest/gtest.h>

using namespace evmone;
using namespace evmone::experimental;

namespace
{
constexpr auto tail_code_padding = 100;

inline bool is_jumpdest(const JumpdestMap& a, size_t index) noexcept
{
    return (index < a.size() && a[index]);
}

inline bool is_jumpdest(const bitset32& a, size_t index) noexcept
{
    return (index < a.size() && a[index]);
}

inline bool is_jumpdest(const code_analysis& a, size_t index) noexcept
{
    return find_jumpdest(a, static_cast<int>(index)) >= 0;
}

const bytecode bytecode_test_cases[]{
    push(0x5b),
    {},
    OP_JUMPDEST,
    push(0),
    push(0x5b) + OP_JUMPDEST,
    push(0x60) + OP_JUMPDEST,
    "5b000000000000000000000000000000",
    "005b0000000000000000000000000000",
    "5b00000000000000000000000000000000000000000000000000000000000060",
};
}  // namespace

TEST(jumpdest_analysis, compare_implementations)
{
    for (const auto& t : bytecode_test_cases)
    {
        SCOPED_TRACE(hex(t));
        const auto a0 = build_jumpdest_map(t.data(), t.size());
        const auto a1 = analyze(EVMC_FRONTIER, t.data(), t.size());
        const auto a2 = build_jumpdest_map_vec1(t.data(), t.size());
        const auto v2 = build_jumpdest_map_vec2(t.data(), t.size());
        const auto x3 = build_jumpdest_map_vec3(t.data(), t.size());
        const auto v3 = build_jumpdest_map_sttni(t.data(), t.size());
        const auto v4 = build_jumpdest_map_str_avx2(t.data(), t.size());
        const auto v5 = build_jumpdest_map_str_avx2_mask(t.data(), t.size());
        const auto a3 = build_jumpdest_map_bitset1(t.data(), t.size());
        const auto a4 = build_internal_code_v1(t.data(), t.size());
        const auto a5 = build_internal_code_v2(t.data(), t.size());
        const auto a6 = build_internal_code_v3(t.data(), t.size());
        const auto ic4 = build_internal_code_v4(t.data(), t.size());
        const auto ic8 = build_internal_code_v8(t.data(), t.size());
        const auto s1 = build_jumpdest_map_simd1(t.data(), t.size());
        const auto s2 = build_jumpdest_map_simd2(t.data(), t.size());
        const auto s3 = build_jumpdest_map_simd3(t.data(), t.size());

        for (size_t i = 0; i < t.size() + tail_code_padding; ++i)
        {
            SCOPED_TRACE(i);
            const bool expected = is_jumpdest(a0, i);
            EXPECT_EQ(is_jumpdest(a1, i), expected);
            EXPECT_EQ(is_jumpdest(a2, i), expected);
            EXPECT_EQ(is_jumpdest(v2, i), expected);
            EXPECT_EQ(is_jumpdest(x3, i), expected);
            EXPECT_EQ(is_jumpdest(v3, i), expected);
            EXPECT_EQ(is_jumpdest(v4, i), expected);
            EXPECT_EQ(is_jumpdest(v5, i), expected);
            EXPECT_EQ(is_jumpdest(a3, i), expected);
            EXPECT_EQ(is_jumpdest(a4.get(), t.size(), i), expected);
            EXPECT_EQ(is_jumpdest(a5.get(), t.size(), i), expected);
            EXPECT_EQ(is_jumpdest(a6.get(), t.size(), i), expected);
            EXPECT_EQ(is_jumpdest(ic4.get(), t.size(), i), expected);
            EXPECT_EQ(is_jumpdest(ic8.get(), t.size(), i), expected);
            EXPECT_EQ(is_jumpdest(s1, i), expected);
            EXPECT_EQ(is_jumpdest(s2, i), expected);
        }
    }
}
