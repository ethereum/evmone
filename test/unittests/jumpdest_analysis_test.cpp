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

inline bool is_jumpdest(const code_analysis& a, size_t index) noexcept
{
    return find_jumpdest(a, static_cast<int>(index)) >= 0;
}

const bytecode bytecode_test_cases[]{
    {},
    OP_JUMPDEST,
    push(0),
    push(0x5b),
    push(0x5b) + OP_JUMPDEST,
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
        const auto a3 = build_jumpdest_map_bitset1(t.data(), t.size());
        const auto a4 = build_internal_code_v1(t.data(), t.size());

        for (size_t i = 0; i < t.size() + tail_code_padding; ++i)
        {
            SCOPED_TRACE(i);
            const bool expected = is_jumpdest(a0, i);
            EXPECT_EQ(is_jumpdest(a1, i), expected);
            EXPECT_EQ(is_jumpdest(a2, i), expected);
            EXPECT_EQ(is_jumpdest(a3, i), expected);
            EXPECT_EQ(is_jumpdest(a4.get(), t.size(), i), expected);
        }
    }
}