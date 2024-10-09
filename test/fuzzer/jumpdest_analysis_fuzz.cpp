// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "test/experimental/jumpdest_analysis.hpp"
#include <evmone/baseline.hpp>


using namespace evmone;
using namespace evmone::experimental;

namespace
{
template <typename T1, typename T2>
inline void EXPECT_EQ(T1 a, T2 b) noexcept
{
    if (a != b)
        __builtin_unreachable();
}

constexpr auto tail_code_padding = 100;

inline bool is_jumpdest(const bitset32& a, size_t index) noexcept
{
    return (index < a.size() && a[index]);
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const auto a0 = official_analyze_jumpdests(data, data_size);
    const auto a2 = build_jumpdest_map_vec1(data, data_size);
    const auto v2 = build_jumpdest_map_vec2(data, data_size);
    const auto x3 = build_jumpdest_map_vec3(data, data_size);
    const auto v3 = build_jumpdest_map_sttni(data, data_size);
    const auto v4 = build_jumpdest_map_str_avx2(data, data_size);
    const auto v5 = build_jumpdest_map_str_avx2_mask(data, data_size);
    const auto v6 = build_jumpdest_map_str_avx2_mask2(data, data_size);
    const auto a3 = build_jumpdest_map_bitset1(data, data_size);
    const auto a4 = build_internal_code_v1(data, data_size);
    const auto a5 = build_internal_code_v2(data, data_size);
    const auto a6 = build_internal_code_v3(data, data_size);
    const auto ic4 = build_internal_code_v4(data, data_size);
    const auto ic8 = build_internal_code_v8(data, data_size);
    const auto s1 = build_jumpdest_map_simd1(data, data_size);
    const auto s2 = build_jumpdest_map_simd2(data, data_size);
    const auto s3 = build_jumpdest_map_simd3(data, data_size);
    const auto s4 = build_jumpdest_map_simd4(data, data_size);

    for (size_t i = 0; i < data_size + tail_code_padding; ++i)
    {
        const bool expected = is_jumpdest(a0, i);
        EXPECT_EQ(is_jumpdest(a2, i), expected);
        EXPECT_EQ(is_jumpdest(v2, i), expected);
        EXPECT_EQ(is_jumpdest(x3, i), expected);
        EXPECT_EQ(is_jumpdest(v3, i), expected);
        EXPECT_EQ(is_jumpdest(v4, i), expected);
        EXPECT_EQ(is_jumpdest(v5, i), expected);
        EXPECT_EQ(is_jumpdest(v6, i), expected);
        EXPECT_EQ(is_jumpdest(a3, i), expected);
        EXPECT_EQ(is_jumpdest(a4.get(), data_size, i), expected);
        EXPECT_EQ(is_jumpdest(a5.get(), data_size, i), expected);
        EXPECT_EQ(is_jumpdest(a6.get(), data_size, i), expected);
        EXPECT_EQ(is_jumpdest(ic4.get(), data_size, i), expected);
        EXPECT_EQ(is_jumpdest(ic8.get(), data_size, i), expected);
        EXPECT_EQ(is_jumpdest(s1, i), expected);
        EXPECT_EQ(is_jumpdest(s2, i), expected);
        EXPECT_EQ(is_jumpdest(s3, i), expected);
        EXPECT_EQ(is_jumpdest(s4, i), expected);
    }
    return 0;
}
