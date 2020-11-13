// evmone-fuzzer: LibFuzzer based testing tool for EVMC-compatible EVM implementations.
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "test/experimental/jumpdest_analysis.hpp"
#include <evmone/analysis.hpp>
#include <evmone/baseline.hpp>


using namespace evmone;
using namespace evmone::experimental;

namespace
{
template <typename T1, typename T2>
inline void expect_eq(T1 a, T2 b) noexcept
{
    if (a != b)
        __builtin_trap();
}

constexpr auto tail_code_padding = 100;

inline bool is_jumpdest(const JumpdestMap& a, size_t index) noexcept
{
    return (index < a.size() && a[index]);
}

inline bool is_jumpdest(const code_analysis& a, size_t index) noexcept
{
    return find_jumpdest(a, static_cast<int>(index)) >= 0;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    const auto a0 = build_jumpdest_map(data, data_size);
    const auto a1 = analyze(EVMC_FRONTIER, data, data_size);
    const auto a2 = build_jumpdest_map_vec1(data, data_size);
    const auto a3 = build_jumpdest_map_bitset1(data, data_size);

    for (size_t i = 0; i < data_size + tail_code_padding; ++i)
    {
        const bool expected = is_jumpdest(a0, i);
        expect_eq(is_jumpdest(a1, i), expected);
        expect_eq(is_jumpdest(a2, i), expected);
        expect_eq(is_jumpdest(a3, i), expected);
    }


    return 0;
}
