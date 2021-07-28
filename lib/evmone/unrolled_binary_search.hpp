// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <cstddef>

namespace evmone
{
// Unrolled version of the binary search that shines for small (pre-sorted) arrays/vectors.
//
// See
// https://dirtyhandscoding.wordpress.com/2017/08/25/performance-comparison-linear-search-vs-binary-search/
// and
// https://arxiv.org/abs/1509.05053
//
// Only suitable for arrays whose size + 1 equals a power of 2!!!
// i.e. ∃ k: n + 1 = 2^k.
// Falls back to std::lower_bound otherwise.
template <typename T>
const T* unrolled_binary_search(const T* vec, size_t n, const T& key)
{
    if (n == 0)
        return vec;

    int pos = -1;
    int step = -1;

#if defined(__GNUC__) && !defined(__clang__)
// For some reason gcc doesn't generate cmov with the ternary operator
#define EVMONE_BINARY_SEARCH_BRANCHLESS_STEP pos += (vec[pos + step] < key) * step;
#else
#define EVMONE_BINARY_SEARCH_BRANCHLESS_STEP pos = (vec[pos + step] < key ? pos + step : pos)
#endif

    switch (n + 1)
    {
    case 1u << 10:
        step = 1 << 9;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 9:
        step = 1 << 8;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 8:
        step = 1 << 7;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 7:
        step = 1 << 6;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 6:
        step = 1 << 5;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 5:
        step = 1 << 4;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 4:
        step = 1 << 3;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 3:
        step = 1 << 2;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 2:
        step = 1 << 1;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 1:
        step = 1 << 0;
        EVMONE_BINARY_SEARCH_BRANCHLESS_STEP;
        [[fallthrough]];
    case 1u << 0:
        return vec + pos + 1;
    }

#undef EVMONE_BINARY_SEARCH_BRANCHLESS_STEP

    return std::lower_bound(vec, vec + n, key);
}

}  // namespace evmone
