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
    switch (n + 1)
    {
    case 1u << 10:
        pos = (vec[pos + (1 << 9)] < key ? pos + (1 << 9) : pos);
        [[fallthrough]];
    case 1u << 9:
        pos = (vec[pos + (1 << 8)] < key ? pos + (1 << 8) : pos);
        [[fallthrough]];
    case 1u << 8:
        pos = (vec[pos + (1 << 7)] < key ? pos + (1 << 7) : pos);
        [[fallthrough]];
    case 1u << 7:
        pos = (vec[pos + (1 << 6)] < key ? pos + (1 << 6) : pos);
        [[fallthrough]];
    case 1u << 6:
        pos = (vec[pos + (1 << 5)] < key ? pos + (1 << 5) : pos);
        [[fallthrough]];
    case 1u << 5:
        pos = (vec[pos + (1 << 4)] < key ? pos + (1 << 4) : pos);
        [[fallthrough]];
    case 1u << 4:
        pos = (vec[pos + (1 << 3)] < key ? pos + (1 << 3) : pos);
        [[fallthrough]];
    case 1u << 3:
        pos = (vec[pos + (1 << 2)] < key ? pos + (1 << 2) : pos);
        [[fallthrough]];
    case 1u << 2:
        pos = (vec[pos + (1 << 1)] < key ? pos + (1 << 1) : pos);
        [[fallthrough]];
    case 1u << 1:
        pos = (vec[pos + (1 << 0)] < key ? pos + (1 << 0) : pos);
        [[fallthrough]];
    case 1u << 0:
        return vec + pos + 1;
    }

    return std::lower_bound(vec, vec + n, key);
}

}  // namespace evmone
