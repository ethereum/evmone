// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "evmmax.hpp"

using namespace intx;

inline constexpr auto BN254Mod =
    0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_u256;

namespace evmmax::bn254
{
inline uint256 expmod(const evmmax::ModArith<uint256>& s, uint256 base, uint256 exponent) noexcept
{
    auto result = s.to_mont(1);

    while (exponent != 0)
    {
        if ((exponent & 1) != 0)
            result = s.mul(result, base);
        base = s.mul(base, base);
        exponent >>= 1;
    }
    return result;
}

inline uint256 inv(const evmmax::ModArith<uint256>& s, const uint256& x) noexcept
{
    return expmod(s, x, s.mod - 2);
}

struct Point
{
    uint256 x;
    uint256 y;

    friend bool operator==(const Point& a, const Point& b) noexcept
    {
        // TODO(intx): C++20 operator<=> = default does not work for uint256.
        return a.x == b.x && a.y == b.y;
    }
};

inline bool is_at_infinity(const Point& pt) noexcept
{
    return pt.x == 0 && pt.y == 0;
}

bool validate(const Point& pt) noexcept;

Point bn254_add(const Point& pt1, const Point& pt2) noexcept;
}  // namespace evmmax::bn254
