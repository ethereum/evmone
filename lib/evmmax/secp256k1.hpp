// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "evmmax.hpp"

using namespace intx;

inline constexpr auto Secp256K1Mod =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;

namespace evmmax::secp256k1
{
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

}  // namespace evmmax::secp256k1
