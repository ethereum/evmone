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
bool is_at_infinity(const uint256& x, const uint256& y, const uint256& z) noexcept;

std::tuple<uint256, uint256, uint256> point_addition_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x1, const uint256& y1, const uint256& z1, const uint256& x2, const uint256& y2,
    const uint256& z2, const uint256& b3) noexcept;

std::tuple<uint256, uint256, uint256> point_doubling_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x, const uint256& y, const uint256& z, const uint256& b3) noexcept;

std::tuple<uint256, uint256, uint256> point_addition_mixed_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x1, const uint256& y1, const uint256& x2, const uint256& y2,
    const uint256& b3) noexcept;

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

uint256 inv(const evmmax::ModArith<uint256>& s, const uint256& x) noexcept;

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
Point bn254_mul(const Point& pt, const uint256& c) noexcept;

bool bn254_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;
bool bn254_mul_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;
}  // namespace evmmax::bn254
