// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "evmmax.hpp"
#include <ethash/keccak.hpp>
#include <optional>

using namespace intx;

inline constexpr auto Secp256K1Mod =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;
inline constexpr auto Secp256K1N =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_u256;

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

uint256 inv(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> sqrt(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> sec256k1_calculate_y(
    const ModArith<uint256>& s, const uint256& x, bool is_odd) noexcept;

std::optional<Point> ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;
}  // namespace evmmax::secp256k1
