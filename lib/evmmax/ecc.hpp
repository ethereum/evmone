// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmmax/evmmax.hpp>

namespace evmmax::ecc
{

/// The affine (two coordinates) point on an Elliptic Curve over a prime field.
template <typename IntT>
struct Point
{
    IntT x = {};
    IntT y = {};

    friend bool operator==(const Point& a, const Point& b) noexcept
    {
        // TODO(intx): C++20 operator<=> = default does not work for uint256.
        return a.x == b.x && a.y == b.y;
    }

    /// Checks if the point represents the special "infinity" value.
    [[nodiscard]] constexpr bool is_inf() const noexcept { return *this == Point{}; }
};

template <typename IntT>
struct ProjPoint
{
    IntT x = {};
    IntT y = {};
    IntT z = {};  // FIXME: 1?

    /// Checks if the point represents the special "infinity" value.
    [[nodiscard]] constexpr bool is_inf() const noexcept { return x == 0 && y == 0; }
};

template <typename IntT>
using InvFn = IntT (*)(const ModArith<IntT>&, const IntT& x) noexcept;

/// Converts a projected point to an affine point.
template <typename IntT>
inline Point<IntT> to_affine(
    const ModArith<IntT>& s, InvFn<IntT> inv, const ProjPoint<IntT>& p) noexcept
{
    const auto z_inv = inv(s, p.z);
    return {s.mul(p.x, z_inv), s.mul(p.y, z_inv)};
}
}  // namespace evmmax::ecc
