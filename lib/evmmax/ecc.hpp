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
    [[nodiscard]] constexpr bool is_inf() const noexcept { return x == 0 && z == 0; }
};

template <typename IntT>
using InvFn = IntT (*)(const ModArith<IntT>&, const IntT& x) noexcept;

/// Converts an affine point to a projected point with coordinates in Montgomery form.
template <typename IntT>
inline ProjPoint<IntT> to_proj(const ModArith<IntT>& s, const Point<IntT>& p) noexcept
{
    // FIXME: Add to_mont(1) to ModArith?
    return {s.to_mont(p.x), s.to_mont(p.y), s.to_mont(1)};
}

/// Converts a projected point to an affine point.
template <typename IntT>
inline Point<IntT> to_affine(
    const ModArith<IntT>& s, InvFn<IntT> inv, const ProjPoint<IntT>& p) noexcept
{
    const auto z_inv = inv(s, p.z);
    return {s.from_mont(s.mul(p.x, z_inv)), s.from_mont(s.mul(p.y, z_inv))};
}

template <typename IntT, int A = 0>
ProjPoint<IntT> add(const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& p,
    const ProjPoint<IntT>& q, const IntT& b3) noexcept
{
    static_assert(A == 0, "point addition procedure is simplified for a = 0");

    if (p.is_inf())
        return q;
    if (q.is_inf())
        return p;

    // https://eprint.iacr.org/2015/1060 algorithm 1.
    // Simplified with a == 0

    auto& x1 = p.x;
    auto& y1 = p.y;
    auto& z1 = p.z;
    auto& x2 = q.x;
    auto& y2 = q.y;
    auto& z2 = q.z;

    IntT x3;
    IntT y3;
    IntT z3;
    IntT t0;
    IntT t1;
    IntT t2;
    IntT t3;
    IntT t4;
    IntT t5;

    t0 = s.mul(x1, x2);  // 1
    t1 = s.mul(y1, y2);  // 2
    t2 = s.mul(z1, z2);  // 3
    t3 = s.add(x1, y1);  // 4
    t4 = s.add(x2, y2);  // 5
    t3 = s.mul(t3, t4);  // 6
    t4 = s.add(t0, t1);  // 7
    t3 = s.sub(t3, t4);  // 8
    t4 = s.add(x1, z1);  // 9
    t5 = s.add(x2, z2);  // 10
    t4 = s.mul(t4, t5);  // 11
    t5 = s.add(t0, t2);  // 12
    t4 = s.sub(t4, t5);  // 13
    t5 = s.add(y1, z1);  // 14
    x3 = s.add(y2, z2);  // 15
    t5 = s.mul(t5, x3);  // 16
    x3 = s.add(t1, t2);  // 17
    t5 = s.sub(t5, x3);  // 18
    // z3 = 0;//s.mul(a, t4);  // 19
    x3 = s.mul(b3, t2);  // 20
    // z3 = x3; //s.add(x3, z3); // 21
    z3 = s.add(t1, x3);  // 23
    x3 = s.sub(t1, x3);  // 22
    y3 = s.mul(x3, z3);  // 24
    t1 = s.add(t0, t0);  // 25
    t1 = s.add(t1, t0);  // 26
    // t2 = 0; // s.mul(a, t2);  // 27
    t4 = s.mul(b3, t4);  // 28
    // t1 = s.add(t1, t2); // 29
    // t2 = t0; //s.sub(t0, t2); // 30
    // t2 = s.mul(a, t2);  // 31
    // t4 = s.add(t4, t2); // 32
    t0 = s.mul(t1, t4);  // 33
    y3 = s.add(y3, t0);  // 34
    t0 = s.mul(t5, t4);  // 35
    x3 = s.mul(t3, x3);  // 36
    x3 = s.sub(x3, t0);  // 37
    t0 = s.mul(t3, t1);  // 38
    z3 = s.mul(t5, z3);  // 39
    z3 = s.add(z3, t0);  // 40

    return {x3, y3, z3};
}


template <typename IntT, int A = 0>
ProjPoint<IntT> dbl(
    const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& p, const IntT& b3) noexcept
{
    static_assert(A == 0, "point doubling procedure is simplified for a = 0");
    if (p.is_inf())
        return p;

    // https://eprint.iacr.org/2015/1060 algorithm 3.
    // Simplified with a == 0

    auto& x = p.x;
    auto& y = p.y;
    auto& z = p.z;

    IntT x3;
    IntT y3;
    IntT z3;
    IntT t0;
    IntT t1;
    IntT t2;
    IntT t3;

    t0 = s.mul(x, x);    // 1
    t1 = s.mul(y, y);    // 2
    t2 = s.mul(z, z);    // 3
    t3 = s.mul(x, y);    // 4
    t3 = s.add(t3, t3);  // 5
    z3 = s.mul(x, z);    // 6
    z3 = s.add(z3, z3);  // 7
    // x3 = s.mul(0, z3); // 8
    y3 = s.mul(b3, t2);  // 9
    // y3 = s.add(x3, y3); // 10
    x3 = s.sub(t1, y3);  // 11
    y3 = s.add(t1, y3);  // 12
    y3 = s.mul(x3, y3);  // 13
    x3 = s.mul(t3, x3);  // 14
    z3 = s.mul(b3, z3);  // 15
    // t2 = s.mul(0, t2); // 16
    // t3 = s.sub(t0, t2); // 17
    // t3 = s.mul(0, t3); // 18
    t3 = z3;             // s.add(t3, z3);  // 19
    z3 = s.add(t0, t0);  // 20
    t0 = s.add(z3, t0);  // 21
    // t0 = s.add(t0, t2); // 22
    t0 = s.mul(t0, t3);  // 23
    y3 = s.add(y3, t0);  // 24
    t2 = s.mul(y, z);    // 25
    t2 = s.add(t2, t2);  // 26
    t0 = s.mul(t2, t3);  // 27
    x3 = s.sub(x3, t0);  // 28
    z3 = s.mul(t2, t1);  // 29
    z3 = s.add(z3, z3);  // 30
    z3 = s.add(z3, z3);  // 31

    return {x3, y3, z3};
}

template <typename IntT, int A = 0>
ProjPoint<IntT> mul(const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& z, const IntT& c,
    const IntT& b3) noexcept
{
    ProjPoint<IntT> p{0, s.to_mont(1), 0};  // FIXME: Why z==0?
    auto q = z;
    auto first_significant_met = false;

    for (int i = 255; i >= 0; --i)
    {
        const auto d = c & (IntT{1} << i);
        if (d == 0)
        {
            if (first_significant_met)
            {
                q = ecc::add(s, p, q, b3);
                p = ecc::dbl(s, p, b3);
            }
        }
        else
        {
            p = ecc::add(s, p, q, b3);
            q = ecc::dbl(s, q, b3);
            first_significant_met = true;
        }
    }

    return p;
}


}  // namespace evmmax::ecc
