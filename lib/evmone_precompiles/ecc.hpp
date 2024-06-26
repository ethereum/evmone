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
    IntT x = 0;
    IntT y = 0;

    friend constexpr bool operator==(const Point& a, const Point& b) noexcept
    {
        // TODO(intx): C++20 operator<=> = default does not work for uint256.
        return a.x == b.x && a.y == b.y;
    }

    /// Checks if the point represents the special "infinity" value.
    [[nodiscard]] constexpr bool is_inf() const noexcept { return *this == Point{}; }
};

static_assert(Point<unsigned>{}.is_inf());

template <typename IntT>
struct ProjPoint
{
    IntT x = 0;
    IntT y = 1;
    IntT z = 0;

    /// Checks if the point represents the special "infinity" value.
    [[nodiscard]] constexpr bool is_inf() const noexcept { return x == 0 && z == 0; }
};

static_assert(ProjPoint<unsigned>{}.is_inf());

template <typename IntT>
using InvFn = IntT (*)(const ModArith<IntT>&, const IntT& x) noexcept;

/// Converts an affine point to a projected point with coordinates in Montgomery form.
template <typename IntT>
inline ProjPoint<IntT> to_proj(const ModArith<IntT>& s, const Point<IntT>& p) noexcept
{
    // FIXME: Add to_mont(1) to ModArith?
    // FIXME: Handle inf
    return {s.to_mont(p.x), s.to_mont(p.y), s.to_mont(1)};
}

/// Converts a projected point to an affine point.
template <typename IntT>
inline Point<IntT> to_affine(
    const ModArith<IntT>& s, InvFn<IntT> inv, const ProjPoint<IntT>& p) noexcept
{
    // FIXME: Split to_affine() and to/from_mont(). This is not good idea.
    // FIXME: Add tests for inf.
    const auto z_inv = inv(s, p.z);
    return {s.from_mont(s.mul(p.x, z_inv)), s.from_mont(s.mul(p.y, z_inv))};
}

template <typename IntT, int A = 0>
ProjPoint<IntT> add(const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& p,
    const ProjPoint<IntT>& q, const IntT& b3) noexcept
{
    static_assert(A == 0, "point addition procedure is simplified for a = 0");

    // Joost Renes and Craig Costello and Lejla Batina
    // "Complete addition formulas for prime order elliptic curves"
    // Cryptology ePrint Archive, Paper 2015/1060
    // https://eprint.iacr.org/2015/1060
    // Algorithm 7.

    const auto& x1 = p.x;
    const auto& y1 = p.y;
    const auto& z1 = p.z;
    const auto& x2 = q.x;
    const auto& y2 = q.y;
    const auto& z2 = q.z;
    IntT x3;
    IntT y3;
    IntT z3;
    IntT t0;
    IntT t1;
    IntT t2;
    IntT t3;
    IntT t4;

    t0 = s.mul(x1, x2);  // 1
    t1 = s.mul(y1, y2);  // 2
    t2 = s.mul(z1, z2);  // 3
    t3 = s.add(x1, y1);  // 4
    t4 = s.add(x2, y2);  // 5
    t3 = s.mul(t3, t4);  // 6
    t4 = s.add(t0, t1);  // 7
    t3 = s.sub(t3, t4);  // 8
    t4 = s.add(y1, z1);  // 9
    x3 = s.add(y2, z2);  // 10
    t4 = s.mul(t4, x3);  // 11
    x3 = s.add(t1, t2);  // 12
    t4 = s.sub(t4, x3);  // 13
    x3 = s.add(x1, z1);  // 14
    y3 = s.add(x2, z2);  // 15
    x3 = s.mul(x3, y3);  // 16
    y3 = s.add(t0, t2);  // 17
    y3 = s.sub(x3, y3);  // 18
    x3 = s.add(t0, t0);  // 19
    t0 = s.add(x3, t0);  // 20
    t2 = s.mul(b3, t2);  // 21
    z3 = s.add(t1, t2);  // 22
    t1 = s.sub(t1, t2);  // 23
    y3 = s.mul(b3, y3);  // 24
    x3 = s.mul(t4, y3);  // 25
    t2 = s.mul(t3, t1);  // 26
    x3 = s.sub(t2, x3);  // 27
    y3 = s.mul(y3, t0);  // 28
    t1 = s.mul(t1, z3);  // 29
    y3 = s.add(t1, y3);  // 30
    t0 = s.mul(t0, t3);  // 31
    z3 = s.mul(z3, t4);  // 32
    z3 = s.add(z3, t0);  // 33

    return {x3, y3, z3};
}


template <typename IntT, int A = 0>
ProjPoint<IntT> dbl(
    const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& p, const IntT& b3) noexcept
{
    static_assert(A == 0, "point doubling procedure is simplified for a = 0");

    // Joost Renes and Craig Costello and Lejla Batina
    // "Complete addition formulas for prime order elliptic curves"
    // Cryptology ePrint Archive, Paper 2015/1060
    // https://eprint.iacr.org/2015/1060
    // Algorithm 9.

    const auto& x = p.x;
    const auto& y = p.y;
    const auto& z = p.z;
    IntT x3;
    IntT y3;
    IntT z3;
    IntT t0;
    IntT t1;
    IntT t2;

    t0 = s.mul(y, y);    // 1
    z3 = s.add(t0, t0);  // 2
    z3 = s.add(z3, z3);  // 3
    z3 = s.add(z3, z3);  // 4
    t1 = s.mul(y, z);    // 5
    t2 = s.mul(z, z);    // 6
    t2 = s.mul(b3, t2);  // 7
    x3 = s.mul(t2, z3);  // 8
    y3 = s.add(t0, t2);  // 9
    z3 = s.mul(t1, z3);  // 10
    t1 = s.add(t2, t2);  // 11
    t2 = s.add(t1, t2);  // 12
    t0 = s.sub(t0, t2);  // 13
    y3 = s.mul(t0, y3);  // 14
    y3 = s.add(x3, y3);  // 15
    t1 = s.mul(x, y);    // 16
    x3 = s.mul(t0, t1);  // 17
    x3 = s.add(x3, x3);  // 18

    return {x3, y3, z3};
}

template <typename IntT, int A = 0>
ProjPoint<IntT> mul(const evmmax::ModArith<IntT>& s, const ProjPoint<IntT>& z, const IntT& c,
    const IntT& b3) noexcept
{
    ProjPoint<IntT> p;
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

// Computes uG + vQ using "Shamir's trick". https://eprint.iacr.org/2003/257.pdf (page 7)
template <typename UIntT>
inline ProjPoint<UIntT> shamir_multiply(const ModArith<UIntT>& m, const UIntT& b3, const UIntT& u,
    const ProjPoint<UIntT>& g, const UIntT& v, const ProjPoint<UIntT>& q)
{
    ProjPoint<UIntT> r;
    const auto h = add(m, g, q, b3);

    const auto u_lz = clz(u);
    const auto v_lz = clz(v);

    auto lz = std::min(u_lz, v_lz);

    if (lz == UIntT::num_bits)
        return {};

    if (u_lz < v_lz)
        r = g;
    else if (u_lz > v_lz)
        r = q;
    else
        r = h;

    auto mask = (UIntT{1} << (UIntT::num_bits - 1 - lz - 1));

    while (mask != 0)
    {
        r = dbl(m, r, b3);
        if (u & v & mask)
            r = add(m, r, h, b3);
        else if (u & mask)
            r = add(m, r, g, b3);
        else if (v & mask)
            r = add(m, r, q, b3);

        mask >>= 1;
    }

    return r;
}

// Decomposes scalar k into k₁ and k₂ such that k₁ + k₂λ ≡ k mod n
// Returns ((is_negative, k1), (is_negative, k2))
template <typename ConfigT, typename UIntT>
inline std::pair<std::pair<bool, UIntT>, std::pair<bool, UIntT>> decompose(const UIntT& k) noexcept
{
    using DIntT = intx::uint<2 * UIntT::num_bits>;

    const auto round_div = [](const DIntT& n) {
        const auto [q, r] = udivrem(n, ConfigT::DET);

        return (r <= (ConfigT::DET / 2)) ? q : (q + 1);
    };

    const auto z1 = round_div(ConfigT::Y2 * k);
    const auto z2 = round_div(ConfigT::Y1 * k);

    auto const z1x1_z2x2 = z1 * ConfigT::X1 + z2 * ConfigT::X2;

    auto k1_is_neg = false;
    auto k2_is_neg = false;

    auto tk = k;
    if (tk < z1x1_z2x2)
        k1_is_neg = true;

    const auto k1 = !k1_is_neg ? (tk - z1x1_z2x2) : z1x1_z2x2 - tk;

    const DIntT z2y2 = z2 * ConfigT::Y2;
    const DIntT z1y1 = z1 * ConfigT::Y1;

    if (z1y1 < z2y2)
        k2_is_neg = true;

    const DIntT k2 = !k2_is_neg ? (z1y1 - z2y2) : z2y2 - z1y1;

    return {{k1_is_neg, UIntT{k1}}, {k2_is_neg, UIntT{k2}}};
}

}  // namespace evmmax::ecc
