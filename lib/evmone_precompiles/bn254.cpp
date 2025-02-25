// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "bn254.hpp"

namespace evmmax::bn254
{
namespace
{
constexpr ModArith Fp{FieldPrime};
constexpr auto B = Fp.to_mont(3);
constexpr auto B3 = Fp.to_mont(3 * 3);
}  // namespace

bool validate(const Point& pt) noexcept
{
    if (pt.is_inf())
        return true;

    const auto xm = Fp.to_mont(pt.x);
    const auto ym = Fp.to_mont(pt.y);
    const auto y2 = Fp.mul(ym, ym);
    const auto x2 = Fp.mul(xm, xm);
    const auto x3 = Fp.mul(x2, xm);
    const auto x3_3 = Fp.add(x3, B);
    return y2 == x3_3;
}

Point add(const Point& pt1, const Point& pt2) noexcept
{
    if (pt1.is_inf())
        return pt2;
    if (pt2.is_inf())
        return pt1;

    // b3 == 9 for y^2 == x^3 + 3
    const auto r = ecc::add(Fp, ecc::to_proj(Fp, pt1), ecc::to_proj(Fp, pt2), B3);

    return ecc::to_affine(Fp, r);
}

Point mul(const Point& pt, const uint256& c) noexcept
{
    if (pt.is_inf())
        return pt;

    if (c == 0)
        return {};

    const auto pr = ecc::mul(Fp, ecc::to_proj(Fp, pt), c, B3);

    return ecc::to_affine(Fp, pr);
}
}  // namespace evmmax::bn254
