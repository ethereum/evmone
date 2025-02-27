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

Point add(const Point& p, const Point& q) noexcept
{
    if (p.is_inf())
        return q;
    if (q.is_inf())
        return p;

    const auto x1 = Fp.to_mont(p.x);
    const auto y1 = Fp.to_mont(p.y);
    const auto x2 = Fp.to_mont(q.x);
    const auto y2 = Fp.to_mont(q.y);

    const auto dx = Fp.sub(x2, x1);
    const auto dy = Fp.sub(y2, y1);

    const auto dx1 = Fp.inv(dx);
    auto slope = Fp.mul(dy, dx1);
    if (dx == 0)
    {
        if (dy != 0)
            return {0, 0};

        const auto xx = Fp.mul(x1, x1);
        const auto xx3 = Fp.add(Fp.add(xx, xx), xx);
        const auto yy = Fp.add(y1, y1);

        slope = Fp.mul(xx3, Fp.inv(yy));
    }

    const auto xr = Fp.sub(Fp.sub(Fp.mul(slope, slope), x1), x2);
    const auto yr = Fp.sub(Fp.mul(Fp.sub(x1, xr), slope), y1);
    return {Fp.from_mont(xr), Fp.from_mont(yr)};
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
