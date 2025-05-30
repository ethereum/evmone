// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "bn254.hpp"
#include <iostream>

namespace evmmax::bn254
{
namespace
{
constexpr ModArith Fp{FieldPrime};
constexpr auto B = Fp.to_mont(3);
// constexpr auto B3 = Fp.to_mont(3 * 3);
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
    const auto expected = ecc::add(Fp, p, q);

    // FIXME: Skip inf for now.
    if (p.is_inf() || q.is_inf())
        return expected;

    // FIXME: Skip double for now.
    if (p == q)
        return expected;

    using namespace ecc;
    JacPoint<uint256> jp{Fp.to_mont(p.x), Fp.to_mont(p.y), Fp.to_mont(1)};
    JacPoint<uint256> jq{Fp.to_mont(q.x), Fp.to_mont(q.y), Fp.to_mont(1)};
    const auto result = ecc::add(Fp, jp, jq);
    const auto actual = ecc::to_affine(Fp, result);

    if (actual != expected)
    {
        std::cerr << hex(p.x) << "\n" << hex(p.y) << "\n" << hex(q.x) << "\n" << hex(q.y) << "\n\n";
        std::cerr << hex(expected.x) << "\n"
                  << hex(result.x) << "\n\n"
                  << hex(expected.y) << "\n"
                  << hex(result.y) << "\n\n\n";
        // assert(false);
        // std::cerr << "expected: " << expected << std::endl;
        // std::cerr << "actual: " << actual << std::endl;
        // std::cerr << "jp: " << jp << std::endl;
        // std::cerr << "jq: " << jq << std::endl;
        // std::cerr << "result: " << result << std::endl;
        // std::cerr << "expected: " << expected << std::endl;
        // std::cerr << "actual: " << actual << std::endl;
        // std::cerr << "expected: " << expected << std::endl;
        // std::cerr << "actual: " << actual << std::endl;
    }

    return expected;
}

Point mul(const Point& pt, const uint256& c) noexcept
{
    if (pt.is_inf())
        return pt;

    if (c == 0)
        return {};

    const Point p_mont{Fp.to_mont(pt.x), Fp.to_mont(pt.y)};
    const auto pr = ecc::mul(Fp, p_mont, c);

    return ecc::to_affine(Fp, pr);
}
}  // namespace evmmax::bn254
