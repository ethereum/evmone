#include "bn254.hpp"

namespace evmmax::bn254
{
bool validate(const Point& pt) noexcept
{
    if (is_at_infinity(pt))
        return true;

    const evmmax::ModArith s{BN254Mod};
    const auto xm = s.to_mont(pt.x);
    const auto ym = s.to_mont(pt.y);
    const auto y2 = s.mul(ym, ym);
    const auto x2 = s.mul(xm, xm);
    const auto x3 = s.mul(x2, xm);
    const auto _3 = s.to_mont(3);
    const auto x3_3 = s.add(x3, _3);
    return y2 == x3_3;
}

Point bn254_add(const Point& pt1, const Point& pt2) noexcept
{
    if (is_at_infinity(pt1))
        return pt2;
    if (is_at_infinity(pt2))
        return pt1;

    const evmmax::ModArith s{BN254Mod};

    // https://eprint.iacr.org/2015/1060 algorithm 2.
    // Simplified with z3 == 1, a == 0, b3 == 9.

    auto b3 = s.to_mont(9);

    auto x1 = s.to_mont(pt1.x);
    auto y1 = s.to_mont(pt1.y);

    auto x2 = s.to_mont(pt2.x);
    auto y2 = s.to_mont(pt2.y);

    uint256 x3, y3, z3, t0, t1, t3, t4, t5;

    t0 = s.mul(x1, x2);
    t1 = s.mul(y1, y2);
    t3 = s.add(x2, y2);
    t4 = s.add(x1, y1);
    t3 = s.mul(t3, t4);
    t4 = s.add(t0, t1);
    t3 = s.sub(t3, t4);
    t4 = s.add(x2, x1);
    t5 = s.add(y2, y1);
    x3 = s.sub(t1, b3);
    z3 = s.add(t1, b3);
    y3 = s.mul(x3, z3);
    t1 = s.add(t0, t0);
    t1 = s.add(t1, t0);
    t4 = s.mul(b3, t4);
    t0 = s.mul(t1, t4);
    y3 = s.add(y3, t0);
    t0 = s.mul(t5, t4);
    x3 = s.mul(t3, x3);
    x3 = s.sub(x3, t0);
    t0 = s.mul(t3, t1);
    z3 = s.mul(t5, z3);
    z3 = s.add(z3, t0);

    auto z3_inv = inv(s, z3);
    x3 = s.mul(x3, z3_inv);
    y3 = s.mul(y3, z3_inv);
    x3 = s.from_mont(x3);
    y3 = s.from_mont(y3);

    return {x3, y3};
}
}  // namespace evmmax::bn254
