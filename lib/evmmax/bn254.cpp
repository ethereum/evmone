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

// bool validate(const uint256& x, const uint256& y, const uint256& z, const uint256& a, const
// uint256& b)
//{
//     if (x == 0 && y == 0 && z == 0)
//         return true;
//
//     const evmmax::ModArith s{BN254Mod};
//
//     const auto xm = s.to_mont(x);
//     const auto ym = s.to_mont(y);
//     const auto zm = s.to_mont(z);
//     const auto am = s.to_mont(a);
//     const auto bm = s.to_mont(b);
//
//     const auto y2 = s.mul(ym, ym);
//     const auto x2 = s.mul(xm, xm);
//     const auto x3 = s.mul(x2, xm);
//
//     const auto z2 = s.mul(zm, zm);
//     const auto z3 = s.mul(z2, zm);
//
//     const auto ls = s.mul(y2, zm);
//     const auto ax = s.mul(am, xm);
//     const auto axz2 = s.mul(ax, z2);
//     const auto bz3 = s.mul(bm, z3);
//
//     const auto rs = s.add(x3, s.add(axz2, bz3));
//
//     return ls == rs;
// }

namespace
{

std::tuple<uint256, uint256> from_proj(
    const evmmax::ModArith<uint256>& s, const uint256& x, const uint256& y, const uint256& z)
{
    auto z_inv = s.inv(z);
    return {s.mul(x, z_inv), s.mul(y, z_inv)};
}

}  // namespace

bool is_at_infinity(const uint256& x, const uint256& y, const uint256& z) noexcept
{
    return x == 0 && y == 0 && z == 0;
}

std::tuple<uint256, uint256, uint256> point_addition_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x1, const uint256& y1, const uint256& z1, const uint256& x2, const uint256& y2,
    const uint256& z2, const uint256& b3) noexcept
{
    if (is_at_infinity(x1, y1, z1))
        return {0, 0, 0};
    if (is_at_infinity(x2, y2, z2))
        return {0, 0, 0};

    // https://eprint.iacr.org/2015/1060 algorithm 1.
    // Simplified with a == 0

    uint256 x3, y3, z3, t0, t1, t2, t3, t4, t5;

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

std::tuple<uint256, uint256, uint256> point_doubling_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x, const uint256& y, const uint256& z, const uint256& b3) noexcept
{
    if (is_at_infinity(x, y, z))
        return {0, 0, 0};

    // https://eprint.iacr.org/2015/1060 algorithm 3.
    // Simplified with a == 0

    uint256 x3, y3, z3, t0, t1, t2, t3;

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

std::tuple<uint256, uint256, uint256> point_addition_mixed_a0(const evmmax::ModArith<uint256>& s,
    const uint256& x1, const uint256& y1, const uint256& x2, const uint256& y2,
    const uint256& b3) noexcept
{
    // https://eprint.iacr.org/2015/1060 algorithm 2.
    // Simplified with z1 == 1, a == 0

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

    return {x3, y3, z3};
}

Point bn254_add(const Point& pt1, const Point& pt2) noexcept
{
    if (is_at_infinity(pt1))
        return pt2;
    if (is_at_infinity(pt2))
        return pt1;

    const evmmax::ModArith s{BN254Mod};

    const auto x1 = s.to_mont(pt1.x);
    const auto y1 = s.to_mont(pt1.y);

    const auto x2 = s.to_mont(pt2.x);
    const auto y2 = s.to_mont(pt2.y);

    // b3 == 9 for y^2 == x^3 + 3
    const auto b3 = s.to_mont(9);
    auto [x3, y3, z3] = point_addition_mixed_a0(s, x1, y1, x2, y2, b3);

    std::tie(x3, y3) = from_proj(s, x3, y3, z3);

    return {s.from_mont(x3), s.from_mont(y3)};
}

Point bn254_mul(const Point& pt, const uint256& c) noexcept
{
    if (is_at_infinity(pt))
        return pt;

    if (c == 0)
        return {0, 0};

    const evmmax::ModArith s{BN254Mod};

    auto _1_mont = s.to_mont(1);

    uint256 x0 = 0;
    uint256 y0 = _1_mont;
    uint256 z0 = 0;

    uint256 x1 = s.to_mont(pt.x);
    uint256 y1 = s.to_mont(pt.y);
    uint256 z1 = _1_mont;

    auto b3 = s.to_mont(9);

    auto first_significant_met = false;

    for (int i = 255; i >= 0; --i)
    {
        const uint256 d = c & (uint256{1} << i);
        if (d == 0)
        {
            if (first_significant_met)
            {
                std::tie(x1, y1, z1) = point_addition_a0(s, x0, y0, z0, x1, y1, z1, b3);
                std::tie(x0, y0, z0) = point_doubling_a0(s, x0, y0, z0, b3);
                // std::tie(x0, y0, z0) = point_addition_a0(s, x0, y0, z0, x0, y0, z0, b3);
            }
        }
        else
        {
            std::tie(x0, y0, z0) = point_addition_a0(s, x0, y0, z0, x1, y1, z1, b3);
            std::tie(x1, y1, z1) = point_doubling_a0(s, x1, y1, z1, b3);
            first_significant_met = true;
            // std::tie(x1, y1, z1) = point_addition_a0(s, x1, y1, z1, x1, y1, z1, b3);
        }
    }

    std::tie(x0, y0) = from_proj(s, x0, y0, z0);

    return {s.from_mont(x0), s.from_mont(y0)};
}

bool is_on_curve_b2(const FE2Point& p)
{
    static const auto B2 =
        bn254::FE2::div(bn254::FE2({3, 0}).to_mont(), bn254::FE2({9, 1}).to_mont());
    return FE2::eq(FE2::sub(FE2::pow(p.y, 2), FE2::pow(p.x, 3)), B2);
}

bool is_on_curve_b12(const FE12Point& p)
{
    static const auto B12 = bn254::FE12({3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    return FE12::eq(FE12::sub(FE12::pow(p.y, 2), FE12::pow(p.x, 3)), B12);
}

FE12Point twist(const FE2Point& pt)
{
    static const auto omega = FE12({0, bn254::FE2::arith.one_mont(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    if (FE2Point::is_at_infinity(pt))
        return FE12Point::infinity();

    auto _x = pt.x;
    auto _y = pt.y;
    // Field isomorphism from Z[p] / x**2 to Z[p] / x**2 - 18*x + 82
    std::vector<uint256> xcoeffs(2);
    xcoeffs[0] = FE2::arith.sub(
        _x.coeffs[0], FE2::arith.mul(_x.coeffs[1], bn254::FE2::arith.template in_mont<9>()));
    xcoeffs[1] = _x.coeffs[1];
    std::vector<uint256> ycoeffs(2);
    ycoeffs[0] = FE2::arith.sub(
        _y.coeffs[0], FE2::arith.mul(_y.coeffs[1], bn254::FE2::arith.template in_mont<9>()));
    ycoeffs[1] = _y.coeffs[1];
    // Isomorphism into subfield of Z[p] / w**12 - 18 * w**6 + 82, where w**6 = x
    auto nx = FE12({xcoeffs[0], 0, 0, 0, 0, 0, xcoeffs[1], 0, 0, 0, 0, 0});
    auto ny = FE12({ycoeffs[0], 0, 0, 0, 0, 0, ycoeffs[1], 0, 0, 0, 0, 0});
    // Divide x coord by w**2 and y coord by w**3
    return {FE12::mul(nx, FE12::pow(omega, 2)), FE12::mul(ny, FE12::pow(omega, 3))};
}

FE12Point cast_to_fe12(const Point& pt)
{
    return {FE12({pt.x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
        FE12({pt.y, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})};
}

template <typename FieldElemT>
FieldElemT line_func(
    const PointExt<FieldElemT>& p1, const PointExt<FieldElemT>& p2, const PointExt<FieldElemT>& t)
{
    assert(!PointExt<FieldElemT>::is_at_infinity(p1));
    assert(!PointExt<FieldElemT>::is_at_infinity(p2));

    if (!FieldElemT::eq(p1.x, p2.x))
    {
        auto m = FieldElemT::div(FieldElemT::sub(p2.y, p1.y), FieldElemT::sub(p2.x, p1.x));
        return FieldElemT::sub(
            FieldElemT::mul(FieldElemT::sub(t.x, p1.x), m), FieldElemT::sub(t.y, p1.y));
    }
    else if (FieldElemT::eq(p1.y, p2.y))
    {
        auto m = FieldElemT::div(
            FieldElemT::mul(FieldElemT::pow(p1.x, 2), FieldElemT::arith.template in_mont<3>()),
            FieldElemT::mul(p1.y, FieldElemT::arith.template in_mont<2>()));
        return FieldElemT::sub(
            FieldElemT::mul(FieldElemT::sub(t.x, p1.x), m), FieldElemT::sub(t.y, p1.y));
    }
    else
        return FieldElemT::sub(t.x, p1.x);
}

// Elliptic curve doubling over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_double(const PointExt<FieldElemT>& p)
{
    using ET = FieldElemT;
    auto lambda = ET::div(ET::mul(ET::pow(p.x, 2), FieldElemT::arith.template in_mont<3>()),
        ET::mul(p.y, FieldElemT::arith.template in_mont<2>()));
    auto new_x = ET::sub(ET::pow(lambda, 2), ET::mul(p.x, FieldElemT::arith.template in_mont<2>()));
    auto new_y = ET::sub(ET::add(ET::mul(ET::neg(lambda), new_x), ET::mul(lambda, p.x)), p.y);

    return {new_x, new_y};
}

// Elliptic curve doubling over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_add(const PointExt<FieldElemT>& p1, const PointExt<FieldElemT>& p2)
{
    using ET = FieldElemT;

    if (PointExt<ET>::eq(p1, p2))
        return point_double(p1);
    else if (ET::eq(p1.x, p2.x))
        return {ET(), ET()};
    else
    {
        auto lambda = ET::div(ET::sub(p2.y, p1.y), ET::sub(p2.x, p1.x));
        auto new_x = ET::sub(ET::sub(ET::pow(lambda, 2), p1.x), p2.x);
        auto new_y = ET::sub(ET::add(ET::mul(ET::neg(lambda), new_x), ET::mul(lambda, p2.x)), p2.y);

        return {new_x, new_y};
    }
}

template <typename FieldElemT>
PointExt<FieldElemT> point_multiply(const PointExt<FieldElemT>& pt, const uint256& n)
{
    if (n == 0)
        return {FieldElemT(), FieldElemT()};
    else if (n == 1)
        return pt;
    else if (n % 2 == 0)
        return point_multiply(point_double(pt), n / 2);
    else
        return point_add(point_multiply(point_double(pt), n / 2), pt);
}

template FE2 line_func<FE2>(const PointExt<FE2>&, const PointExt<FE2>&, const PointExt<FE2>&);
template FE12 line_func<FE12>(const PointExt<FE12>&, const PointExt<FE12>&, const PointExt<FE12>&);
template PointExt<FE2> point_double(const PointExt<FE2>&);
template PointExt<FE12> point_double(const PointExt<FE12>&);
template PointExt<FE2> point_add(const PointExt<FE2>&, const PointExt<FE2>&);
template PointExt<FE12> point_add(const PointExt<FE12>&, const PointExt<FE12>&);
template PointExt<FE2> point_multiply(const PointExt<FE2>&, const uint256&);
template PointExt<FE12> point_multiply(const PointExt<FE12>&, const uint256&);

namespace
{
FE12 miller_loop(const FE12Point& Q, const FE12Point& P)
{
    static constexpr auto ate_loop_count = 29793968203157093288_u256;
    static constexpr auto log_ate_loop_count = 63;
    static const intx::uint<2816> final_exp_pow =  // ((field_modulus ** 12 - 1) // curve_order
        intx::from_string<intx::uint<2816>>(
            "55248423361322409631261712678317314709738210376295765418888273431419691083990754121397"
            "45027615406298170096085486546803436277011538294467478109073732568415510062016396777261"
            "39946029199968412598804882391702273019083653272047566316584365559776493027495458238373"
            "90287593765994350487322055416155052592630230333174746351564471187665317712957830319109"
            "59009091916248178265666882418044080818927857259679317140977167095260922612780719525601"
            "71111444072049229123565057483750161460024353346284167282452756217662335528813519139808"
            "29117053907212538123081572907154486160275093696482931360813732542638373512217522954115"
            "53763464360939302874020895174269731789175697133847480818272554725769374714961957527271"
            "88261435633271238710131736096299798168852925540549342330775279877006784354801422249722"
            "573783561685179618816480037695005515426162362431072245638324744480");
    if (FE12Point::is_at_infinity(Q) || FE12Point::is_at_infinity(P))
        return FE12::one();

    auto R = Q;
    auto f = FE12::one();
    for (auto i = log_ate_loop_count; i >= 0; --i)
    {
        f = FE12::mul(FE12::mul(f, f), line_func(R, R, P));
        R = point_double(R);
        if ((ate_loop_count & (uint256(1) << i)) != 0)
        {
            f = FE12::mul(f, line_func(R, Q, P));
            R = point_add(R, Q);
        }
    }

    FE12Point Q1 = {FE12::pow(Q.x, BN254Mod), FE12::pow(Q.y, BN254Mod)};
    // assert(is_on_curve_b12(Q1));
    FE12Point nQ2 = {FE12::pow(Q1.x, BN254Mod), FE12::pow(FE12::neg(Q1.y), BN254Mod)};
    // assert(is_on_curve_b12(nQ1));
    f = FE12::mul(f, line_func(R, Q1, P));
    R = point_add(R, Q1);
    f = FE12::mul(f, line_func(R, nQ2, P));
    // R = add(R, nQ2) This line is in many specifications but it technically does nothing
    return FE12::pow(f, final_exp_pow);
}
}  // namespace

FE12 pairing(const FE2Point& q, const Point& p)
{
    assert(is_on_curve_b2(q.to_mont()));
    assert(validate(p));

    Point p_mont = {FE2::arith.to_mont(p.x), FE2::arith.to_mont(p.y)};

    auto res = miller_loop(twist(q.to_mont()), cast_to_fe12(p_mont));

    return res.from_mont();
}

bool bn254_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept
{
    uint8_t input_padded[128]{};
    std::copy_n(input, std::min(input_size, sizeof(input_padded)), input_padded);

    const Point a{
        be::unsafe::load<uint256>(&input_padded[0]), be::unsafe::load<uint256>(&input_padded[32])};
    const Point b{
        be::unsafe::load<uint256>(&input_padded[64]), be::unsafe::load<uint256>(&input_padded[96])};

    if (!validate(a) || !validate(b))
        return false;

    const auto s = bn254_add(a, b);
    be::unsafe::store(output, s.x);
    be::unsafe::store(output + 32, s.y);
    return true;
}

bool bn254_mul_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept
{
    uint8_t input_padded[128]{};
    std::copy_n(input, std::min(input_size, sizeof(input_padded)), input_padded);

    const Point a{
        be::unsafe::load<uint256>(&input_padded[0]), be::unsafe::load<uint256>(&input_padded[32])};
    const auto s = be::unsafe::load<uint256>(&input_padded[64]);

    if (!validate(a))
        return false;

    const auto r = bn254_mul(a, s);
    be::unsafe::store(output, r.x);
    be::unsafe::store(output + 32, r.y);
    return true;
}

}  // namespace evmmax::bn254
