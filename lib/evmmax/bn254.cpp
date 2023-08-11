#include "bn254.hpp"

namespace evmmax::bn254
{
bool validate(const Point& pt) noexcept
{
    if (pt.is_inf())
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

std::tuple<uint256, uint256> from_proj(const uint256& x, const uint256& y, const uint256& z)
{
    static const BN254ModArith s;
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

    uint256 x3;
    uint256 y3;
    uint256 z3;
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;
    uint256 t4;
    uint256 t5;

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

    uint256 x3;
    uint256 y3;
    uint256 z3;
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;

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

    uint256 x3;
    uint256 y3;
    uint256 z3;
    uint256 t0;
    uint256 t1;
    uint256 t3;
    uint256 t4;
    uint256 t5;

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
    if (pt1.is_inf())
        return pt2;
    if (pt2.is_inf())
        return pt1;

    const evmmax::ModArith s{BN254Mod};

    const auto x1 = s.to_mont(pt1.x);
    const auto y1 = s.to_mont(pt1.y);

    const auto x2 = s.to_mont(pt2.x);
    const auto y2 = s.to_mont(pt2.y);

    // b3 == 9 for y^2 == x^3 + 3
    const auto b3 = s.to_mont(9);
    auto [x3, y3, z3] = point_addition_mixed_a0(s, x1, y1, x2, y2, b3);

    std::tie(x3, y3) = from_proj(x3, y3, z3);

    return {s.from_mont(x3), s.from_mont(y3)};
}

Point bn254_mul(const Point& pt, const uint256& c) noexcept
{
    if (pt.is_inf())
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

    std::tie(x0, y0) = from_proj(x0, y0, z0);

    return {s.from_mont(x0), s.from_mont(y0)};
}

bool is_on_curve_b(const uint256& x, const uint256& y, const uint256& z) noexcept
{
    static const auto B = bn254::FE2::arith.in_mont<3>();
    return bn254::FE2::arith.sub(bn254::FE2::arith.mul(bn254::FE2::arith.pow(y, 2), z),
               bn254::FE2::arith.pow(x, 3)) ==
           bn254::FE2::arith.mul(B, bn254::FE2::arith.pow(z, 3));
}

bool is_on_curve_b2(const FE2Point& p) noexcept
{
    static const auto B2 =
        bn254::FE2::div(bn254::FE2({3, 0}).to_mont(), bn254::FE2({9, 1}).to_mont());
    return (p.y ^ 2) * p.z - (p.x ^ 3) == B2 * (p.z ^ 3);
}

bool is_on_curve_b12(const FE12Point& p) noexcept
{
    static const auto B12 = bn254::FE12({3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    return (p.y ^ 2) * p.z - (p.x ^ 3) == B12.to_mont() * (p.z ^ 3);
}

FE12Point twist(const FE2Point& pt) noexcept
{
    static const auto omega = FE12({0, bn254::FE2::arith.one_mont(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    if (FE2Point::is_at_infinity(pt))
        return FE12Point::infinity();

    auto _x = pt.x;
    auto _y = pt.y;
    auto _z = pt.z;
    // Field isomorphism from Z[p] / x**2 to Z[p] / x**2 - 18*x + 82
    std::vector<uint256> xcoeffs(2);
    xcoeffs[0] = FE2::arith.sub(
        _x.coeffs[0], FE2::arith.mul(_x.coeffs[1], bn254::FE2::arith.template in_mont<9>()));
    xcoeffs[1] = _x.coeffs[1];
    std::vector<uint256> ycoeffs(2);
    ycoeffs[0] = FE2::arith.sub(
        _y.coeffs[0], FE2::arith.mul(_y.coeffs[1], bn254::FE2::arith.template in_mont<9>()));
    ycoeffs[1] = _y.coeffs[1];
    std::vector<uint256> zcoeffs(2);
    zcoeffs[0] = FE2::arith.sub(
        _z.coeffs[0], FE2::arith.mul(_z.coeffs[1], bn254::FE2::arith.template in_mont<9>()));
    zcoeffs[1] = _z.coeffs[1];
    // Isomorphism into subfield of Z[p] / w**12 - 18 * w**6 + 82, where w**6 = x
    auto nx = FE12({xcoeffs[0], 0, 0, 0, 0, 0, xcoeffs[1], 0, 0, 0, 0, 0});
    auto ny = FE12({ycoeffs[0], 0, 0, 0, 0, 0, ycoeffs[1], 0, 0, 0, 0, 0});
    auto nz = FE12({zcoeffs[0], 0, 0, 0, 0, 0, zcoeffs[1], 0, 0, 0, 0, 0});
    // Multiply x coord by w**2 and y coord by w**3
    return {nx * (omega ^ 2), ny * (omega ^ 3), nz};
}

FE12Point cast_to_fe12(const Point& pt) noexcept
{
    return {FE12({pt.x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
        FE12({pt.y, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), FE12({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})};
}

template <typename FieldElemT>
std::pair<FieldElemT, FieldElemT> line_func(const PointExt<FieldElemT>& p1,
    const PointExt<FieldElemT>& p2, const PointExt<FieldElemT>& t) noexcept
{
    assert(!PointExt<FieldElemT>::is_at_infinity(p1));
    assert(!PointExt<FieldElemT>::is_at_infinity(p2));

    auto m_numerator = p2.y * p1.z - p1.y * p2.z;
    auto m_denominator = p2.x * p1.z - p1.x * p2.z;

    if (m_denominator != FieldElemT::zero())
    {
        return {m_numerator * (t.x * p1.z - p1.x * t.z) - m_denominator * (t.y * p1.z - p1.y * t.z),
            m_denominator * t.z * p1.z};
    }
    else if (m_numerator == FieldElemT::zero())
    {
        static const auto _3_mont = FieldElemT::arith.template in_mont<3>();
        static const auto _2_mont = FieldElemT::arith.template in_mont<2>();

        m_numerator = (p1.x * p1.x) * _3_mont;
        m_denominator = _2_mont * p1.y * p1.z;

        return {m_numerator * (t.x * p1.z - p1.x * t.z) - m_denominator * (t.y * p1.z - p1.y * t.z),
            m_denominator * t.z * p1.z};
    }
    else
        return {t.x * p1.z - p1.x * t.z, p1.z * t.z};
}

// Elliptic curve doubling over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_double(const PointExt<FieldElemT>& p) noexcept
{
    // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates

    static const auto _2_mont = FieldElemT::arith.template in_mont<2>();
    static const auto _3_mont = FieldElemT::arith.template in_mont<3>();
    static const auto _4_mont = FieldElemT::arith.template in_mont<4>();
    static const auto _8_mont = FieldElemT::arith.template in_mont<8>();

    auto W = _3_mont * (p.x * p.x);
    auto S = p.y * p.z;
    auto B = p.x * p.y * S;
    auto H = W * W - _8_mont * B;
    auto S_squared = S * S;

    auto new_x = _2_mont * H * S;
    auto new_y = W * (_4_mont * B - H) - _8_mont * (p.y * p.y) * S_squared;
    auto new_z = _8_mont * S_squared * S;

    return {new_x, new_y, new_z};
}

// Elliptic curve doubling over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_add(
    const PointExt<FieldElemT>& p1, const PointExt<FieldElemT>& p2) noexcept
{
    // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates
    using ET = FieldElemT;

    if (p1.z == ET::zero() || p2.z == ET::zero())
        return p2.z == ET::zero() ? p1 : p2;

    auto X1 = p1.x;
    auto Y1 = p1.y;
    auto Z1 = p1.z;
    auto X2 = p2.x;
    auto Y2 = p2.y;
    auto Z2 = p2.z;

    auto U1 = Y2 * Z1;
    auto U2 = Y1 * Z2;
    auto V1 = X2 * Z1;
    auto V2 = X1 * Z2;
    if (V1 == V2 && U1 == U2)
        return point_double(p1);
    else if (V1 == V2)
        return {ET::one(), ET::one(), ET::zero()};

    static const auto _2_mont = FieldElemT::arith.template in_mont<2>();

    auto U = U1 - U2;
    auto V = V1 - V2;
    auto V_squared = V * V;
    auto V_squared_times_V2 = V_squared * V2;
    auto V_cubed = V * V_squared;
    auto W = Z1 * Z2;
    auto A = U * U * W - V_cubed - _2_mont * V_squared_times_V2;
    auto new_x = V * A;
    auto new_y = U * (V_squared_times_V2 - A) - V_cubed * U2;
    auto new_z = V_cubed * W;

    return {new_x, new_y, new_z};
}

template <typename FieldElemT>
PointExt<FieldElemT> point_multiply(  // NOLINT(misc-no-recursion)
    const PointExt<FieldElemT>& pt, const uint256& n) noexcept
{
    if (n == 0)
        return {FieldElemT(), FieldElemT(), FieldElemT()};
    else if (n == 1)
        return pt;
    else if (n % 2 == 0)
        return point_multiply(point_double(pt), n / 2);
    else
        return point_add(point_multiply(point_double(pt), n / 2), pt);
}

template std::pair<FE2, FE2> line_func<FE2>(
    const PointExt<FE2>&, const PointExt<FE2>&, const PointExt<FE2>&);
template std::pair<FE12, FE12> line_func<FE12>(
    const PointExt<FE12>&, const PointExt<FE12>&, const PointExt<FE12>&);
template PointExt<FE2> point_double(const PointExt<FE2>&);
template PointExt<FE12> point_double(const PointExt<FE12>&);
template PointExt<FE2> point_add(const PointExt<FE2>&, const PointExt<FE2>&);
template PointExt<FE12> point_add(const PointExt<FE12>&, const PointExt<FE12>&);
template PointExt<FE2> point_multiply(const PointExt<FE2>&, const uint256&);
template PointExt<FE12> point_multiply(const PointExt<FE12>&, const uint256&);

FE12 miller_loop(const FE12Point& Q, const FE12Point& P, bool run_final_exp) noexcept
{
    static const int8_t pseudo_binary_encoding[] = {0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1,
        0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
        -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1, 1};

    // static constexpr auto ate_loop_count = 29793968203157093288_u256;
    // static constexpr auto log_ate_loop_count = 63;
    if (FE12Point::is_at_infinity(Q) || FE12Point::is_at_infinity(P))
        return FE12::one_mont();

    auto R = Q;
    auto f_num = FE12::one_mont();
    auto f_den = FE12::one_mont();
    for (int i = sizeof(pseudo_binary_encoding) - 2; i >= 0; --i)
    {
        auto [_n, _d] = line_func(R, R, P);
        f_num = f_num * f_num * _n;
        f_den = f_den * f_den * _d;
        R = point_double(R);
        if (pseudo_binary_encoding[i] == 1)
        {
            std::tie(_n, _d) = line_func(R, Q, P);
            f_num = f_num * _n;
            f_den = f_den * _d;
            R = point_add(R, Q);
        }
        else if (pseudo_binary_encoding[i] == -1)
        {
            const FE12Point nQ = {Q.x, -Q.y, Q.z};
            std::tie(_n, _d) = line_func(R, nQ, P);
            f_num = f_num * _n;
            f_den = f_den * _d;
            R = point_add(R, nQ);
        }
    }

    const FE12Point Q1 = {Q.x ^ BN254Mod, Q.y ^ BN254Mod, Q.z ^ BN254Mod};
    // assert(is_on_curve_b12(Q1));
    const FE12Point nQ2 = {Q1.x ^ BN254Mod, -(Q1.y ^ BN254Mod), Q1.z ^ BN254Mod};
    // assert(is_on_curve_b12(nQ1));
    auto [_n1, _d1] = line_func(R, Q1, P);
    R = point_add(R, Q1);
    auto [_n2, _d2] = line_func(R, nQ2, P);
    auto f = FE12::div(f_num * _n1 * _n2, f_den * _d1 * _d2);
    // R = add(R, nQ2) This line is in many specifications but it technically does nothing
    if (run_final_exp)
        return final_exponentiation(f);
    else
        return f;
}

FE12 bn254_pairing(const FE2Point& q, const Point& p) noexcept
{
    assert(is_on_curve_b2(q.to_mont()));
    assert(is_on_curve_b(p.x, p.y, 1));

    auto p_12 = cast_to_fe12(p);

    auto res = miller_loop(twist(q.to_mont()), p_12.to_mont(), true);

    return res.from_mont();
}

namespace
{
const auto final_exp_pow =  // ((field_modulus ** 12 - 1) // curve_order
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
}  // namespace

FE12 final_exponentiation(const FE12& a) noexcept
{
    return FE12::pow(a, final_exp_pow);
}

bool bn254_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept
{
    using namespace intx;
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
    using namespace intx;
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

bool bn254_ecpairing_precompile(  // NOLINT(bugprone-exception-escape)
    const uint8_t* input, size_t input_size, uint8_t* output) noexcept
{
    using namespace intx;
    static const size_t input_stride = 192;
    if (input_size % input_stride != 0)
        return false;

    auto k = input_size / input_stride;
    FE12 accumulator = FE12::one_mont();

    for (size_t i = 0; i < k; ++i)
    {
        const Point p{be::unsafe::load<uint256>(&input[input_stride * i]),
            be::unsafe::load<uint256>(&input[32 + input_stride * i])};
        const bn254::FE2Point q{
            bn254::FE2({be::unsafe::load<uint256>(&input[96 + input_stride * i]),
                be::unsafe::load<uint256>(&input[64 + input_stride * i])}),
            bn254::FE2({be::unsafe::load<uint256>(&input[160 + input_stride * i]),
                be::unsafe::load<uint256>(&input[128 + input_stride * i])}),
            bn254::FE2::one()};

        if (!is_on_curve_b(
                FE2::arith.to_mont(p.x), FE2::arith.to_mont(p.y), FE2::arith.in_mont<1>()))
            return false;

        const auto p_12 = cast_to_fe12(p);

        const auto q_mont = q.to_mont();
        if (!is_on_curve_b2(q_mont))
            return false;

        const auto tq_mont = twist(q_mont);
        if (!is_on_curve_b12(tq_mont))
            return false;  // Twisting implementation error.

        const auto r = miller_loop(tq_mont, p_12.to_mont(), false);
        accumulator = FE12::mul(accumulator, r);
    }

    accumulator = final_exponentiation(accumulator);

    if (FE12::eq(accumulator, FE12::one_mont()))
        be::unsafe::store(output, uint256{1});
    else
        be::unsafe::store(output, uint256{});

    return true;
}

uint256 BN254ModArith::div(const uint256& x, const uint256& y) const noexcept
{
    return mul(x, inv(y));
}

uint256 BN254ModArith::inv(const uint256& x) const noexcept
{
    // Inversion computation is derived from the addition chain:
    //
    //	_10       = 2*1
    //	_11       = 1 + _10
    //	_101      = _10 + _11
    //	_110      = 1 + _101
    //	_1000     = _10 + _110
    //	_1101     = _101 + _1000
    //	_10010    = _101 + _1101
    //	_10011    = 1 + _10010
    //	_10100    = 1 + _10011
    //	_10111    = _11 + _10100
    //	_11100    = _101 + _10111
    //	_100000   = _1101 + _10011
    //	_100011   = _11 + _100000
    //	_101011   = _1000 + _100011
    //	_101111   = _10011 + _11100
    //	_1000001  = _10010 + _101111
    //	_1010011  = _10010 + _1000001
    //	_1011011  = _1000 + _1010011
    //	_1100001  = _110 + _1011011
    //	_1110101  = _10100 + _1100001
    //	_10010001 = _11100 + _1110101
    //	_10010101 = _100000 + _1110101
    //	_10110101 = _100000 + _10010101
    //	_10111011 = _110 + _10110101
    //	_11000001 = _110 + _10111011
    //	_11000011 = _10 + _11000001
    //	_11010011 = _10010 + _11000001
    //	_11100001 = _100000 + _11000001
    //	_11100011 = _10 + _11100001
    //	_11100111 = _110 + _11100001
    //	i57       = ((_11000001 << 8 + _10010001) << 10 + _11100111) << 7
    //	i76       = ((_10111 + i57) << 9 + _10011) << 7 + _1101
    //	i109      = ((i76 << 14 + _1010011) << 9 + _11100001) << 8
    //	i127      = ((_1000001 + i109) << 10 + _1011011) << 5 + _1101
    //	i161      = ((i127 << 8 + _11) << 12 + _101011) << 12
    //	i186      = ((_10111011 + i161) << 8 + _101111) << 14 + _10110101
    //	i214      = ((i186 << 9 + _10010001) << 5 + _1101) << 12
    //	i236      = ((_11100011 + i214) << 8 + _10010101) << 11 + _11010011
    //	i268      = ((i236 << 7 + _1100001) << 11 + _100011) << 12
    //	i288      = ((_1011011 + i268) << 9 + _11000011) << 8 + _11100111
    //	return      (i288 << 7 + _1110101) << 6 + _101
    //
    // Operations: 247 squares 56 multiplies
    //
    // Generated by github.com/mmcloughlin/addchain v0.4.0.

    // Allocate Temporaries.
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;
    uint256 t4;
    uint256 t5;
    uint256 t6;
    uint256 t7;
    uint256 t8;
    uint256 t9;
    uint256 t10;
    uint256 t11;
    uint256 t12;
    uint256 t13;
    uint256 t14;
    uint256 t15;
    uint256 t16;
    uint256 t17;
    uint256 t18;
    uint256 t19;
    uint256 t20;
    uint256 t21;
    // Step 1: t8 = x^0x2
    t8 = mul(x, x);

    // Step 2: t15 = x^0x3
    t15 = mul(x, t8);

    // Step 3: z = x^0x5
    auto z = mul(t8, t15);

    // Step 4: t1 = x^0x6
    t1 = mul(x, z);

    // Step 5: t3 = x^0x8
    t3 = mul(t8, t1);

    // Step 6: t9 = x^0xd
    t9 = mul(z, t3);

    // Step 7: t6 = x^0x12
    t6 = mul(z, t9);

    // Step 8: t19 = x^0x13
    t19 = mul(x, t6);

    // Step 9: t0 = x^0x14
    t0 = mul(x, t19);

    // Step 10: t20 = x^0x17
    t20 = mul(t15, t0);

    // Step 11: t2 = x^0x1c
    t2 = mul(z, t20);

    // Step 12: t17 = x^0x20
    t17 = mul(t9, t19);

    // Step 13: t4 = x^0x23
    t4 = mul(t15, t17);

    // Step 14: t14 = x^0x2b
    t14 = mul(t3, t4);

    // Step 15: t12 = x^0x2f
    t12 = mul(t19, t2);

    // Step 16: t16 = x^0x41
    t16 = mul(t6, t12);

    // Step 17: t18 = x^0x53
    t18 = mul(t6, t16);

    // Step 18: t3 = x^0x5b
    t3 = mul(t3, t18);

    // Step 19: t5 = x^0x61
    t5 = mul(t1, t3);

    // Step 20: t0 = x^0x75
    t0 = mul(t0, t5);

    // Step 21: t10 = x^0x91
    t10 = mul(t2, t0);

    // Step 22: t7 = x^0x95
    t7 = mul(t17, t0);

    // Step 23: t11 = x^0xb5
    t11 = mul(t17, t7);

    // Step 24: t13 = x^0xbb
    t13 = mul(t1, t11);

    // Step 25: t21 = x^0xc1
    t21 = mul(t1, t13);

    // Step 26: t2 = x^0xc3
    t2 = mul(t8, t21);

    // Step 27: t6 = x^0xd3
    t6 = mul(t6, t21);

    // Step 28: t17 = x^0xe1
    t17 = mul(t17, t21);

    // Step 29: t8 = x^0xe3
    t8 = mul(t8, t17);

    // Step 30: t1 = x^0xe7
    t1 = mul(t1, t17);

    // Step 38: t21 = x^0xc100
    for (int i = 0; i < 8; ++i)
        t21 = mul(t21, t21);

    // Step 39: t21 = x^0xc191
    t21 = mul(t10, t21);

    // Step 49: t21 = x^0x3064400
    for (int i = 0; i < 10; ++i)
        t21 = mul(t21, t21);

    // Step 50: t21 = x^0x30644e7
    t21 = mul(t1, t21);

    // Step 57: t21 = x^0x183227380
    for (int i = 0; i < 7; ++i)
        t21 = mul(t21, t21);

    // Step 58: t20 = x^0x183227397
    t20 = mul(t20, t21);

    // Step 67: t20 = x^0x30644e72e00
    for (int i = 0; i < 9; ++i)
        t20 = mul(t20, t20);

    // Step 68: t19 = x^0x30644e72e13
    t19 = mul(t19, t20);

    // Step 75: t19 = x^0x1832273970980
    for (int i = 0; i < 7; ++i)
        t19 = mul(t19, t19);

    // Step 76: t19 = x^0x183227397098d
    t19 = mul(t9, t19);

    // Step 90: t19 = x^0x60c89ce5c2634000
    for (int i = 0; i < 14; ++i)
        t19 = mul(t19, t19);

    // Step 91: t18 = x^0x60c89ce5c2634053
    t18 = mul(t18, t19);

    // Step 100: t18 = x^0xc19139cb84c680a600
    for (int i = 0; i < 9; ++i)
        t18 = mul(t18, t18);

    // Step 101: t17 = x^0xc19139cb84c680a6e1
    t17 = mul(t17, t18);

    // Step 109: t17 = x^0xc19139cb84c680a6e100
    for (int i = 0; i < 8; ++i)
        t17 = mul(t17, t17);

    // Step 110: t16 = x^0xc19139cb84c680a6e141
    t16 = mul(t16, t17);

    // Step 120: t16 = x^0x30644e72e131a029b850400
    for (int i = 0; i < 10; ++i)
        t16 = mul(t16, t16);

    // Step 121: t16 = x^0x30644e72e131a029b85045b
    t16 = mul(t3, t16);

    // Step 126: t16 = x^0x60c89ce5c263405370a08b60
    for (int i = 0; i < 5; ++i)
        t16 = mul(t16, t16);

    // Step 127: t16 = x^0x60c89ce5c263405370a08b6d
    t16 = mul(t9, t16);

    // Step 135: t16 = x^0x60c89ce5c263405370a08b6d00
    for (int i = 0; i < 8; ++i)
        t16 = mul(t16, t16);

    // Step 136: t15 = x^0x60c89ce5c263405370a08b6d03
    t15 = mul(t15, t16);

    // Step 148: t15 = x^0x60c89ce5c263405370a08b6d03000
    for (int i = 0; i < 12; ++i)
        t15 = mul(t15, t15);

    // Step 149: t14 = x^0x60c89ce5c263405370a08b6d0302b
    t14 = mul(t14, t15);

    // Step 161: t14 = x^0x60c89ce5c263405370a08b6d0302b000
    for (int i = 0; i < 12; ++i)
        t14 = mul(t14, t14);

    // Step 162: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb
    t13 = mul(t13, t14);

    // Step 170: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb00
    for (int i = 0; i < 8; ++i)
        t13 = mul(t13, t13);

    // Step 171: t12 = x^0x60c89ce5c263405370a08b6d0302b0bb2f
    t12 = mul(t12, t13);

    // Step 185: t12 = x^0x183227397098d014dc2822db40c0ac2ecbc000
    for (int i = 0; i < 14; ++i)
        t12 = mul(t12, t12);

    // Step 186: t11 = x^0x183227397098d014dc2822db40c0ac2ecbc0b5
    t11 = mul(t11, t12);

    // Step 195: t11 = x^0x30644e72e131a029b85045b68181585d97816a00
    for (int i = 0; i < 9; ++i)
        t11 = mul(t11, t11);

    // Step 196: t10 = x^0x30644e72e131a029b85045b68181585d97816a91
    t10 = mul(t10, t11);

    // Step 201: t10 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d5220
    for (int i = 0; i < 5; ++i)
        t10 = mul(t10, t10);

    // Step 202: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d
    t9 = mul(t9, t10);

    // Step 214: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d000
    for (int i = 0; i < 12; ++i)
        t9 = mul(t9, t9);

    // Step 215: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e3
    t8 = mul(t8, t9);

    // Step 223: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e300
    for (int i = 0; i < 8; ++i)
        t8 = mul(t8, t8);

    // Step 224: t7 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e395
    t7 = mul(t7, t8);

    // Step 235: t7 = x^0x30644e72e131a029b85045b68181585d97816a916871ca800
    for (int i = 0; i < 11; ++i)
        t7 = mul(t7, t7);

    // Step 236: t6 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3
    t6 = mul(t6, t7);

    // Step 243: t6 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e546980
    for (int i = 0; i < 7; ++i)
        t6 = mul(t6, t6);

    // Step 244: t5 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e1
    t5 = mul(t5, t6);

    // Step 255: t5 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0800
    for (int i = 0; i < 11; ++i)
        t5 = mul(t5, t5);

    // Step 256: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823
    t4 = mul(t4, t5);

    // Step 268: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823000
    for (int i = 0; i < 12; ++i)
        t4 = mul(t4, t4);

    // Step 269: t3 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b
    t3 = mul(t3, t4);

    // Step 278: t3 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b600
    for (int i = 0; i < 9; ++i)
        t3 = mul(t3, t3);

    // Step 279: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3
    t2 = mul(t2, t3);

    // Step 287: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c300
    for (int i = 0; i < 8; ++i)
        t2 = mul(t2, t2);

    // Step 288: t1 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7
    t1 = mul(t1, t2);

    // Step 295: t1 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f380
    for (int i = 0; i < 7; ++i)
        t1 = mul(t1, t1);

    // Step 296: t0 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f5
    t0 = mul(t0, t1);

    // Step 302: t0 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd40
    for (int i = 0; i < 6; ++i)
        t0 = mul(t0, t0);

    // Step 303: z = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
    z = mul(z, t0);

    return z;
}

uint256 BN254ModArith::pow(  // NOLINT(misc-no-recursion)
    const uint256& x, const uint256& y) const noexcept
{
    if (y == 0)
        return 1;
    else if (y == 1)
        return x;
    else if (y % 2 == 0)
        return pow(mul(x, x), y / 2);
    else
        return mul(pow(mul(x, x), y / 2), x);
}

uint256 BN254ModArith::neg(const uint256& x) const noexcept
{
    return sub(0, x);
}

}  // namespace evmmax::bn254
