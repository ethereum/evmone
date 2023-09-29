#include "bls12.hpp"

namespace evmmax::bls12
{
bool validate(const Point& pt) noexcept
{
    if (pt.is_inf())
        return true;

    const evmmax::ModArith s{BLS12Mod};
    const auto xm = s.to_mont(pt.x);
    const auto ym = s.to_mont(pt.y);
    const auto y2 = s.mul(ym, ym);
    const auto x2 = s.mul(xm, xm);
    const auto x3 = s.mul(x2, xm);
    const auto _4 = s.to_mont(4);
    const auto x3_4 = s.add(x3, _4);
    return y2 == x3_4;
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

Point from_proj(const ProjPoint& p)
{
    static const BLS12ModArith s;
    const auto z_inv = s.inv(p.z);
    return {s.mul(p.x, z_inv), s.mul(p.y, z_inv)};
}

}  // namespace

ProjPoint point_addition_mixed_a0(
    const evmmax::ModArith<uint384>& s, const Point& p, const Point& q, const uint384& b3) noexcept
{
    // https://eprint.iacr.org/2015/1060 algorithm 2.
    // Simplified with z1 == 1, a == 0

    const auto& x1 = p.x;
    const auto& y1 = p.y;
    const auto& x2 = q.x;
    const auto& y2 = q.y;

    uint384 x3;
    uint384 y3;
    uint384 z3;
    uint384 t0;
    uint384 t1;
    uint384 t3;
    uint384 t4;
    uint384 t5;

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

Point bls12_add(const Point& pt1, const Point& pt2) noexcept
{
    if (pt1.is_inf())
        return pt2;
    if (pt2.is_inf())
        return pt1;

    const evmmax::ModArith s{BLS12Mod};

    const Point p{s.to_mont(pt1.x), s.to_mont(pt1.y)};
    const Point q{s.to_mont(pt2.x), s.to_mont(pt2.y)};

    // b3 == 12 for y^2 == x^3 + 4
    const auto b3 = s.to_mont(12);
    const auto r = point_addition_mixed_a0(s, p, q, b3);

    const auto [rx, ry] = from_proj(r);
    return {s.from_mont(rx), s.from_mont(ry)};
}

// Point bls12_mul(const Point& pt, const uint384& c) noexcept
//{
//     if (pt.is_inf())
//         return pt;
//
//     if (c == 0)
//         return {0, 0};
//
//     const ModArith s{BLS12Mod};
//     const auto b3 = s.to_mont(9);
//
//     const auto pr = ecc::mul(s, ecc::to_proj(s, pt), c, b3);
//
//     const auto r = from_proj(pr);
//     return {s.from_mont(r.x), s.from_mont(r.y)};
// }

// bool is_on_curve_b(const uint384& x, const uint384& y, const uint384& z) noexcept
//{
//     static const auto B = bls12::FE2::arith.in_mont<3>();
//     return bls12::FE2::arith.sub(bls12::FE2::arith.mul(bls12::FE2::arith.pow(y, 2), z),
//                bls12::FE2::arith.pow(x, 3)) ==
//            bls12::FE2::arith.mul(B, bls12::FE2::arith.pow(z, 3));
// }

// bool is_on_curve_b2(const FE2Point& p) noexcept
//{
//     static const auto B2 =
//         bls12::FE2::div(bls12::FE2({3, 0}).to_mont(), bls12::FE2({9, 1}).to_mont());
//     return (p.y ^ 2) * p.z - (p.x ^ 3) == B2 * (p.z ^ 3);
// }
//
// bool is_on_curve_b12(const FE12Point& p) noexcept
//{
//     static const auto B12 = bls12::FE12({3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
//     return (p.y ^ 2) * p.z - (p.x ^ 3) == B12.to_mont() * (p.z ^ 3);
// }
//
// FE12Point twist(const FE2Point& pt) noexcept
//{
//     static const auto omega = FE12({0, bls12::FE2::arith.one_mont(), 0, 0, 0, 0, 0, 0, 0, 0, 0,
//     0}); if (FE2Point::is_at_infinity(pt))
//         return FE12Point::infinity();
//
//     auto _x = pt.x;
//     auto _y = pt.y;
//     auto _z = pt.z;
//     // Field isomorphism from Z[p] / x**2 to Z[p] / x**2 - 18*x + 82
//     std::vector<uint384> xcoeffs(2);
//     xcoeffs[0] = FE2::arith.sub(
//         _x.coeffs[0], FE2::arith.mul(_x.coeffs[1], bls12::FE2::arith.template in_mont<9>()));
//     xcoeffs[1] = _x.coeffs[1];
//     std::vector<uint384> ycoeffs(2);
//     ycoeffs[0] = FE2::arith.sub(
//         _y.coeffs[0], FE2::arith.mul(_y.coeffs[1], bls12::FE2::arith.template in_mont<9>()));
//     ycoeffs[1] = _y.coeffs[1];
//     std::vector<uint384> zcoeffs(2);
//     zcoeffs[0] = FE2::arith.sub(
//         _z.coeffs[0], FE2::arith.mul(_z.coeffs[1], bls12::FE2::arith.template in_mont<9>()));
//     zcoeffs[1] = _z.coeffs[1];
//     // Isomorphism into subfield of Z[p] / w**12 - 18 * w**6 + 82, where w**6 = x
//     auto nx = FE12({xcoeffs[0], 0, 0, 0, 0, 0, xcoeffs[1], 0, 0, 0, 0, 0});
//     auto ny = FE12({ycoeffs[0], 0, 0, 0, 0, 0, ycoeffs[1], 0, 0, 0, 0, 0});
//     auto nz = FE12({zcoeffs[0], 0, 0, 0, 0, 0, zcoeffs[1], 0, 0, 0, 0, 0});
//     // Multiply x coord by w**2 and y coord by w**3
//     return {nx * (omega ^ 2), ny * (omega ^ 3), nz};
// }
//
// FE12Point cast_to_fe12(const Point& pt) noexcept
//{
//     return {FE12({pt.x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
//         FE12({pt.y, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), FE12({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         0})};
// }
//
// template <typename FieldElemT>
// std::pair<FieldElemT, FieldElemT> line_func(const PointExt<FieldElemT>& p1,
//     const PointExt<FieldElemT>& p2, const PointExt<FieldElemT>& t) noexcept
//{
//     assert(!PointExt<FieldElemT>::is_at_infinity(p1));
//     assert(!PointExt<FieldElemT>::is_at_infinity(p2));
//
//     auto m_numerator = p2.y * p1.z - p1.y * p2.z;
//     auto m_denominator = p2.x * p1.z - p1.x * p2.z;
//
//     if (m_denominator != FieldElemT::zero())
//     {
//         return {m_numerator * (t.x * p1.z - p1.x * t.z) - m_denominator * (t.y * p1.z - p1.y *
//         t.z),
//             m_denominator * t.z * p1.z};
//     }
//     else if (m_numerator == FieldElemT::zero())
//     {
//         static const auto _3_mont = FieldElemT::arith.template in_mont<3>();
//         static const auto _2_mont = FieldElemT::arith.template in_mont<2>();
//
//         m_numerator = (p1.x * p1.x) * _3_mont;
//         m_denominator = _2_mont * p1.y * p1.z;
//
//         return {m_numerator * (t.x * p1.z - p1.x * t.z) - m_denominator * (t.y * p1.z - p1.y *
//         t.z),
//             m_denominator * t.z * p1.z};
//     }
//     else
//         return {t.x * p1.z - p1.x * t.z, p1.z * t.z};
// }
//
//// Elliptic curve doubling over extension field
// template <typename FieldElemT>
// PointExt<FieldElemT> point_double(const PointExt<FieldElemT>& p) noexcept
//{
//     // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates
//
//     static const auto _2_mont = FieldElemT::arith.template in_mont<2>();
//     static const auto _3_mont = FieldElemT::arith.template in_mont<3>();
//     static const auto _4_mont = FieldElemT::arith.template in_mont<4>();
//     static const auto _8_mont = FieldElemT::arith.template in_mont<8>();
//
//     auto W = _3_mont * (p.x * p.x);
//     auto S = p.y * p.z;
//     auto B = p.x * p.y * S;
//     auto H = W * W - _8_mont * B;
//     auto S_squared = S * S;
//
//     auto new_x = _2_mont * H * S;
//     auto new_y = W * (_4_mont * B - H) - _8_mont * (p.y * p.y) * S_squared;
//     auto new_z = _8_mont * S_squared * S;
//
//     return {new_x, new_y, new_z};
// }

//// Elliptic curve doubling over extension field
// template <typename FieldElemT>
// PointExt<FieldElemT> point_add(
//     const PointExt<FieldElemT>& p1, const PointExt<FieldElemT>& p2) noexcept
//{
//     // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates
//     using ET = FieldElemT;
//
//     if (p1.z == ET::zero() || p2.z == ET::zero())
//         return p2.z == ET::zero() ? p1 : p2;
//
//     auto X1 = p1.x;
//     auto Y1 = p1.y;
//     auto Z1 = p1.z;
//     auto X2 = p2.x;
//     auto Y2 = p2.y;
//     auto Z2 = p2.z;
//
//     auto U1 = Y2 * Z1;
//     auto U2 = Y1 * Z2;
//     auto V1 = X2 * Z1;
//     auto V2 = X1 * Z2;
//     if (V1 == V2 && U1 == U2)
//         return point_double(p1);
//     else if (V1 == V2)
//         return {ET::one(), ET::one(), ET::zero()};
//
//     static const auto _2_mont = FieldElemT::arith.template in_mont<2>();
//
//     auto U = U1 - U2;
//     auto V = V1 - V2;
//     auto V_squared = V * V;
//     auto V_squared_times_V2 = V_squared * V2;
//     auto V_cubed = V * V_squared;
//     auto W = Z1 * Z2;
//     auto A = U * U * W - V_cubed - _2_mont * V_squared_times_V2;
//     auto new_x = V * A;
//     auto new_y = U * (V_squared_times_V2 - A) - V_cubed * U2;
//     auto new_z = V_cubed * W;
//
//     return {new_x, new_y, new_z};
// }

// template <typename FieldElemT>
// PointExt<FieldElemT> point_multiply(  // NOLINT(misc-no-recursion)
//     const PointExt<FieldElemT>& pt, const uint384& n) noexcept
//{
//     if (n == 0)
//         return {FieldElemT(), FieldElemT(), FieldElemT()};
//     else if (n == 1)
//         return pt;
//     else if (n % 2 == 0)
//         return point_multiply(point_double(pt), n / 2);
//     else
//         return point_add(point_multiply(point_double(pt), n / 2), pt);
// }

// template std::pair<FE2, FE2> line_func<FE2>(
//     const PointExt<FE2>&, const PointExt<FE2>&, const PointExt<FE2>&);
// template std::pair<FE12, FE12> line_func<FE12>(
//     const PointExt<FE12>&, const PointExt<FE12>&, const PointExt<FE12>&);
// template PointExt<FE2> point_double(const PointExt<FE2>&);
// template PointExt<FE12> point_double(const PointExt<FE12>&);
// template PointExt<FE2> point_add(const PointExt<FE2>&, const PointExt<FE2>&);
// template PointExt<FE12> point_add(const PointExt<FE12>&, const PointExt<FE12>&);
// template PointExt<FE2> point_multiply(const PointExt<FE2>&, const uint384&);
// template PointExt<FE12> point_multiply(const PointExt<FE12>&, const uint384&);

// FE12 miller_loop(const FE12Point& Q, const FE12Point& P, bool run_final_exp) noexcept
//{
//     static const int8_t pseudo_binary_encoding[] = {0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0,
//     1,
//         0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
//         -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1, 1};
//
//     // static constexpr auto ate_loop_count = 29793968203157093288_u256;
//     // static constexpr auto log_ate_loop_count = 63;
//     if (FE12Point::is_at_infinity(Q) || FE12Point::is_at_infinity(P))
//         return FE12::one_mont();
//
//     auto R = Q;
//     auto f_num = FE12::one_mont();
//     auto f_den = FE12::one_mont();
//     for (int i = sizeof(pseudo_binary_encoding) - 2; i >= 0; --i)
//     {
//         auto [_n, _d] = line_func(R, R, P);
//         f_num = f_num * f_num * _n;
//         f_den = f_den * f_den * _d;
//         R = point_double(R);
//         if (pseudo_binary_encoding[i] == 1)
//         {
//             std::tie(_n, _d) = line_func(R, Q, P);
//             f_num = f_num * _n;
//             f_den = f_den * _d;
//             R = point_add(R, Q);
//         }
//         else if (pseudo_binary_encoding[i] == -1)
//         {
//             const FE12Point nQ = {Q.x, -Q.y, Q.z};
//             std::tie(_n, _d) = line_func(R, nQ, P);
//             f_num = f_num * _n;
//             f_den = f_den * _d;
//             R = point_add(R, nQ);
//         }
//     }
//
//     const FE12Point Q1 = {Q.x ^ BLS12Mod, Q.y ^ BLS12Mod, Q.z ^ BLS12Mod};
//     // assert(is_on_curve_b12(Q1));
//     const FE12Point nQ2 = {Q1.x ^ BLS12Mod, -(Q1.y ^ BLS12Mod), Q1.z ^ BLS12Mod};
//     // assert(is_on_curve_b12(nQ1));
//     auto [_n1, _d1] = line_func(R, Q1, P);
//     R = point_add(R, Q1);
//     auto [_n2, _d2] = line_func(R, nQ2, P);
//     auto f = FE12::div(f_num * _n1 * _n2, f_den * _d1 * _d2);
//     // R = add(R, nQ2) This line is in many specifications but it technically does nothing
//     if (run_final_exp)
//         return final_exponentiation(f);
//     else
//         return f;
// }

// FE12 bls12_pairing(const FE2Point& q, const Point& p) noexcept
//{
//     assert(is_on_curve_b2(q.to_mont()));
//     assert(is_on_curve_b(p.x, p.y, 1));
//
//     auto p_12 = cast_to_fe12(p);
//
//     auto res = miller_loop(twist(q.to_mont()), p_12.to_mont(), true);
//
//     return res.from_mont();
// }

// namespace
//{
// const auto final_exp_pow =  // ((field_modulus ** 12 - 1) // curve_order
//     intx::from_string<intx::uint<2816>>(
//         "55248423361322409631261712678317314709738210376295765418888273431419691083990754121397"
//         "45027615406298170096085486546803436277011538294467478109073732568415510062016396777261"
//         "39946029199968412598804882391702273019083653272047566316584365559776493027495458238373"
//         "90287593765994350487322055416155052592630230333174746351564471187665317712957830319109"
//         "59009091916248178265666882418044080818927857259679317140977167095260922612780719525601"
//         "71111444072049229123565057483750161460024353346284167282452756217662335528813519139808"
//         "29117053907212538123081572907154486160275093696482931360813732542638373512217522954115"
//         "53763464360939302874020895174269731789175697133847480818272554725769374714961957527271"
//         "88261435633271238710131736096299798168852925540549342330775279877006784354801422249722"
//         "573783561685179618816480037695005515426162362431072245638324744480");
// }  // namespace
//
// FE12 final_exponentiation(const FE12& a) noexcept
//{
//     return FE12::pow(a, final_exp_pow);
// }

bool bls12_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept
{
    using namespace intx;
    uint8_t input_padded[192]{};
    std::copy_n(input, std::min(input_size, sizeof(input_padded)), input_padded);

    const Point a{
        be::unsafe::load<uint384>(&input_padded[0]), be::unsafe::load<uint384>(&input_padded[48])};
    const Point b{be::unsafe::load<uint384>(&input_padded[96]),
        be::unsafe::load<uint384>(&input_padded[144])};

    if (!validate(a) || !validate(b))
        return false;

    const auto s = bls12_add(a, b);
    be::unsafe::store(output, s.x);
    be::unsafe::store(output + 48, s.y);
    return true;
}

// bool bls12_mul_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept
//{
//     using namespace intx;
//     uint8_t input_padded[128]{};
//     std::copy_n(input, std::min(input_size, sizeof(input_padded)), input_padded);
//
//     const Point a{
//         be::unsafe::load<uint384>(&input_padded[0]),
//         be::unsafe::load<uint384>(&input_padded[32])};
//     const auto s = be::unsafe::load<uint384>(&input_padded[64]);
//
//     if (!validate(a))
//         return false;
//
//     const auto r = bls12_mul(a, s);
//     be::unsafe::store(output, r.x);
//     be::unsafe::store(output + 32, r.y);
//     return true;
// }

// bool bls12_ecpairing_precompile(  // NOLINT(bugprone-exception-escape)
//     const uint8_t* input, size_t input_size, uint8_t* output) noexcept
//{
//     using namespace intx;
//     static const size_t input_stride = 192;
//     if (input_size % input_stride != 0)
//         return false;
//
//     auto k = input_size / input_stride;
//     FE12 accumulator = FE12::one_mont();
//
//     for (size_t i = 0; i < k; ++i)
//     {
//         const Point p{be::unsafe::load<uint384>(&input[input_stride * i]),
//             be::unsafe::load<uint384>(&input[32 + input_stride * i])};
//         const bls12::FE2Point q{
//             bls12::FE2({be::unsafe::load<uint384>(&input[96 + input_stride * i]),
//                 be::unsafe::load<uint384>(&input[64 + input_stride * i])}),
//             bls12::FE2({be::unsafe::load<uint384>(&input[160 + input_stride * i]),
//                 be::unsafe::load<uint384>(&input[128 + input_stride * i])}),
//             bls12::FE2::one()};
//
//         if (!is_on_curve_b(
//                 FE2::arith.to_mont(p.x), FE2::arith.to_mont(p.y), FE2::arith.in_mont<1>()))
//             return false;
//
//         const auto p_12 = cast_to_fe12(p);
//
//         const auto q_mont = q.to_mont();
//         if (!is_on_curve_b2(q_mont))
//             return false;
//
//         const auto tq_mont = twist(q_mont);
//         if (!is_on_curve_b12(tq_mont))
//             return false;  // Twisting implementation error.
//
//         const auto r = miller_loop(tq_mont, p_12.to_mont(), false);
//         accumulator = FE12::mul(accumulator, r);
//     }
//
//     accumulator = final_exponentiation(accumulator);
//
//     if (FE12::eq(accumulator, FE12::one_mont()))
//         be::unsafe::store(output, uint384{1});
//     else
//         be::unsafe::store(output, uint384{});
//
//     return true;
// }

// uint384 BLS12ModArith::div(const uint384& x, const uint384& y) const noexcept
//{
//     return mul(x, inv(y));
// }

uint384 BLS12ModArith::inv(const uint384& x) const noexcept
{
    // Computes modular exponentiation
    // x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9
    // Operations: 376 squares 74 multiplies
    // Generated by github.com/mmcloughlin/addchain v0.4.0.
    //
    // Exponentiation computation is derived from the addition chain:
    //
    // _10       = 2*1
    // _100      = 2*_10
    // _1000     = 2*_100
    // _1001     = 1 + _1000
    // _1011     = _10 + _1001
    // _1101     = _10 + _1011
    // _10001    = _100 + _1101
    // _10100    = _1001 + _1011
    // _11001    = _1000 + _10001
    // _11010    = 1 + _11001
    // _110100   = 2*_11010
    // _110110   = _10 + _110100
    // _110111   = 1 + _110110
    // _1001101  = _11001 + _110100
    // _1001111  = _10 + _1001101
    // _1010101  = _1000 + _1001101
    // _1011101  = _1000 + _1010101
    // _1100111  = _11010 + _1001101
    // _1101001  = _10 + _1100111
    // _1110111  = _11010 + _1011101
    // _1111011  = _100 + _1110111
    // _10001001 = _110100 + _1010101
    // _10010101 = _11010 + _1111011
    // _10010111 = _10 + _10010101
    // _10101001 = _10100 + _10010101
    // _10110001 = _1000 + _10101001
    // _10111111 = _110110 + _10001001
    // _11000011 = _100 + _10111111
    // _11010000 = _1101 + _11000011
    // _11010111 = _10100 + _11000011
    // _11100001 = _10001 + _11010000
    // _11100101 = _100 + _11100001
    // _11101011 = _10100 + _11010111
    // _11110101 = _10100 + _11100001
    // _11111111 = _10100 + _11101011
    // i57       = ((_10111111 + _11100001) << 8 + _10001) << 11 + _11110101
    // i85       = ((i57 << 11 + _11100101) << 8 + _11111111) << 7
    // i107      = ((_1001101 + i85) << 9 + _1101001) << 10 + _10110001
    // i131      = ((i107 << 7 + _1011101) << 9 + _1111011) << 6
    // i154      = ((_11001 + i131) << 11 + _1101001) << 9 + _11101011
    // i182      = ((i154 << 10 + _11010111) << 6 + _11001) << 10
    // i205      = ((_1110111 + i182) << 9 + _10010111) << 11 + _1001111
    // i235      = ((i205 << 10 + _11100001) << 9 + _10001001) << 9
    // i256      = ((_10111111 + i235) << 8 + _1100111) << 10 + _11000011
    // i284      = ((i256 << 9 + _10010101) << 12 + _1111011) << 5
    // i305      = ((_1011 + i284) << 11 + _1111011) << 7 + _1001
    // i337      = ((i305 << 13 + _11110101) << 9 + _10111111) << 8
    // i359      = ((_11111111 + i337) << 8 + _11101011) << 11 + _10101001
    // i383      = ((i359 << 8 + _11111111) << 8 + _11111111) << 6
    // i405      = ((_110111 + i383) << 10 + _11111111) << 9 + _11111111
    // i431      = ((i405 << 8 + _11111111) << 8 + _11111111) << 8
    // return      ((_11111111 + i431) << 7 + _1010101) << 9 + _10101001

    // Allocate Temporaries.
    uint384 z;
    uint384 t0;
    uint384 t1;
    uint384 t2;
    uint384 t3;
    uint384 t4;
    uint384 t5;
    uint384 t6;
    uint384 t7;
    uint384 t8;
    uint384 t9;
    uint384 t10;
    uint384 t11;
    uint384 t12;
    uint384 t13;
    uint384 t14;
    uint384 t15;
    uint384 t16;
    uint384 t17;
    uint384 t18;
    uint384 t19;
    uint384 t20;
    uint384 t21;
    uint384 t22;
    uint384 t23;
    uint384 t24;
    uint384 t25;


    // Step 1: z = x^0x2
    z = mul(x, x);

    // Step 2: t3 = x^0x4
    t3 = mul(z, z);

    // Step 3: t10 = x^0x8
    t10 = mul(t3, t3);

    // Step 4: t6 = x^0x9
    t6 = mul(x, t10);

    // Step 5: t8 = x^0xb
    t8 = mul(z, t6);

    // Step 6: t5 = x^0xd
    t5 = mul(z, t8);

    // Step 7: t24 = x^0x11
    t24 = mul(t3, t5);

    // Step 8: t1 = x^0x14
    t1 = mul(t6, t8);

    // Step 9: t17 = x^0x19
    t17 = mul(t10, t24);

    // Step 10: t9 = x^0x1a
    t9 = mul(x, t17);

    // Step 11: t12 = x^0x34
    t12 = mul(t9, t9);

    // Step 12: t4 = x^0x36
    t4 = mul(z, t12);

    // Step 13: t2 = x^0x37
    t2 = mul(x, t4);

    // Step 14: t22 = x^0x4d
    t22 = mul(t17, t12);

    // Step 15: t14 = x^0x4f
    t14 = mul(z, t22);

    // Step 16: t0 = x^0x55
    t0 = mul(t10, t22);

    // Step 17: t20 = x^0x5d
    t20 = mul(t10, t0);

    // Step 18: t11 = x^0x67
    t11 = mul(t9, t22);

    // Step 19: t19 = x^0x69
    t19 = mul(z, t11);

    // Step 20: t16 = x^0x77
    t16 = mul(t9, t20);

    // Step 21: t7 = x^0x7b
    t7 = mul(t3, t16);

    // Step 22: t12 = x^0x89
    t12 = mul(t12, t0);

    // Step 23: t9 = x^0x95
    t9 = mul(t9, t7);

    // Step 24: t15 = x^0x97
    t15 = mul(z, t9);

    // Step 25: z = x^0xa9
    z = mul(t1, t9);

    // Step 26: t21 = x^0xb1
    t21 = mul(t10, z);

    // Step 27: t4 = x^0xbf
    t4 = mul(t4, t12);

    // Step 28: t10 = x^0xc3
    t10 = mul(t3, t4);

    // Step 29: t5 = x^0xd0
    t5 = mul(t5, t10);

    // Step 30: t18 = x^0xd7
    t18 = mul(t1, t10);

    // Step 31: t13 = x^0xe1
    t13 = mul(t24, t5);

    // Step 32: t23 = x^0xe5
    t23 = mul(t3, t13);

    // Step 33: t3 = x^0xeb
    t3 = mul(t1, t18);

    // Step 34: t5 = x^0xf5
    t5 = mul(t1, t13);

    // Step 35: t1 = x^0xff
    t1 = mul(t1, t3);

    // Step 36: t25 = x^0x1a0
    t25 = mul(t4, t13);

    // Step 44: t25 = x^0x1a000
    for (int i = 0; i < 8; ++i)
        t25 = mul(t25, t25);

    // Step 45: t24 = x^0x1a011
    t24 = mul(t24, t25);

    // Step 56: t24 = x^0xd008800
    for (int i = 0; i < 11; ++i)
        t24 = mul(t24, t24);

    // Step 57: t24 = x^0xd0088f5
    t24 = mul(t5, t24);

    // Step 68: t24 = x^0x680447a800
    for (int i = 0; i < 11; ++i)
        t24 = mul(t24, t24);

    // Step 69: t23 = x^0x680447a8e5
    t23 = mul(t23, t24);

    // Step 77: t23 = x^0x680447a8e500
    for (int i = 0; i < 8; ++i)
        t23 = mul(t23, t23);

    // Step 78: t23 = x^0x680447a8e5ff
    t23 = mul(t1, t23);

    // Step 85: t23 = x^0x340223d472ff80
    for (int i = 0; i < 7; ++i)
        t23 = mul(t23, t23);

    // Step 86: t22 = x^0x340223d472ffcd
    t22 = mul(t22, t23);

    // Step 95: t22 = x^0x680447a8e5ff9a00
    for (int i = 0; i < 9; ++i)
        t22 = mul(t22, t22);

    // Step 96: t22 = x^0x680447a8e5ff9a69
    t22 = mul(t19, t22);

    // Step 106: t22 = x^0x1a0111ea397fe69a400
    for (int i = 0; i < 10; ++i)
        t22 = mul(t22, t22);

    // Step 107: t21 = x^0x1a0111ea397fe69a4b1
    t21 = mul(t21, t22);

    // Step 114: t21 = x^0xd0088f51cbff34d25880
    for (int i = 0; i < 7; ++i)
        t21 = mul(t21, t21);

    // Step 115: t20 = x^0xd0088f51cbff34d258dd
    t20 = mul(t20, t21);

    // Step 124: t20 = x^0x1a0111ea397fe69a4b1ba00
    for (int i = 0; i < 9; ++i)
        t20 = mul(t20, t20);

    // Step 125: t20 = x^0x1a0111ea397fe69a4b1ba7b
    t20 = mul(t7, t20);

    // Step 131: t20 = x^0x680447a8e5ff9a692c6e9ec0
    for (int i = 0; i < 6; ++i)
        t20 = mul(t20, t20);

    // Step 132: t20 = x^0x680447a8e5ff9a692c6e9ed9
    t20 = mul(t17, t20);

    // Step 143: t20 = x^0x340223d472ffcd3496374f6c800
    for (int i = 0; i < 11; ++i)
        t20 = mul(t20, t20);

    // Step 144: t19 = x^0x340223d472ffcd3496374f6c869
    t19 = mul(t19, t20);

    // Step 153: t19 = x^0x680447a8e5ff9a692c6e9ed90d200
    for (int i = 0; i < 9; ++i)
        t19 = mul(t19, t19);

    // Step 154: t19 = x^0x680447a8e5ff9a692c6e9ed90d2eb
    t19 = mul(t3, t19);

    // Step 164: t19 = x^0x1a0111ea397fe69a4b1ba7b6434bac00
    for (int i = 0; i < 10; ++i)
        t19 = mul(t19, t19);

    // Step 165: t18 = x^0x1a0111ea397fe69a4b1ba7b6434bacd7
    t18 = mul(t18, t19);

    // Step 171: t18 = x^0x680447a8e5ff9a692c6e9ed90d2eb35c0
    for (int i = 0; i < 6; ++i)
        t18 = mul(t18, t18);

    // Step 172: t17 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d9
    t17 = mul(t17, t18);

    // Step 182: t17 = x^0x1a0111ea397fe69a4b1ba7b6434bacd76400
    for (int i = 0; i < 10; ++i)
        t17 = mul(t17, t17);

    // Step 183: t16 = x^0x1a0111ea397fe69a4b1ba7b6434bacd76477
    t16 = mul(t16, t17);

    // Step 192: t16 = x^0x340223d472ffcd3496374f6c869759aec8ee00
    for (int i = 0; i < 9; ++i)
        t16 = mul(t16, t16);

    // Step 193: t15 = x^0x340223d472ffcd3496374f6c869759aec8ee97
    t15 = mul(t15, t16);

    // Step 204: t15 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b800
    for (int i = 0; i < 11; ++i)
        t15 = mul(t15, t15);

    // Step 205: t14 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f
    t14 = mul(t14, t15);

    // Step 215: t14 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13c00
    for (int i = 0; i < 10; ++i)
        t14 = mul(t14, t14);

    // Step 216: t13 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce1
    t13 = mul(t13, t14);

    // Step 225: t13 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c200
    for (int i = 0; i < 9; ++i)
        t13 = mul(t13, t13);

    // Step 226: t12 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c289
    t12 = mul(t12, t13);

    // Step 235: t12 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f3851200
    for (int i = 0; i < 9; ++i)
        t12 = mul(t12, t12);

    // Step 236: t12 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf
    t12 = mul(t4, t12);

    // Step 244: t12 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf00
    for (int i = 0; i < 8; ++i)
        t12 = mul(t12, t12);

    // Step 245: t11 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf67
    t11 = mul(t11, t12);

    // Step 255: t11 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9c00
    for (int i = 0; i < 10; ++i)
        t11 = mul(t11, t11);

    // Step 256: t10 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc3
    t10 = mul(t10, t11);

    // Step 265: t10 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb398600
    for (int i = 0; i < 9; ++i)
        t10 = mul(t10, t10);

    // Step 266: t9 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb398695
    t9 = mul(t9, t10);

    // Step 278: t9 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb398695000
    for (int i = 0; i < 12; ++i)
        t9 = mul(t9, t9);

    // Step 279: t9 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b
    t9 = mul(t7, t9);

    // Step 284: t9 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f60
    for (int i = 0; i < 5; ++i)
        t9 = mul(t9, t9);

    // Step 285: t8 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b
    t8 = mul(t8, t9);

    // Step 296: t8 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b5800
    for (int i = 0; i < 11; ++i)
        t8 = mul(t8, t8);

    // Step 297: t7 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b
    t7 = mul(t7, t8);

    // Step 304: t7 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d80
    for (int i = 0; i < 7; ++i)
        t7 = mul(t7, t7);

    // Step 305: t6 = x^0x680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d89
    t6 = mul(t6, t7);

    // Step 318: t6 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12000
    for (int i = 0; i < 13; ++i)
        t6 = mul(t6, t6);

    // Step 319: t5 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f5
    t5 = mul(t5, t6);

    // Step 328: t5 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241ea00
    for (int i = 0; i < 9; ++i)
        t5 = mul(t5, t5);

    // Step 329: t4 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabf
    t4 = mul(t4, t5);

    // Step 337: t4 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabf00
    for (int i = 0; i < 8; ++i)
        t4 = mul(t4, t4);

    // Step 338: t4 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfff
    t4 = mul(t1, t4);

    // Step 346: t4 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfff00
    for (int i = 0; i < 8; ++i)
        t4 = mul(t4, t4);

    // Step 347: t3 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb
    t3 = mul(t3, t4);

    // Step 358: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff5800
    for (int i = 0; i < 11; ++i)
        t3 = mul(t3, t3);

    // Step 359: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9
    t3 = mul(z, t3);

    // Step 367: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a900
    for (int i = 0; i < 8; ++i)
        t3 = mul(t3, t3);

    // Step 368: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ff
    t3 = mul(t1, t3);

    // Step 376: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ff00
    for (int i = 0; i < 8; ++i)
        t3 = mul(t3, t3);

    // Step 377: t3 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffff
    t3 = mul(t1, t3);

    // Step 383: t3 = x^0x340223d472ffcd3496374f6c869759aec8ee9709e70a257ece61a541ed61ec483d57fffd62a7fffc0
    for (int i = 0; i < 6; ++i)
        t3 = mul(t3, t3);

    // Step 384: t2 = x^0x340223d472ffcd3496374f6c869759aec8ee9709e70a257ece61a541ed61ec483d57fffd62a7ffff7
    t2 = mul(t2, t3);

    // Step 394: t2 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdc00
    for (int i = 0; i < 10; ++i)
        t2 = mul(t2, t2);

    // Step 395: t2 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff
    t2 = mul(t1, t2);

    // Step 404: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9fe00
    for (int i = 0; i < 9; ++i)
        t2 = mul(t2, t2);

    // Step 405: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feff
    t2 = mul(t1, t2);

    // Step 413: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feff00
    for (int i = 0; i < 8; ++i)
        t2 = mul(t2, t2);

    // Step 414: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffff
    t2 = mul(t1, t2);

    // Step 422: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffff00
    for (int i = 0; i < 8; ++i)
        t2 = mul(t2, t2);

    // Step 423: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffff
    t2 = mul(t1, t2);

    // Step 431: t2 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffff00
    for (int i = 0; i < 8; ++i)
        t2 = mul(t2, t2);

    // Step 432: t1 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffff
    t1 = mul(t1, t2);

    // Step 439: t1 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffff80
    for (int i = 0; i < 7; ++i)
        t1 = mul(t1, t1);

    // Step 440: t0 = x^0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd5
    t0 = mul(t0, t1);

    // Step 449: t0 = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa00
    for (int i = 0; i < 9; ++i)
        t0 = mul(t0, t0);

    // Step 450: z = x^0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9
    z = mul(z, t0);

    return z;
}

// uint384 BLS12ModArith::pow(  // NOLINT(misc-no-recursion)
//     const uint384& x, const uint384& y) const noexcept
//{
//     if (y == 0)
//         return 1;
//     else if (y == 1)
//         return x;
//     else if (y % 2 == 0)
//         return pow(mul(x, x), y / 2);
//     else
//         return mul(pow(mul(x, x), y / 2), x);
// }
//
// uint384 BLS12ModArith::neg(const uint384& x) const noexcept
//{
//     return sub(0, x);
// }

}  // namespace evmmax::bls12
