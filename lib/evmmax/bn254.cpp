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

Point bn254_add(const Point& pt1, const Point& pt2, bool convert_to_mont) noexcept
{
    if (is_at_infinity(pt1))
        return pt2;
    if (is_at_infinity(pt2))
        return pt1;

    const evmmax::ModArith s{BN254Mod};

    // https://eprint.iacr.org/2015/1060 algorithm 2.
    // Simplified with z3 == 1, a == 0, b3 == 9.

    auto b3 = s.to_mont(9);

    auto x1 = pt1.x;
    auto y1 = pt1.y;

    auto x2 = pt2.x;
    auto y2 = pt2.y;

    if (convert_to_mont)
    {
        x1 = s.to_mont(pt1.x);
        y1 = s.to_mont(pt1.y);

        x2 = s.to_mont(pt2.x);
        y2 = s.to_mont(pt2.y);
    }

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

    if (convert_to_mont)
    {
        x3 = s.from_mont(x3);
        y3 = s.from_mont(y3);
    }

    return {x3, y3};
}

Point bn254_mul(const Point& pt, const uint256& s) noexcept
{
    if (is_at_infinity(pt))
        return pt;

    if (s == 0)
        return {0, 0};

    const evmmax::ModArith sm{BN254Mod};

    Point r0 = {sm.to_mont(0), sm.to_mont(0)};
    Point r1 = {sm.to_mont(pt.x), sm.to_mont(pt.y)};

    for (int16_t i = 255; i >= 0; --i)
    {
        const uint256 d = s & (uint256{1} << i);
        if (d == 0)
        {
            r1 = bn254_add(r0, r1, false);
            r0 = bn254_add(r0, r0, false);
        }
        else
        {
            r0 = bn254_add(r0, r1, false);
            r1 = bn254_add(r1, r1, false);
        }
    }

    return {sm.from_mont(r0.x), sm.from_mont(r0.y)};
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

uint256 inv(const evmmax::ModArith<uint256>& s, const uint256& x) noexcept
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
    t8 = s.mul(x, x);

    // Step 2: t15 = x^0x3
    t15 = s.mul(x, t8);

    // Step 3: z = x^0x5
    auto z = s.mul(t8, t15);

    // Step 4: t1 = x^0x6
    t1 = s.mul(x, z);

    // Step 5: t3 = x^0x8
    t3 = s.mul(t8, t1);

    // Step 6: t9 = x^0xd
    t9 = s.mul(z, t3);

    // Step 7: t6 = x^0x12
    t6 = s.mul(z, t9);

    // Step 8: t19 = x^0x13
    t19 = s.mul(x, t6);

    // Step 9: t0 = x^0x14
    t0 = s.mul(x, t19);

    // Step 10: t20 = x^0x17
    t20 = s.mul(t15, t0);

    // Step 11: t2 = x^0x1c
    t2 = s.mul(z, t20);

    // Step 12: t17 = x^0x20
    t17 = s.mul(t9, t19);

    // Step 13: t4 = x^0x23
    t4 = s.mul(t15, t17);

    // Step 14: t14 = x^0x2b
    t14 = s.mul(t3, t4);

    // Step 15: t12 = x^0x2f
    t12 = s.mul(t19, t2);

    // Step 16: t16 = x^0x41
    t16 = s.mul(t6, t12);

    // Step 17: t18 = x^0x53
    t18 = s.mul(t6, t16);

    // Step 18: t3 = x^0x5b
    t3 = s.mul(t3, t18);

    // Step 19: t5 = x^0x61
    t5 = s.mul(t1, t3);

    // Step 20: t0 = x^0x75
    t0 = s.mul(t0, t5);

    // Step 21: t10 = x^0x91
    t10 = s.mul(t2, t0);

    // Step 22: t7 = x^0x95
    t7 = s.mul(t17, t0);

    // Step 23: t11 = x^0xb5
    t11 = s.mul(t17, t7);

    // Step 24: t13 = x^0xbb
    t13 = s.mul(t1, t11);

    // Step 25: t21 = x^0xc1
    t21 = s.mul(t1, t13);

    // Step 26: t2 = x^0xc3
    t2 = s.mul(t8, t21);

    // Step 27: t6 = x^0xd3
    t6 = s.mul(t6, t21);

    // Step 28: t17 = x^0xe1
    t17 = s.mul(t17, t21);

    // Step 29: t8 = x^0xe3
    t8 = s.mul(t8, t17);

    // Step 30: t1 = x^0xe7
    t1 = s.mul(t1, t17);

    // Step 38: t21 = x^0xc100
    for (int i = 0; i < 8; ++i)
        t21 = s.mul(t21, t21);

    // Step 39: t21 = x^0xc191
    t21 = s.mul(t10, t21);

    // Step 49: t21 = x^0x3064400
    for (int i = 0; i < 10; ++i)
        t21 = s.mul(t21, t21);

    // Step 50: t21 = x^0x30644e7
    t21 = s.mul(t1, t21);

    // Step 57: t21 = x^0x183227380
    for (int i = 0; i < 7; ++i)
        t21 = s.mul(t21, t21);

    // Step 58: t20 = x^0x183227397
    t20 = s.mul(t20, t21);

    // Step 67: t20 = x^0x30644e72e00
    for (int i = 0; i < 9; ++i)
        t20 = s.mul(t20, t20);

    // Step 68: t19 = x^0x30644e72e13
    t19 = s.mul(t19, t20);

    // Step 75: t19 = x^0x1832273970980
    for (int i = 0; i < 7; ++i)
        t19 = s.mul(t19, t19);

    // Step 76: t19 = x^0x183227397098d
    t19 = s.mul(t9, t19);

    // Step 90: t19 = x^0x60c89ce5c2634000
    for (int i = 0; i < 14; ++i)
        t19 = s.mul(t19, t19);

    // Step 91: t18 = x^0x60c89ce5c2634053
    t18 = s.mul(t18, t19);

    // Step 100: t18 = x^0xc19139cb84c680a600
    for (int i = 0; i < 9; ++i)
        t18 = s.mul(t18, t18);

    // Step 101: t17 = x^0xc19139cb84c680a6e1
    t17 = s.mul(t17, t18);

    // Step 109: t17 = x^0xc19139cb84c680a6e100
    for (int i = 0; i < 8; ++i)
        t17 = s.mul(t17, t17);

    // Step 110: t16 = x^0xc19139cb84c680a6e141
    t16 = s.mul(t16, t17);

    // Step 120: t16 = x^0x30644e72e131a029b850400
    for (int i = 0; i < 10; ++i)
        t16 = s.mul(t16, t16);

    // Step 121: t16 = x^0x30644e72e131a029b85045b
    t16 = s.mul(t3, t16);

    // Step 126: t16 = x^0x60c89ce5c263405370a08b60
    for (int i = 0; i < 5; ++i)
        t16 = s.mul(t16, t16);

    // Step 127: t16 = x^0x60c89ce5c263405370a08b6d
    t16 = s.mul(t9, t16);

    // Step 135: t16 = x^0x60c89ce5c263405370a08b6d00
    for (int i = 0; i < 8; ++i)
        t16 = s.mul(t16, t16);

    // Step 136: t15 = x^0x60c89ce5c263405370a08b6d03
    t15 = s.mul(t15, t16);

    // Step 148: t15 = x^0x60c89ce5c263405370a08b6d03000
    for (int i = 0; i < 12; ++i)
        t15 = s.mul(t15, t15);

    // Step 149: t14 = x^0x60c89ce5c263405370a08b6d0302b
    t14 = s.mul(t14, t15);

    // Step 161: t14 = x^0x60c89ce5c263405370a08b6d0302b000
    for (int i = 0; i < 12; ++i)
        t14 = s.mul(t14, t14);

    // Step 162: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb
    t13 = s.mul(t13, t14);

    // Step 170: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb00
    for (int i = 0; i < 8; ++i)
        t13 = s.mul(t13, t13);

    // Step 171: t12 = x^0x60c89ce5c263405370a08b6d0302b0bb2f
    t12 = s.mul(t12, t13);

    // Step 185: t12 = x^0x183227397098d014dc2822db40c0ac2ecbc000
    for (int i = 0; i < 14; ++i)
        t12 = s.mul(t12, t12);

    // Step 186: t11 = x^0x183227397098d014dc2822db40c0ac2ecbc0b5
    t11 = s.mul(t11, t12);

    // Step 195: t11 = x^0x30644e72e131a029b85045b68181585d97816a00
    for (int i = 0; i < 9; ++i)
        t11 = s.mul(t11, t11);

    // Step 196: t10 = x^0x30644e72e131a029b85045b68181585d97816a91
    t10 = s.mul(t10, t11);

    // Step 201: t10 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d5220
    for (int i = 0; i < 5; ++i)
        t10 = s.mul(t10, t10);

    // Step 202: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d
    t9 = s.mul(t9, t10);

    // Step 214: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d000
    for (int i = 0; i < 12; ++i)
        t9 = s.mul(t9, t9);

    // Step 215: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e3
    t8 = s.mul(t8, t9);

    // Step 223: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e300
    for (int i = 0; i < 8; ++i)
        t8 = s.mul(t8, t8);

    // Step 224: t7 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e395
    t7 = s.mul(t7, t8);

    // Step 235: t7 = x^0x30644e72e131a029b85045b68181585d97816a916871ca800
    for (int i = 0; i < 11; ++i)
        t7 = s.mul(t7, t7);

    // Step 236: t6 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3
    t6 = s.mul(t6, t7);

    // Step 243: t6 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e546980
    for (int i = 0; i < 7; ++i)
        t6 = s.mul(t6, t6);

    // Step 244: t5 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e1
    t5 = s.mul(t5, t6);

    // Step 255: t5 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0800
    for (int i = 0; i < 11; ++i)
        t5 = s.mul(t5, t5);

    // Step 256: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823
    t4 = s.mul(t4, t5);

    // Step 268: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823000
    for (int i = 0; i < 12; ++i)
        t4 = s.mul(t4, t4);

    // Step 269: t3 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b
    t3 = s.mul(t3, t4);

    // Step 278: t3 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b600
    for (int i = 0; i < 9; ++i)
        t3 = s.mul(t3, t3);

    // Step 279: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3
    t2 = s.mul(t2, t3);

    // Step 287: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c300
    for (int i = 0; i < 8; ++i)
        t2 = s.mul(t2, t2);

    // Step 288: t1 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7
    t1 = s.mul(t1, t2);

    // Step 295: t1 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f380
    for (int i = 0; i < 7; ++i)
        t1 = s.mul(t1, t1);

    // Step 296: t0 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f5
    t0 = s.mul(t0, t1);

    // Step 302: t0 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd40
    for (int i = 0; i < 6; ++i)
        t0 = s.mul(t0, t0);

    // Step 303: z = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
    z = s.mul(z, t0);

    return z;
}
}  // namespace evmmax::bn254