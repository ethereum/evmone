#include "secp256k1.hpp"

namespace evmmax::secp256k1
{
using Point = ecc::Point<uint256>;
using ProjPoint = ecc::ProjPoint<uint256>;

// Computes z = 1/x (mod p) and returns it.
uint256 field_inv(const ModArith<uint256>& s, const uint256& x) noexcept
{
    uint256 z;
    // Inversion computation is derived from the addition chain:
    //
    // _10     = 2*1
    // _100    = 2*_10
    // _101    = 1 + _100
    // _111    = _10 + _101
    // _1110   = 2*_111
    // _111000 = _1110 << 2
    // _111111 = _111 + _111000
    // i13     = _111111 << 4 + _1110
    // x12     = i13 << 2 + _111
    // x22     = x12 << 10 + i13 + 1
    // i29     = 2*x22
    // i31     = i29 << 2
    // i54     = i31 << 22 + i31
    // i122    = (i54 << 20 + i29) << 46 + i54
    // x223    = i122 << 110 + i122 + _111
    // i269    = ((x223 << 23 + x22) << 7 + _101) << 3
    // return    _101 + i269
    //
    // Operations: 255 squares 15 multiplies
    //
    // Generated by github.com/mmcloughlin/addchain v0.4.0.

    // Allocate Temporaries.
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;
    uint256 t4;
    // Step 1: t0 = x^0x2
    t0 = s.mul(x, x);

    // Step 2: z = x^0x4
    z = s.mul(t0, t0);

    // Step 3: z = x^0x5
    z = s.mul(x, z);

    // Step 4: t1 = x^0x7
    t1 = s.mul(t0, z);

    // Step 5: t0 = x^0xe
    t0 = s.mul(t1, t1);

    // Step 7: t2 = x^0x38
    t2 = s.mul(t0, t0);
    for (int i = 1; i < 2; ++i)
        t2 = s.mul(t2, t2);

    // Step 8: t2 = x^0x3f
    t2 = s.mul(t1, t2);

    // Step 12: t2 = x^0x3f0
    for (int i = 0; i < 4; ++i)
        t2 = s.mul(t2, t2);

    // Step 13: t0 = x^0x3fe
    t0 = s.mul(t0, t2);

    // Step 15: t2 = x^0xff8
    t2 = s.mul(t0, t0);
    for (int i = 1; i < 2; ++i)
        t2 = s.mul(t2, t2);

    // Step 16: t2 = x^0xfff
    t2 = s.mul(t1, t2);

    // Step 26: t2 = x^0x3ffc00
    for (int i = 0; i < 10; ++i)
        t2 = s.mul(t2, t2);

    // Step 27: t0 = x^0x3ffffe
    t0 = s.mul(t0, t2);

    // Step 28: t0 = x^0x3fffff
    t0 = s.mul(x, t0);

    // Step 29: t3 = x^0x7ffffe
    t3 = s.mul(t0, t0);

    // Step 31: t2 = x^0x1fffff8
    t2 = s.mul(t3, t3);
    for (int i = 1; i < 2; ++i)
        t2 = s.mul(t2, t2);

    // Step 53: t4 = x^0x7ffffe000000
    t4 = s.mul(t2, t2);
    for (int i = 1; i < 22; ++i)
        t4 = s.mul(t4, t4);

    // Step 54: t2 = x^0x7ffffffffff8
    t2 = s.mul(t2, t4);

    // Step 74: t4 = x^0x7ffffffffff800000
    t4 = s.mul(t2, t2);
    for (int i = 1; i < 20; ++i)
        t4 = s.mul(t4, t4);

    // Step 75: t3 = x^0x7fffffffffffffffe
    t3 = s.mul(t3, t4);

    // Step 121: t3 = x^0x1ffffffffffffffff800000000000
    for (int i = 0; i < 46; ++i)
        t3 = s.mul(t3, t3);

    // Step 122: t2 = x^0x1fffffffffffffffffffffffffff8
    t2 = s.mul(t2, t3);

    // Step 232: t3 = x^0x7ffffffffffffffffffffffffffe0000000000000000000000000000
    t3 = s.mul(t2, t2);
    for (int i = 1; i < 110; ++i)
        t3 = s.mul(t3, t3);

    // Step 233: t2 = x^0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffff8
    t2 = s.mul(t2, t3);

    // Step 234: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t1 = s.mul(t1, t2);

    // Step 257: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        t1 = s.mul(t1, t1);

    // Step 258: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    t0 = s.mul(t0, t1);

    // Step 265: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff80
    for (int i = 0; i < 7; ++i)
        t0 = s.mul(t0, t0);

    // Step 266: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff85
    t0 = s.mul(z, t0);

    // Step 269: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc28
    for (int i = 0; i < 3; ++i)
        t0 = s.mul(t0, t0);

    // Step 270: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d
    z = s.mul(z, t0);

    return z;
}

// Computes z = 1/x (mod p) and returns it.
static uint256 scalar_inv(const ModArith<uint256>& s, const uint256& x) noexcept
{
    uint256 z;
    // Inversion computation is derived from the addition chain:
    //
    // _10       = 2*1
    // _11       = 1 + _10
    // _101      = _10 + _11
    // _111      = _10 + _101
    // _1001     = _10 + _111
    // _1011     = _10 + _1001
    // _1101     = _10 + _1011
    // _110100   = _1101 << 2
    // _111111   = _1011 + _110100
    // _1111110  = 2*_111111
    // _1111111  = 1 + _1111110
    // _11111110 = 2*_1111111
    // _11111111 = 1 + _11111110
    // i17       = _11111111 << 3
    // i19       = i17 << 2
    // i20       = 2*i19
    // i21       = 2*i20
    // i39       = (i21 << 7 + i20) << 9 + i21
    // i73       = (i39 << 6 + i19) << 26 + i39
    // x127      = (i73 << 4 + i17) << 60 + i73 + _1111111
    // i154      = ((x127 << 5 + _1011) << 3 + _101) << 4
    // i166      = ((_101 + i154) << 4 + _111) << 5 + _1101
    // i181      = ((i166 << 2 + _11) << 5 + _111) << 6
    // i193      = ((_1101 + i181) << 5 + _1011) << 4 + _1101
    // i214      = ((i193 << 3 + 1) << 6 + _101) << 10
    // i230      = ((_111 + i214) << 4 + _111) << 9 + _11111111
    // i247      = ((i230 << 5 + _1001) << 6 + _1011) << 4
    // i261      = ((_1101 + i247) << 5 + _11) << 6 + _1101
    // i283      = ((i261 << 10 + _1101) << 4 + _1001) << 6
    // return      (1 + i283) << 8 + _111111
    //
    // Operations: 253 squares 40 multiplies
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
    // Step 1: z = x^0x2
    z = s.mul(x, x);

    // Step 2: t2 = x^0x3
    t2 = s.mul(x, z);

    // Step 3: t6 = x^0x5
    t6 = s.mul(z, t2);

    // Step 4: t5 = x^0x7
    t5 = s.mul(z, t6);

    // Step 5: t0 = x^0x9
    t0 = s.mul(z, t5);

    // Step 6: t3 = x^0xb
    t3 = s.mul(z, t0);

    // Step 7: t1 = x^0xd
    t1 = s.mul(z, t3);

    // Step 9: z = x^0x34
    z = s.mul(t1, t1);
    for (int i = 1; i < 2; ++i)
        z = s.mul(z, z);

    // Step 10: z = x^0x3f
    z = s.mul(t3, z);

    // Step 11: t4 = x^0x7e
    t4 = s.mul(z, z);

    // Step 12: t7 = x^0x7f
    t7 = s.mul(x, t4);

    // Step 13: t4 = x^0xfe
    t4 = s.mul(t7, t7);

    // Step 14: t4 = x^0xff
    t4 = s.mul(x, t4);

    // Step 17: t9 = x^0x7f8
    t9 = s.mul(t4, t4);
    for (int i = 1; i < 3; ++i)
        t9 = s.mul(t9, t9);

    // Step 19: t10 = x^0x1fe0
    t10 = s.mul(t9, t9);
    for (int i = 1; i < 2; ++i)
        t10 = s.mul(t10, t10);

    // Step 20: t11 = x^0x3fc0
    t11 = s.mul(t10, t10);

    // Step 21: t8 = x^0x7f80
    t8 = s.mul(t11, t11);

    // Step 28: t12 = x^0x3fc000
    t12 = s.mul(t8, t8);
    for (int i = 1; i < 7; ++i)
        t12 = s.mul(t12, t12);

    // Step 29: t11 = x^0x3fffc0
    t11 = s.mul(t11, t12);

    // Step 38: t11 = x^0x7fff8000
    for (int i = 0; i < 9; ++i)
        t11 = s.mul(t11, t11);

    // Step 39: t8 = x^0x7fffff80
    t8 = s.mul(t8, t11);

    // Step 45: t11 = x^0x1fffffe000
    t11 = s.mul(t8, t8);
    for (int i = 1; i < 6; ++i)
        t11 = s.mul(t11, t11);

    // Step 46: t10 = x^0x1fffffffe0
    t10 = s.mul(t10, t11);

    // Step 72: t10 = x^0x7fffffff80000000
    for (int i = 0; i < 26; ++i)
        t10 = s.mul(t10, t10);

    // Step 73: t8 = x^0x7fffffffffffff80
    t8 = s.mul(t8, t10);

    // Step 77: t10 = x^0x7fffffffffffff800
    t10 = s.mul(t8, t8);
    for (int i = 1; i < 4; ++i)
        t10 = s.mul(t10, t10);

    // Step 78: t9 = x^0x7fffffffffffffff8
    t9 = s.mul(t9, t10);

    // Step 138: t9 = x^0x7fffffffffffffff8000000000000000
    for (int i = 0; i < 60; ++i)
        t9 = s.mul(t9, t9);

    // Step 139: t8 = x^0x7fffffffffffffffffffffffffffff80
    t8 = s.mul(t8, t9);

    // Step 140: t7 = x^0x7fffffffffffffffffffffffffffffff
    t7 = s.mul(t7, t8);

    // Step 145: t7 = x^0xfffffffffffffffffffffffffffffffe0
    for (int i = 0; i < 5; ++i)
        t7 = s.mul(t7, t7);

    // Step 146: t7 = x^0xfffffffffffffffffffffffffffffffeb
    t7 = s.mul(t3, t7);

    // Step 149: t7 = x^0x7fffffffffffffffffffffffffffffff58
    for (int i = 0; i < 3; ++i)
        t7 = s.mul(t7, t7);

    // Step 150: t7 = x^0x7fffffffffffffffffffffffffffffff5d
    t7 = s.mul(t6, t7);

    // Step 154: t7 = x^0x7fffffffffffffffffffffffffffffff5d0
    for (int i = 0; i < 4; ++i)
        t7 = s.mul(t7, t7);

    // Step 155: t7 = x^0x7fffffffffffffffffffffffffffffff5d5
    t7 = s.mul(t6, t7);

    // Step 159: t7 = x^0x7fffffffffffffffffffffffffffffff5d50
    for (int i = 0; i < 4; ++i)
        t7 = s.mul(t7, t7);

    // Step 160: t7 = x^0x7fffffffffffffffffffffffffffffff5d57
    t7 = s.mul(t5, t7);

    // Step 165: t7 = x^0xfffffffffffffffffffffffffffffffebaae0
    for (int i = 0; i < 5; ++i)
        t7 = s.mul(t7, t7);

    // Step 166: t7 = x^0xfffffffffffffffffffffffffffffffebaaed
    t7 = s.mul(t1, t7);

    // Step 168: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb4
    for (int i = 0; i < 2; ++i)
        t7 = s.mul(t7, t7);

    // Step 169: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb7
    t7 = s.mul(t2, t7);

    // Step 174: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e0
    for (int i = 0; i < 5; ++i)
        t7 = s.mul(t7, t7);

    // Step 175: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e7
    t7 = s.mul(t5, t7);

    // Step 181: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9c0
    for (int i = 0; i < 6; ++i)
        t7 = s.mul(t7, t7);

    // Step 182: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd
    t7 = s.mul(t1, t7);

    // Step 187: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739a0
    for (int i = 0; i < 5; ++i)
        t7 = s.mul(t7, t7);

    // Step 188: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739ab
    t7 = s.mul(t3, t7);

    // Step 192: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739ab0
    for (int i = 0; i < 4; ++i)
        t7 = s.mul(t7, t7);

    // Step 193: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd
    t7 = s.mul(t1, t7);

    // Step 196: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e8
    for (int i = 0; i < 3; ++i)
        t7 = s.mul(t7, t7);

    // Step 197: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9
    t7 = s.mul(x, t7);

    // Step 203: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a40
    for (int i = 0; i < 6; ++i)
        t7 = s.mul(t7, t7);

    // Step 204: t6 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a45
    t6 = s.mul(t6, t7);

    // Step 214: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e91400
    for (int i = 0; i < 10; ++i)
        t6 = s.mul(t6, t6);

    // Step 215: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e91407
    t6 = s.mul(t5, t6);

    // Step 219: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e914070
    for (int i = 0; i < 4; ++i)
        t6 = s.mul(t6, t6);

    // Step 220: t5 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e914077
    t5 = s.mul(t5, t6);

    // Step 229: t5 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280ee00
    for (int i = 0; i < 9; ++i)
        t5 = s.mul(t5, t5);

    // Step 230: t4 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff
    t4 = s.mul(t4, t5);

    // Step 235: t4 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe0
    for (int i = 0; i < 5; ++i)
        t4 = s.mul(t4, t4);

    // Step 236: t4 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe9
    t4 = s.mul(t0, t4);

    // Step 242: t4 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa40
    for (int i = 0; i < 6; ++i)
        t4 = s.mul(t4, t4);

    // Step 243: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4b
    t3 = s.mul(t3, t4);

    // Step 247: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4b0
    for (int i = 0; i < 4; ++i)
        t3 = s.mul(t3, t3);

    // Step 248: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4bd
    t3 = s.mul(t1, t3);

    // Step 253: t3 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a0
    for (int i = 0; i < 5; ++i)
        t3 = s.mul(t3, t3);

    // Step 254: t2 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3
    t2 = s.mul(t2, t3);

    // Step 260: t2 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8c0
    for (int i = 0; i < 6; ++i)
        t2 = s.mul(t2, t2);

    // Step 261: t2 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd
    t2 = s.mul(t1, t2);

    // Step 271: t2 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a33400
    for (int i = 0; i < 10; ++i)
        t2 = s.mul(t2, t2);

    // Step 272: t1 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d
    t1 = s.mul(t1, t2);

    // Step 276: t1 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d0
    for (int i = 0; i < 4; ++i)
        t1 = s.mul(t1, t1);

    // Step 277: t0 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d9
    t0 = s.mul(t0, t1);

    // Step 283: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03640
    for (int i = 0; i < 6; ++i)
        t0 = s.mul(t0, t0);

    // Step 284: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641
    t0 = s.mul(x, t0);

    // Step 292: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364100
    for (int i = 0; i < 8; ++i)
        t0 = s.mul(t0, t0);

    // Step 293: z = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f
    z = s.mul(z, t0);

    return z;
}

Point secp256k1_add(const Point& p, const Point& q) noexcept
{
    if (p.is_inf())
        return q;
    if (q.is_inf())
        return p;

    const evmmax::ModArith s{Secp256K1Mod};

    const auto pp = ecc::to_proj(s, p);
    const auto pq = ecc::to_proj(s, q);

    // b3 == 21 for y^2 == x^3 + 7
    const auto b3 = s.to_mont(21);
    const auto r = ecc::add(s, pp, pq, b3);
    return ecc::to_affine(s, field_inv, r);
}

Point secp256k1_mul(const Point& p, const uint256& c) noexcept
{
    if (p.is_inf())
        return p;

    if (c == 0)
        return {0, 0};

    const evmmax::ModArith s{Secp256K1Mod};
    const auto b3 = s.to_mont(21);

    const auto r = ecc::mul(s, ecc::to_proj(s, p), c, b3);
    return ecc::to_affine(s, field_inv, r);
}


std::optional<uint256> sqrt(const ModArith<uint256>& s, const uint256& x) noexcept
{
    uint256 z;
    // Inversion computation is derived from the addition chain:
    //
    // _10      = 2*1
    // _11      = 1 + _10
    // _1100    = _11 << 2
    // _1111    = _11 + _1100
    // _11110   = 2*_1111
    // _11111   = 1 + _11110
    // _1111100 = _11111 << 2
    // _1111111 = _11 + _1111100
    // x11      = _1111111 << 4 + _1111
    // x22      = x11 << 11 + x11
    // x27      = x22 << 5 + _11111
    // x54      = x27 << 27 + x27
    // x108     = x54 << 54 + x54
    // x216     = x108 << 108 + x108
    // x223     = x216 << 7 + _1111111
    // return     ((x223 << 23 + x22) << 6 + _11) << 2
    //
    // Operations: 253 squares 13 multiplies
    //
    // Generated by github.com/mmcloughlin/addchain v0.4.0.

    // Allocate Temporaries.
    uint256 t0;
    uint256 t1;
    uint256 t2;
    uint256 t3;
    // Step 1: z = x^0x2
    z = s.mul(x, x);

    // Step 2: z = x^0x3
    z = s.mul(x, z);

    // Step 4: t0 = x^0xc
    t0 = s.mul(z, z);
    for (int i = 1; i < 2; ++i)
        t0 = s.mul(t0, t0);

    // Step 5: t0 = x^0xf
    t0 = s.mul(z, t0);

    // Step 6: t1 = x^0x1e
    t1 = s.mul(t0, t0);

    // Step 7: t2 = x^0x1f
    t2 = s.mul(x, t1);

    // Step 9: t1 = x^0x7c
    t1 = s.mul(t2, t2);
    for (int i = 1; i < 2; ++i)
        t1 = s.mul(t1, t1);

    // Step 10: t1 = x^0x7f
    t1 = s.mul(z, t1);

    // Step 14: t3 = x^0x7f0
    t3 = s.mul(t1, t1);
    for (int i = 1; i < 4; ++i)
        t3 = s.mul(t3, t3);

    // Step 15: t0 = x^0x7ff
    t0 = s.mul(t0, t3);

    // Step 26: t3 = x^0x3ff800
    t3 = s.mul(t0, t0);
    for (int i = 1; i < 11; ++i)
        t3 = s.mul(t3, t3);

    // Step 27: t0 = x^0x3fffff
    t0 = s.mul(t0, t3);

    // Step 32: t3 = x^0x7ffffe0
    t3 = s.mul(t0, t0);
    for (int i = 1; i < 5; ++i)
        t3 = s.mul(t3, t3);

    // Step 33: t2 = x^0x7ffffff
    t2 = s.mul(t2, t3);

    // Step 60: t3 = x^0x3ffffff8000000
    t3 = s.mul(t2, t2);
    for (int i = 1; i < 27; ++i)
        t3 = s.mul(t3, t3);

    // Step 61: t2 = x^0x3fffffffffffff
    t2 = s.mul(t2, t3);

    // Step 115: t3 = x^0xfffffffffffffc0000000000000
    t3 = s.mul(t2, t2);
    for (int i = 1; i < 54; ++i)
        t3 = s.mul(t3, t3);

    // Step 116: t2 = x^0xfffffffffffffffffffffffffff
    t2 = s.mul(t2, t3);

    // Step 224: t3 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
    t3 = s.mul(t2, t2);
    for (int i = 1; i < 108; ++i)
        t3 = s.mul(t3, t3);

    // Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t2 = s.mul(t2, t3);

    // Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
    for (int i = 0; i < 7; ++i)
        t2 = s.mul(t2, t2);

    // Step 233: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    t1 = s.mul(t1, t2);

    // Step 256: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        t1 = s.mul(t1, t1);

    // Step 257: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    t0 = s.mul(t0, t1);

    // Step 263: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc0
    for (int i = 0; i < 6; ++i)
        t0 = s.mul(t0, t0);

    // Step 264: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc3
    z = s.mul(z, t0);

    // Step 266: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    for (int i = 0; i < 2; ++i)
        z = s.mul(z, z);

    const auto z2 = s.mul(z, z);

    return (z2 == x ? std::make_optional(z) : std::nullopt);
}

namespace
{
constexpr Point G{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256};
}  // namespace

std::optional<Point> secp256k1_ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept
{
    // Follows
    // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery

    // 1. Validate r and s are within [1, n-1].
    if (r == 0 || r >= Secp256K1N || s == 0 || s >= Secp256K1N)
        return std::nullopt;

    // 3. Hash of the message is already calculated in e.
    // 4. Convert hash e to z field element by doing z = e % n.
    //    https://www.rfc-editor.org/rfc/rfc6979#section-2.3.2
    //    We can do this by n - e because n > 2^255.
    static_assert(Secp256K1N > 1_u256 << 255);
    auto z = intx::be::load<uint256>(e.bytes);
    if (z >= Secp256K1N)
        z -= Secp256K1N;


    const ModArith<uint256> n{Secp256K1N};

    // 5. Calculate u1 and u2.
    const auto r_n = n.to_mont(r);
    const auto r_inv = scalar_inv(n, r_n);

    const auto z_mont = n.to_mont(z);
    const auto z_neg = n.sub(0, z_mont);
    const auto u1_mont = n.mul(z_neg, r_inv);
    const auto u1 = n.from_mont(u1_mont);

    const auto s_mont = n.to_mont(s);
    const auto u2_mont = n.mul(s_mont, r_inv);
    const auto u2 = n.from_mont(u2_mont);


    const ModArith<uint256> m{Secp256K1Mod};

    // 2. Calculate y coordinate of R from r and v.
    const auto r_mont = m.to_mont(r);
    const auto y_mont = sec256k1_calculate_y(m, r_mont, v);
    if (!y_mont.has_value())
        return std::nullopt;
    const auto y = m.from_mont(*y_mont);

    // 6. Calculate public key point Q.
    const auto b3 = m.to_mont(21);
    const auto R = ecc::to_proj(m, {r,y });
    const auto pG = ecc::to_proj(m, G);
    const auto T1 = ecc::mul(m, pG, u1, b3);
    const auto T2 = ecc::mul(m, R, u2, b3);
    const auto Q = ecc::add(m, T1, T2, b3);

    // Any other validity check needed?
    if (Q.is_inf())
        return std::nullopt;

    return ecc::to_affine(m, field_inv, Q);
}

std::optional<uint256> sec256k1_calculate_y(
    const ModArith<uint256>& s, const uint256& x, bool is_odd) noexcept
{
    static const auto Sec256k1_b = s.to_mont(7);

    // Calculate sqrt(x^3 + 7)
    const auto x3 = s.mul(s.mul(x, x), x);
    const auto y = sqrt(s, s.add(x3, Sec256k1_b));
    if (!y.has_value())
        return std::nullopt;

    // Negate if different oddity requested
    const auto y_is_odd = s.from_mont(*y) & 1;
    return (is_odd == y_is_odd ? *y : s.sub(0, *y));
}

evmc::address secp256k1_point_to_address(const Point& pt) noexcept
{
    // This performs Ethereum's address hashing on an uncompressed pubkey.
    uint8_t serialized[64];
    intx::be::unsafe::store(serialized, pt.x);
    intx::be::unsafe::store(serialized + 32, pt.y);

    const auto hashed = ethash::keccak256(serialized, sizeof(serialized));
    evmc::address ret{};
    std::memcpy(ret.bytes, hashed.bytes + 12, 20);

    return ret;
}

std::optional<evmc::address> ecrecover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept
{
    const auto point = secp256k1_ecdsa_recover(e, r, s, v);
    if (!point.has_value())
        return std::nullopt;

    return std::make_optional(secp256k1_point_to_address(*point));
}
}  // namespace evmmax::secp256k1
