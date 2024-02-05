// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmmax/evmmax.hpp>

typedef unsigned char fiat_p256_uint1;
typedef signed char fiat_p256_int1;
#if defined(__GNUC__) || defined(__clang__)
#define FIAT_P256_FIAT_EXTENSION __extension__
#define FIAT_P256_FIAT_INLINE __inline__
#else
#define FIAT_P256_FIAT_EXTENSION
#define FIAT_P256_FIAT_INLINE
#endif

FIAT_P256_FIAT_EXTENSION typedef signed __int128 fiat_p256_int128;
FIAT_P256_FIAT_EXTENSION typedef unsigned __int128 fiat_p256_uint128;

/* The type fiat_p256_montgomery_domain_field_element is a field element in the Montgomery domain.
 */
/* Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff],
 * [0x0 ~> 0xffffffffffffffff]] */
typedef uint64_t fiat_p256_montgomery_domain_field_element[4];

/* The type fiat_p256_non_montgomery_domain_field_element is a field element NOT in the Montgomery
 * domain. */
/* Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff],
 * [0x0 ~> 0xffffffffffffffff]] */
typedef uint64_t fiat_p256_non_montgomery_domain_field_element[4];


#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif


/*
 * The function fiat_p256_addcarryx_u64 is an addition with carry.
 *
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^64
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
void fiat_p256_addcarryx_u64(
    uint64_t* out1, fiat_p256_uint1* out2, fiat_p256_uint1 arg1, uint64_t arg2, uint64_t arg3)
{
    unsigned long long carryout = 0;  // NOLINT(google-runtime-int)
    *out1 = __builtin_addcll(arg2, arg3, arg1, &carryout);
    *out2 = static_cast<fiat_p256_uint1>(carryout);
}

/*
 * The function fiat_p256_subborrowx_u64 is a subtraction with borrow.
 *
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^64
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
void fiat_p256_subborrowx_u64(
    uint64_t* out1, fiat_p256_uint1* out2, fiat_p256_uint1 arg1, uint64_t arg2, uint64_t arg3)
{
    unsigned long long carryout = 0;  // NOLINT(google-runtime-int)
    *out1 = __builtin_subcll(arg2, arg3, arg1, &carryout);
    *out2 = static_cast<fiat_p256_uint1>(carryout);
}

/*
 * The function fiat_p256_mulx_u64 is a multiplication, returning the full double-width result.
 *
 * Postconditions:
 *   out1 = (arg1 * arg2) mod 2^64
 *   out2 = ⌊arg1 * arg2 / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0xffffffffffffffff]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0xffffffffffffffff]
 */
void fiat_p256_mulx_u64(uint64_t* out1, uint64_t* out2, uint64_t arg1, uint64_t arg2)
{
    fiat_p256_uint128 x1;
    uint64_t x2;
    uint64_t x3;
    x1 = ((fiat_p256_uint128)arg1 * arg2);
    x2 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
    x3 = (uint64_t)(x1 >> 64);
    *out1 = x2;
    *out2 = x3;
}

/*
 * The function fiat_p256_cmovznz_u64 is a single-word conditional move.
 *
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
void fiat_p256_cmovznz_u64(uint64_t* out1, fiat_p256_uint1 arg1, uint64_t arg2, uint64_t arg3)
{
    fiat_p256_uint1 x1;
    uint64_t x2;
    uint64_t x3;
    x1 = (!(!arg1));
    x2 = ((uint64_t)(int64_t)(fiat_p256_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
    x3 = ((x2 & arg3) | ((~x2) & arg2));
    *out1 = x3;
}

using namespace intx;

namespace evmmax
{
namespace
{
/// Compute the modulus inverse for Montgomery multiplication, i.e. N': mod⋅N' = 2⁶⁴-1.
///
/// @param mod0  The least significant word of the modulus.
inline constexpr uint64_t compute_mod_inv(uint64_t mod0) noexcept
{
    // TODO: Find what is this algorithm and why it works.
    uint64_t base = 0 - mod0;
    uint64_t result = 1;
    for (auto i = 0; i < 64; ++i)
    {
        result *= base;
        base *= base;
    }
    return result;
}

/// Compute R² % mod.
template <typename UintT>
inline UintT compute_r_squared(const UintT& mod) noexcept
{
    // R is 2^num_bits, R² is 2^(2*num_bits) and needs 2*num_bits+1 bits to represent,
    // rounded to 2*num_bits+64) for intx requirements.
    static constexpr auto r2 = intx::uint<UintT::num_bits * 2 + 64>{1} << (UintT::num_bits * 2);
    return intx::udivrem(r2, mod).rem;
}

[[maybe_unused]] inline constexpr std::pair<uint64_t, uint64_t> addmul(
    uint64_t t, uint64_t a, uint64_t b, uint64_t c) noexcept
{
    const auto p = umul(a, b) + t + c;
    return {p[1], p[0]};
}
}  // namespace

template <typename UintT>
ModArith<UintT>::ModArith(const UintT& modulus) noexcept
  : mod{modulus}, m_r_squared{compute_r_squared(modulus)}, m_mod_inv{compute_mod_inv(modulus[0])}
{}

template <typename UintT>
UintT ModArith<UintT>::mul(const UintT& arg1, const UintT& arg2) const noexcept
{
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
    uint64_t x6;
    uint64_t x7;
    uint64_t x8;
    uint64_t x9;
    uint64_t x10;
    uint64_t x11;
    uint64_t x12;
    uint64_t x13;
    fiat_p256_uint1 x14;
    uint64_t x15;
    fiat_p256_uint1 x16;
    uint64_t x17;
    fiat_p256_uint1 x18;
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29;
    uint64_t x30;
    fiat_p256_uint1 x31;
    uint64_t x32;
    fiat_p256_uint1 x33;
    uint64_t x34;
    fiat_p256_uint1 x35;
    uint64_t x36;
    uint64_t x37;
    fiat_p256_uint1 x38;
    uint64_t x39;
    fiat_p256_uint1 x40;
    uint64_t x41;
    fiat_p256_uint1 x42;
    uint64_t x43;
    fiat_p256_uint1 x44;
    uint64_t x45;
    fiat_p256_uint1 x46;
    uint64_t x47;
    uint64_t x48;
    uint64_t x49;
    uint64_t x50;
    uint64_t x51;
    uint64_t x52;
    uint64_t x53;
    uint64_t x54;
    uint64_t x55;
    fiat_p256_uint1 x56;
    uint64_t x57;
    fiat_p256_uint1 x58;
    uint64_t x59;
    fiat_p256_uint1 x60;
    uint64_t x61;
    uint64_t x62;
    fiat_p256_uint1 x63;
    uint64_t x64;
    fiat_p256_uint1 x65;
    uint64_t x66;
    fiat_p256_uint1 x67;
    uint64_t x68;
    fiat_p256_uint1 x69;
    uint64_t x70;
    fiat_p256_uint1 x71;
    uint64_t x72;
    uint64_t x73;
    uint64_t x74;
    uint64_t x75;
    uint64_t x76;
    uint64_t x77;
    uint64_t x78;
    uint64_t x79;
    uint64_t x80;
    uint64_t x81;
    uint64_t x82;
    fiat_p256_uint1 x83;
    uint64_t x84;
    fiat_p256_uint1 x85;
    uint64_t x86;
    fiat_p256_uint1 x87;
    uint64_t x88;
    uint64_t x89;
    fiat_p256_uint1 x90;
    uint64_t x91;
    fiat_p256_uint1 x92;
    uint64_t x93;
    fiat_p256_uint1 x94;
    uint64_t x95;
    fiat_p256_uint1 x96;
    uint64_t x97;
    fiat_p256_uint1 x98;
    uint64_t x99;
    uint64_t x100;
    uint64_t x101;
    uint64_t x102;
    uint64_t x103;
    uint64_t x104;
    uint64_t x105;
    uint64_t x106;
    uint64_t x107;
    uint64_t x108;
    fiat_p256_uint1 x109;
    uint64_t x110;
    fiat_p256_uint1 x111;
    uint64_t x112;
    fiat_p256_uint1 x113;
    uint64_t x114;
    uint64_t x115;
    fiat_p256_uint1 x116;
    uint64_t x117;
    fiat_p256_uint1 x118;
    uint64_t x119;
    fiat_p256_uint1 x120;
    uint64_t x121;
    fiat_p256_uint1 x122;
    uint64_t x123;
    fiat_p256_uint1 x124;
    uint64_t x125;
    uint64_t x126;
    uint64_t x127;
    uint64_t x128;
    uint64_t x129;
    uint64_t x130;
    uint64_t x131;
    uint64_t x132;
    uint64_t x133;
    uint64_t x134;
    uint64_t x135;
    fiat_p256_uint1 x136;
    uint64_t x137;
    fiat_p256_uint1 x138;
    uint64_t x139;
    fiat_p256_uint1 x140;
    uint64_t x141;
    uint64_t x142;
    fiat_p256_uint1 x143;
    uint64_t x144;
    fiat_p256_uint1 x145;
    uint64_t x146;
    fiat_p256_uint1 x147;
    uint64_t x148;
    fiat_p256_uint1 x149;
    uint64_t x150;
    fiat_p256_uint1 x151;
    uint64_t x152;
    uint64_t x153;
    uint64_t x154;
    uint64_t x155;
    uint64_t x156;
    uint64_t x157;
    uint64_t x158;
    uint64_t x159;
    uint64_t x160;
    uint64_t x161;
    fiat_p256_uint1 x162;
    uint64_t x163;
    fiat_p256_uint1 x164;
    uint64_t x165;
    fiat_p256_uint1 x166;
    uint64_t x167;
    uint64_t x168;
    fiat_p256_uint1 x169;
    uint64_t x170;
    fiat_p256_uint1 x171;
    uint64_t x172;
    fiat_p256_uint1 x173;
    uint64_t x174;
    fiat_p256_uint1 x175;
    uint64_t x176;
    fiat_p256_uint1 x177;
    uint64_t x178;
    uint64_t x179;
    uint64_t x180;
    uint64_t x181;
    uint64_t x182;
    uint64_t x183;
    uint64_t x184;
    uint64_t x185;
    uint64_t x186;
    uint64_t x187;
    uint64_t x188;
    fiat_p256_uint1 x189;
    uint64_t x190;
    fiat_p256_uint1 x191;
    uint64_t x192;
    fiat_p256_uint1 x193;
    uint64_t x194;
    uint64_t x195;
    fiat_p256_uint1 x196;
    uint64_t x197;
    fiat_p256_uint1 x198;
    uint64_t x199;
    fiat_p256_uint1 x200;
    uint64_t x201;
    fiat_p256_uint1 x202;
    uint64_t x203;
    fiat_p256_uint1 x204;
    uint64_t x205;
    uint64_t x206;
    fiat_p256_uint1 x207;
    uint64_t x208;
    fiat_p256_uint1 x209;
    uint64_t x210;
    fiat_p256_uint1 x211;
    uint64_t x212;
    fiat_p256_uint1 x213;
    uint64_t x214;
    fiat_p256_uint1 x215;
    uint64_t x216;
    uint64_t x217;
    uint64_t x218;
    uint64_t x219;
    x1 = (arg1[1]);
    x2 = (arg1[2]);
    x3 = (arg1[3]);
    x4 = (arg1[0]);
    fiat_p256_mulx_u64(&x5, &x6, x4, (arg2[3]));
    fiat_p256_mulx_u64(&x7, &x8, x4, (arg2[2]));
    fiat_p256_mulx_u64(&x9, &x10, x4, (arg2[1]));
    fiat_p256_mulx_u64(&x11, &x12, x4, (arg2[0]));
    fiat_p256_addcarryx_u64(&x13, &x14, 0x0, x12, x9);
    fiat_p256_addcarryx_u64(&x15, &x16, x14, x10, x7);
    fiat_p256_addcarryx_u64(&x17, &x18, x16, x8, x5);
    x19 = (x18 + x6);
    fiat_p256_mulx_u64(&x20, &x21, x11, m_mod_inv);
    fiat_p256_mulx_u64(&x22, &x23, x20, mod[3]);
    fiat_p256_mulx_u64(&x24, &x25, x20, mod[2]);
    fiat_p256_mulx_u64(&x26, &x27, x20, mod[1]);
    fiat_p256_mulx_u64(&x28, &x29, x20, mod[0]);
    fiat_p256_addcarryx_u64(&x30, &x31, 0x0, x29, x26);
    fiat_p256_addcarryx_u64(&x32, &x33, x31, x27, x24);
    fiat_p256_addcarryx_u64(&x34, &x35, x33, x25, x22);
    x36 = (x35 + x23);
    fiat_p256_addcarryx_u64(&x37, &x38, 0x0, x11, x28);
    fiat_p256_addcarryx_u64(&x39, &x40, x38, x13, x30);
    fiat_p256_addcarryx_u64(&x41, &x42, x40, x15, x32);
    fiat_p256_addcarryx_u64(&x43, &x44, x42, x17, x34);
    fiat_p256_addcarryx_u64(&x45, &x46, x44, x19, x36);
    fiat_p256_mulx_u64(&x47, &x48, x1, (arg2[3]));
    fiat_p256_mulx_u64(&x49, &x50, x1, (arg2[2]));
    fiat_p256_mulx_u64(&x51, &x52, x1, (arg2[1]));
    fiat_p256_mulx_u64(&x53, &x54, x1, (arg2[0]));
    fiat_p256_addcarryx_u64(&x55, &x56, 0x0, x54, x51);
    fiat_p256_addcarryx_u64(&x57, &x58, x56, x52, x49);
    fiat_p256_addcarryx_u64(&x59, &x60, x58, x50, x47);
    x61 = (x60 + x48);
    fiat_p256_addcarryx_u64(&x62, &x63, 0x0, x39, x53);
    fiat_p256_addcarryx_u64(&x64, &x65, x63, x41, x55);
    fiat_p256_addcarryx_u64(&x66, &x67, x65, x43, x57);
    fiat_p256_addcarryx_u64(&x68, &x69, x67, x45, x59);
    fiat_p256_addcarryx_u64(&x70, &x71, x69, x46, x61);
    fiat_p256_mulx_u64(&x72, &x73, x62, m_mod_inv);
    fiat_p256_mulx_u64(&x74, &x75, x72, UINT64_C(0xffffffffffffffff));
    fiat_p256_mulx_u64(&x76, &x77, x72, UINT64_C(0xffffffffffffffff));
    fiat_p256_mulx_u64(&x78, &x79, x72, UINT64_C(0xffffffffffffffff));
    fiat_p256_mulx_u64(&x80, &x81, x72, UINT64_C(0xfffffffefffffc2f));
    fiat_p256_addcarryx_u64(&x82, &x83, 0x0, x81, x78);
    fiat_p256_addcarryx_u64(&x84, &x85, x83, x79, x76);
    fiat_p256_addcarryx_u64(&x86, &x87, x85, x77, x74);
    x88 = (x87 + x75);
    fiat_p256_addcarryx_u64(&x89, &x90, 0x0, x62, x80);
    fiat_p256_addcarryx_u64(&x91, &x92, x90, x64, x82);
    fiat_p256_addcarryx_u64(&x93, &x94, x92, x66, x84);
    fiat_p256_addcarryx_u64(&x95, &x96, x94, x68, x86);
    fiat_p256_addcarryx_u64(&x97, &x98, x96, x70, x88);
    x99 = ((uint64_t)x98 + x71);
    fiat_p256_mulx_u64(&x100, &x101, x2, (arg2[3]));
    fiat_p256_mulx_u64(&x102, &x103, x2, (arg2[2]));
    fiat_p256_mulx_u64(&x104, &x105, x2, (arg2[1]));
    fiat_p256_mulx_u64(&x106, &x107, x2, (arg2[0]));
    fiat_p256_addcarryx_u64(&x108, &x109, 0x0, x107, x104);
    fiat_p256_addcarryx_u64(&x110, &x111, x109, x105, x102);
    fiat_p256_addcarryx_u64(&x112, &x113, x111, x103, x100);
    x114 = (x113 + x101);
    fiat_p256_addcarryx_u64(&x115, &x116, 0x0, x91, x106);
    fiat_p256_addcarryx_u64(&x117, &x118, x116, x93, x108);
    fiat_p256_addcarryx_u64(&x119, &x120, x118, x95, x110);
    fiat_p256_addcarryx_u64(&x121, &x122, x120, x97, x112);
    fiat_p256_addcarryx_u64(&x123, &x124, x122, x99, x114);
    fiat_p256_mulx_u64(&x125, &x126, x115, m_mod_inv);
    fiat_p256_mulx_u64(&x127, &x128, x125, mod[3]);
    fiat_p256_mulx_u64(&x129, &x130, x125, mod[2]);
    fiat_p256_mulx_u64(&x131, &x132, x125, mod[1]);
    fiat_p256_mulx_u64(&x133, &x134, x125, mod[0]);
    fiat_p256_addcarryx_u64(&x135, &x136, 0x0, x134, x131);
    fiat_p256_addcarryx_u64(&x137, &x138, x136, x132, x129);
    fiat_p256_addcarryx_u64(&x139, &x140, x138, x130, x127);
    x141 = (x140 + x128);
    fiat_p256_addcarryx_u64(&x142, &x143, 0x0, x115, x133);
    fiat_p256_addcarryx_u64(&x144, &x145, x143, x117, x135);
    fiat_p256_addcarryx_u64(&x146, &x147, x145, x119, x137);
    fiat_p256_addcarryx_u64(&x148, &x149, x147, x121, x139);
    fiat_p256_addcarryx_u64(&x150, &x151, x149, x123, x141);
    x152 = ((uint64_t)x151 + x124);
    fiat_p256_mulx_u64(&x153, &x154, x3, (arg2[3]));
    fiat_p256_mulx_u64(&x155, &x156, x3, (arg2[2]));
    fiat_p256_mulx_u64(&x157, &x158, x3, (arg2[1]));
    fiat_p256_mulx_u64(&x159, &x160, x3, (arg2[0]));
    fiat_p256_addcarryx_u64(&x161, &x162, 0x0, x160, x157);
    fiat_p256_addcarryx_u64(&x163, &x164, x162, x158, x155);
    fiat_p256_addcarryx_u64(&x165, &x166, x164, x156, x153);
    x167 = (x166 + x154);
    fiat_p256_addcarryx_u64(&x168, &x169, 0x0, x144, x159);
    fiat_p256_addcarryx_u64(&x170, &x171, x169, x146, x161);
    fiat_p256_addcarryx_u64(&x172, &x173, x171, x148, x163);
    fiat_p256_addcarryx_u64(&x174, &x175, x173, x150, x165);
    fiat_p256_addcarryx_u64(&x176, &x177, x175, x152, x167);
    fiat_p256_mulx_u64(&x178, &x179, x168, m_mod_inv);
    fiat_p256_mulx_u64(&x180, &x181, x178, mod[3]);
    fiat_p256_mulx_u64(&x182, &x183, x178, mod[2]);
    fiat_p256_mulx_u64(&x184, &x185, x178, mod[1]);
    fiat_p256_mulx_u64(&x186, &x187, x178, mod[0]);
    fiat_p256_addcarryx_u64(&x188, &x189, 0x0, x187, x184);
    fiat_p256_addcarryx_u64(&x190, &x191, x189, x185, x182);
    fiat_p256_addcarryx_u64(&x192, &x193, x191, x183, x180);
    x194 = (x193 + x181);
    fiat_p256_addcarryx_u64(&x195, &x196, 0x0, x168, x186);
    fiat_p256_addcarryx_u64(&x197, &x198, x196, x170, x188);
    fiat_p256_addcarryx_u64(&x199, &x200, x198, x172, x190);
    fiat_p256_addcarryx_u64(&x201, &x202, x200, x174, x192);
    fiat_p256_addcarryx_u64(&x203, &x204, x202, x176, x194);
    x205 = ((uint64_t)x204 + x177);
    fiat_p256_subborrowx_u64(&x206, &x207, 0x0, x197, mod[0]);
    fiat_p256_subborrowx_u64(&x208, &x209, x207, x199, mod[1]);
    fiat_p256_subborrowx_u64(&x210, &x211, x209, x201, mod[2]);
    fiat_p256_subborrowx_u64(&x212, &x213, x211, x203, mod[3]);
    fiat_p256_subborrowx_u64(&x214, &x215, x213, x205, 0x0);
    fiat_p256_cmovznz_u64(&x216, x215, x206, x197);
    fiat_p256_cmovznz_u64(&x217, x215, x208, x199);
    fiat_p256_cmovznz_u64(&x218, x215, x210, x201);
    fiat_p256_cmovznz_u64(&x219, x215, x212, x203);

    UintT out1;
    out1[0] = x216;
    out1[1] = x217;
    out1[2] = x218;
    out1[3] = x219;

    return out1;
}

template <typename UintT>
UintT ModArith<UintT>::to_mont(const UintT& x) const noexcept
{
    return mul(x, m_r_squared);
}

template <typename UintT>
UintT ModArith<UintT>::from_mont(const UintT& x) const noexcept
{
    return mul(x, 1);
}

template <typename UintT>
UintT ModArith<UintT>::add(const UintT& x, const UintT& y) const noexcept
{
    const auto s = addc(x, y);  // TODO: cannot overflow if modulus is sparse (e.g. 255 bits).
    const auto d = subc(s.value, mod);
    return (!s.carry && d.carry) ? s.value : d.value;
}

template <typename UintT>
UintT ModArith<UintT>::sub(const UintT& x, const UintT& y) const noexcept
{
    const auto d = subc(x, y);
    const auto s = d.value + mod;
    return (d.carry) ? s : d.value;
}

template class ModArith<uint256>;
template class ModArith<uint384>;
}  // namespace evmmax
