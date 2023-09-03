// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include "poly_extension_field.hpp"

inline constexpr intx::uint384 operator"" _u384(const char* s)
{
    return intx::from_string<intx::uint384>(s);
}

inline constexpr auto BLS12Mod =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab_u384;

namespace evmmax::bls12
{
using intx::uint384;
using Point = ecc::Point<uint384>;
using ProjPoint = ecc::ProjPoint<uint384>;

struct ModCoeffs2
{
    static constexpr uint8_t DEGREE = 2;
    // Polynomial modulus FQ2 (x^2 + 1). Coefficients in Montgomery form.
    static constexpr const std::pair<uint8_t, uint384> MODULUS_COEFFS[1] = {
        /* 1 in mont */ {
            0, 0xe0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d_u384}};
    // Implied + [1 in mont form]
};

struct ModCoeffs12
{
    static constexpr uint8_t DEGREE = 12;
    // Polynomial modulus FQ2 (x^12 -18x^6 + 82). Coefficients in Montgomery form.
    static constexpr std::pair<uint8_t, uint384> MODULUS_COEFFS[2] = {
        /* 82 in mont */ {
            0, 0x26574fb11b10196f403a164ef43989b2be1ac00e5788671d4cf30d5bd4979ae9_u384},
        /* (-18 == mod - 18) in mont */
        {6, 0x259d6b14729c0fa51e1a247090812318d087f6872aabf4f68c3488912edefaa0_u384}};
    // Implied + [1 in mont form]
};

class BLS12ModArith : public ModArith<uint384>
{
public:
    explicit BLS12ModArith() : ModArith<uint384>(BLS12Mod) {}

    uint384 inv(const uint384& x) const noexcept;

    uint384 div(const uint384& x, const uint384& y) const noexcept;

    uint384 pow(const uint384& x, const uint384& y) const noexcept;

    uint384 neg(const uint384& x) const noexcept;

    // Calculates Montgomery form for integer literal. Used for optimization only.
    template <size_t N>
    uint384 in_mont() const noexcept
    {
        static const auto n_value = to_mont(N);
        return n_value;
    }

    uint384 one_mont() const noexcept { return in_mont<1>(); }

    using UIntType = uint384;
};

ProjPoint point_addition_mixed_a0(
    const evmmax::ModArith<uint384>& s, const Point& p, const Point& q, const uint384& b3) noexcept;

inline uint384 expmod(const evmmax::ModArith<uint384>& s, uint384 base, uint384 exponent) noexcept
{
    auto result = s.to_mont(1);

    while (exponent != 0)
    {
        if ((exponent & 1) != 0)
            result = s.mul(result, base);
        base = s.mul(base, base);
        exponent >>= 1;
    }
    return result;
}

template <typename FieldElemT>
struct PointExt
{
    FieldElemT x;
    FieldElemT y;
    FieldElemT z;

    static inline constexpr bool eq(const PointExt& a, const PointExt& b) noexcept
    {
        return FieldElemT::eq(a.x, b.x) && FieldElemT::eq(a.y, b.y) && FieldElemT::eq(a.z, b.z);
    }

    static inline constexpr bool is_at_infinity(const PointExt& a) noexcept
    {
        return FieldElemT::eq(a.x, FieldElemT::zero()) && FieldElemT::eq(a.y, FieldElemT::zero()) &&
               FieldElemT::eq(a.z, FieldElemT::zero());
    }

    static inline constexpr PointExt infinity() noexcept
    {
        return {FieldElemT::zero(), FieldElemT::zero(), FieldElemT::zero()};
    }

    friend std::ostream& operator<<(std::ostream& os, const PointExt& p) noexcept
    {
        return os << std::string("[") << p.x << ", " << p.y << ", " << p.z << std::string("]");
    }

    PointExt to_mont() const noexcept { return {x.to_mont(), y.to_mont(), z.to_mont()}; }
    PointExt from_mont() const noexcept { return {x.from_mont(), y.from_mont(), z.from_mont()}; }
};

bool validate(const Point& pt) noexcept;

Point bls12_add(const Point& pt1, const Point& pt2) noexcept;
Point bls12_mul(const Point& pt, const uint384& c) noexcept;

bool bls12_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;
bool bls12_mul_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;
bool bls12_ecpairing_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;

// Extension field FQ2 (x^2 + 1) element
using FE2 = PolyExtFieldElem<BLS12ModArith, ModCoeffs2>;
// Extension field FQ12 (x^12 -18x^6 + 82) element
using FE12 = PolyExtFieldElem<BLS12ModArith, ModCoeffs12>;
// Point of dwo dim space (FQ2xFQ2)
using FE2Point = PointExt<FE2>;
// Point of dwo dim space (FQ12xFQ12)
using FE12Point = PointExt<FE12>;

bool is_on_curve_b(const uint384& x, const uint384& y, const uint384& z) noexcept;
bool is_on_curve_b2(const FE2Point& p) noexcept;
bool is_on_curve_b12(const FE12Point& p) noexcept;

// "Twists" a point in E(FQ2) into a point in E(FQ12)
FE12Point twist(const FE2Point& pt) noexcept;

// Casts point from FQ to FQ12
FE12Point cast_to_fe12(const Point& pt) noexcept;

// Create a function representing the line between P1 and P2, and evaluate it at T
template <typename FieldElemT>
std::pair<FieldElemT, FieldElemT> line_func(const PointExt<FieldElemT>& p1,
    const PointExt<FieldElemT>& p2, const PointExt<FieldElemT>& t) noexcept;

// Elliptic curve point doubling over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_double(const PointExt<FieldElemT>& p) noexcept;

// Elliptic curve point addition over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_add(
    const PointExt<FieldElemT>& p1, const PointExt<FieldElemT>& p2) noexcept;

// Elliptic curve point multiplication over extension field
template <typename FieldElemT>
PointExt<FieldElemT> point_multiply(const PointExt<FieldElemT>& pt, const uint384& n) noexcept;

// Miller loop for pairing bls12 curve points.
FE12 miller_loop(const FE12Point& Q, const FE12Point& P, bool run_final_exp) noexcept;

// Computes paring of bls12 curve points.
FE12 bls12_pairing(const FE2Point& Q, const Point& P) noexcept;

// Computes final exponentiation of bls12 pairing result.
FE12 final_exponentiation(const FE12& a) noexcept;

}  // namespace evmmax::bls12
