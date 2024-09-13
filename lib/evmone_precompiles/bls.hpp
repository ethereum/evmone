#pragma once

#include <intx/intx.hpp>

using namespace intx::literals;

namespace evmone::crypto::bls
{
/// The BLS12-381 field prime number.
inline constexpr auto BLS_FIELD_MODULUS =
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab_u384;

/// Addition in BLS12-381 curve group.
///
/// Computes P ⊕ Q for two points in affine coordinates on the BLS12-381 curve,
[[nodiscard]] bool g1_add(uint8_t _rx[64], uint8_t _ry[64], const uint8_t _x0[64],
    const uint8_t _y0[64], const uint8_t _x1[64], const uint8_t _y1[64]) noexcept;

/// Scalar multiplication in BLS12-381 curve G1 subgroup.
///
/// Computes [c]P for a point in affine coordinate on the BLS12-381 curve, performs subgroup check
/// according to spec https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiplication
[[nodiscard]] bool g1_mul(uint8_t _rx[64], uint8_t _ry[64], const uint8_t _x[64],
    const uint8_t _y[64], const uint8_t _c[32]) noexcept;

/// Addition in BLS12-381 curve group over G2 extension field.
///
/// Computes P ⊕ Q for two points in affine coordinates on the BLS12-381 curve over G2 extension
/// field, performs subgroup checks for both points according to spec
/// https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-addition
[[nodiscard]] bool g2_add(uint8_t _rx[128], uint8_t _ry[128], const uint8_t _x0[128],
    const uint8_t _y0[128], const uint8_t _x1[128], const uint8_t _y1[128]) noexcept;

/// Scalar multiplication in BLS12-381 curve group over G2 extension field
///
/// Computes [c]P for a point in affine coordinate on the BLS12-381 curve over G2 extension
/// field, performs subgroup check according to spec
/// https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-multiplication
[[nodiscard]] bool g2_mul(uint8_t _rx[128], uint8_t _ry[128], const uint8_t _x[128],
    const uint8_t _y[128], const uint8_t _c[32]) noexcept;

}  // namespace evmone::crypto::bls
