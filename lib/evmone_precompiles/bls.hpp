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

}  // namespace evmone::crypto::bls
