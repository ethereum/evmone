// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"

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

bool validate(const Point& pt) noexcept;
uint384 field_inv(const evmmax::ModArith<uint384>& m, const uint384& x) noexcept;
Point bls12_add(const Point& pt1, const Point& pt2) noexcept;

bool bls12_add_precompile(const uint8_t* input, size_t input_size, uint8_t* output) noexcept;

}  // namespace evmmax::bls12
