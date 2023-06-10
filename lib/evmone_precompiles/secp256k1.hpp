// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include <optional>

namespace evmmax::secp256k1
{
using namespace intx;

/// The secp256k1 field prime number (P).
inline constexpr auto FieldPrime =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;

/// The secp256k1 curve group order (N).
inline constexpr auto Order =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_u256;

/// Modular inversion for secp256k1 prime field.
///
/// Computes 1/x mod P modular inversion by computing modular exponentiation x^(P-2),
/// where P is ::FieldPrime.
uint256 field_inv(const ModArith<uint256>& m, const uint256& x) noexcept;

/// Square root for secp256k1 prime field.
///
/// Computes √x mod P by computing modular exponentiation x^((P+1)/4),
/// where P is ::FieldPrime.
///
/// @return Square root of x if it exists, std::nullopt otherwise.
std::optional<uint256> field_sqrt(const ModArith<uint256>& m, const uint256& x) noexcept;

/// Inversion modulo order of secp256k1.
///
/// Computes 1/x mod N modular inversion by computing modular exponentiation x^(N-2),
/// where N is ::Order.
uint256 scalar_inv(const ModArith<uint256>& m, const uint256& x) noexcept;

}  // namespace evmmax::secp256k1
