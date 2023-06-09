// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"

namespace evmmax::secp256k1
{
using namespace intx;

/// The secp256k1 field prime number (P).
inline constexpr auto FieldPrime =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;

/// Modular inversion for secp256k1 prime field.
///
/// Computes 1/x mod P modular inversion by computing modular exponentiation x^(P-2),
/// where P is ::FieldPrime.
uint256 field_inv(const ModArith<uint256>& m, const uint256& x) noexcept;

}  // namespace evmmax::secp256k1
