// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include <ethash/hash_types.hpp>
#include <evmc/evmc.hpp>
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

using Point = ecc::Point<uint256>;


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

/// Calculate y coordinate of a point having x coordinate and y parity.
std::optional<uint256> calculate_y(
    const ModArith<uint256>& m, const uint256& x, bool y_parity) noexcept;

/// Addition in secp256k1.
///
/// Computes P ⊕ Q for two points in affine coordinates on the secp256k1 curve,
Point add(const Point& p, const Point& q) noexcept;

/// Scalar multiplication in secp256k1.
///
/// Computes [c]P for a point in affine coordinate on the secp256k1 curve,
Point mul(const Point& p, const uint256& c) noexcept;

/// Convert the secp256k1 point (uncompressed public key) to Ethereum address.
evmc::address to_address(const Point& pt) noexcept;

std::optional<Point> secp256k1_ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

std::optional<evmc::address> ecrecover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

}  // namespace evmmax::secp256k1
