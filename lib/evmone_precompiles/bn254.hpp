// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include <optional>
#include <vector>

namespace evmmax::bn254
{
using namespace intx;

/// The bn254 field prime number (P).
inline constexpr auto FieldPrime =
    0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_u256;

using Point = ecc::Point<uint256>;
using ExtPoint = ecc::Point<std::pair<uint256, uint256>>;

/// Validates that point is from the bn254 curve group
///
/// Returns true if y^2 == x^3 + 3. Input is converted to the Montgomery form.
bool validate(const Point& pt) noexcept;

/// Modular inversion for bn254 prime field.
///
/// Computes 1/x mod P modular inversion by computing modular exponentiation x^(P-2),
/// where P is ::FieldPrime.
uint256 field_inv(const ModArith<uint256>& m, const uint256& x) noexcept;

/// Addition in bn254 curve group.
///
/// Computes P ⊕ Q for two points in affine coordinates on the bn254 curve,
Point add(const Point& pt1, const Point& pt2) noexcept;

/// Scalar multiplication in bn254 curve group.
///
/// Computes [c]P for a point in affine coordinate on the bn254 curve,
Point mul(const Point& pt, const uint256& c) noexcept;

/// ate paring implementation for bn254 curve according to https://eips.ethereum.org/EIPS/eip-197
///
/// \param vG2 vector containing points from twisted curve G2 group over extension field Fq^2
/// \param vG1 vector of points from the bn254 curve G1 group over the base field
/// These vectors must be same size n.
/// \return `true` when  ∏e(vG2[i], vG1[i]) == 1 for i in [0, n] else `false`. std::nullopt on error
std::optional<bool> pairing(
    const std::vector<ExtPoint>& vG2, const std::vector<Point>& vG1) noexcept;

}  // namespace evmmax::bn254
