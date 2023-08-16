// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmmax/evmmax.hpp>
#include <optional>


namespace evmmax::secp256k1
{
using namespace intx;

inline constexpr auto FieldPrime =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;
inline constexpr auto Order =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_u256;

using Point = ecc::Point<uint256>;

// FIXME: Hide the function.
uint256 field_inv(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> sqrt(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> calculate_y(
    const ModArith<uint256>& s, const uint256& x, bool y_parity) noexcept;

std::optional<Point> secp256k1_ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

Point add(const Point& p, const Point& q) noexcept;
Point mul(const Point& p, const uint256& c) noexcept;

evmc::address secp256k1_point_to_address(const Point& pt) noexcept;

std::optional<evmc::address> ecrecover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

}  // namespace evmmax::secp256k1
