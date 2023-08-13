// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ecc.hpp"
#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmmax/evmmax.hpp>
#include <optional>

using namespace intx;

inline constexpr auto Secp256K1Mod =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;
inline constexpr auto Secp256K1N =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_u256;

namespace evmmax::secp256k1
{
using Point = ecc::Point<uint256>;

uint256 field_inv(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> sqrt(const ModArith<uint256>& s, const uint256& x) noexcept;

std::optional<uint256> sec256k1_calculate_y(
    const ModArith<uint256>& s, const uint256& x, bool is_odd) noexcept;

std::optional<Point> secp256k1_ecdsa_recover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

Point secp256k1_add(const Point& p, const Point& q) noexcept;
Point secp256k1_mul(const Point& pt, const uint256& c) noexcept;

evmc::address secp256k1_point_to_address(const Point& pt) noexcept;

std::optional<evmc::address> ecrecover(
    const ethash::hash256& e, const uint256& r, const uint256& s, bool v) noexcept;

}  // namespace evmmax::secp256k1
