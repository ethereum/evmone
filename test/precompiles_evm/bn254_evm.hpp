// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "utils.hpp"
#include <evmone_precompiles/bn254.hpp>
#include <test/utils/bytecode.hpp>

namespace evmmax::evm::bn254
{
using namespace evmmax::evm::utils;
using namespace evmmax::bn254;

/// Addition in bn254 curve group.
///
/// Computes P ⊕ Q for two points in affine coordinates on the bn254 curve,
Point add(const Point& pt1, const Point& pt2) noexcept;

/// Addition in bn254 curve group function bytecode.
const bytecode& generate_add() noexcept;

/// Scalar multiplication in bn254 curve group.
///
/// Computes [c]P for a point in affine coordinate on the bn254 curve,
Point mul(const Point& pt, const uint256& c) noexcept;

/// Multiplication in bn254 curve group function bytecode.
const bytecode& generate_mul() noexcept;

}  // namespace evmmax::evm::bn254
