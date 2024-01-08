// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "utils.hpp"
#include <test/utils/bytecode.hpp>

namespace evmmax::evm::ecc
{
using namespace evmmax::evm::utils;

void add(bytecode& code, const Scope& parent_scope, uint8_t x1_idx, uint8_t y1_idx, uint8_t z1_idx,
    uint8_t x2_idx, uint8_t y2_idx, uint8_t z2_idx, uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx,
    uint8_t rz_idx) noexcept;

void dbl(bytecode& code, const Scope& parent_scope, uint8_t x_idx, uint8_t y_idx, uint8_t z_idx,
    uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx, uint8_t rz_idx) noexcept;

void mul(bytecode& code, const Scope& parent_scope, uint8_t x_idx, uint8_t y_idx, uint8_t z_idx,
    uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx, uint8_t rz_idx) noexcept;

}  // namespace evmmax::evm::ecc
