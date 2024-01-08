// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "intx/intx.hpp"
#include "utils.hpp"
#include <test/utils/bytecode.hpp>

using namespace intx;

namespace evmmax::evm
{
using field_inv_f = bytecode (*)(
    const utils::Scope& parent_scope, uint8_t x_idx, uint8_t r_idx) noexcept;

bytecode add(const uint256& mod, const uint256& b3, field_inv_f inv) noexcept;

bytecode mul(const uint256& mod, const uint256& b3, field_inv_f inv) noexcept;

}  // namespace evmmax::evm
