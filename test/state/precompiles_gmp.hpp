// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <span>

namespace evmone::state
{
/// Executes the expmod precompile using the GMP library.
///
/// Requires mod not to be zero (having at least one non-zero byte).
void expmod_gmp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept;
}  // namespace evmone::state
