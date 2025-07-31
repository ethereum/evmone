// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "precompiles_internal.hpp"
#include <cstdint>
#include <span>

namespace evmone::state
{
/// Executes the expmod precompile using the GMP library.
///
/// Requires mod not to be zero (having at least one non-zero byte).
void expmod_gmp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept;

ExecutionResult expmod_execute_gmp(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
}  // namespace evmone::state
