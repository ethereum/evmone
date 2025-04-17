// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>

namespace evmone::state
{
using evmc::bytes_view;

/// Executes the expmod precompile using the GMP library.
///
/// Requires mod not to be zero (having at least one non-zero byte).
void expmod_gmp(bytes_view base, bytes_view exp, bytes_view mod, uint8_t* output) noexcept;
}  // namespace evmone::state
