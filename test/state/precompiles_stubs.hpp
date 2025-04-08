// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "precompiles_internal.hpp"

namespace evmone::state
{
using evmc::bytes;
using evmc::bytes_view;

/// Executes the expmod precompile for trivial and pre-defined inputs.
void expmod_stub(bytes_view base, bytes_view exp, bytes_view mod, uint8_t* output) noexcept;
}  // namespace evmone::state
