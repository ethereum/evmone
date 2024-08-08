// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "precompiles_internal.hpp"

namespace evmone::state
{
ExecutionResult expmod_stub(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t max_output_size) noexcept;
}  // namespace evmone::state
