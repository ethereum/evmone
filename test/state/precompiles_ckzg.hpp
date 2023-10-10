// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "precompiles.hpp"

namespace evmone::state
{
ExecutionResult ckzg_point_evaluation_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;
}  // namespace evmone::state
