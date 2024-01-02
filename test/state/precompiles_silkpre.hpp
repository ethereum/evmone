// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "precompiles_internal.hpp"

namespace evmone::state
{
ExecutionResult silkpre_ecrecover_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_sha256_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_ripemd160_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_expmod_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_ecadd_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_ecmul_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_ecpairing_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;

ExecutionResult silkpre_blake2bf_execute(
    const uint8_t* input, size_t input_size, uint8_t* output_buf, size_t max_output_size) noexcept;
}  // namespace evmone::state
