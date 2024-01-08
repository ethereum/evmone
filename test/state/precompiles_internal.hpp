// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>

namespace evmone::state
{
struct ExecutionResult
{
    evmc_status_code status_code;
    size_t output_size;
};

struct PrecompileAnalysis
{
    int64_t gas_cost;
    size_t max_output_size;
};

PrecompileAnalysis ecrecover_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis sha256_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis ripemd160_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis identity_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis expmod_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis ecadd_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis ecmul_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis ecpairing_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis blake2bf_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;
PrecompileAnalysis point_evaluation_analyze(evmc::bytes_view input, evmc_revision rev) noexcept;

ExecutionResult ecrecover_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
ExecutionResult identity_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
ExecutionResult ecadd_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
ExecutionResult ecadd_evm_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
ExecutionResult ecmul_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
ExecutionResult ecmul_evm_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
}  // namespace evmone::state
