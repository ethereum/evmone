// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include <evmc/evmc.h>

namespace evmone
{
/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result baseline_execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter on the given external and initialized state.
evmc_result baseline_execute(ExecutionState& state) noexcept;
}  // namespace evmone
