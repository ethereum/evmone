// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <vector>

namespace evmone::baseline
{
using JumpdestMap = std::vector<bool>;

/// Builds the bitmap of valid JUMPDEST locations in the code.
EVMC_EXPORT JumpdestMap build_jumpdest_map(const uint8_t* code, size_t code_size);

/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter on the given external and initialized state.
evmc_result execute(ExecutionState& state, const JumpdestMap& jumpdest_map) noexcept;
}  // namespace evmone::baseline
