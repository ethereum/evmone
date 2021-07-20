// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <memory>
#include <vector>

namespace evmone
{
struct EOF1Header;
struct ExecutionState;
class VM;

namespace baseline
{
struct CodeAnalysis
{
    using JumpdestMap = std::vector<bool>;
    using TableList = std::vector<std::vector<int16_t>>;

    const std::unique_ptr<uint8_t[]> padded_code;
    const JumpdestMap jumpdest_map;
    size_t code_begin = 0;
    size_t code_end = 0;
    TableList tables;
};

/// Analyze the code to build the bitmap of valid JUMPDEST locations.
EVMC_EXPORT CodeAnalysis analyze(evmc_revision rev, const uint8_t* code, size_t code_size);

/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter on the given external and initialized state.
EVMC_EXPORT evmc_result execute(
    const VM&, ExecutionState& state, const CodeAnalysis& analysis) noexcept;

}  // namespace baseline
}  // namespace evmone
