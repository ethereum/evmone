// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <memory>
#include <string_view>
#include <vector>

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

class ExecutionState;
class VM;

namespace baseline
{
class CodeAnalysis
{
public:
    using JumpdestMap = std::vector<bool>;

    bytes_view executable_code;  ///< Executable code section.
    JumpdestMap jumpdest_map;    ///< Map of valid jump destinations.
    uint8_t eof_version = 0;     ///< The EOF version, 0 means legacy code.

private:
    /// Padded code for faster legacy code execution.
    /// If not nullptr the executable_code must point to it.
    std::unique_ptr<uint8_t[]> m_padded_code;

public:
    CodeAnalysis(std::unique_ptr<uint8_t[]> padded_code, size_t code_size, JumpdestMap map)
      : executable_code{padded_code.get(), code_size},
        jumpdest_map{std::move(map)},
        m_padded_code{std::move(padded_code)}
    {}

    CodeAnalysis(bytes_view code, JumpdestMap map, uint8_t eof_ver)
      : executable_code{code}, jumpdest_map{std::move(map)}, eof_version{eof_ver}
    {}
};
static_assert(std::is_move_constructible_v<CodeAnalysis>);
static_assert(std::is_move_assignable_v<CodeAnalysis>);
static_assert(!std::is_copy_constructible_v<CodeAnalysis>);
static_assert(!std::is_copy_assignable_v<CodeAnalysis>);

/// Analyze the code to build the bitmap of valid JUMPDEST locations.
EVMC_EXPORT CodeAnalysis analyze(evmc_revision rev, bytes_view code);

/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter on the given external and initialized state.
EVMC_EXPORT evmc_result execute(
    const VM&, ExecutionState& state, const CodeAnalysis& analysis) noexcept;

}  // namespace baseline
}  // namespace evmone
