// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "eof.hpp"
#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <memory>
#include <vector>

namespace evmone
{
using evmc::bytes_view;
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
    EOF1Header eof_header;       ///< The EOF header.

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

    CodeAnalysis(bytes_view code, EOF1Header header)
      : executable_code{code}, eof_header{std::move(header)}
    {}
};

/// Analyze the EVM code in preparation for execution.
///
/// For legacy code this builds the map of valid JUMPDESTs.
/// If EOF is enabled, it recognized the EOF code by the code prefix.
///
/// @param code         The reference to the EVM code to be analyzed.
/// @param eof_enabled  Should the EOF code prefix be recognized as EOF code?
EVMC_EXPORT CodeAnalysis analyze(bytes_view code, bool eof_enabled);

/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter on the given external and initialized state.
EVMC_EXPORT evmc_result execute(
    const VM&, int64_t gas_limit, ExecutionState& state, const CodeAnalysis& analysis) noexcept;

}  // namespace baseline
}  // namespace evmone
