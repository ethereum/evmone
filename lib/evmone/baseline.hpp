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

struct BitsetSpan
{
    using word_type = uint64_t;
    static constexpr size_t WORD_BITS = sizeof(word_type) * 8;

    word_type* m_array = nullptr;

    explicit BitsetSpan(word_type* array) noexcept : m_array{array} {}

    [[nodiscard]] bool test(size_t index) const noexcept
    {
        const auto word_index = index / WORD_BITS;
        const auto bit_index = index % WORD_BITS;
        const auto bit_mask = word_type{1} << bit_index;
        return (m_array[word_index] & bit_mask) != 0;
    }

    void set(size_t index) noexcept
    {
        const auto word_index = index / WORD_BITS;
        const auto bit_index = index % WORD_BITS;
        const auto bit_mask = word_type{1} << bit_index;
        m_array[word_index] |= bit_mask;
    }
};

namespace baseline
{
class CodeAnalysis
{
private:
    bytes_view m_raw_code;         ///< Unmodified full code.
    bytes_view m_executable_code;  ///< Executable code section.
    EOF1Header m_eof_header;       ///< The EOF header.

    /// Padded code for faster legacy code execution.
    /// If not nullptr the executable_code must point to it.
    std::unique_ptr<uint8_t[]> m_padded_code;

    std::unique_ptr<BitsetSpan::word_type[]> m_jumpdest_bitset;

public:
    /// Constructor for legacy code.
    CodeAnalysis(std::unique_ptr<uint8_t[]> padded_code, size_t code_size,
        std::unique_ptr<BitsetSpan::word_type[]> map)
      : m_raw_code{padded_code.get(), code_size},
        m_executable_code{padded_code.get(), code_size},
        m_padded_code{std::move(padded_code)},
        m_jumpdest_bitset{std::move(map)}
    {}

    /// Constructor for EOF.
    CodeAnalysis(bytes_view container, bytes_view executable_code, EOF1Header header)
      : m_raw_code{container}, m_executable_code(executable_code), m_eof_header{std::move(header)}
    {}

    /// The raw code as stored in accounts or passes as initcode. For EOF this is full container.
    [[nodiscard]] bytes_view raw_code() const noexcept { return m_raw_code; }

    /// The pre-processed executable code. This is where interpreter should start execution.
    [[nodiscard]] bytes_view executable_code() const noexcept { return m_executable_code; }

    /// Reference to the EOF header.
    [[nodiscard]] const EOF1Header& eof_header() const noexcept { return m_eof_header; }

    /// Reference to the EOF data section. May be empty.
    [[nodiscard]] bytes_view eof_data() const noexcept { return m_eof_header.get_data(m_raw_code); }

    /// Check if given position is valid jump destination. Use only for legacy code.
    [[nodiscard]] bool check_jumpdest(uint64_t position) const noexcept
    {
        if (position >= m_raw_code.size())
            return false;
        return BitsetSpan{m_jumpdest_bitset.get()}.test(static_cast<size_t>(position));
    }
};

/// Analyze the EVM code in preparation for execution.
///
/// For legacy code this builds the map of valid JUMPDESTs.
/// If EOF is enabled, it recognizes the EOF code by the code prefix.
///
/// @param code         The reference to the EVM code to be analyzed.
/// @param eof_enabled  Should the EOF code prefix be recognized as EOF code?
EVMC_EXPORT CodeAnalysis analyze(bytes_view code, bool eof_enabled);

/// Executes in Baseline interpreter using EVMC-compatible parameters.
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

/// Executes in Baseline interpreter with the pre-processed code.
EVMC_EXPORT evmc_result execute(VM&, const evmc_host_interface& host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message& msg, const CodeAnalysis& analysis) noexcept;

}  // namespace baseline
}  // namespace evmone
