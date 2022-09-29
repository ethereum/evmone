// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

struct EOF1Header
{
    /// Size of every code section.
    std::vector<uint16_t> code_sizes;
    /// Offset of every code section start;
    std::vector<uint16_t> code_offsets;
    uint16_t data_size = 0;

    std::vector<std::pair<uint8_t, uint8_t>> types;

    /// Returns offset of code section start.
    [[nodiscard]] EVMC_EXPORT size_t code_begin(size_t index) const noexcept;
    [[nodiscard]] EVMC_EXPORT size_t code_end(size_t index) const noexcept;
};

/// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
[[nodiscard]] EVMC_EXPORT bool is_eof_code(bytes_view code) noexcept;

/// Reads the section sizes assuming that container has valid format.
/// (must be true for all EOF contracts on-chain)
[[nodiscard]] EVMC_EXPORT EOF1Header read_valid_eof1_header(bytes_view container);

enum class EOFValidationError
{
    success,
    starts_with_format,
    invalid_prefix,
    eof_version_mismatch,
    eof_version_unknown,

    incomplete_section_size,
    code_section_missing,
    multiple_data_sections,
    unknown_section_id,
    zero_section_size,
    section_headers_not_terminated,
    invalid_section_bodies_size,
    undefined_instruction,
    missing_terminating_instruction,
    invalid_rjump_destination,
    code_section_before_type_section,
    multiple_type_sections,
    mandatory_type_section_missing,
    too_many_code_sections,
    data_section_before_code_section,
    invalid_type_section_size,
    invalid_first_section_type,

    impossible,
};

/// Determines the EOF version of the container by inspecting container's EOF prefix.
/// If the prefix is missing or invalid, 0 is returned meaning legacy code.
[[nodiscard]] uint8_t get_eof_version(bytes_view container) noexcept;

/// Validates whether given container is a valid EOF according to the rules of given revision.
[[nodiscard]] EVMC_EXPORT EOFValidationError validate_eof(
    evmc_revision rev, bytes_view container) noexcept;
}  // namespace evmone
