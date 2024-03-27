// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace evmone
{
using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;

struct EOFCodeType
{
    uint8_t inputs;             ///< Number of code inputs.
    uint8_t outputs;            ///< Number of code outputs.
    uint16_t max_stack_height;  ///< Maximum stack height reached in the code.

    EOFCodeType(uint8_t inputs_, uint8_t outputs_, uint16_t max_stack_height_)
      : inputs{inputs_}, outputs{outputs_}, max_stack_height{max_stack_height_}
    {}
};

struct EOF1Header
{
    /// The EOF version, 0 means legacy code.
    uint8_t version = 0;

    /// Size of every code section.
    std::vector<uint16_t> code_sizes;

    /// Offset of every code section from the beginning of the EOF container.
    std::vector<uint16_t> code_offsets;

    /// Size of the data section.
    /// In case of deploy container it is the minimal data size of the container that will be
    /// deployed, taking into account part of data appended at deploy-time (static_aux_data).
    /// In this case the size of data section present in current container can be less than
    /// @data_size.
    uint16_t data_size = 0;
    /// Offset of data container section start.
    uint16_t data_offset = 0;
    /// Size of every container section.
    std::vector<uint16_t> container_sizes;
    /// Offset of every container section start;
    std::vector<uint16_t> container_offsets;

    std::vector<EOFCodeType> types;

    /// A helper to extract reference to a specific code section.
    [[nodiscard]] bytes_view get_code(bytes_view container, size_t code_idx) const noexcept
    {
        assert(code_idx < code_offsets.size());
        return container.substr(code_offsets[code_idx], code_sizes[code_idx]);
    }

    /// A helper to extract reference to the data section.
    [[nodiscard]] bytes_view get_data(bytes_view container) const noexcept
    {
        return container.substr(data_offset);
    }

    /// A helper to extract reference to a specific container section.
    [[nodiscard]] bytes_view get_container(
        bytes_view container, size_t container_idx) const noexcept
    {
        assert(container_idx < container_offsets.size());
        return container.substr(container_offsets[container_idx], container_sizes[container_idx]);
    }

    /// Offset of the data section size value in the header.
    [[nodiscard]] size_t data_size_position() const noexcept;
};

/// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
[[nodiscard]] EVMC_EXPORT bool is_eof_container(bytes_view code) noexcept;

/// Reads the section sizes assuming that container has valid format.
/// (must be true for all EOF contracts on-chain)
[[nodiscard]] EVMC_EXPORT EOF1Header read_valid_eof1_header(bytes_view container);

/// Modifies container by appending aux_data to data section and updating data section size
/// in the header.
bool append_data_section(bytes& container, bytes_view aux_data);

enum class EOFValidationError
{
    success,
    invalid_prefix,
    eof_version_unknown,

    incomplete_section_size,
    incomplete_section_number,
    header_terminator_missing,
    type_section_missing,
    code_section_missing,
    data_section_missing,
    zero_section_size,
    section_headers_not_terminated,
    invalid_section_bodies_size,
    unreachable_code_sections,
    undefined_instruction,
    truncated_instruction,
    invalid_rjump_destination,
    too_many_code_sections,
    invalid_type_section_size,
    invalid_first_section_type,
    invalid_max_stack_height,
    no_terminating_instruction,
    stack_height_mismatch,
    stack_higher_than_outputs_required,
    max_stack_height_above_limit,
    inputs_outputs_num_above_limit,
    unreachable_instructions,
    stack_underflow,
    stack_overflow,
    invalid_code_section_index,
    invalid_dataloadn_index,
    jumpf_destination_incompatible_outputs,
    invalid_non_returning_flag,
    callf_to_non_returning_function,
    too_many_container_sections,
    invalid_container_section_index,
    eofcreate_with_truncated_container,

    impossible,
};

/// Determines the EOF version of the container by inspecting container's EOF prefix.
/// If the prefix is missing or invalid, 0 is returned meaning legacy code.
[[nodiscard]] uint8_t get_eof_version(bytes_view container) noexcept;

/// Validates whether given container is a valid EOF according to the rules of given revision.
[[nodiscard]] EVMC_EXPORT EOFValidationError validate_eof(
    evmc_revision rev, bytes_view container) noexcept;

/// Returns the error message corresponding to an error code.
[[nodiscard]] EVMC_EXPORT std::string_view get_error_message(EOFValidationError err) noexcept;

/// Output operator for EOFValidationError.
EVMC_EXPORT std::ostream& operator<<(std::ostream& os, EOFValidationError err) noexcept;

/// Loads big endian int16_t from data. Unsafe.
/// TODO: Move it to intx
inline int16_t read_int16_be(auto it) noexcept
{
    const uint8_t h = *it++;
    const uint8_t l = *it;
    return static_cast<int16_t>((h << 8) | l);
}

/// Loads big endian uint16_t from data. Unsafe.
/// TODO: Move it to intx
inline uint16_t read_uint16_be(auto it) noexcept
{
    const uint8_t h = *it++;
    const uint8_t l = *it;
    return static_cast<uint16_t>((h << 8) | l);
}

}  // namespace evmone
