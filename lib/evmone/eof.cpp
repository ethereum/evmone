// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "instructions_traits.hpp"

#include <array>
#include <cassert>
#include <limits>
#include <variant>

namespace evmone
{
namespace
{
constexpr uint8_t MAGIC[] = {0xef, 0x00};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
constexpr uint8_t MAX_SECTION = DATA_SECTION;

using EOFSectionHeaders = std::array<uint16_t, MAX_SECTION + 1>;

std::variant<EOFSectionHeaders, EOFValidationError> validate_eof_headers(
    bytes_view container) noexcept
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    EOFSectionHeaders section_headers{};
    const auto container_end = container.end();
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    while (it != container_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it++;
            switch (section_id)
            {
            case TERMINATOR:
                if (section_headers[CODE_SECTION] == 0)
                    return EOFValidationError::code_section_missing;
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_headers[CODE_SECTION] == 0)
                    return EOFValidationError::code_section_missing;
                if (section_headers[DATA_SECTION] != 0)
                    return EOFValidationError::multiple_data_sections;
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (section_headers[CODE_SECTION] != 0)
                    return EOFValidationError::multiple_code_sections;
                state = State::section_size;
                break;
            default:
                return EOFValidationError::unknown_section_id;
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it++;
            if (it == container_end)
                return EOFValidationError::incomplete_section_size;
            const auto size_lo = *it++;
            const auto section_size = static_cast<uint16_t>((size_hi << 8) | size_lo);
            if (section_size == 0)
                return EOFValidationError::zero_section_size;

            section_headers[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return EOFValidationError::impossible;
        }
    }

    if (state != State::terminated)
        return EOFValidationError::section_headers_not_terminated;

    const auto section_bodies_size = section_headers[CODE_SECTION] + section_headers[DATA_SECTION];
    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return EOFValidationError::invalid_section_bodies_size;

    return section_headers;
}

EOFValidationError validate_instructions(evmc_revision rev, bytes_view code) noexcept
{
    assert(!code.empty());  // guaranteed by EOF headers validation

    size_t i = 0;
    uint8_t op = code[0];
    while (i < code.size())
    {
        op = code[i];
        const auto& since = instr::traits[op].since;
        if (!since.has_value() || *since > rev)
            return EOFValidationError::undefined_instruction;

        i += instr::traits[op].immediate_size;
        ++i;
    }

    if (!instr::traits[op].is_terminating)
        return EOFValidationError::missing_terminating_instruction;

    return EOFValidationError::success;
}

std::variant<EOF1Header, EOFValidationError> validate_eof1(
    evmc_revision rev, bytes_view container) noexcept
{
    const auto section_headers_or_error = validate_eof_headers(container);
    if (const auto* error = std::get_if<EOFValidationError>(&section_headers_or_error))
        return *error;

    const auto& section_headers = std::get<EOFSectionHeaders>(section_headers_or_error);
    EOF1Header header{section_headers[CODE_SECTION], section_headers[DATA_SECTION]};

    const auto error_instr =
        validate_instructions(rev, {&container[header.code_begin()], header.code_size});
    if (error_instr != EOFValidationError::success)
        return error_instr;

    return header;
}

}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return 7;  // MAGIC + VERSION + SECTION_ID + SIZE + TERMINATOR
    else
        return 10;  // MAGIC + VERSION + SECTION_ID + SIZE + SECTION_ID + SIZE + TERMINATOR
}

bool is_eof_container(bytes_view container) noexcept
{
    return container.size() > 1 && container[0] == MAGIC[0] && container[1] == MAGIC[1];
}

EOF1Header read_valid_eof1_header(bytes_view container) noexcept
{
    EOF1Header header;
    const auto code_size_offset = 4;  // MAGIC + VERSION + CODE_SECTION_ID
    header.code_size =
        static_cast<uint16_t>((container[code_size_offset] << 8) | container[code_size_offset + 1]);
    if (container[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = static_cast<uint16_t>(
            (container[data_size_offset] << 8) | container[data_size_offset + 1]);
    }
    return header;
}

uint8_t get_eof_version(bytes_view container) noexcept
{
    return (container.size() >= 3 && container[0] == MAGIC[0] && container[1] == MAGIC[1]) ?
               container[2] :
               0;
}

EOFValidationError validate_eof(evmc_revision rev, bytes_view container) noexcept
{
    if (!is_eof_container(container))
        return EOFValidationError::invalid_prefix;

    const auto version = get_eof_version(container);

    if (version == 1)
    {
        if (rev < EVMC_CANCUN)
            return EOFValidationError::eof_version_unknown;

        const auto header_or_error = validate_eof1(rev, container);
        if (const auto* error = std::get_if<EOFValidationError>(&header_or_error))
            return *error;
        else
            return EOFValidationError::success;
    }
    else
        return EOFValidationError::eof_version_unknown;
}

std::string_view get_error_message(EOFValidationError err) noexcept
{
    switch (err)
    {
    case EOFValidationError::success:
        return "success";
    case EOFValidationError::starts_with_format:
        return "starts_with_format";
    case EOFValidationError::invalid_prefix:
        return "invalid_prefix";
    case EOFValidationError::eof_version_mismatch:
        return "eof_version_mismatch";
    case EOFValidationError::eof_version_unknown:
        return "eof_version_unknown";
    case EOFValidationError::incomplete_section_size:
        return "incomplete_section_size";
    case EOFValidationError::code_section_missing:
        return "code_section_missing";
    case EOFValidationError::multiple_code_sections:
        return "multiple_code_sections";
    case EOFValidationError::multiple_data_sections:
        return "multiple_data_sections";
    case EOFValidationError::unknown_section_id:
        return "unknown_section_id";
    case EOFValidationError::zero_section_size:
        return "zero_section_size";
    case EOFValidationError::section_headers_not_terminated:
        return "section_headers_not_terminated";
    case EOFValidationError::invalid_section_bodies_size:
        return "invalid_section_bodies_size";
    case EOFValidationError::undefined_instruction:
        return "undefined_instruction";
    case EOFValidationError::missing_terminating_instruction:
        return "missing_terminating_instruction";
    case EOFValidationError::impossible:
        return "impossible";
    }
    return "<unknown>";
}
}  // namespace evmone
