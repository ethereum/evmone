// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"

#include <array>
#include <cassert>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC = 0x00;
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
constexpr uint8_t MAX_SECTION = DATA_SECTION;

using EOFSectionHeaders = std::array<uint16_t, MAX_SECTION + 1>;

std::pair<EOFSectionHeaders, EOFValidationError> validate_eof_headers(bytes_view container) noexcept
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
    auto it = container.begin() + 1 + sizeof(MAGIC) + 1;  // FORMAT + MAGIC + VERSION
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
                    return {{}, EOFValidationError::code_section_missing};
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_headers[CODE_SECTION] == 0)
                    return {{}, EOFValidationError::code_section_missing};
                if (section_headers[DATA_SECTION] != 0)
                    return {{}, EOFValidationError::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (section_headers[CODE_SECTION] != 0)
                    return {{}, EOFValidationError::multiple_code_sections};
                state = State::section_size;
                break;
            default:
                return {{}, EOFValidationError::unknown_section_id};
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it++;
            if (it == container_end)
                return {{}, EOFValidationError::incomplete_section_size};
            const auto size_lo = *it++;
            const auto section_size = static_cast<uint16_t>((size_hi << 8) | size_lo);
            if (section_size == 0)
                return {{}, EOFValidationError::zero_section_size};

            section_headers[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return {{}, EOFValidationError::impossible};
        }
    }

    if (state != State::terminated)
        return {{}, EOFValidationError::section_headers_not_terminated};

    const auto section_bodies_size = section_headers[CODE_SECTION] + section_headers[DATA_SECTION];
    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return {{}, EOFValidationError::invalid_section_bodies_size};

    return {section_headers, EOFValidationError::success};
}

std::pair<EOF1Header, EOFValidationError> validate_eof1(bytes_view container) noexcept
{
    const auto [section_headers, error] = validate_eof_headers(container);
    if (error != EOFValidationError::success)
        return {{}, error};

    const EOF1Header header{section_headers[CODE_SECTION], section_headers[DATA_SECTION]};
    return {header, EOFValidationError::success};
}
}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return 7;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + TERMINATOR
    else
        return 10;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + SECTION_ID + SIZE + TERMINATOR
}

bool is_eof_code(bytes_view code) noexcept
{
    return code.size() > 1 && code[0] == FORMAT && code[1] == MAGIC;
}

EOF1Header read_valid_eof1_header(bytes_view::const_iterator code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = 4;  // FORMAT + MAGIC + VERSION + CODE_SECTION_ID
    header.code_size =
        static_cast<uint16_t>((code[code_size_offset] << 8) | code[code_size_offset + 1]);
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size =
            static_cast<uint16_t>((code[data_size_offset] << 8) | code[data_size_offset + 1]);
    }
    return header;
}

uint8_t get_eof_version(bytes_view container) noexcept
{
    return (container.size() >= 3 && container[0] == FORMAT && container[1] == MAGIC) ?
               container[2] :
               0;
}

EOFValidationError validate_eof(evmc_revision rev, bytes_view container) noexcept
{
    if (!is_eof_code(container))
        return EOFValidationError::invalid_prefix;

    const auto version = get_eof_version(container);

    if (version == 1)
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationError::eof_version_unknown;
        return validate_eof1(container).second;
    }
    else
        return EOFValidationError::eof_version_unknown;
}
}  // namespace evmone
