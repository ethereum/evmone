// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"

#include <array>
#include <cassert>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC[] = {0xca, 0xfe};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return std::size(MAGIC) + 6;
    else
        return std::size(MAGIC) + 9;
}

size_t EOF1Header::code_end() const noexcept
{
    assert(code_size != 0);

    return code_begin() + static_cast<size_t>(code_size);
}

bool is_eof_code(const uint8_t* code, size_t code_size) noexcept
{
    static_assert(std::size(MAGIC) == 2);
    return code_size > 2 && code[0] == FORMAT && code[1] == MAGIC[0] && code[2] == MAGIC[1];
}

EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = std::size(MAGIC) + 3;
    header.code_size = (code[code_size_offset] << 8) | code[code_size_offset + 1];
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = (code[data_size_offset] << 8) | code[data_size_offset + 1];
    }
    return header;
}

uint8_t get_eof_version(const uint8_t* code, size_t code_size) noexcept
{
    return (code_size >= 4 && code[0] == FORMAT && code[1] == MAGIC[0] && code[2] == MAGIC[1]) ?
               code[3] :
               0;
}

std::pair<EOF1Header, EOFValidationErrror> validate_eof1(
    const uint8_t* code, size_t code_size) noexcept
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    int section_sizes[3] = {0, 0, 0};
    const auto* code_end = code + code_size;
    auto it = code + sizeof(MAGIC) + 2;  // FORMAT + MAGIC + VERSION
    while (it != code_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it;
            switch (section_id)
            {
            case TERMINATOR:
                if (section_sizes[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_sizes[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                if (section_sizes[DATA_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (section_sizes[CODE_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_code_sections};
                state = State::section_size;
                break;
            default:
                return {{}, EOFValidationErrror::unknown_section_id};
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it;
            ++it;
            if (it == code_end)
                return {{}, EOFValidationErrror::incomplete_section_size};
            const auto size_lo = *it;
            const auto section_size = (size_hi << 8) | size_lo;
            if (section_size == 0)
                return {{}, EOFValidationErrror::zero_section_size};

            section_sizes[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return {{}, EOFValidationErrror::impossible};
        }

        ++it;
    }

    if (state != State::terminated)
        return {{}, EOFValidationErrror::section_headers_not_terminated};

    const auto section_bodies_size = section_sizes[CODE_SECTION] + section_sizes[DATA_SECTION];
    const auto remaining_code_size = code_end - it;
    if (section_bodies_size != remaining_code_size)
        return {{}, EOFValidationErrror::invalid_section_bodies_size};

    return {{section_sizes[0], section_sizes[1]}, EOFValidationErrror::success};
}

EOFValidationErrror validate_eof(evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    if (!is_eof_code(code, code_size))
        return EOFValidationErrror::invalid_prefix;

    const auto version = get_eof_version(code, code_size);

    switch (version)
    {
    default:
        return EOFValidationErrror::eof_version_unknown;
    case 1:
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationErrror::eof_version_unknown;
        return validate_eof1(code, code_size).second;
    }
    }
}


}  // namespace evmone
