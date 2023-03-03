// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

#include <array>
#include <cassert>
#include <limits>
#include <numeric>
#include <span>
#include <variant>
#include <vector>

namespace evmone
{
namespace
{
constexpr uint8_t MAGIC[] = {0xef, 0x00};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t TYPE_SECTION = 0x01;
constexpr uint8_t CODE_SECTION = 0x02;
constexpr uint8_t DATA_SECTION = 0x03;
constexpr uint8_t MAX_SECTION = DATA_SECTION;
constexpr auto CODE_SECTION_NUMBER_LIMIT = 1024;
constexpr auto MAX_STACK_HEIGHT = 0x0400;
constexpr auto OUTPUTS_INPUTS_NUMBER_LIMIT = 0x7F;

using EOFSectionHeaders = std::array<std::vector<uint16_t>, MAX_SECTION + 1>;

size_t eof_header_size(const EOFSectionHeaders& headers) noexcept
{
    const auto non_code_section_count = 2;  // type section and data section
    const auto code_section_count = headers[CODE_SECTION].size();

    constexpr auto non_code_section_header_size = 3;  // (SECTION_ID + SIZE) per each section
    constexpr auto code_section_size_size = 2;

    return sizeof(MAGIC) + 1 +  // 1 version byte
           non_code_section_count * non_code_section_header_size + sizeof(CODE_SECTION) + 2 +
           code_section_count * code_section_size_size + sizeof(TERMINATOR);
}

EOFValidationError get_section_missing_error(uint8_t section_id) noexcept
{
    return static_cast<EOFValidationError>(
        static_cast<uint8_t>(EOFValidationError::header_terminator_missing) + section_id);
}

std::variant<EOFSectionHeaders, EOFValidationError> validate_eof_headers(bytes_view container)
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    uint16_t section_num = 0;
    EOFSectionHeaders section_headers{};
    const auto container_end = container.end();
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    uint8_t expected_section_id = TYPE_SECTION;
    while (it != container_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it++;

            if (section_id != expected_section_id)
                return get_section_missing_error(expected_section_id);

            switch (section_id)
            {
            case TERMINATOR:
                state = State::terminated;
                break;
            case TYPE_SECTION:
                expected_section_id = CODE_SECTION;
                state = State::section_size;
                break;
            case CODE_SECTION:
            {
                if (it >= container_end - 1)
                    return EOFValidationError::incomplete_section_number;
                section_num = read_uint16_be(it);
                it += 2;
                if (section_num == 0)
                    return EOFValidationError::zero_section_size;
                if (section_num > CODE_SECTION_NUMBER_LIMIT)
                    return EOFValidationError::too_many_code_sections;
                expected_section_id = DATA_SECTION;
                state = State::section_size;
                break;
            }
            case DATA_SECTION:
                expected_section_id = TERMINATOR;
                state = State::section_size;
                break;
            default:
                assert(false);
            }
            break;
        }
        case State::section_size:
        {
            if (section_id == CODE_SECTION)
            {
                assert(section_num > 0);  // Guaranteed by previous validation step.
                for (size_t i = 0; i < section_num; ++i)
                {
                    if (it >= container_end - 1)
                        return EOFValidationError::incomplete_section_size;
                    const auto section_size = read_uint16_be(it);
                    it += 2;
                    if (section_size == 0)
                        return EOFValidationError::zero_section_size;

                    section_headers[section_id].emplace_back(section_size);
                }
            }
            else  // TYPES_SECTION or DATA_SECTION
            {
                if (it >= container_end - 1)
                    return EOFValidationError::incomplete_section_size;
                const auto section_size = read_uint16_be(it);
                it += 2;
                if (section_size == 0 && section_id != DATA_SECTION)
                    return EOFValidationError::zero_section_size;

                section_headers[section_id].emplace_back(section_size);
            }

            state = State::section_id;
            break;
        }
        case State::terminated:
            return EOFValidationError::impossible;
        }
    }

    if (state != State::terminated)
        return EOFValidationError::section_headers_not_terminated;

    const auto section_bodies_size = section_headers[TYPE_SECTION].front() +
                                     std::accumulate(section_headers[CODE_SECTION].begin(),
                                         section_headers[CODE_SECTION].end(), 0) +
                                     section_headers[DATA_SECTION].front();
    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return EOFValidationError::invalid_section_bodies_size;

    if (section_headers[TYPE_SECTION][0] != section_headers[CODE_SECTION].size() * 4)
        return EOFValidationError::invalid_type_section_size;

    return section_headers;
}

std::variant<std::vector<EOFCodeType>, EOFValidationError> validate_types(
    bytes_view container, size_t header_size, uint16_t type_section_size) noexcept
{
    assert(!container.empty());  // guaranteed by EOF headers validation

    std::vector<EOFCodeType> types;

    // guaranteed by EOF headers validation
    assert(header_size + type_section_size < container.size());

    for (auto offset = header_size; offset < header_size + type_section_size; offset += 4)
    {
        types.emplace_back(
            container[offset], container[offset + 1], read_uint16_be(&container[offset + 2]));
    }

    // check 1st section is (0, 0)
    if (types[0].inputs != 0 || types[0].outputs != 0)
        return EOFValidationError::invalid_first_section_type;

    for (const auto& t : types)
    {
        if (t.outputs > OUTPUTS_INPUTS_NUMBER_LIMIT || t.inputs > OUTPUTS_INPUTS_NUMBER_LIMIT)
            return EOFValidationError::inputs_outputs_num_above_limit;

        if (t.max_stack_height > MAX_STACK_HEIGHT)
            return EOFValidationError::max_stack_height_above_limit;
    }

    return types;
}

EOFValidationError validate_instructions(evmc_revision rev, bytes_view code) noexcept
{
    assert(!code.empty());  // guaranteed by EOF headers validation

    const auto& cost_table = baseline::get_baseline_cost_table(rev, 1);

    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (cost_table[op] == instr::undefined)
            return EOFValidationError::undefined_instruction;

        i += instr::traits[op].immediate_size;
        if (i >= code.size())
            return EOFValidationError::truncated_instruction;
    }

    return EOFValidationError::success;
}

std::variant<EOF1Header, EOFValidationError> validate_eof1(
    evmc_revision rev, bytes_view container) noexcept
{
    const auto section_headers_or_error = validate_eof_headers(container);
    if (const auto* error = std::get_if<EOFValidationError>(&section_headers_or_error))
        return *error;

    const auto& section_headers = std::get<EOFSectionHeaders>(section_headers_or_error);
    const auto& code_sizes = section_headers[CODE_SECTION];
    const auto data_size = section_headers[DATA_SECTION][0];

    const auto header_size = eof_header_size(section_headers);

    const auto types_or_error =
        validate_types(container, header_size, section_headers[TYPE_SECTION].front());
    if (const auto* error = std::get_if<EOFValidationError>(&types_or_error))
        return *error;
    const auto& types = std::get<std::vector<EOFCodeType>>(types_or_error);

    std::vector<uint16_t> code_offsets;
    const auto type_section_size = section_headers[TYPE_SECTION][0];
    auto offset = header_size + type_section_size;
    for (const auto code_size : code_sizes)
    {
        assert(offset <= std::numeric_limits<uint16_t>::max());
        code_offsets.emplace_back(static_cast<uint16_t>(offset));
        offset += code_size;
    }

    EOF1Header header{code_sizes, code_offsets, data_size, types};

    for (size_t code_idx = 0; code_idx < header.code_sizes.size(); ++code_idx)
    {
        const auto error_instr = validate_instructions(rev, header.get_code(container, code_idx));
        if (error_instr != EOFValidationError::success)
            return error_instr;
    }

    return header;
}

}  // namespace

bool is_eof_container(bytes_view container) noexcept
{
    return container.size() > 1 && container[0] == MAGIC[0] && container[1] == MAGIC[1];
}

/// This function expects the prefix and version to be valid, as it ignores it.
EOF1Header read_valid_eof1_header(bytes_view container)
{
    EOFSectionHeaders section_headers;
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    while (*it != TERMINATOR)
    {
        const auto section_id = *it++;
        if (section_id == CODE_SECTION)
        {
            const auto code_section_num = read_uint16_be(it);
            it += 2;
            for (uint16_t i = 0; i < code_section_num; ++i)
            {
                const auto section_size = read_uint16_be(it);
                it += 2;
                section_headers[section_id].emplace_back(section_size);
            }
        }
        else
        {
            const auto section_size = read_uint16_be(it);
            it += 2;
            section_headers[section_id].emplace_back(section_size);
        }
    }
    const auto header_size = eof_header_size(section_headers);

    EOF1Header header;

    for (auto type_offset = header_size;
         type_offset < header_size + section_headers[TYPE_SECTION][0]; type_offset += 4)
    {
        header.types.emplace_back(container[type_offset], container[type_offset + 1],
            read_uint16_be(&container[type_offset + 2]));
    }

    header.code_sizes = section_headers[CODE_SECTION];
    auto code_offset = header_size + section_headers[TYPE_SECTION][0];
    for (const auto code_size : header.code_sizes)
    {
        assert(code_offset <= std::numeric_limits<uint16_t>::max());
        header.code_offsets.emplace_back(static_cast<uint16_t>(code_offset));
        code_offset += code_size;
    }

    header.data_size = section_headers[DATA_SECTION][0];

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
    case EOFValidationError::incomplete_section_number:
        return "incomplete_section_number";
    case EOFValidationError::header_terminator_missing:
        return "header_terminator_missing";
    case EOFValidationError::type_section_missing:
        return "type_section_missing";
    case EOFValidationError::code_section_missing:
        return "code_section_missing";
    case EOFValidationError::data_section_missing:
        return "data_section_missing";
    case EOFValidationError::zero_section_size:
        return "zero_section_size";
    case EOFValidationError::section_headers_not_terminated:
        return "section_headers_not_terminated";
    case EOFValidationError::invalid_section_bodies_size:
        return "invalid_section_bodies_size";
    case EOFValidationError::undefined_instruction:
        return "undefined_instruction";
    case EOFValidationError::truncated_instruction:
        return "truncated_instruction";
    case EOFValidationError::too_many_code_sections:
        return "too_many_code_sections";
    case EOFValidationError::invalid_type_section_size:
        return "invalid_type_section_size";
    case EOFValidationError::invalid_first_section_type:
        return "invalid_first_section_type";
    case EOFValidationError::invalid_max_stack_height:
        return "invalid_max_stack_height";
    case EOFValidationError::max_stack_height_above_limit:
        return "max_stack_height_above_limit";
    case EOFValidationError::inputs_outputs_num_above_limit:
        return "inputs_outputs_num_above_limit";
    case EOFValidationError::impossible:
        return "impossible";
    }
    return "<unknown>";
}
}  // namespace evmone
