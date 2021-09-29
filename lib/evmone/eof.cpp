// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include <evmc/instructions.h>

#include <evmc/instructions.h>
#include <array>
#include <cassert>
#include <limits>
#include <numeric>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC[] = {0xca, 0xfe};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
constexpr uint8_t TABLE_SECTION = 0x03;
constexpr uint8_t MAX_SECTION = TABLE_SECTION;

using EOFSectionHeaders = std::array<std::vector<size_t>, MAX_SECTION + 1>;

std::pair<EOFSectionHeaders, EOFValidationErrror> validate_eof_headers(
    uint8_t version, const uint8_t* code, size_t code_size) noexcept
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    EOFSectionHeaders section_headers;
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
                if (section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationErrror::code_section_missing};
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationErrror::code_section_missing};
                if (!section_headers[DATA_SECTION].empty())
                    return {{}, EOFValidationErrror::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (!section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationErrror::multiple_code_sections};
                state = State::section_size;
                break;
            case TABLE_SECTION:
                if (version < 2)
                    return {{}, EOFValidationErrror::unknown_section_id};
                if (section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationErrror::code_section_missing};
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
            const auto section_size = static_cast<size_t>(size_hi << 8) | size_lo;
            if (section_size == 0)
                return {{}, EOFValidationErrror::zero_section_size};
            if (section_id == TABLE_SECTION && section_size % 2 != 0)
                return {{}, EOFValidationErrror::odd_table_section_size};

            section_headers[section_id].push_back(section_size);
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

    auto section_bodies_size = section_headers[CODE_SECTION][0];
    if (!section_headers[DATA_SECTION].empty())
        section_bodies_size += section_headers[DATA_SECTION][0];
    section_bodies_size += std::accumulate(section_headers[TABLE_SECTION].begin(),
        section_headers[TABLE_SECTION].end(), static_cast<size_t>(0));
    const auto remaining_code_size = static_cast<size_t>(code_end - it);
    if (section_bodies_size != remaining_code_size)
        return {{}, EOFValidationErrror::invalid_section_bodies_size};

    return {section_headers, EOFValidationErrror::success};
}

EOFValidationErrror validate_instructions(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    const auto* names = evmc_get_instruction_names_table(rev);

    size_t i = 0;
    while (i < code_size)
    {
        const auto op = code[i];
        if (names[op] == nullptr)
            return EOFValidationErrror::undefined_instruction;

        // TODO use instruction traits table to get number of immediates instead
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        ++i;
    }
    if (i != code_size)
        return EOFValidationErrror::truncated_push;

    return EOFValidationErrror::success;
}

EOFValidationErrror validate_rjump_instructions(const EOF2Header& header,
    std::vector<std::vector<int16_t>> tables, const uint8_t* code) noexcept
{
    // Collect jumpdest locations and immediate locations
    size_t i = header.code_begin();
    // TODO change to set / unordered_set?
    std::vector<size_t> jumpdests;
    std::vector<bool> immediate_map(header.code_end());
    while (i < header.code_end())
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation in
                                                  // baseline.cpp).
        {
            const auto n = op - size_t{OP_PUSH1 - 1};
            std::fill_n(immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, n, true);
            i += n;  // Skip PUSH data.
        }
        else if (op == OP_RJUMP || op == OP_RJUMPI)
        {
            // TODO not needed, should be checked in validate_instructions
            if (i + 2 >= header.code_end())
                return EOFValidationErrror::missing_immediate_argument;
            const auto offset_hi = code[i + 1];
            const auto offset_lo = code[i + 2];
            const auto offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
            const auto jumpdest = static_cast<int32_t>(i) + 3 + offset;
            if (jumpdest < static_cast<int32_t>(header.code_begin()) ||
                jumpdest >= static_cast<int32_t>(header.code_end()))
                return EOFValidationErrror::invalid_rjump_destination;
            jumpdests.push_back(static_cast<size_t>(jumpdest));
            immediate_map[i + 1] = true;
            immediate_map[i + 2] = true;
            i += 2;
        }
        else if (op == OP_RJUMPTABLE)
        {
            // TODO not needed, should be checked in validate_instructions
            if (i + 2 >= header.code_end())
                return EOFValidationErrror::missing_immediate_argument;
            const auto table_index_hi = code[i + 1];
            const auto table_index_lo = code[i + 2];
            const auto table_index = static_cast<uint16_t>((table_index_hi << 8) + table_index_lo);
            if (table_index >= tables.size())
                return EOFValidationErrror::invalid_rjump_table_index;

            for (const auto offset : tables[table_index])
            {
                const auto jumpdest = static_cast<int32_t>(i) + 3 + offset;
                if (jumpdest < static_cast<int32_t>(header.code_begin()) ||
                    jumpdest >= static_cast<int32_t>(header.code_end()))
                    return EOFValidationErrror::invalid_rjump_destination;
                jumpdests.push_back(static_cast<size_t>(jumpdest));
            }

            immediate_map[i + 1] = true;
            immediate_map[i + 2] = true;
            i += 2;
        }
        ++i;
    }

    // Check jumpdest locations against immediate locations.
    for (const auto jumpdest : jumpdests)
        if (immediate_map[jumpdest])
            return EOFValidationErrror::invalid_rjump_destination;

    return EOFValidationErrror::success;
}
}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return std::size(MAGIC) + 6;
    else
        return std::size(MAGIC) + 9;
}

size_t EOF2Header::code_begin() const noexcept
{
    assert(code_size != 0);

    auto header_size = 1 + std::size(MAGIC) + 1;  // FORMAT + MAGIC + VERSION
    header_size += 3;                             // code section header
    if (data_size != 0)
        header_size += 3;                   // data section header
    header_size += 3 * table_sizes.size();  // table section headers
    header_size += 1;                       // header terminator

    return header_size;
}

size_t EOF2Header::code_end() const noexcept
{
    return code_begin() + code_size;
}

size_t EOF2Header::tables_begin() const noexcept
{
    return code_end() + static_cast<size_t>(data_size);
}

bool is_eof_code(const uint8_t* code, size_t code_size) noexcept
{
    static_assert(std::size(MAGIC) == 2);
    return code_size > 2 && code[0] == FORMAT && code[1] == MAGIC[0] && code[2] == MAGIC[1];
}

uint8_t read_eof_version(const uint8_t* code) noexcept
{
    return code[1 + std::size(MAGIC)];
}

EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = std::size(MAGIC) + 3;
    header.code_size = (size_t{code[code_size_offset]} << 8) | code[code_size_offset + 1];
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = (size_t{code[data_size_offset]} << 8) | code[data_size_offset + 1];
    }
    return header;
}

EOF2Header read_valid_eof2_header(const uint8_t* code) noexcept
{
    EOF2Header header;
    const auto code_size_offset = std::size(MAGIC) + 3;
    header.code_size = (size_t{code[code_size_offset]} << 8) | code[code_size_offset + 1];
    const auto* next_section = code + code_size_offset + 2;
    if (*next_section == 2)  // is data section present
    {
        const auto data_size_ptr = next_section + 1;
        header.data_size = (size_t{*data_size_ptr} << 8) | *(data_size_ptr + 1);
        next_section += 3;
    }

    // read table sections
    while (*next_section != 0)
    {
        assert(*next_section == 3);
        const auto size_ptr = next_section + 1;
        const auto size = (size_t{*size_ptr} << 8) | *(size_ptr + 1);
        header.table_sizes.push_back(size);

        next_section += 3;
    }

    return header;
}

TableList read_valid_table_sections(
    const std::vector<size_t> table_sizes, const uint8_t* table_sections) noexcept
{
    TableList tables;
    tables.reserve(table_sizes.size());

    const auto* table_item = table_sections;
    for (const auto table_size : table_sizes)
    {
        std::vector<int16_t> table;
        table.reserve(static_cast<size_t>(table_size));
        const auto* table_section_end = table_item + table_size;
        while (table_item != table_section_end)
        {
            const auto offset_hi = *(table_item);
            const auto offset_lo = *(table_item + 1);
            const int16_t offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
            table.push_back(offset);

            table_item += 2;
        }
        tables.emplace_back(std::move(table));
    }
    return tables;
}

uint8_t get_eof_version(const uint8_t* code, size_t code_size) noexcept
{
    return (code_size >= 4 && code[0] == FORMAT && code[1] == MAGIC[0] && code[2] == MAGIC[1]) ?
               code[3] :
               0;
}

std::pair<EOF1Header, EOFValidationErrror> validate_eof1(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    const auto [section_headers, error_header] = validate_eof_headers(1, code, code_size);
    if (error_header != EOFValidationErrror::success)
        return {{}, error_header};

    EOF1Header header{section_headers[CODE_SECTION][0],
        section_headers[DATA_SECTION].empty() ? 0 : section_headers[DATA_SECTION][0]};

    const auto error_instr =
        validate_instructions(rev, &code[header.code_begin()], header.code_size);
    if (error_instr != EOFValidationErrror::success)
        return {{}, error_instr};

    return {header, EOFValidationErrror::success};
}

std::pair<EOF2Header, EOFValidationErrror> validate_eof2(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    const auto [section_headers, error] = validate_eof_headers(2, code, code_size);
    if (error != EOFValidationErrror::success)
        return {{}, error};

    EOF2Header header{section_headers[CODE_SECTION][0],
        section_headers[DATA_SECTION].empty() ? 0 : section_headers[DATA_SECTION][0],
        section_headers[TABLE_SECTION]};

    const auto error_instr =
        validate_instructions(rev, &code[header.code_begin()], header.code_size);
    if (error_instr != EOFValidationErrror::success)
        return {{}, error_instr};

    // Read jump tables.
    const auto tables = read_valid_table_sections(header.table_sizes, code + header.tables_begin());

    const auto error_rjump = validate_rjump_instructions(header, tables, code);
    if (error_rjump != EOFValidationErrror::success)
        return {{}, error_instr};

    return {header, EOFValidationErrror::success};
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
        return validate_eof1(rev, code, code_size).second;
    }
    case 2:
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationErrror::eof_version_unknown;
        return validate_eof2(rev, code, code_size).second;
    }
    }
}


}  // namespace evmone
