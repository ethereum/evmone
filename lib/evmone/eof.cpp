// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <numeric>
#include <stack>
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

using EOFSectionHeaders = std::array<std::vector<uint16_t>, MAX_SECTION + 1>;

size_t eof_header_size(const EOFSectionHeaders& headers) noexcept
{
    const auto non_code_section_count = headers[TYPE_SECTION].size() + headers[DATA_SECTION].size();
    const auto code_section_count = headers[CODE_SECTION].size();

    constexpr auto non_code_section_header_size = 3;  // (SECTION_ID + SIZE) per each section
    constexpr auto code_section_size_size = 2;

    return sizeof(MAGIC) + 1 +  // 1 version byte
           non_code_section_count * non_code_section_header_size + sizeof(CODE_SECTION) + 2 +
           code_section_count * code_section_size_size + sizeof(TERMINATOR);
}

std::pair<EOFSectionHeaders, EOFValidationError> validate_eof_headers(bytes_view container)
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
    // TODO: Since all sections are mandatory and they have to be ordered (Types, Code+, Data)
    // TODO: this fragment of code can be much simpler. Rewriting needed.
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
                if (section_headers[TYPE_SECTION].empty())
                    return {{}, EOFValidationError::type_section_missing};
                if (section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationError::code_section_missing};
                state = State::terminated;
                break;
            case TYPE_SECTION:
                if (!section_headers[TYPE_SECTION].empty())
                    return {{}, EOFValidationError::multiple_type_sections};
                if (!section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationError::code_section_before_type_section};
                state = State::section_size;
                break;
            case DATA_SECTION:
                if (section_headers[TYPE_SECTION].empty())
                    return {{}, EOFValidationError::data_section_before_types_section};
                if (section_headers[CODE_SECTION].empty())
                    return {{}, EOFValidationError::data_section_before_code_section};
                if (!section_headers[DATA_SECTION].empty())
                    return {{}, EOFValidationError::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
            {
                if (section_headers[TYPE_SECTION].empty())
                    return {{}, EOFValidationError::code_section_before_type_section};
                if (!section_headers[DATA_SECTION].empty())
                    return {{}, EOFValidationError::data_section_before_code_section};
                if (it == container_end)
                    return {{}, EOFValidationError::incomplete_section_number};
                const auto section_number_hi = *it++;
                if (it == container_end)
                    return {{}, EOFValidationError::incomplete_section_number};
                const auto section_number_lo = *it++;
                section_num = static_cast<uint16_t>((section_number_hi << 8) | section_number_lo);
                if (section_num == 0)
                    return {{}, EOFValidationError::zero_section_size};
                state = State::section_size;
                break;
            }
            default:
                return {{}, EOFValidationError::unknown_section_id};
            }
            break;
        }
        case State::section_size:
        {
            for (size_t i = 0; i < (section_id == CODE_SECTION ? section_num : 1); ++i)
            {
                const auto size_hi = *it++;
                if (it == container_end)
                    return {{}, EOFValidationError::incomplete_section_size};
                const auto size_lo = *it++;
                const auto section_size = static_cast<uint16_t>((size_hi << 8) | size_lo);
                if (section_size == 0 && section_id != DATA_SECTION)
                    return {{}, EOFValidationError::zero_section_size};

                if (section_headers[CODE_SECTION].size() == CODE_SECTION_NUMBER_LIMIT)
                    return {{}, EOFValidationError::too_many_code_sections};
                section_headers[section_id].emplace_back(section_size);
            }

            state = State::section_id;
            break;
        }
        case State::terminated:
            return {{}, EOFValidationError::impossible};
        }
    }

    if (state != State::terminated)
        return {{}, EOFValidationError::section_headers_not_terminated};

    const auto section_bodies_size =
        (!section_headers[TYPE_SECTION].empty() ? section_headers[TYPE_SECTION].front() : 0) +
        std::accumulate(
            section_headers[CODE_SECTION].begin(), section_headers[CODE_SECTION].end(), 0) +
        (!section_headers[DATA_SECTION].empty() ? section_headers[DATA_SECTION].front() : 0);
    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return {{}, EOFValidationError::invalid_section_bodies_size};

    if (!section_headers[TYPE_SECTION].empty() &&
        section_headers[TYPE_SECTION][0] != section_headers[CODE_SECTION].size() * 4)
        return {{}, EOFValidationError::invalid_type_section_size};

    return {section_headers, EOFValidationError::success};
}

std::pair<std::vector<EOF1TypeHeader>, EOFValidationError> validate_types(
    bytes_view container, size_t header_size, std::vector<uint16_t> type_section_sizes) noexcept
{
    assert(!container.empty());              // guaranteed by EOF headers validation
    assert(type_section_sizes.size() <= 1);  // guaranteed by EOF headers validation

    if (type_section_sizes.empty())
        return {{{0, 0, 0}}, EOFValidationError::success};

    std::vector<EOF1TypeHeader> types;

    // guaranteed by EOF headers validation
    assert(header_size + type_section_sizes[0] < container.size());

    for (auto offset = header_size; offset < header_size + type_section_sizes[0]; offset += 4)
    {
        types.emplace_back(EOF1TypeHeader{container[offset], container[offset + 1],
            static_cast<uint16_t>(container[offset + 2] << 8 | container[offset + 3])});
    }

    // check 1st section is (0, 0)
    if (types[0].inputs_num != 0 || types[0].outputs_num != 0)
        return {{}, EOFValidationError::invalid_first_section_type};

    if (types[0].max_stack_height > MAX_STACK_HEIGHT)
        return {{}, EOFValidationError::invalid_max_stack_height};

    return {types, EOFValidationError::success};
}

EOFValidationError validate_instructions(evmc_revision rev, bytes_view code) noexcept
{
    assert(!code.empty());  // guaranteed by EOF headers validation

    const auto& cost_table = baseline::get_baseline_cost_table(rev, 1);

    size_t i = 0;
    uint8_t op = 0;
    while (i < code.size())
    {
        op = code[i];
        if (cost_table[op] == instr::undefined)
            return EOFValidationError::undefined_instruction;

        if (op == OP_RJUMPV)
        {
            if (i + 1 < code.size())
                i += static_cast<size_t>(1 /* count */ + code[i + 1] * 2 /* tbl */);
            else
                return EOFValidationError::truncated_instruction;
        }
        else
            i += instr::traits[op].immediate_size;

        if (i >= code.size())
            return EOFValidationError::truncated_instruction;

        ++i;
    }

    return EOFValidationError::success;
}

bool validate_rjump_destinations(
    const EOF1Header& header, size_t code_idx, bytes_view::const_iterator container) noexcept
{
    // Collect relative jump destinations and immediate locations
    std::vector<size_t> rjumpdests;
    const auto code_size = header.code_sizes[code_idx];
    std::vector<bool> immediate_map(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op_pos = header.code_begin(code_idx) + i;
        const auto op = container[op_pos];

        if (op == OP_RJUMP || op == OP_RJUMPI)
        {
            const auto offset_hi = container[op_pos + 1];
            const auto offset_lo = container[op_pos + 2];
            const auto offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
            const auto jumpdest = static_cast<int32_t>(i) + 3 + offset;
            if (jumpdest < 0 || jumpdest >= code_size)
                return false;
            rjumpdests.push_back(static_cast<size_t>(jumpdest));
        }
        else if (op == OP_RJUMPV)
        {
            constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);

            const auto count = container[op_pos + 1];

            const auto post_offset =
                static_cast<int32_t>(1 + 1 /* count */ + count * REL_OFFSET_SIZE /* tbl */);

            for (size_t k = 0; k < count; ++k)
            {
                const auto rel_offset_hi =
                    container[op_pos + 1 + 1 + static_cast<uint16_t>(k) * REL_OFFSET_SIZE];
                const auto rel_offset_lo =
                    container[op_pos + 1 + 2 + static_cast<uint16_t>(k) * REL_OFFSET_SIZE];
                const auto rel_offset = static_cast<int16_t>((rel_offset_hi << 8) + rel_offset_lo);

                const auto jumpdest = static_cast<int32_t>(i) + post_offset + rel_offset;

                if (jumpdest < 0 || jumpdest >= code_size)
                    return false;

                rjumpdests.push_back(static_cast<size_t>(jumpdest));
            }

            const auto rjumpv_imm_size = size_t{1} + count * REL_OFFSET_SIZE;
            std::fill_n(
                immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, rjumpv_imm_size, true);
            i += rjumpv_imm_size;
            continue;
        }

        const auto imm_size = instr::traits[op].immediate_size;
        std::fill_n(immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, imm_size, true);
        i += imm_size;
    }

    // Check relative jump destinations against immediate locations.
    for (const auto rjumpdest : rjumpdests)
        if (immediate_map[rjumpdest])
            return false;

    return true;
}

std::pair<EOFValidationError, int32_t> validate_max_stack_height(
    bytes_view code, size_t func_index, const std::vector<EOF1TypeHeader>& funcs_in_outs)
{
    assert(code.size() > 0);
    std::vector<int32_t> stack_heights = std::vector<int32_t>(code.size(), -1);
    std::stack<size_t> worklist;

    int32_t stack_height = 0;
    stack_heights[0] = funcs_in_outs[func_index].inputs_num;
    worklist.push(0);

    size_t i = 0;
    Opcode opcode = {};
    std::vector<size_t> successors;
    while (!worklist.empty())
    {
        i = worklist.top();
        opcode = static_cast<Opcode>(code[i]);
        worklist.pop();

        auto stack_height_required = instr::traits[opcode].stack_height_required;
        auto stack_height_change = instr::traits[opcode].stack_height_change;

        if (opcode == OP_CALLF)
        {
            auto fid_hi = code[i + 1];
            auto fid_lo = code[i + 2];
            auto fid = static_cast<uint16_t>((fid_hi << 8) | fid_lo);

            stack_height_required = static_cast<int8_t>(funcs_in_outs[fid].inputs_num);
            auto d = funcs_in_outs[fid].outputs_num - stack_height_required;
            stack_height_change = static_cast<int8_t>(d);
        }

        stack_height = stack_heights[i];
        assert(stack_height != -1);

        if (stack_height < stack_height_required)
            return {EOFValidationError::stack_underflow, -1};

        successors.clear();

        // immediate_size for RJUMPV depends on the code. It's calculated below.
        if (opcode != OP_RJUMP && !instr::traits[opcode].is_terminating && opcode != OP_RJUMPV)
        {
            auto next = i + instr::traits[opcode].immediate_size + 1;
            if (next >= code.size())
                return {EOFValidationError::no_terminating_instruction, -1};

            successors.push_back(next);
        }

        if (opcode == OP_RJUMP || opcode == OP_RJUMPI)
        {
            auto target_rel_offset_hi = code[i + 1];
            auto target_rel_offset_lo = code[i + 2];
            auto target_rel_offset =
                static_cast<int16_t>((target_rel_offset_hi << 8) | target_rel_offset_lo);
            successors.push_back(
                static_cast<size_t>(target_rel_offset + 3 + static_cast<int32_t>(i)));
        }

        if (opcode == OP_RJUMPV)
        {
            auto count = code[i + 1];

            auto next = i + count * 2 + 2;
            if (next >= code.size())
                return {EOFValidationError::no_terminating_instruction, -1};

            auto beg = stack_heights.begin() + static_cast<int32_t>(i) + 1;
            std::fill_n(beg, count * 2 + 1, -2);

            successors.push_back(next);

            for (uint16_t k = 0; k < count; ++k)
            {
                auto target_rel_offset_hi = code[i + k * 2 + 2];
                auto target_rel_offset_lo = code[i + k * 2 + 3];
                auto target_rel_offset =
                    static_cast<int16_t>((target_rel_offset_hi << 8) | target_rel_offset_lo);
                successors.push_back(static_cast<size_t>(
                    static_cast<int32_t>(i) + 2 * count + target_rel_offset + 2));
            }
        }
        else
        {
            auto beg = stack_heights.begin() + static_cast<int32_t>(i) + 1;
            std::fill_n(beg, instr::traits[opcode].immediate_size, -2);
        }

        stack_height += stack_height_change;

        for (auto& s : successors)
        {
            if (stack_heights[s] == -1)
            {
                stack_heights[s] = stack_height;
                worklist.push(s);
            }
            else if (stack_heights[s] != stack_height)
                return {EOFValidationError::stack_height_mismatch, -1};
        }

        if (opcode == OP_RETF && stack_height != funcs_in_outs[func_index].outputs_num)
            return {EOFValidationError::non_empty_stack_on_terminating_instruction, -1};
    }

    auto msh_it = std::max_element(stack_heights.begin(), stack_heights.end());

    if (*msh_it > 1023)
        return {EOFValidationError::max_stack_height_above_limit, -1};

    if (std::find(stack_heights.begin(), stack_heights.end(), -1) != stack_heights.end())
        return {EOFValidationError::unreachable_instructions, -1};

    return {EOFValidationError::success, *msh_it};
}

std::pair<EOF1Header, EOFValidationError> validate_eof1(
    evmc_revision rev, bytes_view container) noexcept
{
    const auto [section_headers, error_header] = validate_eof_headers(container);
    if (error_header != EOFValidationError::success)
        return {{}, error_header};

    const auto& code_sizes = section_headers[CODE_SECTION];
    const auto data_size =
        section_headers[DATA_SECTION].empty() ? uint16_t{0} : section_headers[DATA_SECTION][0];

    const auto header_size = eof_header_size(section_headers);

    const auto [types, error_types] =
        validate_types(container, header_size, section_headers[TYPE_SECTION]);
    if (error_types != EOFValidationError::success)
        return {{}, error_types};

    std::vector<uint16_t> code_offsets;
    const auto type_section_size =
        section_headers[TYPE_SECTION].empty() ? 0u : section_headers[TYPE_SECTION][0];
    auto offset = header_size + type_section_size;
    for (const auto code_size : code_sizes)
    {
        code_offsets.emplace_back(static_cast<uint16_t>(offset));
        offset += code_size;
    }

    EOF1Header header{code_sizes, code_offsets, data_size, types};

    for (size_t code_idx = 0; code_idx < header.code_sizes.size(); ++code_idx)
    {
        const auto error_instr = validate_instructions(
            rev, {&container[header.code_begin(code_idx)], header.code_sizes[code_idx]});
        if (error_instr != EOFValidationError::success)
            return {{}, error_instr};

        if (!validate_rjump_destinations(header, code_idx, container.begin()))
            return {{}, EOFValidationError::invalid_rjump_destination};

        auto msh_validation_result = validate_max_stack_height(
            {&container[header.code_begin(code_idx)], header.code_sizes[code_idx]}, code_idx,
            header.types);
        if (msh_validation_result.first != EOFValidationError::success)
            return {{}, msh_validation_result.first};
        if (msh_validation_result.second != header.types[code_idx].max_stack_height)
            return {{}, EOFValidationError::invalid_max_stack_height};
    }

    return {header, EOFValidationError::success};
}

}  // namespace

size_t EOF1Header::code_begin(size_t index) const noexcept
{
    assert(index < code_offsets.size());
    return code_offsets[index];
}

size_t EOF1Header::code_end(size_t index) const noexcept
{
    assert(index < code_offsets.size());
    assert(index < code_sizes.size());
    return size_t{code_offsets[index]} + code_sizes[index];
}

bool is_eof_code(bytes_view code) noexcept
{
    return code.size() > 1 && code[0] == MAGIC[0] && code[1] == MAGIC[1];
}

EOF1Header read_valid_eof1_header(bytes_view container)
{
    EOFSectionHeaders section_headers;
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    while (*it != TERMINATOR)
    {
        const auto section_id = *it++;
        if (section_id == CODE_SECTION)
        {
            const auto code_section_num_hi = *it++;
            const auto code_section_num_lo = *it++;
            const auto code_section_num =
                static_cast<uint16_t>((code_section_num_hi << 8) | code_section_num_lo);
            for (uint16_t i = 0; i < code_section_num; ++i)
            {
                const auto section_size_hi = *it++;
                const auto section_size_lo = *it++;
                const auto section_size =
                    static_cast<uint16_t>((section_size_hi << 8) | section_size_lo);
                section_headers[section_id].emplace_back(section_size);
            }
        }
        else
        {
            const auto section_size_hi = *it++;
            const auto section_size_lo = *it++;
            const auto section_size =
                static_cast<uint16_t>((section_size_hi << 8) | section_size_lo);
            section_headers[section_id].emplace_back(section_size);
        }
    }
    const auto header_size = eof_header_size(section_headers);

    EOF1Header header;

    if (section_headers[TYPE_SECTION].empty())
        header.types.emplace_back(0, 0, 0);
    else
    {
        for (auto type_offset = header_size;
             type_offset < header_size + section_headers[TYPE_SECTION][0]; type_offset += 4)

            header.types.emplace_back(container[type_offset], container[type_offset + 1],
                container[type_offset + 2] << 8 | container[type_offset + 3]);
    }

    header.code_sizes = section_headers[CODE_SECTION];
    std::vector<uint16_t> code_offsets;
    auto code_offset =
        header_size +
        (section_headers[TYPE_SECTION].empty() ? uint16_t{0} : section_headers[TYPE_SECTION][0]);
    for (const auto code_size : header.code_sizes)
    {
        header.code_offsets.emplace_back(static_cast<uint16_t>(code_offset));
        code_offset += code_size;
    }

    header.data_size =
        section_headers[DATA_SECTION].empty() ? uint16_t{0} : section_headers[DATA_SECTION][0];

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
    if (!is_eof_code(container))
        return EOFValidationError::invalid_prefix;

    const auto version = get_eof_version(container);

    if (version == 1)
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationError::eof_version_unknown;
        return validate_eof1(rev, container).second;
    }
    else
        return EOFValidationError::eof_version_unknown;
}
}  // namespace evmone
