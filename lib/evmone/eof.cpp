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
#include <span>
#include <stack>
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
constexpr auto MAX_STACK_HEIGHT = 0x03FF;
constexpr auto OUTPUTS_INPUTS_NUMBER_LIMIT = 0x7F;
constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);

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

std::variant<EOFSectionHeaders, EOFValidationError> validate_eof_headers(bytes_view container)
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto invalid_order = false;
    auto type_section_found = false;
    auto code_section_found = false;
    auto data_section_found = false;
    auto state = State::section_id;
    uint8_t section_id = 0;
    uint16_t section_num = 0;
    EOFSectionHeaders section_headers{};
    const auto container_end = container.end();
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    while (it != container_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            auto prev_section = section_id;
            section_id = *it++;
            if (section_id < prev_section && section_id != TERMINATOR)
                invalid_order = true;

            switch (section_id)
            {
            case TERMINATOR:
                state = State::terminated;
                break;
            case TYPE_SECTION:
                type_section_found = true;
                state = State::section_size;
                break;
            case CODE_SECTION:
            {
                code_section_found = true;
                section_num = read_uint16_be(it);
                it += 2;
                if (section_num > CODE_SECTION_NUMBER_LIMIT)
                    return EOFValidationError::too_many_code_sections;
                state = State::section_size;
                break;
            }
            case DATA_SECTION:
                data_section_found = true;
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
                    const auto section_size = read_uint16_be(it);
                    it += 2;
                    section_headers[section_id].emplace_back(section_size);
                }
            }
            else  // TYPES_SECTION or DATA_SECTION
            {
                const auto section_size = read_uint16_be(it);
                it += 2;
                section_headers[section_id].emplace_back(section_size);
            }

            state = State::section_id;
            break;
        }
        case State::terminated:
            return EOFValidationError::impossible;
        }
    }

    if (!type_section_found) return EOFValidationError::type_section_missing;
    if (!code_section_found) return EOFValidationError::code_section_missing;
    if (!data_section_found) return EOFValidationError::data_section_missing;
    if (invalid_order) return EOFValidationError::invalid_sections_order;

    if (section_headers[TYPE_SECTION].size() > 1)
        return EOFValidationError::too_many_types_sections;
    if (section_headers[DATA_SECTION].size() > 1)
        return EOFValidationError::too_many_data_sections;

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

        if (op == OP_RJUMPV)
        {
            if (i + 1 >= code.size())
                return EOFValidationError::truncated_instruction;

            const auto count = code[i + 1];
            if (count < 1)
                return EOFValidationError::invalid_rjumpv_count;
            i += static_cast<size_t>(1 /* count */ + count * 2 /* tbl */);
        }
        else
            i += instr::traits[op].immediate_size;

        if (i >= code.size())
            return EOFValidationError::truncated_instruction;
    }

    return EOFValidationError::success;
}

/// Validates that that we don't rjump inside an instruction's immediate.
/// Requires that the input is validated against truncation.
bool validate_rjump_destinations(bytes_view code) noexcept
{
    // Collect relative jump destinations and immediate locations
    const auto code_size = code.size();
    // list of all possible absolute rjumps destinations positions
    std::vector<size_t> rjumpdests;
    // bool map of immediate arguments positions in the code
    std::vector<bool> immediate_map(code_size);

    /// Validates relative jump destination. If valid pushes the destination to the rjumpdests.
    const auto check_rjump_destination = [code_size, &rjumpdests](
                                             auto rel_offset_data_it, size_t post_pos) -> bool {
        const auto rel_offset = read_int16_be(rel_offset_data_it);
        const auto jumpdest = static_cast<int32_t>(post_pos) + rel_offset;
        if (jumpdest < 0 || static_cast<size_t>(jumpdest) >= code_size)
            return false;

        rjumpdests.emplace_back(static_cast<size_t>(jumpdest));
        return true;
    };

    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        size_t imm_size = instr::traits[op].immediate_size;

        if (op == OP_RJUMP || op == OP_RJUMPI)
        {
            if (!check_rjump_destination(&code[i + 1], i + REL_OFFSET_SIZE + 1))
                return false;
        }
        else if (op == OP_RJUMPV)
        {
            const auto count = code[i + 1];
            imm_size += size_t{1} /* count */ + count * REL_OFFSET_SIZE /* tbl */;
            const size_t post_pos = i + 1 + imm_size;

            for (size_t k = 0; k < count * REL_OFFSET_SIZE; k += REL_OFFSET_SIZE)
            {
                if (!check_rjump_destination(&code[i + 1 + 1 + static_cast<uint16_t>(k)], post_pos))
                    return false;
            }
        }

        std::fill_n(immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, imm_size, true);
        i += imm_size;
    }

    // Check relative jump destinations against immediate locations.
    for (const auto rjumpdest : rjumpdests)
        if (immediate_map[rjumpdest])
            return false;

    return true;
}

/// Requires that the input is validated against truncation.
std::variant<EOFValidationError, int32_t> validate_max_stack_height(
    bytes_view code, size_t func_index, const std::vector<EOFCodeType>& code_types)
{
    assert(!code.empty());

    // Special values used for detecting errors.
    static constexpr int32_t LOC_UNVISITED = -1;  // Unvisited byte.
    static constexpr int32_t LOC_IMMEDIATE = -2;  // Immediate byte.

    // Stack height in the header is limited to uint16_t,
    // but keeping larger size for ease of calculation.
    std::vector<int32_t> stack_heights(code.size(), LOC_UNVISITED);
    stack_heights[0] = code_types[func_index].inputs;

    std::stack<size_t> worklist;
    worklist.push(0);

    while (!worklist.empty())
    {
        const auto i = worklist.top();
        worklist.pop();

        const auto opcode = static_cast<Opcode>(code[i]);

        auto stack_height_required = instr::traits[opcode].stack_height_required;
        auto stack_height_change = instr::traits[opcode].stack_height_change;

        if (opcode == OP_CALLF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);

            if (fid >= code_types.size())
                return EOFValidationError::invalid_code_section_index;

            stack_height_required = static_cast<int8_t>(code_types[fid].inputs);
            stack_height_change =
                static_cast<int8_t>(code_types[fid].outputs - stack_height_required);
        }

        auto stack_height = stack_heights[i];
        assert(stack_height != LOC_UNVISITED);

        if (stack_height < stack_height_required)
            return EOFValidationError::stack_underflow;

        stack_height += stack_height_change;

        // Determine size of immediate, including the special case of RJUMPV.
        const size_t imm_size = (opcode == OP_RJUMPV) ?
                                    (1 + /*count*/ size_t{code[i + 1]} * REL_OFFSET_SIZE) :
                                    instr::traits[opcode].immediate_size;

        // Mark immediate locations.
        std::fill_n(&stack_heights[i + 1], imm_size, LOC_IMMEDIATE);

        // Validates the successor instruction and updates its stack height.
        const auto validate_successor = [&stack_heights, &worklist](size_t successor_offset,
                                            int32_t expected_stack_height) {
            auto& successor_stack_height = stack_heights[successor_offset];
            if (successor_stack_height == LOC_UNVISITED)
            {
                successor_stack_height = expected_stack_height;
                worklist.push(successor_offset);
                return true;
            }
            else
                return successor_stack_height == expected_stack_height;
        };

        const auto next = i + imm_size + 1;  // Offset of the next instruction (may be invalid).

        // Check validity of next instruction. We skip RJUMP and terminating instructions.
        if (!instr::traits[opcode].is_terminating && opcode != OP_RJUMP)
        {
            if (next >= code.size())
                return EOFValidationError::no_terminating_instruction;
            if (!validate_successor(next, stack_height))
                return EOFValidationError::stack_height_mismatch;
        }

        // Validate non-fallthrough successors of relative jumps.
        if (opcode == OP_RJUMP || opcode == OP_RJUMPI)
        {
            const auto target_rel_offset = read_int16_be(&code[i + 1]);
            const auto target = static_cast<int32_t>(i) + target_rel_offset + 3;
            if (!validate_successor(static_cast<size_t>(target), stack_height))
                return EOFValidationError::stack_height_mismatch;
        }
        else if (opcode == OP_RJUMPV)
        {
            const auto count = code[i + 1];

            // Insert all jump targets.
            for (size_t k = 0; k < count; ++k)
            {
                const auto target_rel_offset = read_int16_be(&code[i + k * REL_OFFSET_SIZE + 2]);
                const auto target = static_cast<int32_t>(next) + target_rel_offset;
                if (!validate_successor(static_cast<size_t>(target), stack_height))
                    return EOFValidationError::stack_height_mismatch;
            }
        }
        else if (opcode == OP_RETF && stack_height != code_types[func_index].outputs)
            return EOFValidationError::non_empty_stack_on_terminating_instruction;
    }

    const auto max_stack_height = *std::max_element(stack_heights.begin(), stack_heights.end());

    if (std::find(stack_heights.begin(), stack_heights.end(), LOC_UNVISITED) != stack_heights.end())
        return EOFValidationError::unreachable_instructions;

    return max_stack_height;
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

    EOF1Header header{container[2], code_sizes, code_offsets, data_size, types};

    for (size_t code_idx = 0; code_idx < header.code_sizes.size(); ++code_idx)
    {
        const auto error_instr = validate_instructions(rev, header.get_code(container, code_idx));
        if (error_instr != EOFValidationError::success)
            return error_instr;

        if (!validate_rjump_destinations(header.get_code(container, code_idx)))
            return EOFValidationError::invalid_rjump_destination;

        auto msh_or_error =
            validate_max_stack_height(header.get_code(container, code_idx), code_idx, header.types);
        if (const auto* error = std::get_if<EOFValidationError>(&msh_or_error))
            return *error;
        if (std::get<int32_t>(msh_or_error) != header.types[code_idx].max_stack_height)
            return EOFValidationError::invalid_max_stack_height;
    }

    return header;
}

}  // namespace

bool is_eof_container(bytes_view container) noexcept
{
    // If no MAGIC and VERSION detected, it is not an EOF container.
    if (container.size() <= 3 ||  container[0] != MAGIC[0] || container[1] != MAGIC[1])
      return false;

    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    std::array<uint8_t, 4> valid_sections = {TYPE_SECTION, CODE_SECTION, DATA_SECTION, TERMINATOR};

    auto state = State::section_id;
    uint8_t section_id = 0;
    uint16_t section_num = 0;
    const auto container_end = container.end();
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    auto section_bodies_size = 0; 
    while (it != container_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it++;

            if (std::find(valid_sections.begin(), valid_sections.end(), section_id) ==
                valid_sections.end())
                return false;

            switch (section_id)
            {
            case TERMINATOR:
                state = State::terminated;
                break;
            case TYPE_SECTION:
                state = State::section_size;
                break;
            case CODE_SECTION:
            {
                if (it >= container_end - 1)
                    return false;
                section_num = read_uint16_be(it);
                it += 2;
                if (section_num == 0)
                    return false;
                state = State::section_size;
                break;
            }
            case DATA_SECTION:
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
                        return false;
                    const auto section_size = read_uint16_be(it);
                    it += 2;
                    if (section_size == 0)
                        return false;

                    section_bodies_size += section_size;
                }
            }
            else  // TYPES_SECTION or DATA_SECTION
            {
                if (it >= container_end - 1)
                    return false;
                const auto section_size = read_uint16_be(it);
                it += 2;
                if (section_size == 0 && section_id != DATA_SECTION)
                    return false;

                section_bodies_size += section_size;
            }

            state = State::section_id;
            break;
        }
        case State::terminated:
            return false; // This should never happen.
        }
    }

    if (state != State::terminated)
        return false;

    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return false;

    return true;
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

    header.version = container[2];

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
    if (rev < EVMC_CANCUN || !is_eof_container(container))
        return EOFValidationError::invalid_format;

    const auto version = get_eof_version(container);
    if (version == 1)
    {
      const auto header_or_error = validate_eof1(rev, container);
      if (const auto* error = std::get_if<EOFValidationError>(&header_or_error))
          return *error;
      else
          return EOFValidationError::success;
    }
    else
        return EOFValidationError::eof_version_mismatch;
}

std::string_view get_error_message(EOFValidationError err) noexcept
{
    switch (err)
    {
    case EOFValidationError::invalid_format:
        return "invalid_format";
    case EOFValidationError::success:
        return "success";
    case EOFValidationError::eof_version_mismatch:
        return "eof_version_mismatch";
    case EOFValidationError::type_section_missing:
        return "type_section_missing";
    case EOFValidationError::code_section_missing:
        return "code_section_missing";
    case EOFValidationError::data_section_missing:
        return "data_section_missing";
    case EOFValidationError::invalid_sections_order:
        return "invalid_sections_order";
    case EOFValidationError::undefined_instruction:
        return "undefined_instruction";
    case EOFValidationError::truncated_instruction:
        return "truncated_instruction";
    case EOFValidationError::invalid_rjumpv_count:
        return "invalid_rjumpv_count";
    case EOFValidationError::invalid_rjump_destination:
        return "invalid_rjump_destination";
    case EOFValidationError::too_many_types_sections:
        return "too_many_types_sections";
    case EOFValidationError::too_many_code_sections:
        return "too_many_code_sections";
    case EOFValidationError::too_many_data_sections:
        return "too_many_data_sections";
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
    case EOFValidationError::no_terminating_instruction:
        return "no_terminating_instruction";
    case EOFValidationError::stack_height_mismatch:
        return "stack_height_mismatch";
    case EOFValidationError::non_empty_stack_on_terminating_instruction:
        return "non_empty_stack_on_terminating_instruction";
    case EOFValidationError::unreachable_instructions:
        return "unreachable_instructions";
    case EOFValidationError::stack_underflow:
        return "stack_underflow";
    case EOFValidationError::invalid_code_section_index:
        return "invalid_code_section_index";
    case EOFValidationError::impossible:
        return "impossible";
    }
    return "<unknown>";
}
}  // namespace evmone
