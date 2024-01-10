// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

#include <intx/intx.hpp>
#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <numeric>
#include <ostream>
#include <span>
#include <stack>
#include <unordered_set>
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
constexpr uint8_t DATA_SECTION = 0x04;
constexpr uint8_t MAX_SECTION = DATA_SECTION;
constexpr auto CODE_SECTION_NUMBER_LIMIT = 1024;
constexpr auto MAX_STACK_HEIGHT = 0x03FF;
constexpr auto OUTPUTS_INPUTS_NUMBER_LIMIT = 0x7F;
constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);
constexpr auto STACK_SIZE_LIMIT = 1024;
constexpr uint8_t NON_RETURNING_FUNCITON = 0x80;

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
    switch (section_id)
    {
    case TERMINATOR:
        return EOFValidationError::header_terminator_missing;
    case TYPE_SECTION:
        return EOFValidationError::type_section_missing;
    case CODE_SECTION:
        return EOFValidationError::code_section_missing;
    case DATA_SECTION:
        return EOFValidationError::data_section_missing;
    default:
        intx::unreachable();
    }
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

    // check 1st section is (0, 0x80)
    if (types[0].inputs != 0 || types[0].outputs != NON_RETURNING_FUNCITON)
        return EOFValidationError::invalid_first_section_type;

    for (const auto& t : types)
    {
        if ((t.outputs > OUTPUTS_INPUTS_NUMBER_LIMIT && t.outputs != NON_RETURNING_FUNCITON) ||
            t.inputs > OUTPUTS_INPUTS_NUMBER_LIMIT)
            return EOFValidationError::inputs_outputs_num_above_limit;

        if (t.max_stack_height > MAX_STACK_HEIGHT)
            return EOFValidationError::max_stack_height_above_limit;
    }

    return types;
}

EOFValidationError validate_instructions(evmc_revision rev, const EOF1Header& header,
    size_t code_idx, bytes_view container,
    std::unordered_set<uint16_t>& accessed_code_sections) noexcept
{
    const bytes_view code{header.get_code(container, code_idx)};
    assert(!code.empty());  // guaranteed by EOF headers validation

    const auto& cost_table = baseline::get_baseline_cost_table(rev, 1);

    bool is_returning = false;

    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (cost_table[op] == instr::undefined)
            return EOFValidationError::undefined_instruction;

        if (i + instr::traits[op].immediate_size >= code.size())
            return EOFValidationError::truncated_instruction;

        if (op == OP_RJUMPV)
        {
            const auto count = code[i + 1] + 1;
            i += static_cast<size_t>(1 /* max_index */ + count * 2 /* tbl */);
            if (i >= code.size())
                return EOFValidationError::truncated_instruction;
        }
        else if (op == OP_CALLF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);
            if (fid >= header.types.size())
                return EOFValidationError::invalid_code_section_index;
            if (header.types[fid].outputs == NON_RETURNING_FUNCITON)
                return EOFValidationError::callf_to_non_returning_function;
            if (code_idx != fid)
                accessed_code_sections.insert(fid);
            i += 2;
        }
        else if (op == OP_RETF)
        {
            is_returning = true;
            static_assert(instr::traits[OP_RETF].immediate_size == 0);
        }
        else if (op == OP_JUMPF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);
            if (fid >= header.types.size())
                return EOFValidationError::invalid_code_section_index;
            // JUMPF into returning function means current function is returning.
            if (header.types[fid].outputs != NON_RETURNING_FUNCITON)
                is_returning = true;
            if (code_idx != fid)
                accessed_code_sections.insert(fid);
            i += 2;
        }
        else if (op == OP_DATALOADN)
        {
            const auto index = read_uint16_be(&code[i + 1]);
            if (header.data_size < 32 || index > header.data_size - 32)
                return EOFValidationError::invalid_dataloadn_index;
            i += 2;
        }
        else
            i += instr::traits[op].immediate_size;
    }

    const auto declared_returning = (header.types[code_idx].outputs != NON_RETURNING_FUNCITON);
    if (is_returning != declared_returning)
        return EOFValidationError::invalid_non_returning_flag;

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
            const auto count = size_t{code[i + 1]} + 1;
            imm_size += count * REL_OFFSET_SIZE /* tbl */;
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

        int stack_height_required = instr::traits[opcode].stack_height_required;
        auto stack_height_change = instr::traits[opcode].stack_height_change;

        auto stack_height = stack_heights[i];
        assert(stack_height != LOC_UNVISITED);

        if (opcode == OP_CALLF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);

            stack_height_required = code_types[fid].inputs;

            if (stack_height + code_types[fid].max_stack_height - stack_height_required >
                STACK_SIZE_LIMIT)
                return EOFValidationError::stack_overflow;

            // Instruction validation ensures target function is returning
            assert(code_types[fid].outputs != NON_RETURNING_FUNCITON);
            stack_height_change =
                static_cast<int8_t>(code_types[fid].outputs - stack_height_required);
        }
        else if (opcode == OP_JUMPF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);

            if (stack_height + code_types[fid].max_stack_height - code_types[fid].inputs >
                STACK_SIZE_LIMIT)
                return EOFValidationError::stack_overflow;

            if (code_types[fid].outputs == NON_RETURNING_FUNCITON)
            {
                stack_height_required = code_types[fid].inputs;
            }
            else
            {
                if (code_types[func_index].outputs < code_types[fid].outputs)
                    return EOFValidationError::jumpf_destination_incompatible_outputs;

                stack_height_required = code_types[func_index].outputs + code_types[fid].inputs -
                                        code_types[fid].outputs;
                if (stack_heights[i] > stack_height_required)
                    return EOFValidationError::stack_higher_than_outputs_required;
            }
        }
        else if (opcode == OP_RETF)
        {
            stack_height_required = code_types[func_index].outputs;
            if (stack_height > code_types[func_index].outputs)
                return EOFValidationError::stack_higher_than_outputs_required;
        }
        else if (opcode == OP_DUPN)
            stack_height_required = code[i + 1] + 1;
        else if (opcode == OP_SWAPN)
            stack_height_required = code[i + 1] + 2;

        if (stack_height < stack_height_required)
            return EOFValidationError::stack_underflow;

        stack_height += stack_height_change;

        // Determine size of immediate, including the special case of RJUMPV.
        const size_t imm_size = (opcode == OP_RJUMPV) ?
                                    (1 + /*count*/ (size_t{code[i + 1]} + 1) * REL_OFFSET_SIZE) :
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
            const auto max_index = code[i + 1];

            // Insert all jump targets.
            for (size_t k = 0; k <= max_index; ++k)
            {
                const auto target_rel_offset = read_int16_be(&code[i + k * REL_OFFSET_SIZE + 2]);
                const auto target = static_cast<int32_t>(next) + target_rel_offset;
                if (!validate_successor(static_cast<size_t>(target), stack_height))
                    return EOFValidationError::stack_height_mismatch;
            }
        }
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

    std::unordered_set<uint16_t> accessed_code_sections = {0};
    EOF1Header header{container[2], code_sizes, code_offsets, data_size, types};

    for (size_t code_idx = 0; code_idx < header.code_sizes.size(); ++code_idx)
    {
        const auto error_instr =
            validate_instructions(rev, header, code_idx, container, accessed_code_sections);
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

    if (accessed_code_sections.size() != header.code_sizes.size())
        return EOFValidationError::unreachable_code_sections;

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
    if (!is_eof_container(container))
        return EOFValidationError::invalid_prefix;

    const auto version = get_eof_version(container);

    if (version == 1)
    {
        if (rev < EVMC_PRAGUE)
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
    case EOFValidationError::unreachable_code_sections:
        return "unreachable_code_sections";
    case EOFValidationError::undefined_instruction:
        return "undefined_instruction";
    case EOFValidationError::truncated_instruction:
        return "truncated_instruction";
    case EOFValidationError::invalid_rjump_destination:
        return "invalid_rjump_destination";
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
    case EOFValidationError::no_terminating_instruction:
        return "no_terminating_instruction";
    case EOFValidationError::stack_height_mismatch:
        return "stack_height_mismatch";
    case EOFValidationError::stack_higher_than_outputs_required:
        return "stack_higher_than_outputs_required";
    case EOFValidationError::unreachable_instructions:
        return "unreachable_instructions";
    case EOFValidationError::stack_underflow:
        return "stack_underflow";
    case EOFValidationError::stack_overflow:
        return "stack_overflow";
    case EOFValidationError::invalid_code_section_index:
        return "invalid_code_section_index";
    case EOFValidationError::invalid_dataloadn_index:
        return "invalid_dataloadn_index";
    case EOFValidationError::jumpf_destination_incompatible_outputs:
        return "jumpf_destination_incompatible_outputs";
    case EOFValidationError::invalid_non_returning_flag:
        return "invalid_non_returning_flag";
    case EOFValidationError::callf_to_non_returning_function:
        return "callf_to_non_returning_function";
    case EOFValidationError::impossible:
        return "impossible";
    }
    return "<unknown>";
}

std::ostream& operator<<(std::ostream& os, EOFValidationError err) noexcept
{
    os << get_error_message(err);
    return os;
}
}  // namespace evmone
