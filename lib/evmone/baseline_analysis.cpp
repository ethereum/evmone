// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "eof.hpp"
#include "instructions.hpp"
#include <memory>

namespace evmone::baseline
{
static_assert(std::is_move_constructible_v<CodeAnalysis>);
static_assert(std::is_move_assignable_v<CodeAnalysis>);
static_assert(!std::is_copy_constructible_v<CodeAnalysis>);
static_assert(!std::is_copy_assignable_v<CodeAnalysis>);

namespace
{
constexpr bool first_instruction_terminates(uint8_t op) noexcept
{
    return op < OP_ADDRESS || op > OP_PUSH32;
}

consteval bool proof() noexcept
{
    for (size_t op = 0; op <= 0x80; ++op)
    {
        if (!first_instruction_terminates(op))
            continue;


        const auto& tr = instr::traits[op];
        const auto& g = instr::gas_costs[EVMC_MAX_REVISION][op];
        if (tr.is_terminating)
            continue;
        if (g == instr::undefined)
            continue;
        if (tr.stack_height_required > 0)
            continue;
        return false;
    }
    return true;
}
static_assert(proof());

// bool is_jumpdest_analysis_needed(bytes_view code) noexcept {}

CodeAnalysis::JumpdestMap analyze_jumpdests(bytes_view code)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    CodeAnalysis::JumpdestMap map(code.size());  // Allocate and init bitmap with zeros.
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            map[i] = true;
    }

    return map;
}

std::unique_ptr<uint8_t[]> pad_code(bytes_view code)
{
    // We need at most 33 bytes of code padding: 32 for possible missing all data bytes of PUSH32
    // at the very end of the code; and one more byte for STOP to guarantee there is a terminating
    // instruction at the code end.
    constexpr auto padding = 32 + 1;

    auto padded_code = std::make_unique_for_overwrite<uint8_t[]>(code.size() + padding);
    std::copy(std::begin(code), std::end(code), padded_code.get());
    std::fill_n(&padded_code[code.size()], padding, uint8_t{OP_STOP});
    return padded_code;
}


CodeAnalysis analyze_legacy(bytes_view code)
{
    // TODO: The padded code buffer and jumpdest bitmap can be created with single allocation.
    return {pad_code(code), code.size(), analyze_jumpdests(code)};
}

CodeAnalysis analyze_eof1(bytes_view container)
{
    auto header = read_valid_eof1_header(container);

    // Extract all code sections as single buffer reference.
    // TODO: It would be much easier if header had code_sections_offset and data_section_offset
    //       with code_offsets[] being relative to code_sections_offset.
    const auto code_sections_offset = header.code_offsets[0];
    const auto code_sections_end = size_t{header.code_offsets.back()} + header.code_sizes.back();
    const auto executable_code =
        container.substr(code_sections_offset, code_sections_end - code_sections_offset);

    return CodeAnalysis{executable_code, std::move(header)};
}
}  // namespace

CodeAnalysis analyze(evmc_revision rev, bytes_view code)
{
    if (rev < EVMC_PRAGUE || !is_eof_container(code))
        return analyze_legacy(code);
    return analyze_eof1(code);
}
}  // namespace evmone::baseline
