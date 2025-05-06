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
// std::unique_ptr<BitsetSpan::word_type[]> analyze_jumpdests(bytes_view code)
// {
//     // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
//     // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
//     // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
//     static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());
//
//     auto map = std::make_unique<BitsetSpan::word_type[]>(
//         (code.size() + sizeof(BitsetSpan::word_type) - 1) /
//         sizeof(BitsetSpan::word_type));  // Allocate and init bitmap with zeros.
//     BitsetSpan s{map.get()};
//     for (size_t i = 0; i < code.size(); ++i)
//     {
//         const auto op = code[i];
//         if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
//             i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
//         else if (INTX_UNLIKELY(op == OP_JUMPDEST))
//             s.set(i);
//     }
//
//     return map;
// }

// std::unique_ptr<uint8_t[]> pad_code(bytes_view code)
// {
//     // We need at most 33 bytes of code padding: 32 for possible missing all data bytes of PUSH32
//     // at the very end of the code; and one more byte for STOP to guarantee there is a terminating
//     // instruction at the code end.
//     constexpr auto padding = 32 + 1;
//
//     auto padded_code = std::make_unique_for_overwrite<uint8_t[]>(code.size() + padding);
//     std::ranges::copy(code, padded_code.get());
//     std::fill_n(&padded_code[code.size()], padding, uint8_t{OP_STOP});
//     return padded_code;
// }


CodeAnalysis analyze_legacy(bytes_view code)
{
    const auto padded_code_size = code.size() + 33;
    const auto aligned_code_size = (padded_code_size + 7) / 8 * 8;
    const auto bitset_size = (code.size() + 7) / 8 * 8;
    const auto total_size = padded_code_size + bitset_size;

    auto d = std::make_unique_for_overwrite<uint8_t[]>(total_size);
    std::ranges::copy(code, d.get());
    std::fill_n(&d[code.size()], total_size - code.size(), 0);

    auto m = new (&d[aligned_code_size]) BitsetSpan::word_type[bitset_size / 8];
    BitsetSpan s{m};

    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            s.set(i);
    }

    // TODO: The padded code buffer and jumpdest bitmap can be created with single allocation.
    return {std::move(d), code.size(), s};
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

    return CodeAnalysis{container, executable_code, std::move(header)};
}
}  // namespace

CodeAnalysis analyze(bytes_view code, bool eof_enabled)
{
    if (eof_enabled && is_eof_container(code))
        return analyze_eof1(code);
    return analyze_legacy(code);
}
}  // namespace evmone::baseline
