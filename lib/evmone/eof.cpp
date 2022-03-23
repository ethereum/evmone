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
}  // namespace evmone
