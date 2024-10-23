// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include <evmone/instructions_opcodes.hpp>

namespace evmone::exp::jda
{
using enum Opcode;

namespace
{
size_t get_push_data_size(uint8_t op) noexcept
{
    return op - size_t{OP_PUSH1 - 1};
}
}  // namespace

/// The reference implementation of the EVM jumpdest analysis.
JumpdestBitset reference(bytes_view code)
{
    JumpdestBitset m(code.size());
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)
            i += op - (OP_PUSH1 - 1);
        else if (op == OP_JUMPDEST) [[unlikely]]
            m[i] = true;
    }
    return m;
}

JumpdestBitset speculate_push_data_size(bytes_view code)
{
    JumpdestBitset m(code.size());
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (op == OP_JUMPDEST) [[unlikely]]
            m[i] = true;
    }
    return m;
}

}  // namespace evmone::exp::jda
