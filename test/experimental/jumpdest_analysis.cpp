// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include <evmc/instructions.h>
#include <evmone/baseline.hpp>

namespace evmone::experimental
{
inline constexpr bool is_push(uint8_t op) noexcept
{
    return (op >> 5) == 0b11;
}

inline constexpr size_t get_push_data_size(uint8_t op) noexcept
{
    return op - size_t{OP_PUSH1 - 1};
}

std::vector<bool> build_jumpdest_map_vec1(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (op == OP_JUMPDEST)
            m[i] = true;
        else if (is_push(op))
            i += get_push_data_size(op);
    }
    return m;
}

JumpdestMap build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size)
{
    JumpdestMap m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (op == OP_JUMPDEST)
            m.set(i);
        else if (is_push(op))
            i += get_push_data_size(op);
    }
    return m;
}

static constexpr size_t padding = 33;

std::unique_ptr<uint8_t[]> build_internal_code_v1(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        m[i] = op;
        if (is_push(op))
        {
            const auto s = get_push_data_size(op);
            std::memset(&m[i + 1], 0, s);
            i += s;
        }
    }
    std::memset(&m[code_size], 0, padding);
    return m;
}

std::unique_ptr<uint8_t[]> build_internal_code_v2(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    long push_data = 0;
    for (size_t i = 0; i < code_size; ++i)
    {
        if (push_data != 0) [[unlikely]]
        {
            --push_data;
            m[i] = 0;
        }
        else
        {
            const auto op = code[i];
            m[i] = op;
            if (is_push(op))
                push_data = static_cast<long>(get_push_data_size(op));
        }
    }
    std::memset(&m[code_size], 0, padding);
    return m;
}

std::unique_ptr<uint8_t[]> build_internal_code_v3(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    std::memcpy(&m[0], code, code_size);
    std::memset(&m[code_size], 0, padding);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = m[i];
        if (is_push(op))
        {
            const auto s = get_push_data_size(op);
            std::memset(&m[i + 1], 0, s);
            i += s;
        }
    }
    return m;
}

}  // namespace evmone::experimental
