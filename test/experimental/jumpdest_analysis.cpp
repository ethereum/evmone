// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include "opcode_manip.hpp"
#include <evmc/instructions.h>
#include <evmone/baseline.hpp>

namespace evmone::experimental
{
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

bitset build_jumpdest_map_simd1(const uint8_t* code, size_t code_size)
{
    constexpr auto v_size = 32;

    std::vector<uint8_t> push_map;
    push_map.resize(code_size);

    bitset jumpdest_map(code_size + 33);

    const auto v_code_size = code_size / v_size;

    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        for (size_t j = v_begin; j < v_begin + v_size; ++j)
        {
            const auto c = code[j];
            if (is_push(c))
                push_map[j] = static_cast<uint8_t>(get_push_data_size(c));

            if (c == OP_JUMPDEST)
                jumpdest_map.set(j);
        }
    }

    for (size_t i = v_code_size; i < code_size; ++i)
    {
        const auto c = code[i];
        if (is_push(c))
            push_map[i] = static_cast<uint8_t>(get_push_data_size(c));

        if (c == OP_JUMPDEST)
            jumpdest_map.set(i);
    }

    for (size_t i = 0; i < code_size; ++i)
    {
        const auto p = push_map[i];
        if (p > 0)
        {
            for (size_t j = i + 1; j <= i + p; ++j)
                jumpdest_map.unset(j);
            i += p;
        }
    }

    jumpdest_map.set_size(code_size);
    return jumpdest_map;
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

std::unique_ptr<uint8_t[]> build_internal_code_v4(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    auto p = m.get();
    const auto end = p + code_size;

    std::memcpy(p, code, code_size);
    std::memset(end, OP_PUSH1, padding);

    while (true)
    {
        const auto op = *p++;
        if (is_push(op))
        {
            if (p > end)
                break;
            const auto s = get_push_data_size(op);
            for (size_t i = 0; i < s; ++i)
            {
                if (*p == OP_JUMPDEST)
                    *p = 0;
                ++p;
            }
        }
    }
    std::memset(end, 0, padding);
    return m;
}

std::unique_ptr<uint8_t[]> build_internal_code_v8(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    std::memcpy(&m[0], code, code_size);
    std::memset(&m[code_size], 0, padding);

    size_t i = 0;

    while (i < code_size)
    {
        const auto pos = find_first_push_opt3(&m[i]);
        if (pos < 0)
        {
            i += 8;
        }
        else
        {
            i += static_cast<size_t>(pos);
            const auto op = m[i];
            ++i;
            const auto s = get_push_data_size(op);
            std::memset(&m[i], 0, s);
            i += s;
        }
    }
    return m;
}

}  // namespace evmone::experimental
