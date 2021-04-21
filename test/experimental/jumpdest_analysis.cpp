// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include "opcode_manip.hpp"
#include <evmc/instructions.h>
#include <evmone/baseline.hpp>

#include <x86intrin.h>

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

bitset32 build_jumpdest_map_simd1(const uint8_t* code, size_t code_size)
{
    constexpr auto v_size = 32;

    std::vector<uint8_t> push_map;
    push_map.resize(code_size);

    bitset32 jumpdest_map(code_size);

    const auto v_code_size = code_size / v_size;

    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        const auto* p = &code[v_begin];

        const auto v1 = _mm256_loadu_si256((const __m256i*)p);
        const auto v_jmpd = _mm256_set1_epi8(OP_JUMPDEST);
        const auto v_eq = _mm256_cmpeq_epi8(v1, v_jmpd);
        const auto mask = static_cast<uint32_t>(_mm256_movemask_epi8(v_eq));

        jumpdest_map.words_[v] = mask;

        for (size_t j = v_begin; j < v_begin + v_size; ++j)
        {
            const auto c = code[j];
            if (is_push(c))
                push_map[j] = static_cast<uint8_t>(get_push_data_size(c));
        }
    }

    uint32_t w = 0;
    for (size_t i = v_code_size * v_size; i < code_size; ++i)
    {
        const auto c = code[i];
        if (c == OP_JUMPDEST)
            w |= (1u << (i - v_code_size * v_size));

        if (is_push(c))
            push_map[i] = static_cast<uint8_t>(get_push_data_size(c));
    }
    jumpdest_map.words_[v_code_size] = w;

    for (size_t i = 0; i < code_size; ++i)
    {
        const auto p = push_map[i];
        if (p > 0)
        {
            const auto s = i + 1;
            const auto v = s / 32;
            const auto u = s % 32;
            uint64_t dw = (uint64_t{jumpdest_map.words_[v + 1]} << 32) | jumpdest_map.words_[v];

            uint64_t mask = ~uint64_t{0};
            mask >>= (64 - p);
            mask <<= u;
            dw &= ~mask;

            jumpdest_map.words_[v] = static_cast<uint32_t>(dw);
            jumpdest_map.words_[v + 1] = static_cast<uint32_t>(dw >> 32);
            i += p;
        }
    }

    return jumpdest_map;
}


bitset32 build_jumpdest_map_simd2(const uint8_t* code, size_t code_size)
{
    constexpr auto v_size = 32;

    bitset32 jumpdest_map(code_size);

    const auto v_code_size = code_size / v_size;
    const auto v_tail_size = code_size % v_size;

    const auto v_jmpd = _mm256_set1_epi8(OP_JUMPDEST);
    const auto v_push_mask = _mm256_set1_epi8(static_cast<char>(0xe0));
    const auto v_push_pattern = _mm256_set1_epi8(0x60);
    uint32_t clear_next = 0;
    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        const auto* ptr = &code[v_begin];

        const auto v_code = _mm256_loadu_si256((const __m256i*)ptr);
        const auto v_eq = _mm256_cmpeq_epi8(v_code, v_jmpd);
        auto j_mask = static_cast<uint32_t>(_mm256_movemask_epi8(v_eq));

        const auto v_push_locs =
            _mm256_cmpeq_epi8(_mm256_and_si256(v_code, v_push_mask), v_push_pattern);
        auto push_locs = static_cast<uint32_t>(_mm256_movemask_epi8(v_push_locs));

        push_locs &= ~clear_next;
        uint64_t clear_mask = clear_next;

        while (push_locs)
        {
            const size_t j = static_cast<size_t>(__builtin_ctz(push_locs));
            const auto p = get_push_data_size(code[v_begin + j]);

            uint64_t mask = ~uint64_t{0};
            mask >>= (64 - (p + 1));
            mask <<= j;

            clear_mask |= mask;
            push_locs &= ~clear_mask;
        }

        // const auto skip = clear_next ? 32 - size_t(__builtin_clz(clear_next)) : 0;
        // for (size_t j = skip; j < v_size; ++j)
        // {
        //     const auto c = code[v_begin + j];
        //
        //     if (((push_locs >> j) & 1) != is_push(c))
        //         __builtin_trap();
        //
        //     if (is_push(c))
        //     {
        //         const auto p = get_push_data_size(c);
        //
        //         uint64_t mask = ~uint64_t{0};
        //         mask >>= (64 - p);
        //         mask <<= ((j + 1) % 64);
        //
        //         clear_mask |= mask;
        //
        //         j += p;
        //     }
        // }

        clear_next = static_cast<uint32_t>(clear_mask >> 32);

        j_mask &= ~static_cast<uint32_t>(clear_mask);
        jumpdest_map.words_[v] = j_mask;
    }

    uint32_t j_mask = 0;
    const auto skip = clear_next ? 32 - size_t(__builtin_clz(clear_next)) : 0;
    for (size_t j = skip; j < v_tail_size; ++j)
    {
        const auto base = code_size - v_tail_size;
        const auto c = code[base + j];
        if (c == OP_JUMPDEST)
            j_mask |= (1u << j);

        if (is_push(c))
        {
            const auto p = get_push_data_size(c);
            j += p;
        }
    }
    jumpdest_map.words_[v_code_size] = j_mask;

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
