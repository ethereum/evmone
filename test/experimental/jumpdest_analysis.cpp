// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include "opcode_manip.hpp"
#include <evmc/instructions.h>
#include <evmone/baseline.hpp>
#include <x86intrin.h>
#include <cstring>
#include <limits>

namespace evmone::experimental
{
JumpdestMap official_analyze_jumpdests(const uint8_t* code, size_t code_size)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    evmone::experimental::JumpdestMap map(code_size);  // Allocate and init bitmap with zeros.
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            map[i] = true;
    }

    return map;
}


inline constexpr size_t get_push_data_size(uint8_t op) noexcept
{
    return op - size_t{OP_PUSH1 - 1};
}

struct pushdata_info
{
    uint32_t mask;
    size_t offset;
};
static pushdata_info build_pushdata_mask(const uint8_t* code, uint32_t push_mask)
{
    size_t pos = 0;
    uint32_t pushdata_mask = 0;

    while (push_mask)
    {
        pos = static_cast<uint32_t>(__builtin_ctz(push_mask));
        const auto op = code[pos];
        const auto len = get_push_data_size(op);
        const auto len_mask = len <= 31 ? ~uint32_t{0} >> (31 - len) : ~uint32_t{0};
        const auto part_mask = len_mask << pos;
        pushdata_mask |= part_mask;
        pos += 1 + len;
        if (pos >= 32)
            return {pushdata_mask, pos};

        push_mask &= ~part_mask;
    }

    return {pushdata_mask, 32};
}

std::vector<bool> build_jumpdest_map_vec1(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (is_push(op))
            i += get_push_data_size(op);
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_vec2(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_vec3(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= static_cast<int8_t>(OP_PUSH1))
            i += get_push_data_size(op);
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_sttni(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);

    __m128i match_ranges{};
    match_ranges = _mm_insert_epi8(match_ranges, OP_PUSH1, 0);
    match_ranges = _mm_insert_epi8(match_ranges, OP_PUSH32, 1);
    match_ranges = _mm_insert_epi8(match_ranges, OP_JUMPDEST, 2);
    match_ranges = _mm_insert_epi8(match_ranges, OP_JUMPDEST, 3);

    const auto match_imm = _SIDD_UBYTE_OPS | _SIDD_CMP_RANGES;


    size_t v_code_size = code_size >= 16 ? code_size - 15 : 0;
    size_t i = 0;
    for (; i < v_code_size;)
    {
        const auto data = _mm_loadu_si128((const __m128i*)&code[i]);
        const auto first_match = (unsigned)_mm_cmpestri(match_ranges, 4, data, 16, match_imm);

        i += first_match;
        if (first_match < 16)
        {
            const auto op = code[i];
            if (__builtin_expect(static_cast<int8_t>(op) >= OP_PUSH1, true))
                i += get_push_data_size(op) + 1;
            else
                m[i++] = true;
        }
    }

    for (; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_str_avx2(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);

    const auto all_jumpdest = _mm256_set1_epi8(OP_JUMPDEST);
    const auto all_push1 = _mm256_set1_epi8(OP_PUSH1 - 1);

    size_t v_code_size = code_size >= 32 ? code_size - 31 : 0;
    size_t i = 0;
    for (; i < v_code_size;)
    {
        const auto data = _mm256_loadu_si256((const __m256i*)&code[i]);
        const auto is_push = _mm256_cmpgt_epi8(data, all_push1);
        const auto is_jumpdest = _mm256_cmpeq_epi8(data, all_jumpdest);
        const auto is_interesting = _mm256_or_si256(is_push, is_jumpdest);
        const auto mask = (unsigned)_mm256_movemask_epi8(is_interesting);
        const auto first_match = mask ? (unsigned)__builtin_ctz(mask) : 32;

        i += first_match;
        if (mask)
        {
            const auto op = code[i];
            if (__builtin_expect(static_cast<int8_t>(op) >= OP_PUSH1, true))
                i += get_push_data_size(op) + 1;
            else
                m[i++] = true;
        }
    }

    for (; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_str_avx2_mask(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);

    const auto all_jumpdest = _mm256_set1_epi8(OP_JUMPDEST);
    const auto all_push1 = _mm256_set1_epi8(OP_PUSH1 - 1);

    size_t v_code_size = code_size >= 32 ? code_size - 31 : 0;
    size_t i = 0;
    for (; i < v_code_size;)
    {
        const auto data = _mm256_loadu_si256((const __m256i*)&code[i]);
        const auto is_push = _mm256_cmpgt_epi8(data, all_push1);
        const auto is_jumpdest = _mm256_cmpeq_epi8(data, all_jumpdest);
        auto push_mask = (unsigned)_mm256_movemask_epi8(is_push);
        auto jumpdest_mask = (unsigned)_mm256_movemask_epi8(is_jumpdest);
        auto mask = push_mask | jumpdest_mask;

        if (!mask)
        {
            i += 32;
            continue;
        }

        const auto end = i + 32;
        while (true)
        {
            auto progress = (unsigned)__builtin_ctz(mask);
            const auto op = code[i + progress];
            if (__builtin_expect(static_cast<int8_t>(op) >= OP_PUSH1, true))
            {
                progress += unsigned(get_push_data_size(op) + 1);
            }
            else
            {
                m[i + progress] = true;
                progress += 1;
            }

            i += progress;
            if (i >= end)
                break;

            mask >>= progress;
            if (!mask)
            {
                i = end;
                break;
            }
        }
    }

    for (; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_str_avx2_mask_v2(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);

    const auto all_jumpdest = _mm256_set1_epi8(OP_JUMPDEST);
    const auto all_push1 = _mm256_set1_epi8(OP_PUSH1 - 1);

    size_t v_code_size = code_size >= 32 ? code_size - 31 : 0;
    size_t i = 0;
    for (; i < v_code_size;)
    {
        const auto data = _mm256_loadu_si256((const __m256i*)&code[i]);
        const auto is_push = _mm256_cmpgt_epi8(data, all_push1);
        const auto is_jumpdest = _mm256_cmpeq_epi8(data, all_jumpdest);
        const auto is_interesting = _mm256_or_si256(is_push, is_jumpdest);
        auto mask = (unsigned)_mm256_movemask_epi8(is_interesting);

        if (!mask)
        {
            i += 32;
            continue;
        }

        const auto end = i + 32;
        while (true)
        {
            auto progress = (unsigned)__builtin_ctz(mask);
            const auto op = code[i + progress];
            if (__builtin_expect(static_cast<int8_t>(op) >= OP_PUSH1, true))
            {
                progress += unsigned(get_push_data_size(op) + 1);
            }
            else
            {
                m[i + progress] = true;
                progress += 1;
            }

            i += progress;
            if (i >= end)
                break;

            mask >>= progress;
            if (!mask)
            {
                i = end;
                break;
            }
        }
    }

    for (; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}

std::vector<bool> build_jumpdest_map_str_avx2_mask2(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);

    const auto all_jumpdest = _mm256_set1_epi8(OP_JUMPDEST);
    const auto all_push1 = _mm256_set1_epi8(OP_PUSH1 - 1);

    size_t v_code_size = code_size >= 32 ? code_size - 31 : 0;
    size_t i = 0;
    for (; i < v_code_size;)
    {
        const auto data = _mm256_loadu_si256((const __m256i*)&code[i]);
        const auto is_push = _mm256_cmpgt_epi8(data, all_push1);
        const auto is_jumpdest = _mm256_cmpeq_epi8(data, all_jumpdest);
        auto push_mask = (unsigned)_mm256_movemask_epi8(is_push);
        auto jumpdest_mask = (unsigned)_mm256_movemask_epi8(is_jumpdest);

        const auto [pushdata_mask, offset] = build_pushdata_mask(&code[i], push_mask);

        jumpdest_mask &= ~pushdata_mask;

        size_t pos = 0;
        while (jumpdest_mask)
        {
            const auto x = static_cast<uint32_t>(__builtin_ctz(jumpdest_mask));
            pos += x;
            m[i + pos] = true;
            if (x >= 31)
                break;
            jumpdest_mask >>= x + 1;
            pos += 1;
        }

        i += offset;
    }

    for (; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto potential_push_data_len = get_push_data_size(op);
        if (potential_push_data_len <= 32)
            i += potential_push_data_len;
        else if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
    }
    return m;
}


JumpdestMap build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size)
{
    JumpdestMap m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
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

    uint32_t clear_next = 0;
    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        const auto* ptr = &code[v_begin];

        const auto v1 = _mm256_loadu_si256((const __m256i*)ptr);
        const auto v_jmpd = _mm256_set1_epi8(OP_JUMPDEST);
        const auto v_eq = _mm256_cmpeq_epi8(v1, v_jmpd);
        auto j_mask = static_cast<uint32_t>(_mm256_movemask_epi8(v_eq));

        uint64_t clear_mask = clear_next;
        const auto skip = clear_next ? 32 - size_t(__builtin_clz(clear_next)) : 0;
        for (size_t j = skip; j < v_size; ++j)
        {
            const auto c = code[v_begin + j];
            if (is_push(c))
            {
                const auto p = get_push_data_size(c);

                uint64_t mask = ~uint64_t{0};
                mask >>= (64 - p);
                mask <<= ((j + 1) % 64);

                clear_mask |= mask;

                j += p;
            }
        }

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

bitset32 build_jumpdest_map_simd3(const uint8_t* code, size_t code_size)
{
    constexpr auto v_size = 32;

    bitset32 jumpdest_map(code_size);

    const auto v_code_size = code_size / v_size;
    const auto v_tail_size = code_size % v_size;

    const auto v_jmpd = _mm256_set1_epi8(OP_JUMPDEST);
    const auto v_push0 = _mm256_set1_epi8(OP_PUSH0);
    uint32_t clear_next = 0;
    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        const auto* ptr = &code[v_begin];

        const auto v_code = _mm256_loadu_si256((const __m256i*)ptr);
        const auto v_eq = _mm256_cmpeq_epi8(v_code, v_jmpd);
        auto j_mask = static_cast<uint32_t>(_mm256_movemask_epi8(v_eq));

        const auto v_push_locs = _mm256_cmpgt_epi8(v_code, v_push0);
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
            push_locs &= static_cast<uint32_t>(~clear_mask);
        }

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

bitset32 build_jumpdest_map_simd4(const uint8_t* code, size_t code_size)
{
    static constexpr auto v_size = 32;

    bitset32 jumpdest_map(code_size);

    const auto v_code_size = code_size / v_size;
    const auto v_tail_size = code_size % v_size;

    const auto v_jumpdes_op = _mm256_set1_epi8(OP_JUMPDEST);
    const auto v_push0_op = _mm256_set1_epi8(OP_PUSH0);
    uint32_t clear_next = 0;

    for (size_t v = 0; v < v_code_size; ++v)
    {
        const auto v_begin = v * v_size;
        const auto* ptr = &code[v_begin];

        const auto v_fragment = _mm256_loadu_si256((const __m256i*)ptr);
        const auto v_is_push = _mm256_cmpgt_epi8(v_fragment, v_push0_op);
        auto m_is_push = (unsigned)_mm256_movemask_epi8(v_is_push);

        m_is_push &= ~clear_next;
        uint64_t datamask = clear_next;

        // #pragma unroll 1
        while (m_is_push != 0)
        {
            const auto p = __builtin_ctz(m_is_push);
            const auto op = ptr[p];
            const auto dl = op - OP_PUSH0;
            const auto dm = ((uint64_t{2} << dl) - 1) << p;
            datamask |= dm;
            m_is_push &= ~static_cast<unsigned>(dm);
        }

        const auto v_is_jumpdest = _mm256_cmpeq_epi8(v_fragment, v_jumpdes_op);
        auto m_is_jumpdest = (unsigned)_mm256_movemask_epi8(v_is_jumpdest);

        m_is_jumpdest &= ~static_cast<unsigned>(datamask);
        jumpdest_map.words_[v] = m_is_jumpdest;
        clear_next = static_cast<uint32_t>(datamask >> 32);
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
        if (push_data != 0)
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
