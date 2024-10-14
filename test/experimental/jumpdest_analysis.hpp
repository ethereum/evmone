// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmone/baseline.hpp>
#include <cstdint>
#include <memory>
#include <vector>

namespace evmone::exp::jda
{
inline constexpr bool is_push(uint8_t op) noexcept
{
    return static_cast<int8_t>(op) >= OP_PUSH1;
}

inline constexpr int find_first_push(const uint8_t* code) noexcept
{
    for (int i = 0; i < 8; ++i)
    {
        if (is_push(code[i]))
            return i;
    }
    return -1;
}

inline int find_first_push_opt1(const uint8_t* code) noexcept
{
    uint64_t b;
    __builtin_memcpy(&b, code, sizeof(b));
    b = __builtin_bswap64(b);

    const auto d = (~b) & (b << 1) & (b << 2) & 0x8080808080808080;

    if (d == 0)
        return -1;

    auto z = __builtin_clzll(d);
    auto z2 = z / 8;
    return z2;
}

inline int find_first_push_opt2(const uint8_t* code) noexcept
{
    uint64_t b;
    __builtin_memcpy(&b, code, sizeof(b));
    b = __builtin_bswap64(b);
    uint64_t mask = 0x8080808080808080;

    auto e2 = b << 2;
    auto f2 = b << 1;
    auto g2 = ~b;
    auto d1 = e2 & f2 & g2 & mask;

    if (d1 == 0)
        return -1;

    auto z = __builtin_clzll(d1);
    auto z2 = z / 8;
    return z2;
}

inline int find_first_push_opt3(const uint8_t* code) noexcept
{
    uint64_t b;
    __builtin_memcpy(&b, code, sizeof(b));

    const auto d = (b >> 5) & (b >> 6) & (~b >> 7) & 0x0101010101010101;

    if (d == 0)
        return -1;

    auto z = __builtin_ctzll(d);
    auto z2 = z / 8;
    return z2;
}

class JumpdestBitset : std::vector<bool>
{
public:
    using std::vector<bool>::operator[];

    JumpdestBitset(size_t size) : std::vector<bool>(size) {}

    bool check_jumpdest(size_t index) const noexcept { return index < size() && (*this)[index]; }
};

using JumpdestMap = std::vector<bool>;

inline bool is_jumpdest(const JumpdestMap& jumpdest_map, size_t index) noexcept
{
    return (index < jumpdest_map.size() && jumpdest_map[index]);
}

inline bool is_jumpdest(const uint8_t* code, size_t code_size, size_t index) noexcept
{
    return (index < code_size && code[index] == 0x5b);
}

class bitset32
{
public:
    static constexpr auto bpw = 32;
    using word_type = uint32_t;
    std::unique_ptr<word_type[]> words_;
    std::size_t size_;


    explicit bitset32(std::size_t size)
      : words_{new word_type[(size + 33 + (bpw - 1)) / bpw]}, size_{size}
    {}

    std::size_t size() const noexcept { return size_; }

    bool operator[](std::size_t index) const noexcept
    {
        const auto w = index / bpw;
        const auto x = index % bpw;
        const auto bitmask = word_type{1} << x;
        return (words_[w] & bitmask) != 0;
    }

    void unset(std::size_t index) noexcept
    {
        const auto w = index / bpw;
        const auto x = index % bpw;
        const auto bitmask = word_type(~(word_type{1} << x));
        words_[w] &= bitmask;
    }
};

JumpdestBitset reference(bytes_view code);
JumpdestBitset speculate_push_data_size(bytes_view code);
JumpdestBitset jda_speculate_push_data_size2(bytes_view code);
JumpdestBitset build_jumpdest_map_sttni(bytes_view code);
std::vector<bool> build_jumpdest_map_str_avx2(const uint8_t* code, size_t code_size);
std::vector<bool> build_jumpdest_map_str_avx2_mask(const uint8_t* code, size_t code_size);
std::vector<bool> build_jumpdest_map_str_avx2_mask_v2(const uint8_t* code, size_t code_size);
std::vector<bool> build_jumpdest_map_str_avx2_mask2(const uint8_t* code, size_t code_size);
bitset32 build_jumpdest_map_simd1(const uint8_t* code, size_t code_size);
bitset32 build_jumpdest_map_simd2(const uint8_t* code, size_t code_size);
bitset32 build_jumpdest_map_simd3(const uint8_t* code, size_t code_size);
bitset32 build_jumpdest_map_simd4(const uint8_t* code, size_t code_size);
JumpdestMap build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v1(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v2(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v3(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v4(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v8(const uint8_t* code, size_t code_size);
}  // namespace evmone::exp::jda
