// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/instructions.h>

namespace evmone::experimental
{
inline constexpr bool is_push(uint8_t op) noexcept
{
    return (op & 0xe0) == 0x60;
    // TODO: check what is better. return (op >> 5) == 0b11;
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
}  // namespace evmone::experimental
