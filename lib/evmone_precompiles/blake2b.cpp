// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "blake2b.hpp"
#include <array>

namespace evmone::crypto
{
namespace
{
[[gnu::always_inline]]
inline uint64_t rotr(uint64_t x, unsigned r) noexcept
{
    return (x >> r) | (x << (64 - r));
}

/// Mixing Function G.
/// https://datatracker.ietf.org/doc/html/rfc7693#section-3.1
///
/// The G primitive function mixes two input words, "x" and "y", into
/// four words indexed by "a", "b", "c", and "d" in the working vector v[0..15].
[[gnu::always_inline, clang::no_sanitize("coverage"), clang::no_sanitize("undefined")]]
void g(uint64_t v[16], size_t a, size_t b, size_t c, size_t d, uint64_t x, uint64_t y) noexcept
{
    v[a] = v[a] + v[b] + x;
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 63);
}
}  // namespace

[[clang::no_sanitize("undefined")]]
void blake2b_compress(
    uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2], bool last) noexcept
{
    // Message Schedule SIGMA.
    // https://datatracker.ietf.org/doc/html/rfc7693#section-2.7
    static constexpr uint8_t sigma[10][16]{
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };


    // Initialize local work vector v[0..15].
    uint64_t v[16]{h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],  // First half from state.
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,                     // Second half from IV.
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1 ^ t[0],                  // Low word of the offset.
        0x9b05688c2b3e6c1f ^ t[1],                  // High word.
        0x1f83d9abfb41bd6b ^ (0 - uint64_t{last}),  // Last block flag? Invert all bits.
        0x5be0cd19137e2179};

    // Cryptographic mixing.
    for (size_t i = 0; i < rounds; ++i)
    {
        // Message word selection permutation for this round.
        const auto& s = sigma[i % std::size(sigma)];

        g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (size_t i = 0; i < 8; ++i)  // XOR the two halves.
        h[i] ^= v[i] ^ v[i + 8];
}
}  // namespace evmone::crypto
