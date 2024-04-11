// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <cstdint>

namespace evmone::crypto
{
/// BLAKE2b compress function F.
/// https://datatracker.ietf.org/doc/html/rfc7693#section-3.2
///
/// @param         rounds  the number of rounds to perform
/// @param[in,out] h       the state vector
/// @param         m       the block vector
/// @param         t       the 128-bit offset counter, {low word, high word}
/// @param         last    the final block indicator flag "f"
void blake2b_compress(
    uint32_t rounds, uint64_t h[8], const uint64_t m[16], const uint64_t t[2], bool last) noexcept;
}  // namespace evmone::crypto
