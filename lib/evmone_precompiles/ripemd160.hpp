// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef>

namespace evmone::crypto
{
/// The size (20 bytes) of the RIPEMD-160 message digest.
static constexpr std::size_t RIPEMD160_HASH_SIZE = 160 / 8;

/// Computes the RIPEMD-160 hash function.
///
/// @param[out] hash  The result message digest is written to the provided memory.
/// @param      data  The input data.
/// @param      size  The size of the input data.
void ripemd160(
    std::byte hash[RIPEMD160_HASH_SIZE], const std::byte* data, std::size_t size) noexcept;

}  // namespace evmone::crypto
