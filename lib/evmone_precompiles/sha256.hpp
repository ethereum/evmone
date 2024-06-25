// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The Silkworm & evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>

namespace evmone::crypto
{
/// The size (32 bytes) of the SHA256 message digest.
static constexpr std::size_t SHA256_HASH_SIZE = 256 / 8;

/// Computes the SHA256 hash function.
///
/// @param[out] hash  The result message digest is written to the provided memory.
/// @param      data  The input data.
/// @param      size  The size of the input data.
void sha256(std::byte hash[SHA256_HASH_SIZE], const std::byte* data, size_t size);
}  // namespace evmone::crypto
