// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef>

namespace evmone::crypto
{
static constexpr std::size_t RIPEMD160_HASH_SIZE = 160 / 8;
void ripemd160(
    std::byte out[RIPEMD160_HASH_SIZE], const std::byte* data, std::size_t size) noexcept;
}  // namespace evmone::crypto
