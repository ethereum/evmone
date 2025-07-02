// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <span>
#include <cstdint>

namespace evmone::crypto
{
bool modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp, std::span<const uint8_t> mod, uint8_t* output) noexcept;
}
