// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/bytes.hpp>
#include <evmc/evmc.hpp>

namespace evmone
{
using evmc::bytes_view;

/// Prefix of code for delegated accounts
/// defined by [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)
constexpr uint8_t DELEGATION_MAGIC_BYTES[] = {0xef, 0x01, 0x00};
constexpr bytes_view DELEGATION_MAGIC{DELEGATION_MAGIC_BYTES, std::size(DELEGATION_MAGIC_BYTES)};

/// Check if code contains EIP-7702 delegation designator
inline constexpr bool is_code_delegated(bytes_view code) noexcept
{
    return code.starts_with(DELEGATION_MAGIC);
}
}  // namespace evmone
