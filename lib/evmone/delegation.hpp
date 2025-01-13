// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/bytes.hpp>
#include <evmc/evmc.hpp>
#include <cassert>

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

/// Get EIP-7702 delegate address from the code of addr, if it is delegated.
inline std::optional<evmc::address> get_delegate_address(
    const evmc::address& addr, const evmc::HostInterface& host) noexcept
{
    uint8_t prefix[std::size(DELEGATION_MAGIC)] = {};
    host.copy_code(addr, 0, prefix, std::size(prefix));

    if (!is_code_delegated(bytes_view{prefix, std::size(prefix)}))
        return {};

    evmc::address delegate_address;
    assert(host.get_code_size(addr) ==
           std::size(DELEGATION_MAGIC) + std::size(delegate_address.bytes));
    host.copy_code(
        addr, std::size(prefix), delegate_address.bytes, std::size(delegate_address.bytes));
    return delegate_address;
}
}  // namespace evmone
