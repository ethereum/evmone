// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "delegation.hpp"
#include <cassert>

namespace evmone
{
std::optional<evmc::address> get_delegate_address(
    const evmc::HostInterface& host, const evmc::address& addr) noexcept
{
    // Load the code prefix up to the delegation designation size.
    // The HostInterface::copy_code() copies up to the addr's code size
    // and returns the number of bytes copied.
    uint8_t designation_buffer[std::size(DELEGATION_MAGIC) + sizeof(evmc::address)];
    const auto size = host.copy_code(addr, 0, designation_buffer, std::size(designation_buffer));
    const bytes_view designation{designation_buffer, size};

    if (!is_code_delegated(designation))
        return {};

    // Copy the delegate address from the designation buffer.
    evmc::address delegate_address;
    // Assume the designation with the valid magic has also valid length.
    assert(designation.size() == std::size(designation_buffer));
    std::ranges::copy(designation.substr(std::size(DELEGATION_MAGIC)), delegate_address.bytes);
    return delegate_address;
}
}  // namespace evmone
