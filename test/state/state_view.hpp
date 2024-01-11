// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <optional>

namespace evmone::state
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using intx::uint256;

class StateView
{
public:
    struct Account
    {
        uint64_t nonce = 0;
        uint256 balance;
        std::unordered_map<bytes32, bytes32> storage;
        bytes code;
    };

    virtual ~StateView() = default;
    [[nodiscard]] virtual std::optional<Account> get_account(address addr) const noexcept = 0;
};
}  // namespace evmone::state
