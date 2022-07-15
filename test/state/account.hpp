// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <unordered_map>

namespace evmone::state
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;

/// The representation of the account storage value.
struct StorageValue
{
    /// The current value.
    bytes32 current{};

    /// The original value.
    bytes32 original{};
};

/// The state account.
struct Account
{
    /// The account nonce.
    uint64_t nonce = 0;

    /// The account balance.
    intx::uint256 balance;

    /// The account storage map.
    std::unordered_map<bytes32, StorageValue> storage;

    /// The account code.
    bytes code;
};
}  // namespace evmone::state
