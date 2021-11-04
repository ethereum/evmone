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
    bytes32 current = {};

    /// The original value.
    bytes32 original = {};

    evmc_access_status access_status = EVMC_ACCESS_COLD;
};

/// The state account.
struct Account
{
    /// The maximum allowed nonce value.
    static constexpr auto NonceMax = std::numeric_limits<uint64_t>::max();

    /// The account nonce.
    uint64_t nonce = 0;

    /// The account balance.
    intx::uint256 balance = {};

    /// The account storage map.
    std::unordered_map<bytes32, StorageValue> storage = {};

    /// The account code.
    bytes code = {};

    /// The account has been destructed and should be erased at the end of of a transaction.
    bool destructed = false;

    /// The account should be erased if it is empty at the end of a transaction.
    /// This flag means the account has been "touched" as defined in EIP-161
    /// or it is a newly created temporary account.
    bool erasable = false;

    evmc_access_status access_status = EVMC_ACCESS_COLD;

    [[nodiscard]] bool is_empty() const noexcept
    {
        return code.empty() && nonce == 0 && balance == 0;
    }
};
}  // namespace evmone::state
