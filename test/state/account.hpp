// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <silkworm/core/common/hash_maps.hpp>

namespace evmone::state
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using namespace evmc::literals;

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

    static constexpr auto EMPTY_CODE_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

    /// The account nonce.
    uint64_t nonce = 0;

    /// The account balance.
    intx::uint256 balance;

    bytes32 code_hash = EMPTY_CODE_HASH;

    /// The account storage map.
    silkworm::FlatHashMap<bytes32, StorageValue> _storage;

    silkworm::FlatHashMap<bytes32, bytes32> transient_storage;

    /// The account code.
    bytes _code;

    /// The account has been destructed and should be erased at the end of of a transaction.
    bool destructed = false;

    /// The account should be erased if it is empty at the end of a transaction.
    /// This flag means the account has been "touched" as defined in EIP-161
    /// or it is a newly created temporary account.
    ///
    /// Yellow Paper uses term "delete" but it is a keyword in C++ while
    /// the term "erase" is used for deleting objects from C++ collections.
    bool erase_if_empty = false;

    /// The account has been created in the current transaction.
    bool just_created = false;

    evmc_access_status access_status = EVMC_ACCESS_COLD;

    [[nodiscard]] bool is_empty() const noexcept
    {
        return code_hash == EMPTY_CODE_HASH && nonce == 0 && balance == 0;
    }
};
}  // namespace evmone::state
