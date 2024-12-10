// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_utils.hpp"
#include <evmc/evmc.hpp>
#include <span>
#include <vector>

namespace evmone::state
{
/// `requests` object.
///
/// Defined by EIP-7685: General purpose execution layer requests.
/// https://eips.ethereum.org/EIPS/eip-7685.
struct Requests
{
    /// The type of the requests.
    enum class Type : uint8_t
    {
        /// Deposit requests.
        /// Introduced by EIP-6110 https://eips.ethereum.org/EIPS/eip-6110.
        deposit = 0,

        /// Withdrawal requests.
        /// Introduced by EIP-7002 https://eips.ethereum.org/EIPS/eip-7002.
        withdrawal = 1,

        /// Consolidation requests.
        /// Introduced by EIP-7251 https://eips.ethereum.org/EIPS/eip-7251.
        consolidation = 2,
    };

    /// Requests type.
    Type type = Type::deposit;
    /// Requests data - an opaque byte array, contains zero or more encoded request objects.
    evmc::bytes data;
};

/// Calculate commitment value of block requests list
hash256 calculate_requests_hash(std::span<const Requests> requests_list);

}  // namespace evmone::state
