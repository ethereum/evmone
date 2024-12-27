// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_utils.hpp"
#include "transaction.hpp"
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

    /// Raw encoded data of requests object: first byte is type, the rest is request objects.
    evmc::bytes raw_data;

    explicit Requests(Type _type, evmc::bytes_view data = {})
    {
        raw_data.reserve(1 + data.size());
        raw_data += static_cast<uint8_t>(_type);
        raw_data += data;
    }

    /// Requests type.
    Type type() const noexcept { return static_cast<Type>(raw_data[0]); }

    /// Requests data - an opaque byte array, contains zero or more encoded request objects.
    evmc::bytes_view data() const noexcept { return {raw_data.data() + 1, raw_data.size() - 1}; }

    /// Append data to requests object byte array.
    void append(bytes_view data) { raw_data.append(data); }
};

/// Calculate commitment value of block requests list
hash256 calculate_requests_hash(std::span<const Requests> requests_list);

/// Construct requests object from logs of the deposit contract.
Requests collect_deposit_requests(std::span<const TransactionReceipt> receipts);
}  // namespace evmone::state
