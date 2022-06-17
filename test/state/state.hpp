// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "hash_utils.hpp"
#include <cassert>
#include <optional>
#include <vector>

namespace evmone::state
{
class State
{
    std::unordered_map<address, Account> m_accounts;

public:
    /// Creates new account under the address.
    Account& create(const address& addr)
    {
        const auto r = m_accounts.insert({addr, {}});
        assert(r.second);
        return r.first->second;
    }
};

struct BlockInfo
{
    int64_t number;
    int64_t timestamp;
    int64_t gas_limit;
    address coinbase;
    evmc::uint256be difficulty;
    bytes32 chain_id;
    uint64_t base_fee;
};

using AccessList = std::vector<std::pair<address, std::vector<bytes32>>>;

struct Transaction
{
    enum class Kind
    {
        legacy,
        eip1559
    };

    Kind kind = Kind::legacy;
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    uint64_t nonce;
    address sender;
    std::optional<address> to;
    intx::uint256 value;
    AccessList access_list;
};
}  // namespace evmone::state
