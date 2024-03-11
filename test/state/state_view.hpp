// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <optional>
#include <unordered_map>
#include <unordered_set>

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
        bytes32 code_hash;
    };

    virtual ~StateView() = default;
    [[nodiscard]] virtual std::optional<Account> get_account(address addr) const noexcept = 0;
    [[nodiscard]] virtual bytes get_account_code(address addr) const noexcept = 0;
    [[nodiscard]] virtual bytes32 get_storage(address addr, bytes32 key) const noexcept = 0;
    [[nodiscard]] virtual bytes32 get_block_hash(int64_t n) const = 0;
};

struct StateDiff
{
    struct Account
    {
        std::optional<uint64_t> nonce;
        std::optional<intx::uint256> balance;
        std::optional<bytes> code;
    };

    silkworm::FlatHashMap<address, Account> modified_accounts;
    silkworm::FlatHashSet<address> deleted_accounts;
    silkworm::FlatHashMap<address, silkworm::FlatHashMap<bytes32, bytes32>> modified_storage;
};
}  // namespace evmone::state
