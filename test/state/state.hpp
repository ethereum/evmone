// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "bloom_filter.hpp"
#include "hash_utils.hpp"
#include <cassert>
#include <optional>
#include <variant>
#include <vector>

namespace evmone::state
{
class State
{
    std::unordered_map<address, Account> m_accounts;

public:
    /// Inserts the new account at the address.
    /// There must not exist any account under this address before.
    Account& insert(const address& addr, Account account = {})
    {
        const auto r = m_accounts.insert({addr, std::move(account)});
        assert(r.second);
        return r.first->second;
    }

    /// Returns the pointer to the account at the address if the account exists. Null otherwise.
    Account* find(const address& addr) noexcept
    {
        const auto it = m_accounts.find(addr);
        if (it != m_accounts.end())
            return &it->second;
        return nullptr;
    }

    /// Gets the account at the address (the account must exist).
    Account& get(const address& addr) noexcept
    {
        auto acc = find(addr);
        assert(acc != nullptr);
        return *acc;
    }

    /// Gets an existing account or inserts new account.
    Account& get_or_insert(const address& addr, Account account = {})
    {
        if (const auto acc = find(addr); acc != nullptr)
            return *acc;
        return insert(addr, std::move(account));
    }

    /// Touches (as in EIP-161) an existing account or inserts new erasable account.
    Account& touch(const address& addr)
    {
        auto& acc = get_or_insert(addr);
        acc.erasable = true;
        return acc;
    }

    [[nodiscard]] auto& get_accounts() noexcept { return m_accounts; }

    [[nodiscard]] const auto& get_accounts() const noexcept { return m_accounts; }
};

struct Ommer
{
    address beneficiary;  ///< Ommer block beneficiary address.
    uint32_t delta = 0;   ///< Difference between current and ommer block number.
};

struct Withdrawal
{
    uint64_t index = 0;
    uint64_t validator_index = 0;
    address recipient;
    uint64_t amount_in_gwei = 0;  ///< The amount is denominated in gwei.

    /// Returns withdrawal amount in wei.
    [[nodiscard]] intx::uint256 get_amount() const noexcept
    {
        return intx::uint256{amount_in_gwei} * 1'000'000'000;
    }
};

struct BlockInfo
{
    int64_t number = 0;
    int64_t timestamp = 0;
    int64_t parent_timestamp = 0;
    int64_t gas_limit = 0;
    address coinbase;
    int64_t difficulty = 0;
    int64_t parent_difficulty = 0;
    hash256 parent_ommers_hash = {};
    bytes32 prev_randao;
    uint64_t base_fee = 0;
    std::vector<Ommer> ommers = {};
    std::vector<Withdrawal> withdrawals;
    std::unordered_map<int64_t, hash256> known_block_hashes = {};
};

using AccessList = std::vector<std::pair<address, std::vector<bytes32>>>;

struct Transaction
{
    /// The type of the transaction.
    ///
    /// The format is defined by EIP-2718: Typed Transaction Envelope.
    /// https://eips.ethereum.org/EIPS/eip-2718.
    enum class Type : uint8_t
    {
        /// The legacy RLP-encoded transaction without leading "type" byte.
        legacy = 0,

        /// The typed transaction with optional account/storage access list.
        /// Introduced by EIP-2930 https://eips.ethereum.org/EIPS/eip-2930.
        access_list = 1,

        /// The typed transaction with priority gas price.
        /// Introduced by EIP-1559 https://eips.ethereum.org/EIPS/eip-1559.
        eip1559 = 2,
    };

    Type type = Type::legacy;
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    address sender;
    std::optional<address> to;
    intx::uint256 value;
    AccessList access_list;
    uint64_t chain_id = 0;
    uint64_t nonce = 0;
    intx::uint256 r;
    intx::uint256 s;
    uint8_t v = 0;
};

struct Log
{
    address addr;
    bytes data;
    std::vector<hash256> topics;
};

/// Transaction Receipt
///
/// This struct is used in two contexts:
/// 1. As the formally specified, RLP-encode transaction receipt included in the Ethereum blocks.
/// 2. As the internal representation of the transaction execution result.
/// These both roles share most, but not all the information. There are some fields that cannot be
/// assigned in the single transaction execution context. There are also fields that are not a part
/// of the RLP-encoded transaction receipts.
/// TODO: Consider splitting the struct into two based on the duality explained above.
struct TransactionReceipt
{
    Transaction::Type type = Transaction::Type::legacy;
    evmc_status_code status = EVMC_INTERNAL_ERROR;

    /// Amount of gas used by this transaction.
    int64_t gas_used = 0;

    /// Amount of gas used by this and previous transactions in the block.
    int64_t cumulative_gas_used = 0;
    std::vector<Log> logs;
    BloomFilter logs_bloom_filter;

    /// Root hash of the state after this transaction. Used only in old pre-Byzantium transactions.
    std::optional<bytes32> post_state;
};

/// Finalize state after applying a "block" of transactions.
///
/// Applies block reward to coinbase, withdrawals (post Shanghai) and deletes empty touched accounts
/// (post Spurious Dragon).
void finalize(State& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const Ommer> ommers,
    std::span<const Withdrawal> withdrawals);

[[nodiscard]] std::variant<TransactionReceipt, std::error_code> transition(State& state,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm,
    int64_t block_gas_left);

std::variant<int64_t, std::error_code> validate_transaction(const Account& sender_acc,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev,
    int64_t block_gas_left) noexcept;

/// Defines how to RLP-encode a Transaction.
[[nodiscard]] bytes rlp_encode(const Transaction& tx);

/// Defines how to RLP-encode a TransactionReceipt.
[[nodiscard]] bytes rlp_encode(const TransactionReceipt& receipt);

/// Defines how to RLP-encode a Log.
[[nodiscard]] bytes rlp_encode(const Log& log);

/// Defines how to RLP-encode a Withdrawal.
[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal);

}  // namespace evmone::state
