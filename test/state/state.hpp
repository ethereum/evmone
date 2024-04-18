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
/// The Ethereum State: the collection of accounts mapped by their addresses.
///
/// TODO: This class is copyable for testing. Consider making it non-copyable.
class State
{
    struct JournalBase
    {
        address addr;
    };

    struct JournalBalanceChange : JournalBase
    {
        intx::uint256 prev_balance;
    };

    struct JournalTouched : JournalBase
    {};

    struct JournalStorageChange : JournalBase
    {
        bytes32 key;
        bytes32 prev_value;
        evmc_access_status prev_access_status;
    };

    struct JournalTransientStorageChange : JournalBase
    {
        bytes32 key;
        bytes32 prev_value;
    };

    struct JournalNonceBump : JournalBase
    {};

    struct JournalCreate : JournalBase
    {
        bool existed;
    };

    struct JournalDestruct : JournalBase
    {};

    struct JournalAccessAccount : JournalBase
    {};

    using JournalEntry =
        std::variant<JournalBalanceChange, JournalTouched, JournalStorageChange, JournalNonceBump,
            JournalCreate, JournalTransientStorageChange, JournalDestruct, JournalAccessAccount>;

    std::unordered_map<address, Account> m_accounts;

    /// The state journal: the list of changes made in the state
    /// with information how to revert them.
    std::vector<JournalEntry> m_journal;

public:
    /// Inserts the new account at the address.
    /// There must not exist any account under this address before.
    Account& insert(const address& addr, Account account = {});

    /// Returns the pointer to the account at the address if the account exists. Null otherwise.
    Account* find(const address& addr) noexcept;

    /// Gets the account at the address (the account must exist).
    Account& get(const address& addr) noexcept;

    /// Gets an existing account or inserts new account.
    Account& get_or_insert(const address& addr, Account account = {});

    [[nodiscard]] auto& get_accounts() noexcept { return m_accounts; }

    [[nodiscard]] const auto& get_accounts() const noexcept { return m_accounts; }

    /// Returns the state journal checkpoint. It can be later used to in rollback()
    /// to revert changes newer than the checkpoint.
    [[nodiscard]] size_t checkpoint() const noexcept { return m_journal.size(); }

    /// Reverts state changes made after the checkpoint.
    void rollback(size_t checkpoint);

    /// Methods performing changes to the state which can be reverted by rollback().
    /// @{

    /// Touches (as in EIP-161) an existing account or inserts new erasable account.
    Account& touch(const address& addr);

    void journal_balance_change(const address& addr, const intx::uint256& prev_balance);

    void journal_storage_change(const address& addr, const bytes32& key, const StorageValue& value);

    void journal_transient_storage_change(
        const address& addr, const bytes32& key, const bytes32& value);

    void journal_bump_nonce(const address& addr);

    void journal_create(const address& addr, bool existed);

    void journal_destruct(const address& addr);

    void journal_access_account(const address& addr);

    /// @}
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
    /// Max amount of blob gas allowed in block. It's constant now but can be dynamic in the future.
    static constexpr int64_t MAX_BLOB_GAS_PER_BLOCK = 786432;

    int64_t number = 0;
    int64_t timestamp = 0;
    int64_t parent_timestamp = 0;
    int64_t gas_limit = 0;
    address coinbase;
    int64_t difficulty = 0;
    int64_t parent_difficulty = 0;
    hash256 parent_ommers_hash;
    bytes32 prev_randao;
    hash256 parent_beacon_block_root;
    uint64_t base_fee = 0;

    /// The "excess blob gas" parameter from EIP-4844
    /// for computing the blob gas price in the current block.
    uint64_t excess_blob_gas = 0;

    /// The blob gas price parameter from EIP-4844.
    /// This values is not stored in block headers directly but computed from excess_blob_gas.
    intx::uint256 blob_base_fee = 0;

    std::vector<Ommer> ommers;
    std::vector<Withdrawal> withdrawals;
    std::unordered_map<int64_t, hash256> known_block_hashes;
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

        /// The typed blob transaction (with array of blob hashes).
        /// Introduced by EIP-4844 https://eips.ethereum.org/EIPS/eip-4844.
        blob = 3,

        /// The typed transaction with initcode list.
        initcodes = 4,
    };

    /// Returns amount of blob gas used by this transaction
    [[nodiscard]] int64_t blob_gas_used() const
    {
        static constexpr auto GAS_PER_BLOB = 0x20000;
        return GAS_PER_BLOB * static_cast<int64_t>(blob_hashes.size());
    }

    Type type = Type::legacy;
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    intx::uint256 max_blob_gas_price;
    address sender;
    std::optional<address> to;
    intx::uint256 value;
    AccessList access_list;
    std::vector<bytes32> blob_hashes;
    uint64_t chain_id = 0;
    uint64_t nonce = 0;
    intx::uint256 r;
    intx::uint256 s;
    uint8_t v = 0;
    std::vector<bytes> initcodes;
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

/// Computes the current blob gas price based on the excess blob gas.
intx::uint256 compute_blob_gas_price(uint64_t excess_blob_gas) noexcept;

/// Finalize state after applying a "block" of transactions.
///
/// Applies block reward to coinbase, withdrawals (post Shanghai) and deletes empty touched accounts
/// (post Spurious Dragon).
void finalize(State& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const Ommer> ommers,
    std::span<const Withdrawal> withdrawals);

[[nodiscard]] std::variant<TransactionReceipt, std::error_code> transition(State& state,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm,
    int64_t block_gas_left, int64_t blob_gas_left);

std::variant<int64_t, std::error_code> validate_transaction(const Account& sender_acc,
    const BlockInfo& block, const Transaction& tx, evmc_revision rev, int64_t block_gas_left,
    int64_t blob_gas_left) noexcept;

/// Performs the system call.
///
/// Executes code at pre-defined accounts from the system sender (0xff...fe).
/// The sender's nonce is not increased.
void system_call(State& state, const BlockInfo& block, evmc_revision rev, evmc::VM& vm);

/// Defines how to RLP-encode a Transaction.
[[nodiscard]] bytes rlp_encode(const Transaction& tx);

/// Defines how to RLP-encode a TransactionReceipt.
[[nodiscard]] bytes rlp_encode(const TransactionReceipt& receipt);

/// Defines how to RLP-encode a Log.
[[nodiscard]] bytes rlp_encode(const Log& log);

/// Defines how to RLP-encode a Withdrawal.
[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal);

}  // namespace evmone::state
