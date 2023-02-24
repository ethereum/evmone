// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "mpt_hash.hpp"
#include "account.hpp"
#include "mpt.hpp"
#include "rlp.hpp"
#include "state.hpp"

namespace evmone::state
{
namespace
{
hash256 mpt_hash(const std::unordered_map<hash256, StorageValue>& storage)
{
    MPT trie;
    for (const auto& [key, value] : storage)
    {
        if (!is_zero(value.current))  // Skip "deleted" values.
            trie.insert(keccak256(key), rlp::encode(rlp::trim(value.current)));
    }
    return trie.hash();
}
}  // namespace

hash256 mpt_hash(const std::unordered_map<address, Account>& accounts)
{
    MPT trie;
    for (const auto& [addr, acc] : accounts)
    {
        trie.insert(keccak256(addr),
            rlp::encode_tuple(acc.nonce, acc.balance, mpt_hash(acc.storage), keccak256(acc.code)));
    }
    return trie.hash();
}

hash256 mpt_hash(std::span<const Transaction> transactions)
{
    MPT trie;
    for (size_t i = 0; i < transactions.size(); ++i)
        trie.insert(rlp::encode(i), rlp::encode(transactions[i]));

    return trie.hash();
}

hash256 mpt_hash(std::span<const TransactionReceipt> receipts)
{
    MPT trie;
    for (size_t i = 0; i < receipts.size(); ++i)
        trie.insert(rlp::encode(i), rlp::encode(receipts[i]));

    return trie.hash();
}

}  // namespace evmone::state
