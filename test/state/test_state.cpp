// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "test_state.hpp"
#include "state.hpp"

namespace evmone::test
{
std::optional<state::StateView::Account> TestState::get_account(address addr) const noexcept
{
    const auto it = find(addr);
    if (it == end())
        return std::nullopt;

    const auto& acc = it->second;
    // TODO: Cache code hash for MTP root hash calculation?
    return Account{acc.nonce, acc.balance, keccak256(acc.code), acc.storage, acc.code};
}

void TestState::apply_diff(const state::StateDiff& diff)
{
    for (const auto& [addr, e] : diff.modified_storage)
    {
        auto& a = (*this)[addr];
        for (const auto& [k, v] : e)
        {
            if (v)
                a.storage.insert_or_assign(k, v);
            else
                a.storage.erase(k);
        }
    }

    for (auto& [addr, m] : diff.modified_accounts)
    {
        auto& a = (*this)[addr];
        if (m.balance)
            a.balance = *m.balance;
        if (m.nonce)
            a.nonce = *m.nonce;
        if (m.code)
            a.code = *m.code;
    }

    for (const auto& addr : diff.deleted_accounts)
        erase(addr);
}
}  // namespace evmone::test
