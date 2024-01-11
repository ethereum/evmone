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
    return Account{acc.nonce, acc.balance, acc.storage, acc.code};
}

TestState::TestState(const state::State& intra_state)
{
    for (const auto& [addr, acc] : intra_state.get_accounts())
    {
        auto& test_acc =
            (*this)[addr] = {.nonce = acc.nonce, .balance = acc.balance, .code = acc.code};
        auto& test_storage = test_acc.storage;
        for (const auto& [key, value] : acc.storage)
            test_storage[key] = value.current;
    }
}

state::State TestState::to_intra_state() const
{
    state::State intra_state{*this};
    for (const auto& [addr, _] : *this)
        intra_state.find(addr);  // Preload all accounts.
    return intra_state;
}
}  // namespace evmone::test
