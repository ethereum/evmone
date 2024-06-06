// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "test_state.hpp"
#include "state.hpp"

namespace evmone::test
{
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
    state::State intra_state;
    for (const auto& [addr, acc] : *this)
    {
        auto& intra_acc = intra_state.insert(
            addr, {.nonce = acc.nonce, .balance = acc.balance, .code = acc.code});
        auto& storage = intra_acc.storage;
        for (const auto& [key, value] : acc.storage)
            storage[key] = {.current = value, .original = value};
    }
    return intra_state;
}
}  // namespace evmone::test
