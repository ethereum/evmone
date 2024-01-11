// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "test_state.hpp"
#include "state.hpp"
#include "system_contracts.hpp"

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

[[nodiscard]] std::variant<state::TransactionReceipt, std::error_code> transition(TestState& state,
    const state::BlockInfo& block, const state::Transaction& tx, evmc_revision rev, evmc::VM& vm,
    int64_t block_gas_left, int64_t blob_gas_left)
{
    auto intra_state = state.to_intra_state();
    auto res = state::transition(intra_state, block, tx, rev, vm, block_gas_left, blob_gas_left);
    state = TestState{intra_state};
    return res;
}

void finalize(TestState& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const state::Ommer> ommers,
    std::span<const state::Withdrawal> withdrawals)
{
    auto intra_state = state.to_intra_state();
    state::finalize(intra_state, rev, coinbase, block_reward, ommers, withdrawals);
    state = TestState{intra_state};
}

void system_call(TestState& state, const state::BlockInfo& block, evmc_revision rev, evmc::VM& vm)
{
    auto intra_state = state.to_intra_state();
    state::system_call(intra_state, block, rev, vm);
    state = TestState{intra_state};
}
}  // namespace evmone::test
