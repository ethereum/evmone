// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#include "test_state.hpp"
#include "state.hpp"
#include "system_contracts.hpp"

namespace evmone::test
{
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

void TestState::apply(const state::StateDiff& diff)
{
    for (const auto& m : diff.modified_accounts)
    {
        auto& a = (*this)[m.addr];
        a.nonce = m.nonce;
        a.balance = m.balance;
        if (!m.code.empty())
            a.code = m.code;  // TODO: Consider taking rvalue ref to avoid code copy.
        for (const auto& [k, v] : m.modified_storage)
        {
            if (v)
                a.storage.insert_or_assign(k, v);
            else
                a.storage.erase(k);
        }
    }

    for (const auto& addr : diff.deleted_accounts)
        erase(addr);
}

[[nodiscard]] std::variant<state::TransactionReceipt, std::error_code> transition(TestState& state,
    const state::BlockInfo& block, const state::Transaction& tx, evmc_revision rev, evmc::VM& vm,
    int64_t block_gas_left, int64_t blob_gas_left)
{
    auto intra_state = state.to_intra_state();
    const auto result_or_error =
        state::transition(intra_state, block, tx, rev, vm, block_gas_left, blob_gas_left);
    if (const auto result = get_if<state::TransactionReceipt>(&result_or_error))
        state.apply(result->state_diff);
    return result_or_error;
}

void finalize(TestState& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const state::Ommer> ommers,
    std::span<const state::Withdrawal> withdrawals)
{
    auto intra_state = state.to_intra_state();
    const auto diff =
        state::finalize(intra_state, rev, coinbase, block_reward, ommers, withdrawals);
    state.apply(diff);
}

void system_call(TestState& state, const state::BlockInfo& block, evmc_revision rev, evmc::VM& vm)
{
    auto intra_state = state.to_intra_state();
    const auto diff = state::system_call(intra_state, block, rev, vm);
    state.apply(diff);
}
}  // namespace evmone::test
