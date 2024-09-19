// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <map>
#include <span>
#include <variant>

namespace evmone
{
namespace state
{
struct BlockInfo;
struct Ommer;
struct StateDiff;
struct Transaction;
struct TransactionReceipt;
struct Withdrawal;
class State;
}  // namespace state

namespace test
{
using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using intx::uint256;

/// Ethereum account representation for tests.
struct TestAccount
{
    uint64_t nonce = 0;
    uint256 balance;
    std::map<bytes32, bytes32> storage;
    bytes code;

    bool operator==(const TestAccount&) const noexcept = default;
};

/// Ethereum State representation for tests.
///
/// This is a simplified variant of state::State:
/// it hides some details related to transaction execution (e.g. original storage values)
/// and is also easier to work with in tests.
class TestState : public std::map<address, TestAccount>
{
public:
    using map::map;

    /// Inserts new account to the state.
    ///
    /// This method is for compatibility with state::State::insert().
    /// Don't use it in new tests, use std::map interface instead.
    /// TODO: deprecate this method.
    void insert(const address& addr, TestAccount&& acc) { (*this)[addr] = std::move(acc); }

    /// Gets the reference to an existing account.
    ///
    /// This method is for compatibility with state::State::get().
    /// Don't use it in new tests, use std::map interface instead.
    /// TODO: deprecate this method.
    TestAccount& get(const address& addr) { return (*this)[addr]; }

    /// Converts the intra state to TestState.
    explicit TestState(const state::State& intra_state);

    /// Converts the TestState to intra state for transaction execution.
    [[nodiscard]] state::State to_intra_state() const;

    /// Apply the state changes.
    void apply(const state::StateDiff& diff);
};

/// Wrapping of state::transition() which operates on TestState.
[[nodiscard]] std::variant<state::TransactionReceipt, std::error_code> transition(TestState& state,
    const state::BlockInfo& block, const state::Transaction& tx, evmc_revision rev, evmc::VM& vm,
    int64_t block_gas_left, int64_t blob_gas_left);

/// Wrapping of state::finalize() which operates on TestState.
void finalize(TestState& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const state::Ommer> ommers,
    std::span<const state::Withdrawal> withdrawals);

/// Wrapping of state::system_call() which operates on TestState.
void system_call(TestState& state, const state::BlockInfo& block, evmc_revision rev, evmc::VM& vm);

}  // namespace test
}  // namespace evmone
