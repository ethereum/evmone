// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <map>

namespace evmone
{
namespace state
{
class State;
}

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
};

}  // namespace test
}  // namespace evmone
