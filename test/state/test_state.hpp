// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "state_view.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <unordered_map>

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

// TestAccount struct based on state::Account
struct TestAccount
{
    uint64_t nonce = 0;
    uint256 balance;
    std::unordered_map<bytes32, bytes32> storage;
    bytes code;

    bool operator==(const TestAccount&) const noexcept = default;
};

class TestState : public state::StateView, public std::unordered_map<address, TestAccount>
{
public:
    using unordered_map::unordered_map;

    std::optional<Account> get_account(address addr) const noexcept override;

    void insert(const address& addr, TestAccount&& acc) { (*this)[addr] = std::move(acc); }
    TestAccount& get(const address& addr) { return (*this)[addr]; }

    void apply_diff(evmc_revision rev, state::State&& intra_state);
    void apply_diff(const state::StateDiff& diff);
};

}  // namespace test
}  // namespace evmone
