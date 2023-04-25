// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/host.hpp>

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace evmone::test
{
using namespace evmone;
using namespace evmone::state;

/// Fixture to defining test cases in form similar to JSON State Tests.
///
/// It takes the "pre" state and produces "post" state by applying the defined "tx" transaction.
/// Then expectations declared in "except" are checked in the "post" state.
class state_transition : public testing::Test
{
protected:
    /// The default sender address of the test transaction.
    /// Private key: 0x2b1263d2b.
    static constexpr auto Sender = 0xe100713FC15400D1e94096a545879E7c6407001e_address;

    /// The default destination address of the test transaction.
    static constexpr auto To = 0xc0de_address;

    static constexpr auto Coinbase = 0xc014bace_address;

    static inline evmc::VM vm{evmc_create_evmone()};

    struct ExpectedAccount
    {
        bool exists = true;
        std::optional<uint64_t> nonce;
        std::optional<intx::uint256> balance;
        std::optional<bytes> code;
        std::unordered_map<bytes32, bytes32> storage;
    };

    struct Expectation
    {
        evmc_status_code status = EVMC_SUCCESS;
        std::optional<int64_t> gas_used;

        std::unordered_map<address, ExpectedAccount> post;
    };


    evmc_revision rev = EVMC_SHANGHAI;
    BlockInfo block{
        .gas_limit = 1'000'000,
        .coinbase = Coinbase,
        .base_fee = 999,
    };
    Transaction tx{
        .gas_limit = block.gas_limit,
        .max_gas_price = block.base_fee + 1,
        .max_priority_gas_price = 1,
        .sender = Sender,
    };
    State pre;
    Expectation expect;

    void SetUp() override;

    /// The test runner.
    void TearDown() override;
};

}  // namespace evmone::test
