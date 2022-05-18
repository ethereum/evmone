// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/state.hpp"
#include <filesystem>

namespace fs = std::filesystem;

namespace evmone::test
{
struct TestMultiTransaction : state::Transaction
{
    struct Indexes
    {
        size_t input;
        size_t gas_limit;
        size_t value;
    };

    std::vector<state::AccessList> access_lists;
    std::vector<bytes> inputs;
    std::vector<int64_t> gas_limits;
    std::vector<intx::uint256> values;

    [[nodiscard]] Transaction get(const Indexes& indexes) const noexcept
    {
        Transaction tx{*this};
        if (!access_lists.empty())
            tx.access_list = access_lists.at(indexes.input);
        tx.data = inputs.at(indexes.input);
        tx.gas_limit = gas_limits.at(indexes.gas_limit);
        tx.value = values.at(indexes.value);
        return tx;
    }
};

struct TestCase
{
    struct Case
    {
        TestMultiTransaction::Indexes indexes;
        hash256 state_hash;
        hash256 logs_hash;
        bool exception;
    };

    evmc_revision rev;
    std::vector<Case> cases;
};

struct StateTransitionTest
{
    state::State pre_state;
    state::BlockInfo block;
    TestMultiTransaction multi_tx;
    std::vector<TestCase> cases;
};

StateTransitionTest load_state_test(const fs::path& test_file);

}  // namespace evmone::test
