// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/state.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>

namespace fs = std::filesystem;
namespace json = nlohmann;

namespace evmone::test
{

struct TestMultiTransaction : state::Transaction
{
    struct Indexes
    {
        size_t input = 0;
        size_t gas_limit = 0;
        size_t value = 0;
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

struct StateTransitionTest
{
    struct Case
    {
        struct Expectation
        {
            TestMultiTransaction::Indexes indexes;
            hash256 state_hash;
            hash256 logs_hash = EmptyListHash;
            bool exception = false;
        };

        evmc_revision rev;
        std::vector<Expectation> expectations;
    };

    state::State pre_state;
    state::BlockInfo block;
    TestMultiTransaction multi_tx;
    std::vector<Case> cases;
    std::unordered_map<uint64_t, std::string> input_labels;
};

template <typename T>
T from_json(const json::json& j) = delete;

template <>
uint64_t from_json<uint64_t>(const json::json& j);

template <>
int64_t from_json<int64_t>(const json::json& j);

template <>
address from_json<address>(const json::json& j);

template <>
hash256 from_json<hash256>(const json::json& j);

template <>
bytes from_json<bytes>(const json::json& j);

template <>
state::BlockInfo from_json<state::BlockInfo>(const json::json& j);

template <>
state::Withdrawal from_json<state::Withdrawal>(const json::json& j);

template <>
state::State from_json<state::State>(const json::json& j);

template <>
state::Transaction from_json<state::Transaction>(const json::json& j);

StateTransitionTest load_state_test(std::istream& input);

/// Validates deployed EOF containers before running state test.
/// Throws exception on any invalid EOF in state.
void validate_deployed_code(const state::State& state, evmc_revision rev);

/// Execute the state @p test using the @p vm.
///
/// @param trace_summary  Output execution summary to the default trace stream.
void run_state_test(const StateTransitionTest& test, evmc::VM& vm, bool trace_summary);

/// Computes the hash of the RLP-encoded list of transaction logs.
/// This method is only used in tests.
hash256 logs_hash(const std::vector<state::Log>& logs);

/// Converts an integer to hex string representation with 0x prefix.
///
/// This handles also builtin types like uint64_t. Not optimal but works for now.
inline std::string hex0x(const intx::uint256& v)
{
    return "0x" + intx::hex(v);
}

/// Encodes bytes as hex with 0x prefix.
inline std::string hex0x(const bytes_view& v)
{
    return "0x" + evmc::hex(v);
}

}  // namespace evmone::test
