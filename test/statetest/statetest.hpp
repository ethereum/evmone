// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/account.hpp"
#include "../state/state.hpp"
#include <nlohmann/json.hpp>

namespace json = nlohmann;

namespace evmone::test
{
class TestState : public state::StateView
{
    std::unordered_map<address, state::AccountBase> m_accounts;

public:
    const auto& get_accounts() const noexcept { return m_accounts; }

    state::AccountBase& insert(address addr, state::AccountBase acc)
    {
        const auto [it, inserted] = m_accounts.insert({addr, std::move(acc)});
        assert(inserted);
        return it->second;
    }

    std::optional<state::AccountBase> get_account(address addr) const noexcept override
    {
        const auto it = m_accounts.find(addr);
        if (it == m_accounts.end())
            return std::nullopt;
        else
            return it->second;
    }

    /// For tests only.
    state::AccountBase* find(const address& addr) noexcept
    {
        if (const auto it = m_accounts.find(addr); it != m_accounts.end())
            return &it->second;
        return nullptr;
    }

    /// For tests only.
    state::AccountBase& get(const address& addr) noexcept { return *find(addr); }

    /// For tests only.
    void erase(const address& addr) noexcept { m_accounts.erase(addr); }

    void apply_diff(const state::StateDiff& d)
    {
        for (const auto& [addr, e] : d.modified_storage)
        {
            auto& a = m_accounts[addr];
            for (const auto& [k, v] : e)
            {
                if (v)
                    a.storage.insert_or_assign(k, v);
                else
                    a.storage.erase(k);
            }
        }

        for (const auto& [addr, m] : d.modified_accounts)
        {
            auto& a = m_accounts[addr];
            if (m.balance)
                a.balance = *m.balance;
            if (m.nonce)
                a.nonce = *m.nonce;
            if (m.code)
                a.code = *m.code;
        }

        for (const auto& addr : d.deleted_accounts)
            m_accounts.erase(addr);
    }
};

[[nodiscard]] inline std::variant<state::TransactionReceipt, std::error_code> transition(
    TestState& state, const state::BlockInfo& block, const state::Transaction& tx,
    evmc_revision rev, evmc::VM& vm, int64_t block_gas_left, int64_t blob_gas_left)
{
    const auto res = state::transition(state, block, tx, rev, vm, block_gas_left, blob_gas_left);
    if (holds_alternative<state::TransactionReceipt>(res))
    {
        const auto& r = get<state::TransactionReceipt>(res);
        state.apply_diff(r.state_diff);
    }
    return res;
}

inline void finalize(TestState& state, evmc_revision rev, const address& coinbase,
    std::optional<uint64_t> block_reward, std::span<const state::Ommer> ommers,
    std::span<const state::Withdrawal> withdrawals)
{
    const auto diff = state::finalize(state, rev, coinbase, block_reward, ommers, withdrawals);
    state.apply_diff(diff);
}

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

    TestState pre_state;
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
TestState from_json<TestState>(const json::json& j);

template <>
state::Transaction from_json<state::Transaction>(const json::json& j);

/// Exports the State (accounts) to JSON format (aka pre/post/alloc state).
json::json to_json(const std::unordered_map<address, state::AccountBase>& accounts);

StateTransitionTest load_state_test(std::istream& input);

/// Validates an Ethereum state:
/// - checks that there are no zero-value storage entries,
/// - checks that there are no invalid EOF codes.
/// Throws std::invalid_argument exception.
void validate_state(const TestState& state, evmc_revision rev);

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
