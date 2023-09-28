// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "../state/state.hpp"
#include "../test/statetest/statetest.hpp"
#include "blockchaintest.hpp"
#include <gtest/gtest.h>

namespace evmone::test
{

struct RejectedTransaction
{
    hash256 hash;
    size_t index;
    std::string message;
};

struct TransitionResult
{
    std::vector<state::TransactionReceipt> receipts;
    std::vector<RejectedTransaction> rejected;
    int64_t gas_used;
    state::BloomFilter bloom;
};

namespace
{
TransitionResult apply_block(state::State& state, evmc::VM& vm, const state::BlockInfo& block,
    const std::vector<state::Transaction>& txs, evmc_revision rev,
    std::optional<int64_t> block_reward)
{
    std::vector<state::Log> txs_logs;
    int64_t block_gas_left = block.gas_limit;

    std::vector<RejectedTransaction> rejected_txs;
    std::vector<state::TransactionReceipt> receipts;

    int64_t cumulative_gas_used = 0;

    for (size_t i = 0; i < txs.size(); ++i)
    {
        const auto& tx = txs[i];

        const auto computed_tx_hash = keccak256(rlp::encode(tx));
        auto res = state::transition(state, block, tx, rev, vm, block_gas_left);

        if (holds_alternative<std::error_code>(res))
        {
            const auto ec = std::get<std::error_code>(res);
            rejected_txs.push_back({computed_tx_hash, i, ec.message()});
        }
        else
        {
            auto& receipt = get<state::TransactionReceipt>(res);

            const auto& tx_logs = receipt.logs;

            txs_logs.insert(txs_logs.end(), tx_logs.begin(), tx_logs.end());
            cumulative_gas_used += receipt.gas_used;
            receipt.cumulative_gas_used = cumulative_gas_used;
            if (rev < EVMC_BYZANTIUM)
                receipt.post_state = state::mpt_hash(state.get_accounts());

            block_gas_left -= receipt.gas_used;
            receipts.emplace_back(std::move(receipt));
        }
    }

    state::finalize(state, rev, block.coinbase, block_reward, block.ommers, block.withdrawals);

    const auto bloom = compute_bloom_filter(receipts);
    return {std::move(receipts), std::move(rejected_txs), cumulative_gas_used, bloom};
}

std::optional<int64_t> mining_reward(evmc_revision rev) noexcept
{
    if (rev < EVMC_BYZANTIUM)
        return 5'000000000'000000000;
    if (rev < EVMC_CONSTANTINOPLE)
        return 3'000000000'000000000;
    if (rev < EVMC_PARIS)
        return 2'000000000'000000000;
    return std::nullopt;
}

std::string print_state(const state::State& s)
{
    std::stringstream out;
    const std::map<address, state::Account> ordered(
        s.get_accounts().begin(), s.get_accounts().end());

    for (const auto& [key, acc] : ordered)
    {
        out << key << " : \n";
        out << "\tnonce : " << acc.nonce << "\n";
        out << "\tbalance : " << hex0x(acc.balance) << "\n";
        out << "\tcode : " << hex0x(acc.code) << "\n";

        if (!acc.storage.empty())
        {
            const std::map<bytes32, state::StorageValue> ordered_storage(
                acc.storage.begin(), acc.storage.end());

            out << "\tstorage : "
                << "\n";
            for (const auto& [s_key, val] : ordered_storage)
                out << "\t\t" << s_key << " : " << hex0x(val.current) << "\n";
        }
    }

    return out.str();
}
}  // namespace

void run_blockchain_tests(std::span<const BlockchainTest> tests, evmc::VM& vm)
{
    for (size_t case_index = 0; case_index != tests.size(); ++case_index)
    {
        const auto& c = tests[case_index];
        SCOPED_TRACE(
            std::string{evmc::to_string(c.rev)} + '/' + std::to_string(case_index) + '/' + c.name);

        auto state = c.pre_state;

        const state::BlockInfo genesis{
            .number = c.genesis_block_header.block_number,
            .timestamp = c.genesis_block_header.timestamp,
            .parent_timestamp = 0,
            .gas_limit = c.genesis_block_header.gas_limit,
            .coinbase = c.genesis_block_header.coinbase,
            .difficulty = c.genesis_block_header.difficulty,
            .parent_difficulty = 0,
            .parent_ommers_hash = {},
            .prev_randao = c.genesis_block_header.prev_randao,
            .base_fee = c.genesis_block_header.base_fee_per_gas,
            .ommers = {},
            .withdrawals = {},
            .known_block_hashes = {},
        };

        const auto genesis_res = apply_block(state, vm, genesis, {}, c.rev, {});

        EXPECT_EQ(
            state::mpt_hash(state.get_accounts()), state::mpt_hash(c.pre_state.get_accounts()));

        if (c.rev >= EVMC_SHANGHAI)
        {
            EXPECT_EQ(state::mpt_hash(genesis.withdrawals), c.genesis_block_header.withdrawal_root);
        }

        EXPECT_EQ(state::mpt_hash({}), c.genesis_block_header.transactions_root);
        EXPECT_EQ(state::mpt_hash(genesis_res.receipts), c.genesis_block_header.receipts_root);
        EXPECT_EQ(genesis_res.gas_used, c.genesis_block_header.gas_used);
        EXPECT_EQ(bytes_view{genesis_res.bloom}, bytes_view{c.genesis_block_header.logs_bloom});

        std::unordered_map<int64_t, hash256> known_block_hashes;
        known_block_hashes[c.genesis_block_header.block_number] = c.genesis_block_header.hash;

        for (const auto& test_block : c.test_blocks)
        {
            auto bi = test_block.block_info;
            bi.known_block_hashes = known_block_hashes;
            const auto res =
                apply_block(state, vm, bi, test_block.transactions, c.rev, mining_reward(c.rev));

            known_block_hashes[test_block.expected_block_header.block_number] =
                test_block.expected_block_header.hash;

            SCOPED_TRACE(std::string{evmc::to_string(c.rev)} + '/' + std::to_string(case_index) +
                         '/' + c.name + '/' + std::to_string(test_block.block_info.number));

            EXPECT_EQ(
                state::mpt_hash(state.get_accounts()), test_block.expected_block_header.state_root);

            if (c.rev >= EVMC_SHANGHAI)
            {
                EXPECT_EQ(state::mpt_hash(test_block.block_info.withdrawals),
                    test_block.expected_block_header.withdrawal_root);
            }

            EXPECT_EQ(state::mpt_hash(test_block.transactions),
                test_block.expected_block_header.transactions_root);
            EXPECT_EQ(
                state::mpt_hash(res.receipts), test_block.expected_block_header.receipts_root);
            EXPECT_EQ(res.gas_used, test_block.expected_block_header.gas_used);
            EXPECT_EQ(
                bytes_view{res.bloom}, bytes_view{test_block.expected_block_header.logs_bloom});

            // TODO: Add difficulty calculation verification.
        }

        const auto post_state_hash =
            std::holds_alternative<state::State>(c.expectation.post_state) ?
                state::mpt_hash(std::get<state::State>(c.expectation.post_state).get_accounts()) :
                std::get<hash256>(c.expectation.post_state);
        EXPECT_TRUE(state::mpt_hash(state.get_accounts()) == post_state_hash)
            << "Result state:\n"
            << print_state(state)
            << (std::holds_alternative<state::State>(c.expectation.post_state) ?
                       "\n\nExpected state:\n" +
                           print_state(std::get<state::State>(c.expectation.post_state)) :
                       "");
    }
}

}  // namespace evmone::test
