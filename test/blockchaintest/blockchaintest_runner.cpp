// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/requests.hpp"
#include "../state/rlp.hpp"
#include "../state/system_contracts.hpp"
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
    std::vector<state::Requests> requests;
    int64_t gas_used;
    state::BloomFilter bloom;
    int64_t blob_gas_left;
    TestState block_state;
};

namespace
{
TransitionResult apply_block(TestState& state, evmc::VM& vm, const state::BlockInfo& block,
    const state::BlockHashes& block_hashes, const std::vector<state::Transaction>& txs,
    evmc_revision rev, std::optional<int64_t> block_reward)
{
    TestState block_state(state);
    system_call_block_start(block_state, block, block_hashes, rev, vm);

    std::vector<state::Log> txs_logs;
    int64_t block_gas_left = block.gas_limit;
    auto blob_gas_left = static_cast<int64_t>(block.blob_gas_used.value_or(0));

    std::vector<RejectedTransaction> rejected_txs;
    std::vector<state::TransactionReceipt> receipts;

    int64_t cumulative_gas_used = 0;

    for (size_t i = 0; i < txs.size(); ++i)
    {
        const auto& tx = txs[i];

        const auto computed_tx_hash = keccak256(rlp::encode(tx));
        auto res = test::transition(
            block_state, block, block_hashes, tx, rev, vm, block_gas_left, blob_gas_left);

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
                receipt.post_state = state::mpt_hash(block_state);

            block_gas_left -= receipt.gas_used;
            blob_gas_left -= static_cast<int64_t>(tx.blob_gas_used());
            receipts.emplace_back(std::move(receipt));
        }
    }

    std::vector<state::Requests> requests;
    if (rev >= EVMC_PRAGUE)
        requests.emplace_back(collect_deposit_requests(receipts));

    auto system_call_requests = system_call_block_end(block_state, block, block_hashes, rev, vm);
    std::ranges::move(system_call_requests, std::back_inserter(requests));

    finalize(block_state, rev, block.coinbase, block_reward, block.ommers, block.withdrawals);

    const auto bloom = compute_bloom_filter(receipts);

    return {std::move(receipts), std::move(rejected_txs), std::move(requests), cumulative_gas_used,
        bloom, blob_gas_left, std::move(block_state)};
}

bool validate_block(
    evmc_revision rev, const TestBlock& test_block, const BlockHeader& parent_header) noexcept
{
    // NOTE: includes only block validity unrelated to individual txs. See `apply_block`.

    if (rev >= EVMC_CANCUN)
    {
        // `excess_blob_gas` and `blob_gas_used` mandatory after Cancun and invalid before.
        if (!test_block.block_info.excess_blob_gas.has_value() ||
            !test_block.block_info.blob_gas_used.has_value())
            return false;

        // Check that the excess blob gas was updated correctly.
        if (*test_block.block_info.excess_blob_gas !=
            state::calc_excess_blob_gas(rev, parent_header.blob_gas_used.value_or(0),
                parent_header.excess_blob_gas.value_or(0)))
            return false;

        // Ensure the total blob gas spent is at most equal to the limit
        if (*test_block.block_info.blob_gas_used > state::max_blob_gas_per_block(rev))
            return false;
    }
    else
    {
        if (test_block.block_info.excess_blob_gas.has_value() ||
            test_block.block_info.blob_gas_used.has_value())
            return false;
    }
    return true;
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

std::string print_state(const TestState& s)
{
    std::stringstream out;

    for (const auto& [key, acc] : s)
    {
        out << key << " : \n";
        out << "\tnonce : " << acc.nonce << "\n";
        out << "\tbalance : " << hex0x(acc.balance) << "\n";
        out << "\tcode : " << hex0x(acc.code) << "\n";

        if (!acc.storage.empty())
        {
            out << "\tstorage : \n";
            for (const auto& [s_key, val] : acc.storage)
            {
                if (!is_zero(val))  // Skip 0 values.
                    out << "\t\t" << s_key << " : " << hex0x(val) << "\n";
            }
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
        SCOPED_TRACE(std::string{evmc::to_string(c.rev.get_revision(0))} + '/' +
                     std::to_string(case_index) + '/' + c.name);

        // Validate the genesis block header.
        EXPECT_EQ(c.genesis_block_header.block_number, 0);
        EXPECT_EQ(c.genesis_block_header.gas_used, 0);
        EXPECT_EQ(c.genesis_block_header.transactions_root, state::EMPTY_MPT_HASH);
        EXPECT_EQ(c.genesis_block_header.receipts_root, state::EMPTY_MPT_HASH);
        EXPECT_EQ(c.genesis_block_header.withdrawal_root,
            c.rev.get_revision(c.genesis_block_header.timestamp) >= EVMC_SHANGHAI ?
                state::EMPTY_MPT_HASH :
                bytes32{});
        EXPECT_EQ(c.genesis_block_header.logs_bloom, bytes_view{state::BloomFilter{}});

        auto state = c.pre_state;

        TestBlockHashes block_hashes{
            {c.genesis_block_header.block_number, c.genesis_block_header.hash}};
        for (size_t i = 0; i < c.test_blocks.size(); ++i)
        {
            const auto& test_block = c.test_blocks[i];
            const auto& parent_header =
                i == 0 ? c.genesis_block_header : c.test_blocks[i - 1].expected_block_header;

            auto bi = test_block.block_info;

            const auto rev = c.rev.get_revision(bi.timestamp);

            SCOPED_TRACE(std::string{evmc::to_string(rev)} + '/' + std::to_string(case_index) +
                         '/' + c.name + '/' + std::to_string(test_block.block_info.number));

            if (test_block.valid)
            {
                EXPECT_TRUE(validate_block(rev, test_block, parent_header))
                    << "Expected block to be valid (validate_block)";

                const auto res = apply_block(
                    state, vm, bi, block_hashes, test_block.transactions, rev, mining_reward(rev));

                block_hashes[test_block.expected_block_header.block_number] =
                    test_block.expected_block_header.hash;
                state = res.block_state;

                EXPECT_TRUE(res.rejected.empty())
                    << "Invalid transaction in block expected to be valid";
                EXPECT_TRUE(res.blob_gas_left == 0)
                    << "Transactions used more or less blob gas than expected in block header";

                EXPECT_EQ(state::mpt_hash(state), test_block.expected_block_header.state_root);

                if (rev >= EVMC_SHANGHAI)
                {
                    EXPECT_EQ(state::mpt_hash(test_block.block_info.withdrawals),
                        test_block.expected_block_header.withdrawal_root);
                }

                EXPECT_EQ(state::mpt_hash(test_block.transactions),
                    test_block.expected_block_header.transactions_root);
                EXPECT_EQ(
                    state::mpt_hash(res.receipts), test_block.expected_block_header.receipts_root);
                if (rev >= EVMC_PRAGUE)
                {
                    EXPECT_EQ(calculate_requests_hash(res.requests),
                        test_block.expected_block_header.requests_hash);
                }
                EXPECT_EQ(res.gas_used, test_block.expected_block_header.gas_used);
                EXPECT_EQ(
                    bytes_view{res.bloom}, bytes_view{test_block.expected_block_header.logs_bloom});
            }
            else
            {
                if (!validate_block(rev, test_block, parent_header))
                    continue;

                const auto res = apply_block(
                    state, vm, bi, block_hashes, test_block.transactions, rev, mining_reward(rev));
                if (!res.rejected.empty())
                    continue;
                if (res.blob_gas_left != 0)
                    continue;

                if (state::mpt_hash(res.block_state) != test_block.expected_block_header.state_root)
                    continue;

                if (rev >= EVMC_SHANGHAI && state::mpt_hash(test_block.block_info.withdrawals) !=
                                                test_block.expected_block_header.withdrawal_root)
                    continue;
                if (state::mpt_hash(test_block.transactions) !=
                    test_block.expected_block_header.transactions_root)
                    continue;
                if (state::mpt_hash(res.receipts) != test_block.expected_block_header.receipts_root)
                    continue;
                if (rev >= EVMC_PRAGUE && calculate_requests_hash(res.requests) !=
                                              test_block.expected_block_header.requests_hash)
                    continue;
                if (res.gas_used != test_block.expected_block_header.gas_used)
                    continue;
                if (bytes_view{res.bloom} !=
                    bytes_view{test_block.expected_block_header.logs_bloom})
                    continue;

                EXPECT_TRUE(false) << "Expected block to be invalid but resulted valid";

                // Apply the resulting state in order to continue testing expectations, even if
                // the test already has gone into failed state here.
                block_hashes[test_block.expected_block_header.block_number] =
                    test_block.expected_block_header.hash;
                state = res.block_state;
            }
        }
        const auto expected_post_hash =
            std::holds_alternative<TestState>(c.expectation.post_state) ?
                state::mpt_hash(std::get<TestState>(c.expectation.post_state)) :
                std::get<hash256>(c.expectation.post_state);
        EXPECT_EQ(state::mpt_hash(state), expected_post_hash)
            << "Result state:\n"
            << print_state(state)
            << (std::holds_alternative<TestState>(c.expectation.post_state) ?
                       "\n\nExpected state:\n" +
                           print_state(std::get<TestState>(c.expectation.post_state)) :
                       "");
    }
    // TODO: Add difficulty calculation verification.
}

}  // namespace evmone::test
