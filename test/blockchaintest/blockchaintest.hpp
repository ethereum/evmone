// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../state/bloom_filter.hpp"
#include "../state/state.hpp"
#include <evmc/evmc.hpp>
#include <span>
#include <vector>

namespace evmone::test
{
struct UnsupportedTestFeature : std::runtime_error
{
    using runtime_error::runtime_error;
};

// https://ethereum.org/en/developers/docs/blocks/
struct BlockHeader
{
    hash256 parent_hash;
    address coinbase;
    hash256 state_root;
    hash256 receipts_root;
    state::BloomFilter logs_bloom;
    int64_t difficulty;
    bytes32 prev_randao;
    int64_t block_number;
    int64_t gas_limit;
    int64_t gas_used;
    int64_t timestamp;
    bytes extra_data;
    uint64_t base_fee_per_gas;
    hash256 hash;
    hash256 transactions_root;
    hash256 withdrawal_root;
};

struct TestBlock
{
    state::BlockInfo block_info;
    state::State pre_state;
    std::vector<state::Transaction> transactions;

    BlockHeader expected_block_header;
};

struct BlockchainTest
{
    struct Expectation
    {
        hash256 last_block_hash;
        std::variant<state::State, hash256> post_state;
    };

    std::string name;

    std::vector<TestBlock> test_blocks;
    BlockHeader genesis_block_header;
    state::State pre_state;
    evmc_revision rev;

    Expectation expectation;
};

std::vector<BlockchainTest> load_blockchain_tests(std::istream& input);

void run_blockchain_tests(std::span<const BlockchainTest> tests, evmc::VM& vm);

}  // namespace evmone::test
