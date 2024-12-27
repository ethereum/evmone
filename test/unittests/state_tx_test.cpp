// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/errors.hpp>
#include <test/state/state.hpp>
#include <test/state/test_state.hpp>
#include <test/utils/utils.hpp>

using namespace evmc::literals;
using namespace evmone::state;
using namespace evmone::test;

TEST(state_tx, validate_nonce)
{
    const BlockInfo bi{.gas_limit = 0x989680,
        .coinbase = 0x01_address,
        .prev_randao = {},
        .base_fee = 0x0a,
        .withdrawals = {}};
    Transaction tx{
        .data = {},
        .gas_limit = 60000,
        .max_gas_price = bi.base_fee,
        .max_priority_gas_price = 0,
        .sender = 0x02_address,
        .to = {},
        .value = 0,
        .access_list = {},
        .nonce = 1,
        .r = 0,
        .s = 0,
    };
    const TestState state{{tx.sender, {.nonce = 1, .balance = 0xe8d4a51000}}};

    ASSERT_FALSE(holds_alternative<std::error_code>(
        validate_transaction(state, bi, tx, EVMC_BERLIN, 60000, 0)));

    tx.nonce = 0;
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_BERLIN, 60000, 0))
                  .message(),
        "nonce too low");

    tx.nonce = 2;
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_BERLIN, 60000, 0))
                  .message(),
        "nonce too high");
}

TEST(state_tx, validate_sender)
{
    BlockInfo bi{.gas_limit = 0x989680,
        .coinbase = 0x01_address,
        .prev_randao = {},
        .base_fee = 0,
        .withdrawals = {}};
    Transaction tx{
        .data = {},
        .gas_limit = 60000,
        .max_gas_price = bi.base_fee,
        .max_priority_gas_price = 0,
        .sender = 0x02_address,
        .to = {},
        .value = 0,
        .access_list = {},
        .nonce = 0,
        .r = 0,
        .s = 0,
    };
    const TestState state{{tx.sender, {.nonce = 0, .balance = 0}}};

    ASSERT_FALSE(holds_alternative<std::error_code>(
        validate_transaction(state, bi, tx, EVMC_BERLIN, 60000, 0)));

    bi.base_fee = 1;

    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_LONDON, 60000, 0))
                  .message(),
        "max fee per gas less than block base fee");

    tx.max_gas_price = bi.base_fee;

    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_LONDON, 60000, 0))
                  .message(),
        "insufficient funds for gas * price + value");
}

TEST(state_tx, validate_blob_tx)
{
    const BlockInfo bi{.gas_limit = 0x989680,
        .base_fee = 1,
        .blob_gas_used = 786432,
        .excess_blob_gas = 0,
        .blob_base_fee = 1};
    Transaction tx{
        .type = Transaction::Type::blob,
        .gas_limit = 60000,
        .max_gas_price = bi.base_fee,
        .sender = 0x02_address,
        .to = {},
    };
    const TestState state{{tx.sender, {.nonce = 0, .balance = 1000000}}};

    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_SHANGHAI, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::TX_TYPE_NOT_SUPPORTED).message());

    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::CREATE_BLOB_TX).message());

    tx.to = 0x01_address;
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::EMPTY_BLOB_HASHES_LIST).message());

    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000001_bytes32);
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000002_bytes32);
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000003_bytes32);
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000004_bytes32);
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000005_bytes32);
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000006_bytes32);

    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::FEE_CAP_LESS_THEN_BLOCKS).message());

    tx.max_blob_gas_price = 1;
    tx.blob_hashes.push_back(
        0x0100000000000000000000000000000000000000000000000000000000000007_bytes32);
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::BLOB_GAS_LIMIT_EXCEEDED).message());

    tx.blob_hashes.pop_back();
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK - 1))
                  .message(),
        make_error_code(ErrorCode::BLOB_GAS_LIMIT_EXCEEDED).message());

    EXPECT_EQ(std::get<TransactionProperties>(validate_transaction(state, bi, tx, EVMC_CANCUN,
                                                  60000, BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .execution_gas_limit,
        39000);

    tx.blob_hashes[0] = 0x0200000000000000000000000000000000000000000000000000000000000001_bytes32;
    EXPECT_EQ(std::get<std::error_code>(validate_transaction(state, bi, tx, EVMC_CANCUN, 60000,
                                            BlockInfo::MAX_BLOB_GAS_PER_BLOCK))
                  .message(),
        make_error_code(ErrorCode::INVALID_BLOB_HASH_VERSION).message());
}

TEST(state_tx, validate_eof_create_transaction)
{
    const BlockInfo bi{.gas_limit = 0x989680,
        .coinbase = 0x01_address,
        .prev_randao = {},
        .base_fee = 0x0a,
        .withdrawals = {}};
    const Transaction tx{
        .data = "EF00 01 010004 0200010001 030004 00 00000000 00 AABBCCDD"_hex,
        .gas_limit = 60000,
        .max_gas_price = bi.base_fee,
        .max_priority_gas_price = 0,
        .sender = 0x02_address,
        .to = {},
        .value = 0,
        .access_list = {},
        .nonce = 1,
        .r = 0,
        .s = 0,
    };
    const TestState state{{tx.sender, {.nonce = 1, .balance = 0xe8d4a51000}}};

    ASSERT_FALSE(holds_alternative<std::error_code>(validate_transaction(
        state, bi, tx, EVMC_CANCUN, 60000, BlockInfo::MAX_BLOB_GAS_PER_BLOCK)));
    ASSERT_FALSE(holds_alternative<std::error_code>(validate_transaction(
        state, bi, tx, EVMC_PRAGUE, 60000, BlockInfo::MAX_BLOB_GAS_PER_BLOCK)));
}

TEST(state_tx, validate_tx_data_cost)
{
    // This test checks the transactions data cost calculation for different EVM revisions.

    const BlockInfo block{.gas_limit = 1'000'000, .base_fee = 1};
    Transaction tx{
        .data = "aa00bb00cc"_hex,
        .gas_limit = block.gas_limit,
        .max_gas_price = block.base_fee,
        .to = 0x00_address,
    };
    const TestState state{{tx.sender, {.nonce = 0, .balance = 1000000}}};

    const auto get_props = [&](evmc_revision rev) {
        const auto res = validate_transaction(state, block, tx, rev, block.gas_limit, 0);
        EXPECT_TRUE(holds_alternative<TransactionProperties>(res));
        if (holds_alternative<TransactionProperties>(res))
            return get<TransactionProperties>(res);
        return TransactionProperties{};
    };
    const auto from_data_cost = [&](int64_t nonzero_cost, int64_t zero_cost) {
        // The counts for the zero/nonzero bytes are taken from the test tx.data input.
        return tx.gas_limit - (21000 + 3 * nonzero_cost + 2 * zero_cost);
    };

    EXPECT_EQ(get_props(EVMC_PETERSBURG).execution_gas_limit, from_data_cost(68, 4));
    EXPECT_EQ(get_props(EVMC_ISTANBUL).execution_gas_limit, from_data_cost(16, 4));
    EXPECT_EQ(get_props(EVMC_CANCUN).execution_gas_limit, from_data_cost(16, 4));
    EXPECT_EQ(get_props(EVMC_PRAGUE).execution_gas_limit, from_data_cost(16, 4));

    EXPECT_EQ(get_props(EVMC_PETERSBURG).min_gas_cost, 0);
    EXPECT_EQ(get_props(EVMC_ISTANBUL).min_gas_cost, 0);
    EXPECT_EQ(get_props(EVMC_CANCUN).min_gas_cost, 0);
    EXPECT_EQ(get_props(EVMC_PRAGUE).min_gas_cost, 21000 + (4 * 3 + 2) * 10);
}
