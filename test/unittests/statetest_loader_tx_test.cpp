// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gmock/gmock.h>
#include <intx/intx.hpp>
#include <test/statetest/statetest.hpp>

using namespace evmone;
using namespace intx;
using namespace testing;

// TODO: Add specific test of loading nonce, chainId, r, s, v

TEST(statetest_loader, tx_create_legacy)
{
    constexpr std::string_view input = R"({
        "input": "b0b1",
        "gas": "0x9091",
        "chainId": "0x5",
        "value": "0xe0e1",
        "sender": "a0a1",
        "to": "",
        "gasPrice": "0x7071",
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    const auto tx = test::from_json<state::Transaction>(json::json::parse(input));
    EXPECT_EQ(tx.kind, state::Transaction::Kind::legacy);
    EXPECT_EQ(tx.data, (bytes{0xb0, 0xb1}));
    EXPECT_EQ(tx.gas_limit, 0x9091);
    EXPECT_EQ(tx.chain_id, 5);
    EXPECT_EQ(tx.value, 0xe0e1);
    EXPECT_EQ(tx.sender, 0xa0a1_address);
    EXPECT_FALSE(tx.to.has_value());
    EXPECT_EQ(tx.max_gas_price, 0x7071);
    EXPECT_EQ(tx.max_priority_gas_price, 0x7071);
    EXPECT_TRUE(tx.access_list.empty());
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.r, 0x1111111111111111111111111111111111111111111111111111111111111111_u256);
    EXPECT_EQ(tx.s, 0x2222222222222222222222222222222222222222222222222222222222222222_u256);
    EXPECT_EQ(tx.v, 1);
}

TEST(statetest_loader, tx_eip1559)
{
    constexpr std::string_view input = R"({
        "input": "b0b1",
        "gas": "0x9091",
        "value": "0xe0e1",
        "sender": "a0a1",
        "to": "c0c1",
        "maxFeePerGas": "0x7071",
        "maxPriorityFeePerGas": "0x6061",
        "accessList": [],
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    const auto tx = test::from_json<state::Transaction>(json::json::parse(input));
    EXPECT_EQ(tx.kind, state::Transaction::Kind::eip1559);
    EXPECT_EQ(tx.data, (bytes{0xb0, 0xb1}));
    EXPECT_EQ(tx.gas_limit, 0x9091);
    EXPECT_EQ(tx.chain_id, 0);
    EXPECT_EQ(tx.value, 0xe0e1);
    EXPECT_EQ(tx.sender, 0xa0a1_address);
    EXPECT_EQ(tx.to, 0xc0c1_address);
    EXPECT_EQ(tx.max_gas_price, 0x7071);
    EXPECT_EQ(tx.max_priority_gas_price, 0x6061);
    EXPECT_TRUE(tx.access_list.empty());
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.r, 0x1111111111111111111111111111111111111111111111111111111111111111_u256);
    EXPECT_EQ(tx.s, 0x2222222222222222222222222222222222222222222222222222222222222222_u256);
    EXPECT_EQ(tx.v, 1);
}

TEST(statetest_loader, tx_access_list)
{
    constexpr std::string_view input = R"({
        "input": "",
        "gas": "0",
        "value": "0",
        "sender": "",
        "to": "",
        "maxFeePerGas": "0",
        "maxPriorityFeePerGas": "0",
        "accessList": [
            {"address": "ac01", "storageKeys": []},
            {"address": "ac02", "storageKeys": ["fe", "00"]}
        ],
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    const auto tx = test::from_json<state::Transaction>(json::json::parse(input));
    EXPECT_EQ(tx.kind, state::Transaction::Kind::eip1559);
    EXPECT_TRUE(tx.data.empty());
    EXPECT_EQ(tx.gas_limit, 0);
    EXPECT_EQ(tx.value, 0);
    EXPECT_EQ(tx.sender, address{});  // TODO: use 0x0_address?
    EXPECT_FALSE(tx.to.has_value());
    EXPECT_EQ(tx.max_gas_price, 0);
    EXPECT_EQ(tx.max_priority_gas_price, 0);
    ASSERT_EQ(tx.access_list.size(), 2);
    EXPECT_EQ(tx.access_list[0].first, 0xac01_address);
    EXPECT_EQ(tx.access_list[0].second.size(), 0);
    EXPECT_EQ(tx.access_list[1].first, 0xac02_address);
    EXPECT_EQ(tx.access_list[1].second, (std::vector{0xfe_bytes32, 0x00_bytes32}));
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.r, 0x1111111111111111111111111111111111111111111111111111111111111111_u256);
    EXPECT_EQ(tx.s, 0x2222222222222222222222222222222222222222222222222222222222222222_u256);
    EXPECT_EQ(tx.v, 1);
}

TEST(statetest_loader, tx_confusing)
{
    constexpr std::string_view input = R"({
        "input": "b0b1",
        "gas": "9091",
        "value": "0xe0e1",
        "sender": "a0a1",
        "to": "c0c1",
        "gasPrice": "0x8081",
        "maxFeePerGas": "0x7071",
        "maxPriorityFeePerGas": "0x6061",
        "accessList": [],
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    EXPECT_THAT([&] { test::from_json<state::Transaction>(json::json::parse(input)); },
        ThrowsMessage<std::invalid_argument>(
            "invalid transaction: contains both legacy and EIP-1559 fees"));
}

TEST(statetest_loader, tx_type_1)
{
    constexpr std::string_view input = R"({
        "input": "",
        "gas": "0",
        "type": "1",
        "value": "0",
        "sender": "",
        "to": "",
        "gasPrice": "0",
        "accessList": [
            {"address": "ac01", "storageKeys": []},
            {"address": "ac02", "storageKeys": ["fe", "00"]}
        ],
        "nonce": "0",
        "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "v": "1"
    })";

    const auto tx = test::from_json<state::Transaction>(json::json::parse(input));
    EXPECT_EQ(tx.kind, state::Transaction::Kind::eip2930);
    EXPECT_TRUE(tx.data.empty());
    EXPECT_EQ(tx.gas_limit, 0);
    EXPECT_EQ(tx.value, 0);
    EXPECT_EQ(tx.sender, 0x00_address);
    EXPECT_FALSE(tx.to.has_value());
    EXPECT_EQ(tx.max_gas_price, 0);
    EXPECT_EQ(tx.max_priority_gas_price, 0);
    ASSERT_EQ(tx.access_list.size(), 2);
    EXPECT_EQ(tx.access_list[0].first, 0xac01_address);
    EXPECT_EQ(tx.access_list[0].second.size(), 0);
    EXPECT_EQ(tx.access_list[1].first, 0xac02_address);
    EXPECT_EQ(tx.access_list[1].second, (std::vector{0xfe_bytes32, 0x00_bytes32}));
    EXPECT_EQ(tx.nonce, 0);
    EXPECT_EQ(tx.r, 0x1111111111111111111111111111111111111111111111111111111111111111_u256);
    EXPECT_EQ(tx.s, 0x2222222222222222222222222222222222222222222222222222222222222222_u256);
    EXPECT_EQ(tx.v, 1);
}

TEST(statetest_loader, invalid_tx_type)
{
    {
        constexpr std::string_view input = R"({
                "input": "",
                "gas": "0",
                "type": "2",
                "value": "0",
                "sender": "",
                "to": "",
                "gasPrice": "0",
                "accessList": [
                    {"address": "ac01", "storageKeys": []},
                    {"address": "ac02", "storageKeys": ["fe", "00"]}
                ],
                "nonce": "0",
                "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "v": "1"
            })";

        EXPECT_THAT([&] { test::from_json<state::Transaction>(json::json::parse(input)); },
            ThrowsMessage<std::invalid_argument>("wrong transaction type"));
    }
    {
        constexpr std::string_view input = R"({
            "input": "",
            "gas": "0",
            "type": "1",
            "value": "0",
            "sender": "",
            "to": "",
            "gasPrice": "0",
            "nonce": "0",
            "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "v": "1"
        })";

        EXPECT_THAT([&] { test::from_json<state::Transaction>(json::json::parse(input)); },
            ThrowsMessage<std::invalid_argument>("wrong transaction type"));
    }

    {
        constexpr std::string_view input = R"({
            "input": "",
            "gas": "0",
            "type": "1",
            "value": "0",
            "sender": "",
            "to": "",
            "maxFeePerGas": "0",
            "maxPriorityFeePerGas": "0",
            "accessList": [
                {"address": "ac01", "storageKeys": []},
                {"address": "ac02", "storageKeys": ["fe", "00"]}
            ],
            "nonce": "0",
            "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "v": "1"
        })";

        EXPECT_THAT([&] { test::from_json<state::Transaction>(json::json::parse(input)); },
            ThrowsMessage<std::invalid_argument>("wrong transaction type"));
    }
}

namespace evmone::test
{
// This function is used only by the following test case and in `statetest_loader.cpp` where it is
// defined.
template <>
uint8_t from_json<uint8_t>(const json::json& j);
}  // namespace evmone::test

TEST(statetest_loader, load_uint8_t)
{
    {
        constexpr std::string_view input = R"({
            "v": "0xFF"
        })";

        EXPECT_EQ(test::from_json<uint8_t>(json::json::parse(input)["v"]), 255);
    }
    {
        constexpr std::string_view input = R"({
            "v": "0x100"
        })";

        EXPECT_THROW(test::from_json<uint8_t>(json::json::parse(input)["v"]), std::out_of_range);
    }
}
