// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include <gtest/gtest.h>
#include <test/state/account.hpp>
#include <test/state/bloom_filter.hpp>
#include <test/state/mpt.hpp>
#include <test/state/mpt_hash.hpp>
#include <test/state/rlp.hpp>
#include <test/state/state.hpp>
#include <array>

using namespace evmone;
using namespace evmone::state;
using namespace intx;

TEST(state_mpt_hash, empty)
{
    EXPECT_EQ(mpt_hash(std::unordered_map<evmone::address, Account>()), emptyMPTHash);
}

TEST(state_mpt_hash, single_account_v1)
{
    // Expected value computed in go-ethereum.
    constexpr auto expected =
        0x084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e_bytes32;

    Account acc;
    acc.balance = 1_u256;
    const std::unordered_map<address, Account> accounts{{0x02_address, acc}};
    EXPECT_EQ(mpt_hash(accounts), expected);
}

TEST(state_mpt_hash, two_accounts)
{
    std::unordered_map<address, Account> accounts;
    EXPECT_EQ(mpt_hash(accounts), emptyMPTHash);

    accounts[0x00_address] = Account{};
    EXPECT_EQ(mpt_hash(accounts),
        0x0ce23f3c809de377b008a4a3ee94a0834aac8bec1f86e28ffe4fdb5a15b0c785_bytes32);

    Account acc2;
    acc2.nonce = 1;
    acc2.balance = -2_u256;
    acc2.code = {0x00};
    acc2.storage[0x01_bytes32] = {0xfe_bytes32};
    acc2.storage[0x02_bytes32] = {0xfd_bytes32};
    accounts[0x01_address] = acc2;
    EXPECT_EQ(mpt_hash(accounts),
        0xd3e845156fca75de99712281581304fbde104c0fc5a102b09288c07cdde0b666_bytes32);
}

TEST(state_mpt_hash, deleted_storage)
{
    Account acc;
    acc.storage[0x01_bytes32] = {};
    acc.storage[0x02_bytes32] = {0xfd_bytes32};
    acc.storage[0x03_bytes32] = {};
    const std::unordered_map<address, Account> accounts{{0x07_address, acc}};
    EXPECT_EQ(mpt_hash(accounts),
        0x4e7338c16731491e0fb5d1623f5265c17699c970c816bab71d4d717f6071414d_bytes32);
}

TEST(state_mpt_hash, one_transactions)
{
    // https://sepolia.etherscan.io/tx/0xd4070618ed3026722ae5dbacc95e70714327d65abce292bba9de38201895cdff

    Transaction tx{};

    tx.kind = Transaction::Kind::eip1559;
    tx.data =
        "04a7e62e00000000000000000000000000000000000000000000000000000000000000c0000000000000000000"
        "000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000"
        "0000000000000000028000000000000000000000000000000000000000000000000000000000000002c0000000"
        "000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000"
        "000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000"
        "000001ba90df364951119f0e935b90ed342b9e686985fb7805f532c5432c2a46ba1233be5ed196ab7d467c8cc0"
        "73686342699c000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000063ecd7e7000000000000000000000000000000000000000000000000000000000000000200000000"
        "0000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000"
        "000000000000000000000000000001000000000000000000000000aafb72183a85a66ec7eec6a9d3374f3a06d8"
        "a25100000000000000000000000000000000000000000000000000000000000000010000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000040000000000000000000000000000000000000000000000054c7bff9ff28e80000000000000"
        "000000000000000000000000000000000000000000000000000001964617c9cbc649c28b9710bbe61cc10e0000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "01ba90df364951119f0e935b90ed342b9e686985fb7805f532c5432c2a46ba1233000000000000000000000000"
        "000000000000000000000000000000000000000155f6604df131609d8058c7f0ad8bbdf96f4bb6b5cc00c96aad"
        "da6f61455681990000000000000000000000000000000000000000000000000000000000000001000000000000"
        "000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000"
        "000000000000000000000000010000000000000000000000000000000000000000000000054c7bff9ff28e8000"
        ""_hex;

    tx.gas_limit = 387780;
    tx.max_gas_price = 1500000014;
    tx.max_priority_gas_price = 1500000000;
    tx.sender = 0x3a091a68661d40dafc2a532f8ba89ad2c0b4f184_address;
    tx.to = 0xacd9a09eb3123602937cb30ff717e746c57a5132_address;
    tx.value = 0;
    tx.nonce = 10246;
    tx.r = 0xdf2ff0c61a24ece7b4c24d9a1a7061881043fd8285ea0be8ea55b42c8a119225_u256;
    tx.s = 0x644cd7390b5f274ee947121837da3deab1638c0c7d9f5aa4ebe9f9a3149f192d_u256;
    tx.v = 1;
    tx.chain_id = 11155111;

    const auto tx_root = mpt_hash(std::array{tx});
    EXPECT_EQ(tx_root, 0x6ce50bfaaebabe884433c144fa4d8a4c1087e443587a9788b30381636dedbeb2_bytes32);
}

TEST(state_mpt_hash, legacy_and_eip1559_receipt_three_logs_no_logs)
{
    // https://sepolia.etherscan.io/tx/0x1e68d9dbbf933399a6dfe5686ba0b51e04a4da81ab17aa5ff84334fdf2d4a3a7

    //{
    //    "blockHash": "0xd30a523496844aa39a31a0b5f1ac76cb140b4d904394e59ef3d2b813098de8eb",
    //    "blockNumber": "0x2c727f",
    //    "contractAddress": null,
    //    "cumulativeGasUsed": "0x24522",
    //    "effectiveGasPrice": "0x77359407",
    //    "from": "0x38dc84830b92d171d7b4c129c813360d6ab8b54e",
    //    "gasUsed": "0x24522",
    //    "logs": [
    //        {
    //            "address": "0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c",
    //            "blockHash":
    //            "0xd30a523496844aa39a31a0b5f1ac76cb140b4d904394e59ef3d2b813098de8eb",
    //            "blockNumber": "0x2c727f",
    //            "data": "0x0000000000000000000000000000000000000000000000000000000063ee2f6c",
    //            "logIndex": "0x0",
    //            "removed": false,
    //            "topics": [
    //                "0x0109fc6f55cf40689f02fbaad7af7fe7bbac8a3d2186600afc7d3e10cac60271",
    //                "0x00000000000000000000000000000000000000000000000000000000000027b6",
    //                "0x00000000000000000000000038dc84830b92d171d7b4c129c813360d6ab8b54e"
    //            ],
    //            "transactionHash":
    //            "0x1e68d9dbbf933399a6dfe5686ba0b51e04a4da81ab17aa5ff84334fdf2d4a3a7",
    //            "transactionIndex": "0x0"
    //        },
    //        {
    //            "address": "0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c",
    //            "blockHash":
    //            "0xd30a523496844aa39a31a0b5f1ac76cb140b4d904394e59ef3d2b813098de8eb",
    //            "blockNumber": "0x2c727f",
    //            "data": "0x",
    //            "logIndex": "0x1",
    //            "removed": false,
    //            "topics": [
    //                "0x92e98423f8adac6e64d0608e519fd1cefb861498385c6dee70d58fc926ddc68c",
    //                "0x00000000000000000000000000000000000000000000000000000000481f2280",
    //                "0x00000000000000000000000000000000000000000000000000000000000027b6",
    //                "0x00000000000000000000000038dc84830b92d171d7b4c129c813360d6ab8b54e"
    //            ],
    //            "transactionHash":
    //            "0x1e68d9dbbf933399a6dfe5686ba0b51e04a4da81ab17aa5ff84334fdf2d4a3a7",
    //            "transactionIndex": "0x0"
    //        },
    //        {
    //            "address": "0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c",
    //            "blockHash":
    //            "0xd30a523496844aa39a31a0b5f1ac76cb140b4d904394e59ef3d2b813098de8eb",
    //            "blockNumber": "0x2c727f",
    //            "data": "0x",
    //            "logIndex": "0x2",
    //            "removed": false,
    //            "topics": [
    //                "0xfe25c73e3b9089fac37d55c4c7efcba6f04af04cebd2fc4d6d7dbb07e1e5234f",
    //                "0x000000000000000000000000000000000000000000000c958b4bca4282ac0000"
    //            ],
    //            "transactionHash":
    //            "0x1e68d9dbbf933399a6dfe5686ba0b51e04a4da81ab17aa5ff84334fdf2d4a3a7",
    //            "transactionIndex": "0x0"
    //        }
    //    ],
    //    "logsBloom":
    //    "0x000000110000000000000000000000000000000002000000000000000080200000000000000000000000000000000000000000000000000000000000000000001000c0000000000000000400002000000000000001000000000000000000000000000000000000000000000200000000400000000400000000000020100000000000000000000000000000000000000000000000000000000000000000000000000000001000020000000400000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000004000000000000000000000400000000000000000008000004",
    //    "status": "0x1",
    //    "to": "0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c",
    //    "transactionHash":
    //    "0x1e68d9dbbf933399a6dfe5686ba0b51e04a4da81ab17aa5ff84334fdf2d4a3a7",
    //    "transactionIndex": "0x0",
    //    "type": "0x0"
    //}

    TransactionReceipt receipt0{};
    receipt0.kind = evmone::state::Transaction::Kind::legacy;
    receipt0.status = EVMC_SUCCESS;
    receipt0.gas_used = 0x24522;

    Log l0;
    l0.addr = 0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c_address;
    l0.data = "0x0000000000000000000000000000000000000000000000000000000063ee2f6c"_hex;
    l0.topics = {0x0109fc6f55cf40689f02fbaad7af7fe7bbac8a3d2186600afc7d3e10cac60271_bytes32,
        0x00000000000000000000000000000000000000000000000000000000000027b6_bytes32,
        0x00000000000000000000000038dc84830b92d171d7b4c129c813360d6ab8b54e_bytes32};

    Log l1;
    l1.addr = 0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c_address;
    l1.data = ""_b;
    l1.topics = {
        0x92e98423f8adac6e64d0608e519fd1cefb861498385c6dee70d58fc926ddc68c_bytes32,
        0x00000000000000000000000000000000000000000000000000000000481f2280_bytes32,
        0x00000000000000000000000000000000000000000000000000000000000027b6_bytes32,
        0x00000000000000000000000038dc84830b92d171d7b4c129c813360d6ab8b54e_bytes32,
    };

    Log l2;
    l2.addr = 0x84bf5c35c54a994c72ff9d8b4cca8f5034153a2c_address;
    l2.data = ""_b;
    l2.topics = {0xfe25c73e3b9089fac37d55c4c7efcba6f04af04cebd2fc4d6d7dbb07e1e5234f_bytes32,
        0x000000000000000000000000000000000000000000000c958b4bca4282ac0000_bytes32};

    receipt0.logs = {l0, l1, l2};
    receipt0.logs_bloom_filter = compute_bloom_filter(receipt0.logs);

    //{
    //    "blockHash": "0xd30a523496844aa39a31a0b5f1ac76cb140b4d904394e59ef3d2b813098de8eb",
    //    "blockNumber": "0x2c727f",
    //    "contractAddress": null,
    //    "cumulativeGasUsed": "0x2cd9b",
    //    "effectiveGasPrice": "0x77359407",
    //    "from": "0xb3fa644a498d4d3913675389391c803968b171e3",
    //    "gasUsed": "0x8879",
    //    "logs": [],
    //    "logsBloom":
    //    "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    //    "status": "0x1",
    //    "to": "0xda50cdedb4ce0c08a5f780bb3e09974f06c21be0",
    //    "transactionHash":
    //    "0x6f674702416e1f1566706b8f7784d33a39faa12f7f78e07d8d6270af7ad0bf70",
    //    "transactionIndex": "0x1",
    //    "type": "0x2"
    //}

    TransactionReceipt receipt1{};
    receipt1.kind = evmone::state::Transaction::Kind::eip1559;
    receipt1.status = EVMC_SUCCESS;
    receipt1.gas_used = 0x2cd9b;
    receipt1.logs_bloom_filter = compute_bloom_filter(receipt1.logs);

    EXPECT_EQ(mpt_hash(std::array{receipt0, receipt1}),
        0x7199a3a86010634dc205a1cdd6ec609f70b954167583cb3acb6a2e3057916016_bytes32);
}
