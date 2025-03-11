// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/requests.hpp>

using namespace evmc::literals;
using namespace evmone::state;

TEST(state_deposit_requests, collect_deposit_requests)
{
    std::array receipts{
        TransactionReceipt{.logs = {Log{.addr = DEPOSIT_CONTRACT_ADDRESS,
                               .topics = {DEPOSIT_EVENT_SIGNATURE_HASH}}}},
    };

    auto& log_data = receipts[0].logs[0].data;
    log_data = bytes(576, 0xfe);              // fill expected length with 0xfe
    log_data.replace(6 * 32, 48, 48, 0x01);   // pubkey
    log_data.replace(9 * 32, 32, 32, 0x02);   // withdrawal_credentials
    log_data.replace(11 * 32, 8, 8, 0x03);    // amount
    log_data.replace(13 * 32, 96, 96, 0x04);  // signature
    log_data.replace(17 * 32, 8, 8, 0x05);    // index

    const auto requests = collect_deposit_requests(receipts);
    EXPECT_EQ(requests.type(), Requests::Type::deposit);
    EXPECT_EQ(requests.data(),
        bytes(48, 0x01) + bytes(32, 0x02) + bytes(8, 0x03) + bytes(96, 0x04) + bytes(8, 0x05));
}

TEST(state_deposit_requests, collect_deposit_requests_skips_wrong_topic)
{
    constexpr auto DUMMPY_EVENT_SIGNATURE_HASH = 0xdeadbeef_bytes32;
    const std::array receipts{
        TransactionReceipt{.logs = {Log{.addr = DEPOSIT_CONTRACT_ADDRESS,
                               .data = {0x01, 0x02, 0x03},
                               .topics = {DUMMPY_EVENT_SIGNATURE_HASH}}}},
    };

    const auto requests = collect_deposit_requests(receipts);
    EXPECT_EQ(requests.type(), Requests::Type::deposit);
    EXPECT_TRUE(requests.data().empty());
}
