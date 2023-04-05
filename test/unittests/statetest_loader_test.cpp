// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gmock/gmock.h>
#include <test/statetest/statetest.hpp>
#include <test/utils/utils.hpp>

using namespace evmone;
using namespace evmone::test;
using namespace testing;

TEST(json_loader, uint64_t)
{
    using json::basic_json;

    EXPECT_EQ(from_json<uint64_t>(basic_json("0x00000005")), 5);
    EXPECT_EQ(from_json<uint64_t>(basic_json("5")), 5);
    EXPECT_EQ(from_json<uint64_t>(basic_json(7)), 7);

    EXPECT_EQ(from_json<uint64_t>(basic_json("0xffffffffffffffff")),
        std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(from_json<uint64_t>(basic_json("18446744073709551615")),
        std::numeric_limits<uint64_t>::max());
    EXPECT_THROW(from_json<uint64_t>(basic_json("0x10000000000000000")), std::out_of_range);
    EXPECT_THROW(from_json<uint64_t>(basic_json("18446744073709551616")), std::out_of_range);
    EXPECT_EQ(from_json<uint64_t>(basic_json(std::numeric_limits<uint64_t>::max())),
        std::numeric_limits<uint64_t>::max());

    // Octal is also supported.
    EXPECT_EQ(from_json<uint64_t>(basic_json("0777")), 0777);

    EXPECT_THROW(from_json<uint64_t>(basic_json("0x000000000000000k")), std::invalid_argument);
    EXPECT_THROW(from_json<uint64_t>(basic_json("k")), std::invalid_argument);
    EXPECT_THROW(from_json<uint64_t>(basic_json("")), std::invalid_argument);
}

TEST(json_loader, int64_t)
{
    using json::basic_json;

    EXPECT_EQ(from_json<int64_t>(basic_json("0x00000005")), 5);
    EXPECT_EQ(from_json<int64_t>(basic_json("-0x5")), -5);
    EXPECT_EQ(from_json<int64_t>(basic_json("-5")), -5);

    EXPECT_EQ(from_json<int64_t>(basic_json(-7)), -7);
    EXPECT_EQ(from_json<int64_t>(basic_json(0xffffffffffffffff)), -1);

    EXPECT_EQ(
        from_json<int64_t>(basic_json("0x7fffffffffffffff")), std::numeric_limits<int64_t>::max());
    EXPECT_EQ(
        from_json<int64_t>(basic_json("9223372036854775807")), std::numeric_limits<int64_t>::max());
    EXPECT_EQ(from_json<int64_t>(basic_json("-9223372036854775808")),
        std::numeric_limits<int64_t>::min());
    EXPECT_THROW(from_json<int64_t>(basic_json("0xffffffffffffffff")), std::out_of_range);
    EXPECT_THROW(from_json<int64_t>(basic_json("9223372036854775808")), std::out_of_range);
    EXPECT_THROW(from_json<int64_t>(basic_json("-9223372036854775809")), std::out_of_range);

    // Octal is also supported.
    EXPECT_EQ(from_json<int64_t>(basic_json("0777")), 0777);

    EXPECT_THROW(from_json<int64_t>(basic_json("0x000000000000000k")), std::invalid_argument);
    EXPECT_THROW(from_json<int64_t>(basic_json("k")), std::invalid_argument);
    EXPECT_THROW(from_json<int64_t>(basic_json("")), std::invalid_argument);
}

TEST(statetest_loader, load_empty_test)
{
    std::istringstream s{"{}"};
    EXPECT_THROW(load_state_test(s), std::invalid_argument);
}

TEST(statetest_loader, load_minimal_test)
{
    std::istringstream s{R"({
        "test": {
            "_info": {},
            "pre": {},
            "transaction": {
                "gasPrice": "",
                "sender": "",
                "to": "",
                "data": null,
                "gasLimit": "0",
                "value": null
            },
            "post": {},
            "env": {
                "currentNumber": "0",
                "currentTimestamp": "0",
                "currentGasLimit": "0",
                "currentCoinbase": ""
            }
        }
    })"};
    const StateTransitionTest st = load_state_test(s);
    // TODO: should add some comparison operator to State, BlockInfo, AccessList
    EXPECT_EQ(st.pre_state.get_accounts().size(), 0);
    EXPECT_EQ(st.block.number, 0);
    EXPECT_EQ(st.block.timestamp, 0);
    EXPECT_EQ(st.block.gas_limit, 0);
    EXPECT_EQ(st.block.coinbase, address{});
    EXPECT_EQ(st.block.prev_randao, bytes32{});
    EXPECT_EQ(st.block.base_fee, 0);
    EXPECT_EQ(st.multi_tx.kind, test::TestMultiTransaction::Kind::legacy);
    EXPECT_EQ(st.multi_tx.data, bytes{});
    EXPECT_EQ(st.multi_tx.gas_limit, 0);
    EXPECT_EQ(st.multi_tx.max_gas_price, 0);
    EXPECT_EQ(st.multi_tx.max_priority_gas_price, 0);
    EXPECT_EQ(st.multi_tx.sender, address{});
    EXPECT_EQ(st.multi_tx.to, std::nullopt);
    EXPECT_EQ(st.multi_tx.value, 0);
    EXPECT_EQ(st.multi_tx.access_list.size(), 0);
    EXPECT_EQ(st.multi_tx.chain_id, 0);
    EXPECT_EQ(st.multi_tx.nonce, 0);
    EXPECT_EQ(st.multi_tx.r, 0);
    EXPECT_EQ(st.multi_tx.s, 0);
    EXPECT_EQ(st.multi_tx.v, 0);
    EXPECT_EQ(st.multi_tx.access_lists.size(), 0);
    EXPECT_EQ(st.multi_tx.inputs.size(), 0);
    EXPECT_EQ(st.multi_tx.gas_limits.size(), 1);
    EXPECT_EQ(st.multi_tx.gas_limits[0], 0);
    EXPECT_EQ(st.multi_tx.values.size(), 0);
    EXPECT_EQ(st.cases.size(), 0);
    EXPECT_EQ(st.input_labels.size(), 0);
}

TEST(statetest_loader, validate_deployed_code_test)
{
    {
        state::State state;
        state.insert(0xadd4_address, {.code = "EF0001010000020001000103000100FEDA"_hex});
        EXPECT_THAT([&] { validate_deployed_code(state, EVMC_CANCUN); },
            ThrowsMessage<std::invalid_argument>(
                "EOF container at 0x000000000000000000000000000000000000add4 is invalid: "
                "zero_section_size"));
    }

    {
        state::State state;
        state.insert(0xadd4_address, {.code = "EF00"_hex});
        EXPECT_THAT([&] { validate_deployed_code(state, EVMC_SHANGHAI); },
            ThrowsMessage<std::invalid_argument>(
                "code at 0x000000000000000000000000000000000000add4 "
                "starts with 0xEF00 in Shanghai"));
    }
}
