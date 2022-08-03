// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests that access or modify the contract storage.

#include "evm_fixture.hpp"

using namespace evmc::literals;
using evmone::test::evm;

TEST_P(evm, storage)
{
    const auto code = sstore(0xee, 0xff) + sload(0xee) + mstore8(0) + ret(0, 1);
    execute(100000, code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 20224);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), bytes{0xff});
}

TEST_P(evm, sstore_pop_stack)
{
    execute(100000, sstore(1, dup1(0)) + mstore8(0) + ret(0, 1));
    EXPECT_GAS_USED(EVMC_SUCCESS, 5024);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), bytes{0x00});
    EXPECT_EQ(
        host.accounts[msg.recipient].storage.find(0x01_bytes32)->second.current, 0x00_bytes32);
}

TEST_P(evm, sload_cost_pre_tangerine_whistle)
{
    rev = EVMC_HOMESTEAD;
    execute(56, sload(dup1(0)));
    EXPECT_GAS_USED(EVMC_SUCCESS, 56);
    EXPECT_EQ(host.accounts[msg.recipient].storage.size(), 0);
}

TEST_P(evm, sstore_out_of_block_gas)
{
    const auto code = push(0) + sstore(0, 1) + OP_POP;

    // Barely enough gas to execute successfully.
    host.accounts[msg.recipient] = {};  // Reset contract account.
    execute(20011, code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 20011);

    // Out of block gas - 1 too low.
    host.accounts[msg.recipient] = {};  // Reset contract account.
    execute(20010, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);

    // Out of block gas - 2 too low.
    host.accounts[msg.recipient] = {};  // Reset contract account.
    execute(20009, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);

    // SSTORE instructions out of gas.
    host.accounts[msg.recipient] = {};  // Reset contract account.
    execute(20008, code);
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
}

TEST_P(evm, sstore_cost)
{
    auto& storage = host.accounts[msg.recipient].storage;

    constexpr auto v1 = 0x01_bytes32;

    for (auto r : {EVMC_BYZANTIUM, EVMC_CONSTANTINOPLE, EVMC_PETERSBURG, EVMC_ISTANBUL})
    {
        rev = r;

        // Added:
        storage.clear();
        execute(20006, sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage.clear();
        execute(20005, sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Deleted:
        storage.clear();
        storage[v1] = v1;
        execute(5006, sstore(1, 0));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage[v1] = v1;
        execute(5005, sstore(1, 0));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Modified:
        storage.clear();
        storage[v1] = v1;
        execute(5006, sstore(1, 2));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        storage[v1] = v1;
        execute(5005, sstore(1, 2));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Unchanged:
        storage.clear();
        storage[v1] = v1;
        execute(sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 806);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 206);
        else
            EXPECT_EQ(gas_used, 5006);
        execute(205, sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

        // Added & unchanged:
        storage.clear();
        execute(sstore(1, 1) + sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 20812);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 20212);
        else
            EXPECT_EQ(gas_used, 25012);

        // Modified again:
        storage.clear();
        storage[v1] = {v1, 0x00_bytes32};
        execute(sstore(1, 2));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 806);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 206);
        else
            EXPECT_EQ(gas_used, 5006);

        // Added & modified again:
        storage.clear();
        execute(sstore(1, 1) + sstore(1, 2));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 20812);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 20212);
        else
            EXPECT_EQ(gas_used, 25012);

        // Modified & modified again:
        storage.clear();
        storage[v1] = v1;
        execute(sstore(1, 2) + sstore(1, 3));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 5812);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 5212);
        else
            EXPECT_EQ(gas_used, 10012);

        // Modified & modified again back to original:
        storage.clear();
        storage[v1] = v1;
        execute(sstore(1, 2) + sstore(1, 1));
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);
        if (rev >= EVMC_ISTANBUL)
            EXPECT_EQ(gas_used, 5812);
        else if (rev == EVMC_CONSTANTINOPLE)
            EXPECT_EQ(gas_used, 5212);
        else
            EXPECT_EQ(gas_used, 10012);
    }
}

TEST_P(evm, sstore_below_stipend)
{
    const auto code = sstore(0, 0);

    rev = EVMC_HOMESTEAD;
    execute(2306, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

    rev = EVMC_CONSTANTINOPLE;
    execute(2306, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    rev = EVMC_ISTANBUL;
    execute(2306, code);
    EXPECT_EQ(result.status_code, EVMC_OUT_OF_GAS);

    execute(2307, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
}
