// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-3860 "Limit and meter initcode"
/// https://eips.ethereum.org/EIPS/eip-3860

#include "evm_fixture.hpp"

using namespace evmc::literals;
using evmone::test::evm;

inline constexpr size_t initcode_size_limit = 0xc000;

TEST_P(evm, create_initcode_limit)
{
    host.call_result.create_address = 0x02_address;
    const auto code = create().input(0, calldataload(0)) + ret_top();
    for (const auto r : {EVMC_PARIS, EVMC_SHANGHAI})
    {
        rev = r;
        for (const auto s : {initcode_size_limit, initcode_size_limit + 1})
        {
            execute(code, evmc::uint256be{s});
            EXPECT_STATUS(EVMC_SUCCESS);
            const unsigned expected_output =
                rev >= EVMC_SHANGHAI && s > initcode_size_limit ? 0 : 2;
            EXPECT_OUTPUT_INT(expected_output);
        }
    }
}

TEST_P(evm, create2_initcode_limit)
{
    host.call_result.create_address = 0x02_address;
    const auto code = create2().input(0, calldataload(0)) + ret_top();
    for (const auto r : {EVMC_PARIS, EVMC_SHANGHAI})
    {
        rev = r;
        for (const auto s : {initcode_size_limit, initcode_size_limit + 1})
        {
            execute(code, evmc::uint256be{s});
            EXPECT_STATUS(EVMC_SUCCESS);
            const unsigned expected_output =
                rev >= EVMC_SHANGHAI && s > initcode_size_limit ? 0 : 2;
            EXPECT_OUTPUT_INT(expected_output);
        }
    }
}

TEST_P(evm, create_initcode_gas_cost)
{
    rev = EVMC_SHANGHAI;
    const auto code = create().input(0, calldataload(0));
    execute(44300, code, evmc::uint256be{initcode_size_limit});
    EXPECT_GAS_USED(EVMC_SUCCESS, 44300);
    execute(44299, code, evmc::uint256be{initcode_size_limit});
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
}

TEST_P(evm, create2_initcode_gas_cost)
{
    rev = EVMC_SHANGHAI;
    const auto code = create2().input(0, calldataload(0));
    execute(53519, code, evmc::uint256be{initcode_size_limit});
    EXPECT_GAS_USED(EVMC_SUCCESS, 53519);
    execute(53518, code, evmc::uint256be{initcode_size_limit});
    EXPECT_STATUS(EVMC_OUT_OF_GAS);
}

TEST_P(evm, create2_stack_check)
{
    // Checks if CREATE2 properly handles values on EVM stack.
    rev = EVMC_SHANGHAI;
    host.call_result.create_address = 0xca_address;
    const auto code =
        push(0x84) + create2().input(0, calldataload(0)).salt(0x42) + sstore(0) + sstore(1);

    for (const auto& input : {0xC000_bytes32, 0xC001_bytes32})
    {
        execute(code, input);
        EXPECT_STATUS(EVMC_SUCCESS);
        auto& storage = host.accounts[msg.recipient].storage;
        EXPECT_EQ(
            storage[0x00_bytes32].current, input == 0xC001_bytes32 ? 0x00_bytes32 : 0xca_bytes32);
        EXPECT_EQ(storage[0x01_bytes32].current, 0x84_bytes32);
    }
}
