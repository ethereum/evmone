// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
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
    for (const auto& c : {create().input(0, calldataload(0)) + ret_top(),
             create2().input(0, calldataload(0)) + ret_top()})
    {
        for (const auto r : {EVMC_PARIS, EVMC_SHANGHAI})
        {
            rev = r;
            for (const auto s : {initcode_size_limit, initcode_size_limit + 1})
            {
                execute(c, evmc::uint256be{s});
                if (rev >= EVMC_SHANGHAI && s > initcode_size_limit)
                {
                    EXPECT_STATUS(EVMC_OUT_OF_GAS);
                }
                else
                {
                    EXPECT_OUTPUT_INT(2);
                }
            }
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
