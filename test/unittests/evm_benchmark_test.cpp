// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM code generators for micro benchmarks,
/// organized as unit tests.

#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, grow_memory_with_mload)
{
    const auto code = calldataload(0) + push(0) +
                      4096 * (bytecode{OP_DUP1} + OP_MLOAD + OP_POP + OP_DUP2 + OP_ADD);
    ASSERT_LT(code.size(), 0x6000);
    // EXPECT_EQ(hex(code), "");  // Uncomment to get the code dump.

    // Pokes the same offset 0 all the time.
    execute(code, "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_GAS_USED(EVMC_SUCCESS, 57356);

    // Pokes memory offset increasing by 1, memory grows every 32nd "iteration".
    execute(code, "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_GAS_USED(EVMC_SUCCESS, 57772);

    // Pokes memory offset increasing by 32, memory grows every "iteration".
    execute(code, "0000000000000000000000000000000000000000000000000000000000000020");
    EXPECT_GAS_USED(EVMC_SUCCESS, 102409);
}

TEST_P(evm, grow_memory_with_mstore)
{
    const auto code = calldataload(0) + push(0) +
                      4096 * (bytecode{OP_DUP1} + OP_DUP1 + OP_MSTORE + OP_DUP2 + OP_ADD);
    ASSERT_LT(code.size(), 0x6000);
    // EXPECT_EQ(hex(code), "");  // Uncomment to get the code dump.

    // Pokes the same offset 0 all the time.
    execute(code, "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_GAS_USED(EVMC_SUCCESS, 61452);

    // Pokes memory offset increasing by 1, memory grows every 32nd "iteration".
    execute(code, "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_GAS_USED(EVMC_SUCCESS, 61868);

    // Pokes memory offset increasing by 32, memory grows every "iteration".
    execute(code, "0000000000000000000000000000000000000000000000000000000000000020");
    EXPECT_GAS_USED(EVMC_SUCCESS, 106505);
}
