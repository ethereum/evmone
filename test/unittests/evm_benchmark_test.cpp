// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM code generators for micro benchmarks,
/// organized as unit tests.

#include "evm_fixture.hpp"
#include <numeric>
#include <random>

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

TEST_P(evm, jump_around)
{
    // Generates code built from a number of "jumppads" (JUMPDEST PUSH JUMP).
    // Each jumppad is visited exactly once in pseudo-random order.

    constexpr size_t num_jumps = 4096;
    std::vector<uint16_t> jump_order(num_jumps, 0);

    // Generate sequence starting from 1, 0 is the execution starting point.
    std::iota(std::begin(jump_order), std::end(jump_order), uint16_t{1});

    // Shuffle jump order, leaving the highest value in place for the last jump to the code end.
    std::shuffle(std::begin(jump_order), std::prev(std::end(jump_order)), std::mt19937_64{0});

    const auto jumppad_code = bytecode{OP_JUMPDEST} + push(OP_PUSH2, "") + OP_JUMP;
    auto code = num_jumps * jumppad_code + OP_JUMPDEST;

    uint16_t cur_target = 0;
    for (const auto next_target : jump_order)
    {
        const auto pushdata_loc = &code[cur_target * std::size(jumppad_code) + 2];
        const auto next_offset = next_target * std::size(jumppad_code);
        pushdata_loc[0] = static_cast<uint8_t>(next_offset >> 8);
        pushdata_loc[1] = static_cast<uint8_t>(next_offset);
        cur_target = next_target;
    }

    // EXPECT_EQ(hex(code), "");  // Uncomment to get the code dump.

    execute(code);
    EXPECT_GAS_USED(EVMC_SUCCESS, int64_t{(1 + 3 + 8) * num_jumps + 1});
}
