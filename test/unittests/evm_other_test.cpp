// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

/// This file contains non-mainstream EVM unit tests not matching any concrete category:
/// - regression tests,
/// - tests from fuzzers,
/// - evmone's internal tests.

#include "evm_fixture.hpp"
#include <evmone/limits.hpp>

using evm_other = evm;

TEST_F(evm_other, evmone_loaded_program_relocation)
{
    // The bytecode of size 2 will create evmone's loaded program of size 4 and will cause
    // the relocation of the C++ vector containing the program instructions.
    execute(bytecode{} + OP_STOP + OP_ORIGIN);
    EXPECT_GAS_USED(EVMC_SUCCESS, 0);
}

TEST_F(evm_other, evmone_block_stack_req_overflow)
{
    // This tests constructs a code with single basic block which stack requirement is > int16 max.
    // Such basic block can cause int16_t overflow during analysis.
    // The CALL instruction is going to be used because it has -6 stack change.

    const auto code = push(1) + 10 * OP_DUP1 + 5463 * OP_CALL;
    execute(code);
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);

    execute(code + ret_top());  // A variant with terminator.
    EXPECT_STATUS(EVMC_STACK_UNDERFLOW);
}

TEST_F(evm_other, loop_full_of_jumpdests)
{
    // The code is a simple loop with a counter taken from the input or a constant (325) if the
    // input is zero. The loop body contains of only JUMPDESTs, as much as the code size limit
    // allows.

    // The `mul(325, iszero(dup1(calldataload(0)))) + OP_OR` is equivalent of
    // `((x == 0) * 325) | x`
    // what is
    // `x == 0 ? 325 : x`.

    // The `not_(0)` is -1 so we can do `loop_counter + (-1)` to decrease the loop counter.

    const auto code = push(15) + not_(0) + mul(325, iszero(dup1(calldataload(0)))) + OP_OR +
                      (max_code_size - 20) * OP_JUMPDEST + OP_DUP2 + OP_ADD + OP_DUP1 + OP_DUP4 +
                      OP_JUMPI;

    EXPECT_EQ(code.size(), max_code_size);

    execute(code);
    EXPECT_GAS_USED(EVMC_SUCCESS, 7987882);
}
