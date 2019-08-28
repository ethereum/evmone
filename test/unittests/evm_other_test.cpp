// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

/// This file contains non-mainstream EVM unit tests not matching any concrete category:
/// - regression tests,
/// - tests from fuzzers,
/// - evmone's internal tests.

#include "evm_fixture.hpp"
#include <test/utils/bytecode.hpp>

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
}
