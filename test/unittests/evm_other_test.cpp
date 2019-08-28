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
