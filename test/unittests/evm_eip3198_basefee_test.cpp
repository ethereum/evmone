// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-3198 "BASEFEE opcode"
/// https://eips.ethereum.org/EIPS/eip-3198

#include "evm_fixture.hpp"

using namespace evmc::literals;
using evmone::test::evm;

TEST_P(evm, basefee_pre_london)
{
    rev = EVMC_BERLIN;
    const auto code = bytecode{OP_BASEFEE};

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, basefee_nominal_case)
{
    // https://eips.ethereum.org/EIPS/eip-3198#nominal-case
    rev = EVMC_LONDON;
    host.tx_context.block_base_fee = evmc::bytes32{7};

    execute(bytecode{} + OP_BASEFEE + OP_STOP);
    EXPECT_GAS_USED(EVMC_SUCCESS, 2);

    execute(bytecode{} + OP_BASEFEE + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 17);
    EXPECT_OUTPUT_INT(7);
}
