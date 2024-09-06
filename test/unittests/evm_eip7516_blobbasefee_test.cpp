// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for EIP-7516: "BLOBBASEFEE opcode"
/// https://eips.ethereum.org/EIPS/eip-7516

#include "evm_fixture.hpp"

using namespace evmc::literals;
using namespace intx::literals;
using namespace evmone::test;

TEST_P(evm, blobbasefee_pre_cancun)
{
    rev = EVMC_SHANGHAI;
    const auto code = bytecode{OP_BLOBBASEFEE};

    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, blobbasefee_1)
{
    rev = EVMC_CANCUN;
    host.tx_context.blob_base_fee = 0x01_bytes32;

    execute(bytecode{} + OP_BLOBBASEFEE);
    EXPECT_GAS_USED(EVMC_SUCCESS, 2);

    execute(bytecode{} + OP_BLOBBASEFEE + ret_top());
    EXPECT_GAS_USED(EVMC_SUCCESS, 17);
    EXPECT_OUTPUT_INT(1);
}

TEST_P(evm, blobbasefee_dede)
{
    rev = EVMC_CANCUN;
    host.tx_context.blob_base_fee =
        0x8ededededededededededededededededededededededededededededededed1_bytes32;

    execute(bytecode{} + OP_BLOBBASEFEE + ret_top());
    EXPECT_OUTPUT_INT(0x8ededededededededededededededededededededededededededededededed1_u256);
}
