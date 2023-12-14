// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include "evmone/eof.hpp"

using evmone::test::evm;
using namespace evmc::literals;

TEST_P(evm, eof1_delegatecall_eof1)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.accounts[callee].code = eof_bytecode(OP_STOP);
    bytes call_output{0x01, 0x02, 0x03};
    host.call_result.output_data = std::data(call_output);
    host.call_result.output_size = std::size(call_output);
    host.call_result.gas_left = 100;
    host.call_result.status_code = EVMC_SUCCESS;

    const auto code = eof_bytecode(delegatecall(callee) + OP_RETURNDATASIZE + OP_PUSH0 + OP_PUSH0 +
                                       OP_RETURNDATACOPY + ret(0, evmone::OP_RETURNDATASIZE),
        6);

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "010203");
}

TEST_P(evm, eof1_delegatecall_legacy)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    host.access_account(callee);

    for (const auto& target_code : {""_hex, "EF"_hex, "EF01"_hex, "000000"_hex})
    {
        SCOPED_TRACE("target code: " + hex(target_code));
        host.accounts[callee].code = target_code;

        const auto code = eof_bytecode(delegatecall(callee) + ret_top(), 6);

        execute(code);
        EXPECT_GAS_USED(EVMC_SUCCESS, 133);  // Low gas usage because DELEGATECALL fails lightly.
        EXPECT_OUTPUT_INT(0);
    }
}
