// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, eof1_delegatecall2_eof1)
{
    rev = EVMC_PRAGUE;

    constexpr auto callee = 0xca11ee_address;
    pre.insert(callee,
        {
            .storage = {{0x02_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code =
                eof_bytecode(sstore(2, 0xcc_bytes32) + mstore(0, 0x010203_bytes32) + ret(0, 32), 2),
        });
    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x02_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + sstore(1, returndataload(0)) + OP_STOP, 3),
        });

    expect.gas_used = 50742;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x010203_bytes32;
    // SSTORE executed on caller.
    expect.post[callee].storage[0x02_bytes32] = 0xdd_bytes32;
    expect.post[*tx.to].storage[0x02_bytes32] = 0xcc_bytes32;
}

TEST_F(state_transition, eof1_delegatecall2_legacy)
{
    rev = EVMC_PRAGUE;

    constexpr auto callee = 0xca11ee_address;
    pre.insert(callee, {
                           .code = sstore(3, 0xcc_bytes32),
                       });
    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}},
                {0x02_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                sstore(1, delegatecall2(callee)) + sstore(2, returndatasize()) + OP_STOP, 3),
        });

    expect.gas_used = 26894;  // Low gas usage because DELEGATECALL2 fails lightly
    // Call - light failure.
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    // Returndata empty.
    expect.post[*tx.to].storage[0x02_bytes32] = 0x00_bytes32;
    // SSTORE not executed.
    expect.post[callee].storage[0x03_bytes32] = 0x00_bytes32;
    expect.post[*tx.to].storage[0x03_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, delegatecall2_static)
{
    rev = EVMC_PRAGUE;
    // Checks if DELEGATECALL2 forwards the "static" flag.
    constexpr auto callee1 = 0xca11ee01_address;
    constexpr auto callee2 = 0xca11ee02_address;
    pre.insert(callee2,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });
    pre.insert(callee1,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(ret(delegatecall2(callee2)), 3),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}},
                {0x02_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                sstore(1, staticcall2(callee1)) + sstore(2, returndataload(0)) + OP_STOP, 3),
        });
    expect.gas_used = 974995;
    // Outer call - success.
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    // Inner call - abort.
    expect.post[*tx.to].storage[0x02_bytes32] = 0x02_bytes32;
    // SSTORE failed.
    expect.post[callee1].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee2].storage[0x01_bytes32] = 0xdd_bytes32;
}

TEST_F(state_transition, call2_failing_with_value_balance_check)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, call2(callee).input(0x0, 0xff).value(0x1)) + OP_STOP, 4),
        });
    // Fails on balance check.
    tx.gas_limit = 21000 + 12000 + 5000;

    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[callee].storage[0x01_bytes32] = 0xdd_bytes32;
}

TEST_F(state_transition, call2_failing_with_value_additional_cost)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, call2(callee).input(0x0, 0xff).value(0x1)) + OP_STOP, 4),
        });
    // Fails on value transfer additional cost - maximum gas limit that triggers this
    tx.gas_limit = 37639 - 1;

    expect.gas_used = tx.gas_limit;
    expect.post[*tx.to].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.status = EVMC_OUT_OF_GAS;
}

TEST_F(state_transition, call2_with_value)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .balance = 0x01,
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, call2(callee).input(0x0, 0xff).value(0x1)) + OP_STOP, 4),
        });
    expect.gas_used = 37845;

    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[callee].storage[0x01_bytes32] = 0xcc_bytes32;
}

TEST_F(state_transition, call2_output)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(0x0a0b_bytes32), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                call2(callee) + sstore(1, returndatacopy(31, 30, 1) + mload(0)) + OP_STOP, 4),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x000a_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, delegatecall2_output)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(0x0a0b_bytes32), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                delegatecall2(callee) + sstore(1, returndatacopy(31, 30, 1) + mload(0)) + OP_STOP,
                4),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x000a_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, staticcall2_output)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(0x0a0b_bytes32), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                staticcall2(callee) + sstore(1, returndatacopy(31, 30, 1) + mload(0)) + OP_STOP, 4),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x000a_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_value_zero_to_nonexistent_account)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, call2(callee).input(0x0, 0xff).value(0x0)) + OP_STOP, 4),
        });
    tx.gas_limit = 30000;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, call2_then_oog)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + call2(callee) + rjump(-3), 4),
        });
    // Enough to complete CALL2, OOG in infinite loop.
    tx.gas_limit = 35000;

    expect.gas_used = tx.gas_limit;
    expect.post[*tx.to].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.status = EVMC_OUT_OF_GAS;
}

TEST_F(state_transition, delegatecall2_then_oog)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + delegatecall2(callee) + rjump(-3), 3),
        });
    // Enough to complete DELEGATECALL2, OOG in infinite loop.
    tx.gas_limit = 35000;

    expect.gas_used = tx.gas_limit;
    expect.post[*tx.to].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.status = EVMC_OUT_OF_GAS;
}

TEST_F(state_transition, staticcall2_then_oog)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(OP_STOP),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0xcc_bytes32) + staticcall2(callee) + rjump(-3), 3),
        });
    // Enough to complete STATICCALL2, OOG in infinite loop.
    tx.gas_limit = 35000;

    expect.gas_used = tx.gas_limit;
    expect.post[*tx.to].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee].exists = true;
    expect.status = EVMC_OUT_OF_GAS;
}

TEST_F(state_transition, call2_input)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(eq(calldataload(0), 0x010203)), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(mstore(0, 0x010203) + call2(callee).input(0, 32) +
                                     sstore(1, returndataload(0)) + OP_STOP,
                4),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, delegatecall2_input)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(eq(calldataload(0), 0x010203)), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(mstore(0, 0x010203) + delegatecall2(callee).input(0, 32) +
                                     sstore(1, returndataload(0)) + OP_STOP,
                3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, staticcall2_input)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(eq(calldataload(0), 0x010203)), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(mstore(0, 0x010203) + staticcall2(callee).input(0, 32) +
                                     sstore(1, returndataload(0)) + OP_STOP,
                3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_with_value_enough_gas)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {.balance = 0x1});

    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_bytecode(call2(callee).value(1) + OP_POP + OP_STOP, 4),
                       });

    // Just enough to ensure MIN_CALLEE_GAS.
    // FIXME: should be too little when MIN_CALLEE_GAS is implemented
    tx.gas_limit = 21000 + 4 * 3 + 9000 + 2600 + 2;
    expect.gas_used = tx.gas_limit;
    expect.post[*tx.to].exists = true;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_with_value_low_gas)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {.balance = 0x1});

    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_bytecode(call2(callee).value(1) + OP_POP + OP_STOP, 4),
                       });

    // Not enough to ensure MIN_CALLEE_GAS.
    // FIXME: should be too little when MIN_CALLEE_GAS is implemented
    tx.gas_limit = 21000 + 4 * 3 + 9000 + 2600 + 2 - 1;
    expect.gas_used = tx.gas_limit;
    expect.status = EVMC_OUT_OF_GAS;
    expect.post[*tx.to].exists = true;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_recipient_and_code_address)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .code = eof_bytecode(ret(eq(OP_ADDRESS, callee) + eq(OP_CALLER, To) + OP_AND), 3),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(call2(callee) + sstore(1, returndataload(0)) + OP_STOP, 4),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, delegatecall2_recipient_and_code_address)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .code = eof_bytecode(ret(eq(OP_ADDRESS, To) + eq(OP_CALLER, tx.sender) + OP_AND), 3),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + sstore(1, returndataload(0)) + OP_STOP, 3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, staticcall2_recipient_and_code_address)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .code = eof_bytecode(ret(eq(OP_ADDRESS, callee) + eq(OP_CALLER, To) + OP_AND), 3),
        });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(staticcall2(callee) + sstore(1, returndataload(0)) + OP_STOP, 3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[callee].exists = true;
}


TEST_F(state_transition, call2_value)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .balance = 0x0,
                           .code = eof_bytecode(OP_STOP),
                       });

    tx.to = To;
    pre.insert(*tx.to, {
                           .balance = 0x1,
                           .code = eof_bytecode(call2(callee).value(0x1) + OP_STOP, 4),
                       });
    expect.post[*tx.to].exists = true;
    expect.post[callee].balance = 1;
}

TEST_F(state_transition, returndatasize_before_call2)
{
    rev = EVMC_PRAGUE;

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, returndatasize()) + OP_STOP, 2),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, delegatecall2_returndatasize)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(0, 0x13), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + sstore(1, returndatasize()) + OP_STOP, 3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x13_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, delegatecall2_returndatasize_abort)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(OP_INVALID),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + sstore(1, returndatasize()) + OP_STOP, 3),
        });
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, returndatacopy)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    const auto call_output =
        0x497f3c9f61479c1cfa53f0373d39d2bf4e5f73f71411da62f1d6b85c03a60735_bytes32;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(call_output), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                delegatecall2(callee) + sstore(1, returndatacopy(0, 0, 32) + mload(0)) + OP_STOP,
                4),
        });
    expect.gas_used = 28654;
    expect.post[*tx.to].storage[0x01_bytes32] = call_output;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, returndataload)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    const auto call_output =
        0x497f3c9f61479c1cfa53f0373d39d2bf4e5f73f71411da62f1d6b85c03a60735_bytes32;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(call_output), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + sstore(1, returndataload(0)) + OP_STOP, 3),
        });
    expect.gas_used = 28636;
    expect.post[*tx.to].storage[0x01_bytes32] = call_output;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_clears_returndata)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;
    const auto call_output =
        0x497f3c9f61479c1cfa53f0373d39d2bf4e5f73f71411da62f1d6b85c03a60735_bytes32;

    pre.insert(callee, {
                           .code = eof_bytecode(ret(call_output), 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(
                call2(callee) + call2(callee).value(1) + sstore(1, returndatasize()) + OP_STOP, 5),
        });

    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[callee].exists = true;
}

TEST_F(state_transition, call2_gas_refund_propagation)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(sstore(1, 0x00) + OP_STOP, 2),
        });

    tx.to = To;
    pre.insert(*tx.to, {
                           .code = eof_bytecode(call2(callee) + OP_STOP, 4),
                       });
    expect.gas_used = 21000 + 2600 + 5000 + 6 * 3 - 4800;
    expect.post[*tx.to].exists = true;
    expect.post[callee].storage[0x01_bytes32] = 0x00_bytes32;
}

TEST_F(state_transition, delegatecall2_gas_refund_propagation)
{
    rev = EVMC_PRAGUE;
    constexpr auto callee = 0xca11ee_address;

    pre.insert(callee, {
                           .code = eof_bytecode(sstore(1, 0x00) + OP_STOP, 2),
                       });

    tx.to = To;
    pre.insert(*tx.to,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = eof_bytecode(delegatecall2(callee) + OP_STOP, 3),
        });
    expect.gas_used = 21000 + 2600 + 5000 + 5 * 3 - 4800;
    expect.post[*tx.to].storage[0x01_bytes32] = 0x00_bytes32;
    expect.post[callee].exists = true;
}
