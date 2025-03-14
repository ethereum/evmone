// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, call_value_to_empty)
{
    rev = EVMC_LONDON;
    static constexpr auto BENEFICIARY = 0xbe_address;
    tx.to = To;
    pre[To] = {.balance = 1, .code = call(BENEFICIARY).value(1)};
    pre[BENEFICIARY] = {};

    expect.post[To].balance = 0;
    expect.post[BENEFICIARY].balance = 1;
}

TEST_F(state_transition, delegatecall_static_legacy)
{
    rev = EVMC_OSAKA;
    // Checks if DELEGATECALL forwards the "static" flag.
    static constexpr auto CALLEE1 = 0xca11ee01_address;
    static constexpr auto CALLEE2 = 0xca11ee02_address;
    pre[CALLEE2] = {
        .storage = {{0x01_bytes32, 0xdd_bytes32}},
        .code = sstore(1, 0xcc_bytes32),
    };
    pre[CALLEE1] = {
        .storage = {{0x01_bytes32, 0xdd_bytes32}},
        .code = ret(delegatecall(CALLEE2).gas(100'000)),
    };
    tx.to = To;
    pre[To] = {
        .storage = {{0x01_bytes32, 0xdd_bytes32}, {0x02_bytes32, 0xdd_bytes32}},
        .code = sstore(1, staticcall(CALLEE1).gas(200'000)) +
                sstore(2, returndatacopy(0, 0, returndatasize()) + mload(0)),
    };

    expect.gas_used = 131480;
    // Outer call - success.
    expect.post[To].storage[0x01_bytes32] = 0x01_bytes32;
    // Inner call - no success.
    expect.post[To].storage[0x02_bytes32] = 0x00_bytes32;
    // SSTORE failed.
    expect.post[CALLEE1].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[CALLEE2].storage[0x01_bytes32] = 0xdd_bytes32;
}

TEST_F(state_transition, precompile_proxy)
{
    rev = EVMC_PRAGUE;
    static constexpr auto PRECOMPILE_PROXY = 0x707265636f6d70696c652070726f7879_address;

    const auto store_loop_head = 29;
    const auto store_loop_body = 37;
    auto code = bytecode() +                                       //
                OP_PUSH0 + OP_PUSH0 + OP_CALLDATASIZE +            // [input_size, 0, 0]
                OP_DUP1 + OP_PUSH0 + OP_PUSH0 + OP_CALLDATACOPY +  // [input_size, 0, 0]
                OP_PUSH0 + OP_CALLVALUE + OP_GAS +  // [gas, addr, 0, input_size, 0, 0]
                OP_STATICCALL +                     // [return_code]
                sstore(1) +                         // [] store the return code @ 1.
                OP_RETURNDATASIZE +                 // [output_size]
                OP_DUP1 + OP_PUSH0 + OP_PUSH0 + OP_RETURNDATACOPY +  // [output_size]
                OP_PUSH0 + OP_DUP2 + OP_MSTORE +  // [output_size]  clear 32 bytes after the output.
                OP_DUP1 + sstore(2) +             // [output_size]  store the output size @ 2.
                push(32) +                        // [32, output_size]
                OP_PUSH0 +                        // [off=0, 32, output_size]
                OP_JUMPDEST +                     // @store-loop-head
                OP_DUP3 + OP_DUP2 + OP_LT +       // [off < output_size, off, 32, output_size]
                store_loop_body + OP_JUMPI +      // [off, 32, output_size] → @store-loop-body
                OP_STOP +                         //
                OP_JUMPDEST +                     // @store-loop-body
                OP_DUP1 + OP_MLOAD +              // [output[off], off, 32, output_size]
                OP_DUP2 + OP_SSTORE +             // [off, 32, output_size] store output[off] @ off.
                OP_DUP2 + OP_ADD +                // [off+=32, 32, output_size]
                store_loop_head + OP_JUMP;        // [off, 32, output_size] → @store-loop-head

    EXPECT_EQ(code.find(OP_JUMPDEST), store_loop_head);
    EXPECT_EQ(code.find(OP_JUMPDEST, store_loop_head + 1), store_loop_body);

    pre[PRECOMPILE_PROXY] = {.code = code};
    pre[Sender] = {.balance = 10'000'000'000};
    tx.to = PRECOMPILE_PROXY;
    tx.nonce = 0;
    tx.value = 5;
    tx.data = bytes(213, 0);
    tx.data[31] = 1;
    tx.data[63] = 1;
    tx.data[95] = 100;
    tx.data[96] = 17;
    tx.data[97] = 0xff;
    tx.data[101] = 1;

    expect.post[PRECOMPILE_PROXY].storage[0x01_bytes32] = 0x01_bytes32;
    expect.post[PRECOMPILE_PROXY].storage[0x02_bytes32] = 0x64_bytes32;

    expect.post[PRECOMPILE_PROXY].storage[0x00_bytes32] =
        0x00000000c8e4a8fcde71481761e3f9dff38755b7701ea66ee12a392a2bb8e211_bytes32;
    expect.post[PRECOMPILE_PROXY].storage[0x20_bytes32] =
        0x6ca83dbae17957bb3de73ae80f68c59293df4bdcccc6a7d280c56c0bfb2218a5_bytes32;
    expect.post[PRECOMPILE_PROXY].storage[0x40_bytes32] =
        0x438c174b51dcaf20972674a3057273567b0cdcf9f3b88e058dc164a023343343_bytes32;
    expect.post[PRECOMPILE_PROXY].storage[0x60_bytes32] =
        0x5b7780f100000000000000000000000000000000000000000000000000000000_bytes32;
}
