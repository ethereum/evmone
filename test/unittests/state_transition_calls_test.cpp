// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, delegatecall_static_legacy)
{
    rev = EVMC_PRAGUE;
    // Checks if DELEGATECALL forwards the "static" flag.
    constexpr auto callee1 = 0xca11ee01_address;
    constexpr auto callee2 = 0xca11ee02_address;
    pre.insert(callee2,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = sstore(1, 0xcc_bytes32),
        });
    pre.insert(callee1,
        {
            .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
            .code = ret(delegatecall(callee2).gas(100'000)),
        });

    tx.to = To;
    pre.insert(
        *tx.to, {
                    .storage = {{0x01_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}},
                        {0x02_bytes32, {.current = 0xdd_bytes32, .original = 0xdd_bytes32}}},
                    .code = sstore(1, staticcall(callee1).gas(200'000)) +
                            sstore(2, returndatacopy(0, 0, returndatasize()) + mload(0)),
                });
    expect.gas_used = 131480;
    // Outer call - success.
    expect.post[*tx.to].storage[0x01_bytes32] = 0x01_bytes32;
    // Inner call - no success.
    expect.post[*tx.to].storage[0x02_bytes32] = 0x00_bytes32;
    // SSTORE failed.
    expect.post[callee1].storage[0x01_bytes32] = 0xdd_bytes32;
    expect.post[callee2].storage[0x01_bytes32] = 0xdd_bytes32;
}
