// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests that perform any kind of calls.

#include "evm_fixture.hpp"

using namespace intx;
using evmone::test::evm;

constexpr auto identity_addr = 4;

TEST_P(evm, precompiled_identity)
{
    const auto code =
        mstore(0, 0xaabbccdd) + call(identity_addr).gas(18).input(27, 6).output(1, 4) + ret(0, 32);

    execute(code);
    EXPECT_EQ(host.recorded_calls.size(), 0);
    //                     output                                                 input
    //                    /      \                                            /          \.
    EXPECT_OUTPUT_INT(0x0000aabbcc0000000000000000000000000000000000000000000000aabbccdd_u256);
}

TEST_P(evm, precompiled_identity_oog)
{
    const auto code = delegatecall(identity_addr).gas(20).input(0, 64) + ret_top();

    execute(code);
    EXPECT_EQ(host.recorded_calls.size(), 0);
    EXPECT_OUTPUT_INT(0);
}
