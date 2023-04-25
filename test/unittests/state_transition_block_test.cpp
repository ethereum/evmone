// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, block_apply_withdrawal)
{
    static constexpr auto withdrawal_address = 0x8888_address;

    block.withdrawals = {{withdrawal_address, 3}};
    tx.to = To;
    expect.post[withdrawal_address].balance = intx::uint256{3} * 1'000'000'000;
}
