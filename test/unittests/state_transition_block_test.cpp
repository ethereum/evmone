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

TEST_F(state_transition, block_apply_ommers_reward)
{
    static constexpr auto o1 = Ommer{0x0eeee1_address, 1};
    static constexpr auto o2 = Ommer{0x0eeee2_address, 3};

    rev = EVMC_LONDON;
    block_reward = 9'700'000;
    block.ommers = {o1, o2};
    tx.to = To;
    expect.post[o1.beneficiary].balance = block_reward * (8 - o1.delta) / 8;
    expect.post[o2.beneficiary].balance = block_reward * (8 - o2.delta) / 8;

    // Two ommers +1/32 * block_reward for each. +21000 cost of the tx goes to coinbase.
    expect.post[Coinbase].balance = 21000 + block_reward + block_reward / 16;
}
