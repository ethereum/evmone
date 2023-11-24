// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/bytecode.hpp"
#include "state_transition.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_F(state_transition, selfdestruct_shanghai)
{
    rev = EVMC_SHANGHAI;
    tx.to = To;
    pre.insert(*tx.to, {.balance = 0x4e, .code = selfdestruct(0xbe_address)});

    expect.post[To].exists = false;
    expect.post[0xbe_address].balance = 0x4e;
}

TEST_F(state_transition, selfdestruct_cancun)
{
    rev = EVMC_CANCUN;
    tx.to = To;
    pre.insert(*tx.to, {.balance = 0x4e, .code = selfdestruct(0xbe_address)});

    expect.post[To].balance = 0;
    expect.post[0xbe_address].balance = 0x4e;
}

TEST_F(state_transition, selfdestruct_to_self_cancun)
{
    rev = EVMC_CANCUN;
    tx.to = To;
    pre.insert(*tx.to, {.balance = 0x4e, .code = selfdestruct(To)});

    expect.post[To].balance = 0x4e;
}

TEST_F(state_transition, selfdestruct_same_tx_cancun)
{
    rev = EVMC_CANCUN;
    tx.value = 0x4e;
    tx.data = selfdestruct(0xbe_address);
    pre.get(Sender).balance += 0x4e;

    expect.post[0xbe_address].balance = 0x4e;
}
