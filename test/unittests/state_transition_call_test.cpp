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
    pre.insert(*tx.to, {.balance = 1, .code = call(BENEFICIARY).value(1)});
    pre.insert(BENEFICIARY, {});

    expect.post[To].balance = 0;
    expect.post[BENEFICIARY].balance = 1;
}
