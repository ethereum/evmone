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

TEST_F(state_transition, selfdestruct_double_revert)
{
    rev = EVMC_SHANGHAI;

    static constexpr auto CALL_PROXY = 0xc0_address;
    static constexpr auto REVERT_PROXY = 0xd0_address;
    static constexpr auto SELFDESTRUCT = 0xff_address;
    static constexpr auto BENEFICIARY = 0xbe_address;

    pre.insert(SELFDESTRUCT, {.balance = 1, .code = selfdestruct(BENEFICIARY)});
    pre.insert(CALL_PROXY, {.code = call(SELFDESTRUCT).gas(0xffffff)});
    pre.insert(REVERT_PROXY, {.code = call(SELFDESTRUCT).gas(0xffffff) + revert(0, 0)});
    pre.insert(To, {.code = call(CALL_PROXY).gas(0xffffff) + call(REVERT_PROXY).gas(0xffffff)});
    tx.to = To;

    expect.post[SELFDESTRUCT].exists = false;
    expect.post[CALL_PROXY].exists = true;
    expect.post[REVERT_PROXY].exists = true;
    expect.post[To].exists = true;
    expect.post[BENEFICIARY].balance = 1;
}

TEST_F(state_transition, massdestruct_shanghai)
{
    rev = EVMC_SHANGHAI;

    static constexpr auto BASE = 0xdead0000_address;
    static constexpr auto SINK = 0xbeef_address;
    static constexpr size_t N = 3930;

    const auto b = intx::be::load<intx::uint256>(BASE);
    const auto selfdestruct_code = selfdestruct(SINK);
    bytecode driver_code;
    for (size_t i = 0; i < N; ++i)
    {
        const auto a = intx::be::trunc<address>(b + i);
        pre.insert(a, {.balance = 1, .code = selfdestruct_code});
        driver_code += 5 * OP_PUSH0 + push(a) + OP_DUP1 + OP_CALL + OP_POP;
    }

    tx.to = To;
    tx.gas_limit = 30'000'000;
    block.gas_limit = tx.gas_limit;

    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price;
    pre.insert(*tx.to, {.code = driver_code});
    expect.post[*tx.to].exists = true;

    expect.post[SINK].balance = N;
}

TEST_F(state_transition, massdestruct_cancun)
{
    rev = EVMC_CANCUN;

    static constexpr auto BASE = 0xdead0000_address;
    static constexpr auto SINK = 0xbeef_address;
    static constexpr size_t N = 3930;

    const auto b = intx::be::load<intx::uint256>(BASE);
    const auto selfdestruct_code = selfdestruct(SINK);
    bytecode driver_code;
    for (size_t i = 0; i < N; ++i)
    {
        const auto a = intx::be::trunc<address>(b + i);
        pre.insert(a, {.balance = 1, .code = selfdestruct_code});
        driver_code += 5 * OP_PUSH0 + push(a) + OP_DUP1 + OP_CALL + OP_POP;
        expect.post[a].balance = 0;
    }

    tx.to = To;
    tx.gas_limit = 30'000'000;
    block.gas_limit = tx.gas_limit;

    pre.get(tx.sender).balance = tx.gas_limit * tx.max_gas_price;
    pre.insert(*tx.to, {.code = driver_code});
    expect.post[*tx.to].exists = true;

    expect.post[SINK].balance = N;
}
