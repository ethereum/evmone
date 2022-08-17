// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"

namespace evmone::instr::core
{
evmc_status_code sload(StackTop stack, ExecutionState& state) noexcept
{
    auto& x = stack.top();
    const auto key = intx::be::store<evmc::bytes32>(x);

    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
    {
        // The warm storage access cost is already applied (from the cost table).
        // Here we need to apply additional cold storage access cost.
        constexpr auto additional_cold_sload_cost =
            instr::cold_sload_cost - instr::warm_storage_read_cost;
        if ((state.gas_left -= additional_cold_sload_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_storage(state.msg->recipient, key));

    return EVMC_SUCCESS;
}

evmc_status_code sstore(StackTop stack, ExecutionState& state) noexcept
{
    if (state.in_static_mode())
        return EVMC_STATIC_MODE_VIOLATION;

    if (state.rev >= EVMC_ISTANBUL && state.gas_left <= 2300)
        return EVMC_OUT_OF_GAS;

    const auto key = intx::be::store<evmc::bytes32>(stack.pop());
    const auto value = intx::be::store<evmc::bytes32>(stack.pop());

    int cost = 0;
    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
        cost = instr::cold_sload_cost;

    const auto status = state.host.set_storage(state.msg->recipient, key, value);

    if (state.rev <= EVMC_BYZANTIUM || state.rev == EVMC_PETERSBURG)  // legacy
    {
        switch (status)
        {
        case EVMC_STORAGE_ASSIGNED:
        case EVMC_STORAGE_MODIFIED_DELETED:
        case EVMC_STORAGE_ADDED_DELETED:
        case EVMC_STORAGE_MODIFIED_RESTORED:
        case EVMC_STORAGE_MODIFIED:
        case EVMC_STORAGE_DELETED:
            cost = 5000;
            break;
        case EVMC_STORAGE_ADDED:
        case EVMC_STORAGE_DELETED_ADDED:
        case EVMC_STORAGE_DELETED_RESTORED:
            cost = 20000;
            break;
        }
    }
    else  // net gas cost metering
    {
        switch (status)
        {
        case EVMC_STORAGE_ASSIGNED:
        case EVMC_STORAGE_DELETED_ADDED:
        case EVMC_STORAGE_DELETED_RESTORED:
        case EVMC_STORAGE_MODIFIED_DELETED:
        case EVMC_STORAGE_ADDED_DELETED:
        case EVMC_STORAGE_MODIFIED_RESTORED:
            if (state.rev >= EVMC_BERLIN)
                cost += instr::warm_storage_read_cost;
            else if (state.rev == EVMC_ISTANBUL)
                cost = 800;
            else
                cost = 200;  // Constantinople
            break;
        case EVMC_STORAGE_MODIFIED:
        case EVMC_STORAGE_DELETED:
            if (state.rev >= EVMC_BERLIN)
                cost += 5000 - instr::cold_sload_cost;
            else
                cost = 5000;
            break;
        case EVMC_STORAGE_ADDED:
            cost += 20000;
            break;
        }
    }
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}
}  // namespace evmone::instr::core
