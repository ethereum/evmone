// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"

namespace evmone
{
template <evmc_call_kind Kind, bool Static>
evmc_status_code call(ExecutionState& state) noexcept
{
    const auto gas = state.stack.pop();
    const auto dst = intx::be::trunc<evmc::address>(state.stack.pop());
    const auto value = (Static || Kind == EVMC_DELEGATECALL) ? 0 : state.stack.pop();
    const auto has_value = value != 0;
    const auto input_offset = state.stack.pop();
    const auto input_size = state.stack.pop();
    const auto output_offset = state.stack.pop();
    const auto output_size = state.stack.pop();

    state.stack.push(0);  // Assume failure.

    if (state.rev >= EVMC_BERLIN && state.host.access_account(dst) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    if (!check_memory(state, input_offset, input_size))
        return EVMC_OUT_OF_GAS;

    if (!check_memory(state, output_offset, output_size))
        return EVMC_OUT_OF_GAS;

    auto msg = evmc_message{};
    msg.kind = Kind;
    msg.flags = Static ? uint32_t{EVMC_STATIC} : state.msg->flags;
    msg.depth = state.msg->depth + 1;
    msg.destination = dst;
    msg.sender = (Kind == EVMC_DELEGATECALL) ? state.msg->sender : state.msg->destination;
    msg.value =
        (Kind == EVMC_DELEGATECALL) ? state.msg->value : intx::be::store<evmc::uint256be>(value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto cost = has_value ? 9000 : 0;

    if constexpr (Kind == EVMC_CALL)
    {
        if (has_value && state.msg->flags & EVMC_STATIC)
            return EVMC_STATIC_MODE_VIOLATION;

        if ((has_value || state.rev < EVMC_SPURIOUS_DRAGON) && !state.host.account_exists(dst))
            cost += 25000;
    }

    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)  // TODO: Always true for STATICCALL.
        msg.gas = std::min(msg.gas, state.gas_left - state.gas_left / 64);
    else if (msg.gas > state.gas_left)
        return EVMC_OUT_OF_GAS;

    if (has_value)
    {
        msg.gas += 2300;  // Add stipend.
        state.gas_left += 2300;
    }

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return EVMC_SUCCESS;

    if (has_value &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->destination)) < value)
        return EVMC_SUCCESS;

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    state.stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    const auto gas_used = msg.gas - result.gas_left;
    state.gas_left -= gas_used;
    return EVMC_SUCCESS;
}

template evmc_status_code call<EVMC_CALL>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CALL, true>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_DELEGATECALL>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CALLCODE>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CREATE>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CREATE2>(ExecutionState& state) noexcept;


template <evmc_call_kind Kind>
evmc_status_code create(ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    const auto endowment = state.stack.pop();
    const auto init_code_offset = state.stack.pop();
    const auto init_code_size = state.stack.pop();

    if (!check_memory(state, init_code_offset, init_code_size))
        return EVMC_OUT_OF_GAS;

    auto salt = uint256{};
    if constexpr (Kind == EVMC_CREATE2)
    {
        salt = state.stack.pop();
        auto salt_cost = num_words(static_cast<size_t>(init_code_size)) * 6;
        if ((state.gas_left -= salt_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    state.stack.push(0);
    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return EVMC_SUCCESS;

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->destination)) < endowment)
        return EVMC_SUCCESS;

    auto msg = evmc_message{};
    msg.gas = state.gas_left;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    msg.kind = Kind;
    if (size_t(init_code_size) > 0)
    {
        msg.input_data = &state.memory[size_t(init_code_offset)];
        msg.input_size = size_t(init_code_size);
    }
    msg.sender = state.msg->destination;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    const auto result = state.host.call(msg);
    state.gas_left -= msg.gas - result.gas_left;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        state.stack.top() = intx::be::load<uint256>(result.create_address);

    return EVMC_SUCCESS;
}

template evmc_status_code create<EVMC_CREATE>(ExecutionState& state) noexcept;
template evmc_status_code create<EVMC_CREATE2>(ExecutionState& state) noexcept;
}  // namespace evmone
