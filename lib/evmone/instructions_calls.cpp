// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"

namespace evmone
{
template <evmc_call_kind Kind, bool Static>
evmc_status_code call(ExecutionState& state) noexcept
{
    auto gas = state.stack.pop();
    const auto dst = intx::be::trunc<evmc::address>(state.stack.pop());
    const auto value = (Static || Kind == EVMC_DELEGATECALL) ? uint256{0} : state.stack.pop();
    const auto input_offset = state.stack.pop();
    const auto input_size = state.stack.pop();
    const auto output_offset = state.stack.pop();
    const auto output_size = state.stack.pop();

    state.stack.push(0);  // Assume failure.

    if (!check_memory(state, input_offset, input_size))
        return EVMC_OUT_OF_GAS;

    if (!check_memory(state, output_offset, output_size))
        return EVMC_OUT_OF_GAS;

    auto msg = evmc_message{};
    msg.kind = Kind;
    msg.flags = Static ? uint32_t{EVMC_STATIC} : state.msg.flags;
    msg.depth = state.msg.depth + 1;
    msg.destination = dst;
    msg.sender = (Kind == EVMC_DELEGATECALL) ? state.msg.sender : state.msg.destination;
    msg.value =
        (Kind == EVMC_DELEGATECALL) ? state.msg.value : intx::be::store<evmc::uint256be>(value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto cost = 0;
    const auto has_value = value != 0;
    if (has_value)
        cost += 9000;

    if constexpr (Kind == EVMC_CALL)
    {
        if (has_value && state.msg.flags & EVMC_STATIC)
            return EVMC_STATIC_MODE_VIOLATION;

        if (has_value || state.rev < EVMC_SPURIOUS_DRAGON)
        {
            if (!state.host.account_exists(dst))
                cost += 25000;
        }
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

    state.return_data.clear();

    if (state.msg.depth >= 1024)
    {
        if (has_value)
            state.gas_left += 2300;  // Return unused stipend.
        if (state.gas_left < 0)
            return EVMC_OUT_OF_GAS;
        return EVMC_SUCCESS;
    }

    if (has_value)
    {
        const auto balance = intx::be::load<uint256>(state.host.get_balance(state.msg.destination));
        if (balance < value)
        {
            state.gas_left += 2300;  // Return unused stipend.
            if (state.gas_left < 0)
                return EVMC_OUT_OF_GAS;
            return EVMC_SUCCESS;
        }

        msg.gas += 2300;  // Add stipend.
    }

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    state.stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;
    if (has_value)
        gas_used -= 2300;

    if ((state.gas_left -= gas_used) < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}

template evmc_status_code call<EVMC_CALL>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CALL, true>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_DELEGATECALL>(ExecutionState& state) noexcept;
template evmc_status_code call<EVMC_CALLCODE>(ExecutionState& state) noexcept;
}  // namespace evmone
