// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"

namespace evmone::instr::core
{
template <evmc_opcode Op>
evmc_status_code call_impl(StackTop stack, ExecutionState& state) noexcept
{
    static_assert(
        Op == OP_CALL || Op == OP_CALLCODE || Op == OP_DELEGATECALL || Op == OP_STATICCALL);

    const auto gas = stack.pop();
    const auto dst = intx::be::trunc<evmc::address>(stack.pop());
    const auto value = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? 0 : stack.pop();
    const auto has_value = value != 0;
    const auto input_offset = stack.pop();
    const auto input_size = stack.pop();
    const auto output_offset = stack.pop();
    const auto output_size = stack.pop();

    stack.push(0);  // Assume failure.

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
    msg.kind = (Op == OP_DELEGATECALL) ? EVMC_DELEGATECALL :
               (Op == OP_CALLCODE)     ? EVMC_CALLCODE :
                                         EVMC_CALL;
    msg.flags = (Op == OP_STATICCALL) ? uint32_t{EVMC_STATIC} : state.msg->flags;
    msg.depth = state.msg->depth + 1;
    msg.recipient = (Op == OP_CALL || Op == OP_STATICCALL) ? dst : state.msg->recipient;
    msg.code_address = dst;
    msg.sender = (Op == OP_DELEGATECALL) ? state.msg->sender : state.msg->recipient;
    msg.value =
        (Op == OP_DELEGATECALL) ? state.msg->value : intx::be::store<evmc::uint256be>(value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto cost = has_value ? 9000 : 0;

    if constexpr (Op == OP_CALL)
    {
        if (has_value && state.in_static_mode())
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

    if (has_value && intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < value)
        return EVMC_SUCCESS;

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    const auto gas_used = msg.gas - result.gas_left;
    state.gas_left -= gas_used;
    return EVMC_SUCCESS;
}

template evmc_status_code call_impl<OP_CALL>(StackTop stack, ExecutionState& state) noexcept;
template evmc_status_code call_impl<OP_STATICCALL>(StackTop stack, ExecutionState& state) noexcept;
template evmc_status_code call_impl<OP_DELEGATECALL>(
    StackTop stack, ExecutionState& state) noexcept;
template evmc_status_code call_impl<OP_CALLCODE>(StackTop stack, ExecutionState& state) noexcept;


template <evmc_opcode Op>
evmc_status_code create_impl(StackTop stack, ExecutionState& state) noexcept
{
    static_assert(Op == OP_CREATE || Op == OP_CREATE2);

    if (state.in_static_mode())
        return EVMC_STATIC_MODE_VIOLATION;

    const auto endowment = stack.pop();
    const auto init_code_offset = stack.pop();
    const auto init_code_size = stack.pop();

    if (!check_memory(state, init_code_offset, init_code_size))
        return EVMC_OUT_OF_GAS;

    auto salt = uint256{};
    if constexpr (Op == OP_CREATE2)
    {
        salt = stack.pop();
        auto salt_cost = num_words(static_cast<size_t>(init_code_size)) * 6;
        if ((state.gas_left -= salt_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    stack.push(0);
    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return EVMC_SUCCESS;

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment)
        return EVMC_SUCCESS;

    auto msg = evmc_message{};
    msg.gas = state.gas_left;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    msg.kind = (Op == OP_CREATE) ? EVMC_CREATE : EVMC_CREATE2;
    if (size_t(init_code_size) > 0)
    {
        msg.input_data = &state.memory[size_t(init_code_offset)];
        msg.input_size = size_t(init_code_size);
    }
    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    const auto result = state.host.call(msg);
    state.gas_left -= msg.gas - result.gas_left;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = intx::be::load<uint256>(result.create_address);

    return EVMC_SUCCESS;
}

template evmc_status_code create_impl<OP_CREATE>(StackTop stack, ExecutionState& state) noexcept;
template evmc_status_code create_impl<OP_CREATE2>(StackTop stack, ExecutionState& state) noexcept;
}  // namespace evmone::instr::core
