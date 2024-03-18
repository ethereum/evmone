// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "instructions.hpp"

namespace evmone::instr::core
{
template <Opcode Op>
Result call_impl(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    static_assert(
        Op == OP_CALL || Op == OP_CALLCODE || Op == OP_DELEGATECALL || Op == OP_STATICCALL);

    const auto gas = stack.pop();
    const auto dst = intx::be::trunc<evmc::address>(stack.pop());
    const auto value = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? 0 : stack.pop();
    const auto has_value = value != 0;
    const auto input_offset_u256 = stack.pop();
    const auto input_size_u256 = stack.pop();
    const auto output_offset_u256 = stack.pop();
    const auto output_size_u256 = stack.pop();

    stack.push(0);  // Assume failure.
    state.return_data.clear();

    if (state.rev >= EVMC_BERLIN && state.host.access_account(dst) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    if (!check_memory(gas_left, state.memory, input_offset_u256, input_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    if (!check_memory(gas_left, state.memory, output_offset_u256, output_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto input_offset = static_cast<size_t>(input_offset_u256);
    const auto input_size = static_cast<size_t>(input_size_u256);
    const auto output_offset = static_cast<size_t>(output_offset_u256);
    const auto output_size = static_cast<size_t>(output_size_u256);

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

    if (input_size > 0)
    {
        // input_offset may be garbage if input_size == 0.
        msg.input_data = &state.memory[input_offset];
        msg.input_size = input_size;
    }

    auto cost = has_value ? 9000 : 0;

    if constexpr (Op == OP_CALL)
    {
        if (has_value && state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        if ((has_value || state.rev < EVMC_SPURIOUS_DRAGON) && !state.host.account_exists(dst))
            cost += 25000;
    }

    if ((gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)  // TODO: Always true for STATICCALL.
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (has_value)
    {
        msg.gas += 2300;  // Add stipend.
        gas_left += 2300;
    }

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (has_value && intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < value)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if constexpr (Op == OP_DELEGATECALL)
    {
        if (state.rev >= EVMC_PRAGUE && is_eof_container(state.original_code))
        {
            // The code targeted by DELEGATECALL must also be an EOF.
            // This restriction has been added to EIP-3540 in
            // https://github.com/ethereum/EIPs/pull/7131
            uint8_t target_code_prefix[2];
            const auto s = state.host.copy_code(
                msg.code_address, 0, target_code_prefix, std::size(target_code_prefix));
            if (!is_eof_container({target_code_prefix, s}))
                return {EVMC_SUCCESS, gas_left};
        }
    }

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(output_size, result.output_size); copy_size > 0)
        std::memcpy(&state.memory[output_offset], result.output_data, copy_size);

    const auto gas_used = msg.gas - result.gas_left;
    gas_left -= gas_used;
    state.gas_refund += result.gas_refund;
    return {EVMC_SUCCESS, gas_left};
}

template Result call_impl<OP_CALL>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;
template Result call_impl<OP_STATICCALL>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;
template Result call_impl<OP_DELEGATECALL>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;
template Result call_impl<OP_CALLCODE>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;


template <Opcode Op>
Result create_impl(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    static_assert(Op == OP_CREATE || Op == OP_CREATE2);

    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, gas_left};

    const auto endowment = stack.pop();
    const auto init_code_offset_u256 = stack.pop();
    const auto init_code_size_u256 = stack.pop();
    const auto salt = (Op == OP_CREATE2) ? stack.pop() : uint256{};

    stack.push(0);  // Assume failure.
    state.return_data.clear();

    if (!check_memory(gas_left, state.memory, init_code_offset_u256, init_code_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto init_code_offset = static_cast<size_t>(init_code_offset_u256);
    const auto init_code_size = static_cast<size_t>(init_code_size_u256);

    if (state.rev >= EVMC_SHANGHAI && init_code_size > 0xC000)
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto init_code_word_cost = 6 * (Op == OP_CREATE2) + 2 * (state.rev >= EVMC_SHANGHAI);
    const auto init_code_cost = num_words(init_code_size) * init_code_word_cost;
    if ((gas_left -= init_code_cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    auto msg = evmc_message{};
    msg.gas = gas_left;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    msg.kind = (Op == OP_CREATE) ? EVMC_CREATE : EVMC_CREATE2;
    if (init_code_size > 0)
    {
        // init_code_offset may be garbage if init_code_size == 0.
        msg.input_data = &state.memory[init_code_offset];
        msg.input_size = init_code_size;

        // EOF initcode is not allowed for legacy creation
        if (is_eof_container({msg.input_data, msg.input_size}))
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.
    }
    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    const auto result = state.host.call(msg);
    gas_left -= msg.gas - result.gas_left;
    state.gas_refund += result.gas_refund;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = intx::be::load<uint256>(result.create_address);

    return {EVMC_SUCCESS, gas_left};
}

template <Opcode Op>
Result create_eof_impl(
    StackTop stack, int64_t gas_left, ExecutionState& state, code_iterator& pos) noexcept
{
    static_assert(Op == OP_EOFCREATE || Op == OP_TXCREATE);

    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, gas_left};

    const auto initcode_hash = (Op == OP_TXCREATE) ? stack.pop() : uint256{};
    const auto endowment = stack.pop();
    const auto salt = stack.pop();
    const auto input_offset_u256 = stack.pop();
    const auto input_size_u256 = stack.pop();

    stack.push(0);  // Assume failure.
    state.return_data.clear();

    if (!check_memory(gas_left, state.memory, input_offset_u256, input_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    bytes_view initcontainer;
    if constexpr (Op == OP_EOFCREATE)
    {
        const auto initcontainer_index = uint8_t{pos[1]};
        pos += 2;
        const auto& container = state.original_code;
        const auto eof_header = read_valid_eof1_header(state.original_code);
        initcontainer = eof_header.get_container(container, initcontainer_index);
    }
    else
    {
        pos += 1;

        const auto initcode =
            state.get_tx_initcode_by_hash(intx::be::store<evmc::bytes32>(initcode_hash));
        if (initcode.data == nullptr)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure

        initcontainer = {initcode.data, initcode.size};

        // Charge for initcode validation.
        constexpr auto initcode_word_cost_validation = 2;
        const auto initcode_cost_validation =
            num_words(initcontainer.size()) * initcode_word_cost_validation;
        if ((gas_left -= initcode_cost_validation) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    // Charge for initcode hashing.
    constexpr auto initcode_word_cost_hashing = 6;
    const auto initcode_cost_hashing = num_words(initcontainer.size()) * initcode_word_cost_hashing;
    if ((gas_left -= initcode_cost_hashing) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto input_offset = static_cast<size_t>(input_offset_u256);
    const auto input_size = static_cast<size_t>(input_size_u256);

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if constexpr (Op == OP_TXCREATE)
    {
        const auto error_subcont = validate_eof(state.rev, initcontainer);
        if (error_subcont != EOFValidationError::success)
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.

        const auto initcontainer_header = read_valid_eof1_header(initcontainer);
        if (!initcontainer_header.can_init(initcontainer.size()))
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.
    }

    auto msg = evmc_message{};
    msg.gas = gas_left - gas_left / 64;
    msg.kind = EVMC_EOFCREATE;
    if (input_size > 0)
    {
        // input_data may be garbage if init_code_size == 0.
        msg.input_data = &state.memory[input_offset];
        msg.input_size = input_size;
    }

    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);
    // init_code is guaranteed to be non-empty by validation of container sections
    msg.code = initcontainer.data();
    msg.code_size = initcontainer.size();

    const auto result = state.host.call(msg);
    gas_left -= msg.gas - result.gas_left;
    state.gas_refund += result.gas_refund;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = intx::be::load<uint256>(result.create_address);

    return {EVMC_SUCCESS, gas_left};
}

template Result create_impl<OP_CREATE>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;
template Result create_impl<OP_CREATE2>(
    StackTop stack, int64_t gas_left, ExecutionState& state) noexcept;
template Result create_eof_impl<OP_EOFCREATE>(
    StackTop stack, int64_t gas_left, ExecutionState& state, code_iterator& pos) noexcept;
template Result create_eof_impl<OP_TXCREATE>(
    StackTop stack, int64_t gas_left, ExecutionState& state, code_iterator& pos) noexcept;
}  // namespace evmone::instr::core
