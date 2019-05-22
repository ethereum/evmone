// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

namespace evmone
{
namespace
{
constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

bool check_memory(execution_state& state, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)
        return true;

    constexpr auto limit = uint32_t(-1);

    if (offset > limit || size > limit)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return false;
    }

    const auto o = static_cast<int64_t>(offset);
    const auto s = static_cast<int64_t>(size);

    const auto m = static_cast<int64_t>(state.memory.size());

    const auto new_size = o + s;
    if (m < new_size)
    {
        auto w = (new_size + 31) / 32;
        auto new_cost = 3 * w + w * w / 512;
        auto cost = new_cost - state.memory_prev_cost;
        state.memory_prev_cost = new_cost;

        state.gas_left -= cost;
        if (state.gas_left < 0)
        {
            state.run = false;
            state.status = EVMC_OUT_OF_GAS;
            return false;
        }

        state.memory.resize(static_cast<size_t>(w * 32));
    }

    return true;
}


void op_stop(execution_state& state, instr_argument) noexcept
{
    state.run = false;
}

void op_add(execution_state& state, instr_argument) noexcept
{
    state.item(1) += state.item(0);
    state.stack.pop_back();
}

void op_mul(execution_state& state, instr_argument) noexcept
{
    state.item(1) *= state.item(0);
    state.stack.pop_back();
}

void op_sub(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) - state.item(1);
    state.stack.pop_back();
}

void op_div(execution_state& state, instr_argument) noexcept
{
    auto& v = state.item(1);
    v = v != 0 ? state.item(0) / v : 0;
    state.stack.pop_back();
}

void op_sdiv(execution_state& state, instr_argument) noexcept
{
    auto& v = state.item(1);
    v = v != 0 ? intx::sdivrem(state.item(0), v).quot : 0;
    state.stack.pop_back();
}

void op_mod(execution_state& state, instr_argument) noexcept
{
    auto& v = state.item(1);
    v = v != 0 ? state.item(0) % v : 0;
    state.stack.pop_back();
}

void op_smod(execution_state& state, instr_argument) noexcept
{
    auto& v = state.item(1);
    v = v != 0 ? intx::sdivrem(state.item(0), v).rem : 0;
    state.stack.pop_back();
}

void op_addmod(execution_state& state, instr_argument) noexcept
{
    using intx::uint512;
    auto x = state.item(0);
    auto y = state.item(1);
    auto m = state.item(2);
    state.stack.pop_back();
    state.stack.pop_back();

    state.item(0) = m != 0 ? ((uint512{x} + uint512{y}) % uint512{m}).lo : 0;
}

void op_mulmod(execution_state& state, instr_argument) noexcept
{
    using intx::uint512;
    auto x = state.item(0);
    auto y = state.item(1);
    auto m = state.item(2);
    state.stack.pop_back();
    state.stack.pop_back();

    state.item(0) = m != 0 ? ((uint512{x} * uint512{y}) % uint512{m}).lo : 0;
}

void op_exp(execution_state& state, instr_argument arg) noexcept
{
    auto base = state.item(0);
    auto& exponent = state.item(1);

    auto exponent_significant_bytes = intx::count_significant_words<uint8_t>(exponent);

    auto additional_cost = exponent_significant_bytes * arg.p.number;
    state.gas_left -= additional_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    exponent = intx::exp(base, exponent);
    state.stack.pop_back();
}

void op_signextend(execution_state& state, instr_argument) noexcept
{
    auto ext = state.item(0);
    state.stack.pop_back();
    auto& x = state.item(0);

    if (ext < 31)
    {
        auto sign_bit = static_cast<int>(ext) * 8 + 7;
        auto sign_mask = intx::uint256{1} << sign_bit;
        auto value_mask = sign_mask - 1;
        auto is_neg = (x & sign_mask) != 0;
        x = is_neg ? x | ~value_mask : x & value_mask;
    }
}

void op_lt(execution_state& state, instr_argument) noexcept
{
    // OPT: Have single function implementing all comparisons.
    state.item(1) = state.item(0) < state.item(1);
    state.stack.pop_back();
}

void op_gt(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(1) < state.item(0);
    state.stack.pop_back();
}

void op_slt(execution_state& state, instr_argument) noexcept
{
    auto x = state.item(0);
    auto y = state.item(1);
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.item(1) = (x_neg ^ y_neg) ? x_neg : x < y;
    state.stack.pop_back();
}

void op_sgt(execution_state& state, instr_argument) noexcept
{
    auto x = state.item(0);
    auto y = state.item(1);
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.item(1) = (x_neg ^ y_neg) ? y_neg : y < x;
    state.stack.pop_back();
}

void op_eq(execution_state& state, instr_argument) noexcept
{
    state.item(1) = state.item(0) == state.item(1);
    state.stack.pop_back();
}

void op_iszero(execution_state& state, instr_argument) noexcept
{
    state.item(0) = state.item(0) == 0;
}

void op_and(execution_state& state, instr_argument) noexcept
{
    state.item(1) &= state.item(0);
    state.stack.pop_back();
}

void op_or(execution_state& state, instr_argument) noexcept
{
    state.item(1) |= state.item(0);
    state.stack.pop_back();
}

void op_xor(execution_state& state, instr_argument) noexcept
{
    state.item(1) ^= state.item(0);
    state.stack.pop_back();
}

void op_not(execution_state& state, instr_argument) noexcept
{
    state.item(0) = ~state.item(0);
}

void op_byte(execution_state& state, instr_argument) noexcept
{
    auto n = state.item(0);
    auto& x = state.item(1);

    if (n > 31)
        x = 0;
    else
    {
        auto sh = (31 - static_cast<unsigned>(n)) * 8;
        auto y = x >> sh;
        x = y & 0xff;
    }

    state.stack.pop_back();
}

void op_shl(execution_state& state, instr_argument) noexcept
{
    state.item(1) <<= state.item(0);
    state.stack.pop_back();
}

void op_shr(execution_state& state, instr_argument) noexcept
{
    state.item(1) >>= state.item(0);
    state.stack.pop_back();
}

void op_sar(execution_state& state, instr_argument arg) noexcept
{
    if ((state.item(1) & (intx::uint256{1} << 255)) == 0)
        return op_shr(state, arg);

    constexpr auto allones = ~uint256{};

    if (state.item(0) >= 256)
        state.item(1) = allones;
    else
    {
        const auto shift = static_cast<unsigned>(state.item(0));
        state.item(1) = (state.item(1) >> shift) | (allones << (256 - shift));
    }

    state.stack.pop_back();
}

void op_sha3(execution_state& state, instr_argument) noexcept
{
    auto index = state.item(0);
    auto size = state.item(1);

    if (!check_memory(state, index, size))
        return;

    auto i = static_cast<size_t>(index);
    auto s = static_cast<size_t>(size);
    auto w = (static_cast<int64_t>(s) + 31) / 32;
    auto cost = w * 6;
    state.gas_left -= cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    auto h = ethash::keccak256(&state.memory[i], s);

    state.stack.pop_back();
    state.item(0) = intx::be::uint256(h.bytes);
}

void op_address(execution_state& state, instr_argument) noexcept
{
    // TODO: Might be generalized using pointers to class member.
    uint8_t data[32] = {};
    std::memcpy(&data[12], state.msg->destination.bytes, sizeof(state.msg->destination));
    auto a = intx::be::uint256(data);
    state.stack.push_back(a);
}

void op_balance(execution_state& state, instr_argument) noexcept
{
    auto& x = state.item(0);
    uint8_t data[32];
    intx::be::store(data, x);
    evmc_address addr;
    std::memcpy(addr.bytes, &data[12], sizeof(addr));
    x = intx::be::uint256(state.host.get_balance(addr).bytes);
}

void op_origin(execution_state& state, instr_argument) noexcept
{
    uint8_t data[32] = {};
    std::memcpy(&data[12], state.host.get_tx_context().tx_origin.bytes, sizeof(evmc_address));
    auto x = intx::be::uint256(data);
    state.stack.push_back(x);
}

void op_caller(execution_state& state, instr_argument) noexcept
{
    // TODO: Might be generalized using pointers to class member.
    uint8_t data[32] = {};
    std::memcpy(&data[12], state.msg->sender.bytes, sizeof(state.msg->sender));
    auto a = intx::be::uint256(data);
    state.stack.push_back(a);
}

void op_callvalue(execution_state& state, instr_argument) noexcept
{
    auto a = intx::be::uint256(state.msg->value.bytes);
    state.stack.push_back(a);
}

void op_calldataload(execution_state& state, instr_argument) noexcept
{
    auto& index = state.item(0);

    if (state.msg->input_size < index)
        index = 0;
    else
    {
        const auto begin = static_cast<size_t>(index);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        index = intx::be::uint256(data);
    }
}

void op_calldatasize(execution_state& state, instr_argument) noexcept
{
    auto s = intx::uint256{state.msg->input_size};
    state.stack.push_back(s);
}

void op_calldatacopy(execution_state& state, instr_argument) noexcept
{
    auto mem_index = state.item(0);
    auto input_index = state.item(1);
    auto size = state.item(2);

    if (!check_memory(state, mem_index, size))
        return;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.msg->input_size < input_index ? state.msg->input_size :
                                                     static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.msg->input_size - src);

    auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
    state.gas_left -= copy_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
}

void op_codesize(execution_state& state, instr_argument) noexcept
{
    auto s = intx::uint256{state.code_size};
    state.stack.push_back(s);
}

void op_codecopy(execution_state& state, instr_argument) noexcept
{
    auto mem_index = state.item(0);
    auto input_index = state.item(1);
    auto size = state.item(2);

    if (!check_memory(state, mem_index, size))
        return;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.code_size < input_index ? state.code_size : static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.code_size - src);

    auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
    state.gas_left -= copy_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    std::memcpy(&state.memory[dst], &state.code[src], copy_size);
    std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
}

void op_mload(execution_state& state, instr_argument) noexcept
{
    auto& index = state.item(0);

    if (!check_memory(state, index, 32))
        return;

    index = intx::be::uint256(&state.memory[static_cast<size_t>(index)]);
}

void op_mstore(execution_state& state, instr_argument) noexcept
{
    auto index = state.item(0);
    auto x = state.item(1);

    if (!check_memory(state, index, 32))
        return;

    intx::be::store(&state.memory[static_cast<size_t>(index)], x);

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_mstore8(execution_state& state, instr_argument) noexcept
{
    auto index = state.item(0);
    auto x = state.item(1);

    if (!check_memory(state, index, 1))
        return;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(x);

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_sload(execution_state& state, instr_argument) noexcept
{
    auto& x = state.item(0);
    evmc_bytes32 key;
    intx::be::store(key.bytes, x);
    x = intx::be::uint256(state.host.get_storage(state.msg->destination, key).bytes);
}

void op_sstore(execution_state& state, instr_argument arg) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
    {
        // TODO: Implement static mode violation in analysis.
        state.run = false;
        state.status = EVMC_STATIC_MODE_VIOLATION;
        return;
    }

    evmc_bytes32 key;
    evmc_bytes32 value;
    intx::be::store(key.bytes, state.item(0));
    intx::be::store(value.bytes, state.item(1));
    state.stack.pop_back();
    state.stack.pop_back();
    auto status = state.host.set_storage(state.msg->destination, key, value);
    auto rev = static_cast<evmc_revision>(arg.p.number);
    int cost = 0;
    switch (status)
    {
    case EVMC_STORAGE_UNCHANGED:
        cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
        break;
    case EVMC_STORAGE_MODIFIED:
        cost = 5000;
        break;
    case EVMC_STORAGE_MODIFIED_AGAIN:
        cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
        break;
    case EVMC_STORAGE_ADDED:
        cost = 20000;
        break;
    case EVMC_STORAGE_DELETED:
        cost = 5000;
        break;
    }
    state.gas_left -= cost;
    if (state.gas_left < 0)
    {
        state.status = EVMC_OUT_OF_GAS;
        state.run = false;
    }
}

void op_jump(execution_state& state, instr_argument) noexcept
{
    auto dst = state.item(0);
    int pc = -1;
    if (std::numeric_limits<int>::max() < dst ||
        (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
    {
        state.run = false;
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return;
    }

    state.pc = static_cast<size_t>(pc);
    state.stack.pop_back();
}

void op_jumpi(execution_state& state, instr_argument) noexcept
{
    auto condition = state.item(1);
    if (condition != 0)
    {
        // TODO: Call op_jump here.
        auto dst = state.item(0);
        int pc = -1;
        if (std::numeric_limits<int>::max() < dst ||
            (pc = state.analysis->find_jumpdest(static_cast<int>(dst))) < 0)
        {
            state.run = false;
            state.status = EVMC_BAD_JUMP_DESTINATION;
            return;
        }
        state.pc = static_cast<size_t>(pc);
    }

    state.stack.pop_back();
    state.stack.pop_back();
}

void op_pc(execution_state& state, instr_argument arg) noexcept
{
    state.stack.emplace_back(arg.p.number);
}

void op_msize(execution_state& state, instr_argument) noexcept
{
    state.stack.emplace_back(state.memory.size());
}

void op_gas(execution_state& state, instr_argument arg) noexcept
{
    auto correction = state.current_block_cost - arg.p.number;
    intx::uint256 gas = static_cast<uint64_t>(state.gas_left + correction);
    state.stack.push_back(gas);
}

void op_jumpdest(execution_state&, instr_argument) noexcept
{
    // OPT: We can skip JUMPDEST instruction in analysis.
}

void op_gasprice(execution_state& state, instr_argument) noexcept
{
    auto x = intx::be::uint256(state.host.get_tx_context().tx_gas_price.bytes);
    state.stack.push_back(x);
}

void op_extcodesize(execution_state& state, instr_argument) noexcept
{
    auto& x = state.item(0);
    uint8_t data[32];
    intx::be::store(data, x);
    evmc_address addr;
    std::memcpy(addr.bytes, &data[12], sizeof(addr));
    x = state.host.get_code_size(addr);
}

void op_extcodecopy(execution_state& state, instr_argument) noexcept
{
    auto addr_data = state.item(0);
    auto mem_index = state.item(1);
    auto input_index = state.item(2);
    auto size = state.item(3);

    if (!check_memory(state, mem_index, size))
        return;

    auto dst = static_cast<size_t>(mem_index);
    auto src = max_buffer_size < input_index ? max_buffer_size : static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);

    auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
    state.gas_left -= copy_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    uint8_t data[32];
    intx::be::store(data, addr_data);
    evmc_address addr;
    std::memcpy(addr.bytes, &data[12], sizeof(addr));

    auto num_bytes_copied = state.host.copy_code(addr, src, &state.memory[dst], s);

    std::memset(&state.memory[dst + num_bytes_copied], 0, s - num_bytes_copied);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
}

void op_returndatasize(execution_state& state, instr_argument) noexcept
{
    state.stack.emplace_back(state.return_data.size());
}

void op_returndatacopy(execution_state& state, instr_argument) noexcept
{
    auto mem_index = state.item(0);
    auto input_index = state.item(1);
    auto size = state.item(2);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();

    if (!check_memory(state, mem_index, size))
        return;

    auto dst = static_cast<size_t>(mem_index);
    auto s = static_cast<size_t>(size);

    if (state.return_data.size() < input_index)
    {
        state.run = false;
        state.status = EVMC_INVALID_MEMORY_ACCESS;
        return;
    }
    auto src = static_cast<size_t>(input_index);

    if (src + s > state.return_data.size())
    {
        state.run = false;
        state.status = EVMC_INVALID_MEMORY_ACCESS;
        return;
    }

    auto copy_cost = ((static_cast<int64_t>(s) + 31) / 32) * 3;
    state.gas_left -= copy_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    if (s > 0)
        std::memcpy(&state.memory[dst], &state.return_data[src], s);
}

void op_extcodehash(execution_state& state, instr_argument) noexcept
{
    auto& x = state.item(0);
    uint8_t data[32];
    intx::be::store(data, x);
    evmc_address addr;
    std::memcpy(addr.bytes, &data[12], sizeof(addr));
    x = intx::be::uint256(state.host.get_code_hash(addr).bytes);
}

void op_blockhash(execution_state& state, instr_argument) noexcept
{
    auto& number = state.item(0);

    auto upper_bound = state.host.get_tx_context().block_number;
    auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    auto n = static_cast<int64_t>(number);
    auto header = evmc_bytes32{};
    if (number < upper_bound && n >= lower_bound)
        header = state.host.get_block_hash(n);
    number = intx::be::uint256(header.bytes);
}

void op_coinbase(execution_state& state, instr_argument) noexcept
{
    uint8_t data[32] = {};
    std::memcpy(&data[12], state.host.get_tx_context().block_coinbase.bytes, sizeof(evmc_address));
    auto x = intx::be::uint256(data);
    state.stack.push_back(x);
}

void op_timestamp(execution_state& state, instr_argument) noexcept
{
    auto x = intx::uint256{static_cast<uint64_t>(state.host.get_tx_context().block_timestamp)};
    state.stack.push_back(x);
}

void op_number(execution_state& state, instr_argument) noexcept
{
    auto x = intx::uint256{static_cast<uint64_t>(state.host.get_tx_context().block_number)};
    state.stack.push_back(x);
}

void op_difficulty(execution_state& state, instr_argument) noexcept
{
    auto x = intx::be::uint256(state.host.get_tx_context().block_difficulty.bytes);
    state.stack.push_back(x);
}

void op_gaslimit(execution_state& state, instr_argument) noexcept
{
    auto x = intx::uint256{static_cast<uint64_t>(state.host.get_tx_context().block_gas_limit)};
    state.stack.push_back(x);
}

void op_push_full(execution_state& state, instr_argument arg) noexcept
{
    // OPT: For smaller pushes, use pointer data directly.
    auto x = intx::be::uint256(arg.data);
    state.stack.push_back(x);
}

void op_pop(execution_state& state, instr_argument) noexcept
{
    state.stack.pop_back();
}

void op_dup(execution_state& state, instr_argument arg) noexcept
{
    state.stack.push_back(state.item(static_cast<size_t>(arg.p.number)));
}

void op_swap(execution_state& state, instr_argument arg) noexcept
{
    std::swap(state.item(0), state.item(static_cast<size_t>(arg.p.number)));
}

void op_log(execution_state& state, instr_argument arg) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
    {
        // TODO: Implement static mode violation in analysis.
        state.run = false;
        state.status = EVMC_STATIC_MODE_VIOLATION;
        return;
    }

    auto offset = state.item(0);
    auto size = state.item(1);

    if (!check_memory(state, offset, size))
        return;

    auto o = static_cast<size_t>(offset);
    auto s = static_cast<size_t>(size);

    auto cost = int64_t(s) * 8;
    state.gas_left -= cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
    }

    state.stack.pop_back();
    state.stack.pop_back();

    std::array<evmc_bytes32, 4> topics;
    for (auto i = 0; i < arg.p.number; ++i)
    {
        intx::be::store(topics[i].bytes, state.item(0));
        state.stack.pop_back();
    }

    state.host.emit_log(state.msg->destination, &state.memory[o], s, topics.data(),
        static_cast<size_t>(arg.p.number));
}

void op_invalid(execution_state& state, instr_argument) noexcept
{
    state.run = false;
    state.status = EVMC_INVALID_INSTRUCTION;
}

void op_return(execution_state& state, instr_argument) noexcept
{
    auto offset = state.item(0);
    auto size = state.item(1);

    if (!check_memory(state, offset, size))
        return;

    state.run = false;
    state.output_offset = static_cast<size_t>(offset);
    state.output_size = static_cast<size_t>(size);
}

void op_revert(execution_state& state, instr_argument) noexcept
{
    auto offset = state.item(0);
    auto size = state.item(1);

    if (!check_memory(state, offset, size))
        return;

    state.run = false;
    state.status = EVMC_REVERT;
    state.output_offset = static_cast<size_t>(offset);
    state.output_size = static_cast<size_t>(size);
}

void op_call(execution_state& state, instr_argument arg) noexcept
{
    auto gas = state.item(0);

    uint8_t data[32];
    intx::be::store(data, state.item(1));
    auto dst = evmc_address{};
    std::memcpy(dst.bytes, &data[12], sizeof(dst));

    auto value = state.item(2);
    auto input_offset = state.item(3);
    auto input_size = state.item(4);
    auto output_offset = state.item(5);
    auto output_size = state.item(6);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = 0;

    if (!check_memory(state, input_offset, input_size))
        return;

    if (!check_memory(state, output_offset, output_size))
        return;


    auto msg = evmc_message{};
    msg.kind = arg.p.call_kind;
    msg.flags = state.msg->flags;
    intx::be::store(msg.value.bytes, value);

    auto correction = state.current_block_cost - arg.p.number;
    auto gas_left = state.gas_left + correction;

    auto cost = 0;
    auto has_value = value != 0;
    if (has_value)
    {
        if (arg.p.call_kind == EVMC_CALL && state.msg->flags & EVMC_STATIC)
        {
            state.run = false;
            state.status = EVMC_STATIC_MODE_VIOLATION;
            return;
        }
        cost += 9000;
    }

    if (arg.p.call_kind == EVMC_CALL && (has_value || state.rev < EVMC_SPURIOUS_DRAGON))
    {
        if (!state.host.account_exists(dst))
            cost += 25000;
    }

    state.gas_left -= cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    gas_left -= cost;

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    state.return_data.clear();

    if (state.msg->depth >= 1024)
    {
        if (has_value)
            state.gas_left += 2300;  // Return unused stipend.
        return;
    }

    msg.destination = dst;
    msg.sender = state.msg->destination;
    intx::be::store(msg.value.bytes, value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    msg.depth = state.msg->depth + 1;

    if (has_value)
    {
        auto balance = state.host.get_balance(state.msg->destination);
        auto b = intx::be::uint256(balance.bytes);
        if (b < value)
        {
            state.gas_left += 2300;  // Return unused stipend.
            return;
        }

        msg.gas += 2300;  // Add stipend.
    }

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);


    state.item(0) = result.status_code == EVMC_SUCCESS;

    if (auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    if (has_value)
        gas_used -= 2300;

    state.gas_left -= gas_used;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }
}

void op_delegatecall(execution_state& state, instr_argument arg) noexcept
{
    auto gas = state.item(0);

    uint8_t data[32];
    intx::be::store(data, state.item(1));
    auto dst = evmc_address{};
    std::memcpy(dst.bytes, &data[12], sizeof(dst));

    auto input_offset = state.item(2);
    auto input_size = state.item(3);
    auto output_offset = state.item(4);
    auto output_size = state.item(5);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = 0;

    if (!check_memory(state, input_offset, input_size))
        return;

    if (!check_memory(state, output_offset, output_size))
        return;

    auto msg = evmc_message{};
    msg.kind = EVMC_DELEGATECALL;

    auto correction = state.current_block_cost - arg.p.number;
    auto gas_left = state.gas_left + correction;

    // TEST: Gas saturation for big gas values.
    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)  // TEST: gas_left vs state.gas_left.
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    if (state.msg->depth >= 1024)
        return;

    msg.depth = state.msg->depth + 1;
    msg.flags = state.msg->flags;
    msg.destination = dst;
    msg.sender = state.msg->sender;
    msg.value = state.msg->value;

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);

    state.item(0) = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    state.gas_left -= gas_used;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }
}

void op_staticcall(execution_state& state, instr_argument arg) noexcept
{
    auto gas = state.item(0);

    uint8_t data[32];
    intx::be::store(data, state.item(1));
    auto dst = evmc_address{};
    std::memcpy(dst.bytes, &data[12], sizeof(dst));

    auto input_offset = state.item(2);
    auto input_size = state.item(3);
    auto output_offset = state.item(4);
    auto output_size = state.item(5);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = 0;

    if (!check_memory(state, input_offset, input_size))
        return;

    if (!check_memory(state, output_offset, output_size))
        return;

    if (state.msg->depth >= 1024)
        return;

    auto msg = evmc_message{};
    msg.kind = EVMC_CALL;
    msg.flags |= EVMC_STATIC;

    msg.depth = state.msg->depth + 1;

    auto correction = state.current_block_cost - arg.p.number;
    auto gas_left = state.gas_left + correction;

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    msg.gas = std::min(msg.gas, gas_left - gas_left / 64);

    msg.destination = dst;
    msg.sender = state.msg->destination;

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    state.item(0) = result.status_code == EVMC_SUCCESS;

    if (auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    state.gas_left -= gas_used;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }
}

void op_create(execution_state& state, instr_argument arg) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
    {
        // TODO: Implement static mode violation in analysis.
        state.run = false;
        state.status = EVMC_STATIC_MODE_VIOLATION;
        return;
    }

    auto endowment = state.item(0);
    auto init_code_offset = state.item(1);
    auto init_code_size = state.item(2);

    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = 0;

    if (!check_memory(state, init_code_offset, init_code_size))
        return;

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return;

    if (endowment != 0)
    {
        auto balance = intx::be::uint256(state.host.get_balance(state.msg->destination).bytes);
        if (balance < endowment)
            return;
    }

    auto msg = evmc_message{};

    auto correction = state.current_block_cost - arg.p.number;
    msg.gas = state.gas_left + correction;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    msg.kind = EVMC_CREATE;

    if (size_t(init_code_size) > 0)
    {
        msg.input_data = &state.memory[size_t(init_code_offset)];
        msg.input_size = size_t(init_code_size);
    }

    msg.sender = state.msg->destination;
    msg.depth = state.msg->depth + 1;
    intx::be::store(msg.value.bytes, endowment);

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
    {
        uint8_t data[32] = {};
        std::memcpy(&data[12], &result.create_address, sizeof(result.create_address));
        state.item(0) = intx::be::uint256(data);
    }

    state.gas_left -= msg.gas - result.gas_left;
}

void op_create2(execution_state& state, instr_argument arg) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
    {
        // TODO: Implement static mode violation in analysis.
        state.run = false;
        state.status = EVMC_STATIC_MODE_VIOLATION;
        return;
    }

    auto endowment = state.item(0);
    auto init_code_offset = state.item(1);
    auto init_code_size = state.item(2);
    auto salt = state.item(3);

    state.stack.pop_back();
    state.stack.pop_back();
    state.stack.pop_back();
    state.item(0) = 0;

    if (!check_memory(state, init_code_offset, init_code_size))
        return;

    auto salt_cost = ((int64_t(init_code_size) + 31) / 32) * 6;
    state.gas_left -= salt_cost;
    if (state.gas_left < 0)
    {
        state.run = false;
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return;

    if (endowment != 0)
    {
        auto balance = intx::be::uint256(state.host.get_balance(state.msg->destination).bytes);
        if (balance < endowment)
            return;
    }

    auto msg = evmc_message{};

    auto correction = state.current_block_cost - arg.p.number;
    auto gas = state.gas_left + correction;
    msg.gas = gas - gas / 64;

    msg.kind = EVMC_CREATE2;
    if (size_t(init_code_size) > 0)
    {
        msg.input_data = &state.memory[size_t(init_code_offset)];
        msg.input_size = size_t(init_code_size);
    }
    msg.sender = state.msg->destination;
    msg.depth = state.msg->depth + 1;
    intx::be::store(msg.create2_salt.bytes, salt);
    intx::be::store(msg.value.bytes, endowment);

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
    {
        uint8_t data[32] = {};
        std::memcpy(&data[12], &result.create_address, sizeof(result.create_address));
        state.item(0) = intx::be::uint256(data);
    }

    state.gas_left -= msg.gas - result.gas_left;
}

void op_undefined(execution_state& state, instr_argument) noexcept
{
    state.run = false;
    state.status = EVMC_UNDEFINED_INSTRUCTION;
}

void op_selfdestruct(execution_state& state, instr_argument) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
    {
        // TODO: Implement static mode violation in analysis.
        state.run = false;
        state.status = EVMC_STATIC_MODE_VIOLATION;
        return;
    }

    uint8_t data[32];
    intx::be::store(data, state.item(0));
    evmc_address addr;
    std::memcpy(addr.bytes, &data[12], sizeof(addr));

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        auto check_existance = true;

        if (state.rev >= EVMC_SPURIOUS_DRAGON)
        {
            auto balance = state.host.get_balance(state.msg->destination);
            check_existance = !is_zero(balance);
        }

        if (check_existance)
        {
            // After EIP150 hard fork charge additional cost of sending
            // ethers to non-existing account.
            bool exists = state.host.account_exists(addr);
            if (!exists)
            {
                state.gas_left -= 25000;
                if (state.gas_left < 0)
                {
                    state.run = false;
                    state.status = EVMC_OUT_OF_GAS;
                    return;
                }
            }
        }
    }

    state.host.selfdestruct(state.msg->destination, addr);
    state.run = false;
}

constexpr auto num_revisions = int{EVMC_MAX_REVISION + 1};
exec_fn_table op_table[num_revisions] = {};

exec_fn_table create_op_table_frontier() noexcept
{
    exec_fn_table table{};

    // First, mark all opcodes as undefined.
    std::fill(table.begin(), table.end(), op_undefined);

    table[OP_STOP] = op_stop;
    table[OP_ADD] = op_add;
    table[OP_MUL] = op_mul;
    table[OP_SUB] = op_sub;
    table[OP_DIV] = op_div;
    table[OP_SDIV] = op_sdiv;
    table[OP_MOD] = op_mod;
    table[OP_SMOD] = op_smod;
    table[OP_ADDMOD] = op_addmod;
    table[OP_MULMOD] = op_mulmod;
    table[OP_EXP] = op_exp;
    table[OP_SIGNEXTEND] = op_signextend;
    table[OP_LT] = op_lt;
    table[OP_GT] = op_gt;
    table[OP_SLT] = op_slt;
    table[OP_SGT] = op_sgt;
    table[OP_EQ] = op_eq;
    table[OP_ISZERO] = op_iszero;
    table[OP_AND] = op_and;
    table[OP_OR] = op_or;
    table[OP_XOR] = op_xor;
    table[OP_NOT] = op_not;
    table[OP_BYTE] = op_byte;
    table[OP_SHA3] = op_sha3;
    table[OP_ADDRESS] = op_address;
    table[OP_BALANCE] = op_balance;
    table[OP_ORIGIN] = op_origin;
    table[OP_CALLER] = op_caller;
    table[OP_CALLVALUE] = op_callvalue;
    table[OP_CALLDATALOAD] = op_calldataload;
    table[OP_CALLDATASIZE] = op_calldatasize;
    table[OP_CALLDATACOPY] = op_calldatacopy;
    table[OP_CODESIZE] = op_codesize;
    table[OP_CODECOPY] = op_codecopy;
    table[OP_EXTCODESIZE] = op_extcodesize;
    table[OP_EXTCODECOPY] = op_extcodecopy;
    table[OP_GASPRICE] = op_gasprice;
    table[OP_BLOCKHASH] = op_blockhash;
    table[OP_COINBASE] = op_coinbase;
    table[OP_TIMESTAMP] = op_timestamp;
    table[OP_NUMBER] = op_number;
    table[OP_DIFFICULTY] = op_difficulty;
    table[OP_GASLIMIT] = op_gaslimit;
    table[OP_POP] = op_pop;
    table[OP_MLOAD] = op_mload;
    table[OP_MSTORE] = op_mstore;
    table[OP_MSTORE8] = op_mstore8;
    table[OP_SLOAD] = op_sload;
    table[OP_SSTORE] = op_sstore;
    table[OP_JUMP] = op_jump;
    table[OP_JUMPI] = op_jumpi;
    table[OP_PC] = op_pc;
    table[OP_MSIZE] = op_msize;
    table[OP_GAS] = op_gas;
    table[OP_JUMPDEST] = op_jumpdest;
    for (size_t op = OP_PUSH1; op <= OP_PUSH32; ++op)
        table[op] = op_push_full;
    for (size_t op = OP_DUP1; op <= OP_DUP16; ++op)
        table[op] = op_dup;
    for (size_t op = OP_SWAP1; op <= OP_SWAP16; ++op)
        table[op] = op_swap;
    for (auto op = size_t{OP_LOG0}; op <= OP_LOG4; ++op)
        table[op] = op_log;
    table[OP_CREATE] = op_create;
    table[OP_CALL] = op_call;
    table[OP_CALLCODE] = op_call;
    table[OP_RETURN] = op_return;
    table[OP_INVALID] = op_invalid;
    table[OP_SELFDESTRUCT] = op_selfdestruct;
    return table;
}

exec_fn_table create_op_table_homestead() noexcept
{
    auto table = create_op_table_frontier();
    table[OP_DELEGATECALL] = op_delegatecall;
    return table;
}

exec_fn_table create_op_table_byzantium() noexcept
{
    auto table = create_op_table_homestead();
    table[OP_RETURNDATASIZE] = op_returndatasize;
    table[OP_RETURNDATACOPY] = op_returndatacopy;
    table[OP_STATICCALL] = op_staticcall;
    table[OP_REVERT] = op_revert;
    return table;
}

exec_fn_table create_op_table_constantinople() noexcept
{
    auto table = create_op_table_byzantium();
    table[OP_SHL] = op_shl;
    table[OP_SHR] = op_shr;
    table[OP_SAR] = op_sar;
    table[OP_EXTCODEHASH] = op_extcodehash;
    table[OP_CREATE2] = op_create2;
    return table;
}

exec_fn_table create_op_table_petersburg() noexcept
{
    auto table = create_op_table_constantinople();
    return table;
}

exec_fn_table create_op_table_istanbul() noexcept
{
    auto table = create_op_table_petersburg();
    return table;
}

const auto op_table_initialized = []() noexcept
{
    op_table[EVMC_FRONTIER] = create_op_table_frontier();
    op_table[EVMC_HOMESTEAD] = create_op_table_homestead();
    op_table[EVMC_TANGERINE_WHISTLE] = create_op_table_homestead();
    op_table[EVMC_SPURIOUS_DRAGON] = create_op_table_homestead();
    op_table[EVMC_BYZANTIUM] = create_op_table_byzantium();
    op_table[EVMC_CONSTANTINOPLE] = create_op_table_constantinople();
    op_table[EVMC_PETERSBURG] = create_op_table_petersburg();
    op_table[EVMC_ISTANBUL] = create_op_table_istanbul();
    return true;
}
();

}  // namespace


evmc_result execute(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
    auto analysis = analyze(op_table[rev], rev, code, code_size);

    execution_state state;
    state.analysis = &analysis;
    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = evmc::HostContext{ctx};
    state.gas_left = msg->gas;
    state.rev = rev;
    while (state.run)
    {
        auto& instr = analysis.instrs[state.pc];
        if (instr.block_index >= 0)
        {
            auto& block = analysis.blocks[static_cast<size_t>(instr.block_index)];

            state.gas_left -= block.gas_cost;
            if (state.gas_left < 0)
            {
                state.status = EVMC_OUT_OF_GAS;
                break;
            }

            if (static_cast<int>(state.stack.size()) < block.stack_req)
            {
                state.status = EVMC_STACK_UNDERFLOW;
                break;
            }

            if (static_cast<int>(state.stack.size()) + block.stack_max > 1024)
            {
                state.status = EVMC_STACK_OVERFLOW;
                break;
            }

            state.current_block_cost = block.gas_cost;
        }

        // Advance the PC not to allow jump opcodes to overwrite it.
        ++state.pc;

        instr.fn(state, instr.arg);
    }

    evmc_result result{};
    result.status_code = state.status;
    if (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
        result.gas_left = state.gas_left;

    if (state.output_size > 0)
    {
        result.output_size = state.output_size;
        auto output_data = static_cast<uint8_t*>(std::malloc(result.output_size));
        std::memcpy(output_data, &state.memory[state.output_offset], result.output_size);
        result.output_data = output_data;
        result.release = [](const evmc_result* result) noexcept
        {
            std::free(const_cast<uint8_t*>(result->output_data));
        };
    }

    return result;
}

}  // namespace evmone
