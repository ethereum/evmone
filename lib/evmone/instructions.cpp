// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"

#include <ethash/keccak.hpp>

#include <cassert>

namespace evmone
{
namespace
{
constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return (static_cast<int64_t>(size_in_bytes) + (word_size - 1)) / word_size;
}

inline bool check_memory(execution_state& state, const uint256& offset, uint64_t size) noexcept
{
    if (offset > max_buffer_size)
    {
        state.exit(EVMC_OUT_OF_GAS);
        return false;
    }

    const auto new_size = static_cast<uint64_t>(offset) + size;
    const auto current_size = state.memory.size();
    if (new_size > current_size)
    {
        const auto new_words = num_words(new_size);
        const auto current_words = static_cast<int64_t>(current_size / 32);
        const auto new_cost = 3 * new_words + new_words * new_words / 512;
        const auto current_cost = 3 * current_words + current_words * current_words / 512;
        const auto cost = new_cost - current_cost;

        if ((state.gas_left -= cost) < 0)
        {
            state.exit(EVMC_OUT_OF_GAS);
            return false;
        }

        state.memory.resize(static_cast<size_t>(new_words * word_size));
    }

    return true;
}

inline bool check_memory(
    execution_state& state, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)
        return true;

    if (size > max_buffer_size)
    {
        state.exit(EVMC_OUT_OF_GAS);
        return false;
    }

    return check_memory(state, offset, static_cast<uint64_t>(size));
}


const instr_info* op_stop(const instr_info*, execution_state& state) noexcept
{
    return state.exit(EVMC_SUCCESS);
}

const instr_info* op_add(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() += state.stack.pop();
    return ++instr;
}

const instr_info* op_mul(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() *= state.stack.pop();
    return ++instr;
}

const instr_info* op_sub(const instr_info* instr, execution_state& state) noexcept
{
    state.stack[1] = state.stack[0] - state.stack[1];
    state.stack.pop();
    return ++instr;
}

const instr_info* op_div(const instr_info* instr, execution_state& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? state.stack[0] / v : 0;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_sdiv(const instr_info* instr, execution_state& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? intx::sdivrem(state.stack[0], v).quot : 0;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_mod(const instr_info* instr, execution_state& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? state.stack[0] % v : 0;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_smod(const instr_info* instr, execution_state& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? intx::sdivrem(state.stack[0], v).rem : 0;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_addmod(const instr_info* instr, execution_state& state) noexcept
{
    const auto x = state.stack.pop();
    const auto y = state.stack.pop();
    auto& m = state.stack.top();

    m = m != 0 ? intx::addmod(x, y, m) : 0;
    return ++instr;
}

const instr_info* op_mulmod(const instr_info* instr, execution_state& state) noexcept
{
    const auto x = state.stack.pop();
    const auto y = state.stack.pop();
    auto& m = state.stack.top();

    m = m != 0 ? intx::mulmod(x, y, m) : 0;
    return ++instr;
}

const instr_info* op_exp(const instr_info* instr, execution_state& state) noexcept
{
    const auto base = state.stack.pop();
    auto& exponent = state.stack.top();

    const auto exponent_significant_bytes =
        static_cast<int>(intx::count_significant_words<uint8_t>(exponent));
    const auto exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    const auto additional_cost = exponent_significant_bytes * exponent_cost;
    if ((state.gas_left -= additional_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    exponent = intx::exp(base, exponent);
    return ++instr;
}

auto op_signextend(const instr_info* pc, execution_state& state) noexcept
{
    const auto ext = state.stack.pop();
    auto& x = state.stack.top();

    if (ext < 31)
    {
        auto sign_bit = static_cast<int>(ext) * 8 + 7;
        auto sign_mask = uint256{1} << sign_bit;
        auto value_mask = sign_mask - 1;
        auto is_neg = (x & sign_mask) != 0;
        x = is_neg ? x | ~value_mask : x & value_mask;
    }
    return ++pc;
}

const instr_info* op_lt(const instr_info* instr, execution_state& state) noexcept
{
    // OPT: Have single function implementing all comparisons.
    state.stack[1] = state.stack[0] < state.stack[1];
    state.stack.pop();
    return ++instr;
}

const instr_info* op_gt(const instr_info* instr, execution_state& state) noexcept
{
    state.stack[1] = state.stack[1] < state.stack[0];
    state.stack.pop();
    return ++instr;
}

const instr_info* op_slt(const instr_info* instr, execution_state& state) noexcept
{
    auto x = state.stack[0];
    auto y = state.stack[1];
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.stack[1] = (x_neg ^ y_neg) ? x_neg : x < y;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_sgt(const instr_info* instr, execution_state& state) noexcept
{
    auto x = state.stack[0];
    auto y = state.stack[1];
    auto x_neg = static_cast<bool>(x >> 255);
    auto y_neg = static_cast<bool>(y >> 255);
    state.stack[1] = (x_neg ^ y_neg) ? y_neg : y < x;
    state.stack.pop();
    return ++instr;
}

const instr_info* op_eq(const instr_info* instr, execution_state& state) noexcept
{
    state.stack[1] = state.stack[0] == state.stack[1];
    state.stack.pop();
    return ++instr;
}

const instr_info* op_iszero(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() = state.stack.top() == 0;
    return ++instr;
}

const instr_info* op_and(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() &= state.stack.pop();
    return ++instr;
}

const instr_info* op_or(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() |= state.stack.pop();
    return ++instr;
}

const instr_info* op_xor(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() ^= state.stack.pop();
    return ++instr;
}

const instr_info* op_not(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() = ~state.stack.top();
    return ++instr;
}

const instr_info* op_byte(const instr_info* instr, execution_state& state) noexcept
{
    const auto n = state.stack.pop();
    auto& x = state.stack.top();

    if (n > 31)
        x = 0;
    else
    {
        auto sh = (31 - static_cast<unsigned>(n)) * 8;
        auto y = x >> sh;
        x = y & 0xff;
    }
    return ++instr;
}

const instr_info* op_shl(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() <<= state.stack.pop();
    return ++instr;
}

const instr_info* op_shr(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.top() >>= state.stack.pop();
    return ++instr;
}

const instr_info* op_sar(const instr_info* instr, execution_state& state) noexcept
{
    if ((state.stack[1] & (uint256{1} << 255)) == 0)
        return op_shr(instr, state);

    constexpr auto allones = ~uint256{};

    if (state.stack[0] >= 256)
        state.stack[1] = allones;
    else
    {
        const auto shift = static_cast<unsigned>(state.stack[0]);
        state.stack[1] = (state.stack[1] >> shift) | (allones << (256 - shift));
    }

    state.stack.pop();
    return ++instr;
}

const instr_info* op_sha3(const instr_info* instr, execution_state& state) noexcept
{
    const auto index = state.stack.pop();
    auto& size = state.stack.top();

    if (!check_memory(state, index, size))
        return nullptr;

    const auto i = static_cast<size_t>(index);
    const auto s = static_cast<size_t>(size);
    const auto w = num_words(s);
    const auto cost = w * 6;
    if ((state.gas_left -= cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    auto data = s != 0 ? &state.memory[i] : nullptr;
    size = intx::be::load<uint256>(ethash::keccak256(data, s));
    return ++instr;
}

const instr_info* op_address(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Might be generalized using pointers to class member.
    state.stack.push(intx::be::load<uint256>(state.msg->destination));
    return ++instr;
}

const instr_info* op_balance(const instr_info* instr, execution_state& state) noexcept
{
    auto& x = state.stack.top();
    x = intx::be::load<uint256>(state.host.get_balance(intx::be::trunc<evmc::address>(x)));
    return ++instr;
}

const instr_info* op_origin(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_origin));
    return ++instr;
}

const instr_info* op_caller(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Might be generalized using pointers to class member.
    state.stack.push(intx::be::load<uint256>(state.msg->sender));
    return ++instr;
}

const instr_info* op_callvalue(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->value));
    return ++instr;
}

const instr_info* op_calldataload(const instr_info* instr, execution_state& state) noexcept
{
    auto& index = state.stack.top();

    if (state.msg->input_size < index)
        index = 0;
    else
    {
        const auto begin = static_cast<size_t>(index);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        index = intx::be::load<uint256>(data);
    }
    return ++instr;
}

const instr_info* op_calldatasize(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(state.msg->input_size);
    return ++instr;
}

const instr_info* op_calldatacopy(const instr_info* instr, execution_state& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return nullptr;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.msg->input_size < input_index ? state.msg->input_size :
                                                     static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.msg->input_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
    return ++instr;
}

const instr_info* op_codesize(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(state.code_size);
    return ++instr;
}

const instr_info* op_codecopy(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Similar to op_calldatacopy().

    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return nullptr;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.code_size < input_index ? state.code_size : static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.code_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    // TODO: Add unit tests for each combination of conditions.
    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.code[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
    return ++instr;
}

const instr_info* op_mload(const instr_info* instr, execution_state& state) noexcept
{
    auto& index = state.stack.top();

    if (!check_memory(state, index, 32))
        return nullptr;

    index = intx::be::unsafe::load<uint256>(&state.memory[static_cast<size_t>(index)]);
    return ++instr;
}

const instr_info* op_mstore(const instr_info* instr, execution_state& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 32))
        return nullptr;

    intx::be::unsafe::store(&state.memory[static_cast<size_t>(index)], value);
    return ++instr;
}

const instr_info* op_mstore8(const instr_info* instr, execution_state& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 1))
        return nullptr;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(value);
    return ++instr;
}

const instr_info* op_sload(const instr_info* instr, execution_state& state) noexcept
{
    auto& x = state.stack.top();
    x = intx::be::load<uint256>(
        state.host.get_storage(state.msg->destination, intx::be::store<evmc::bytes32>(x)));
    return ++instr;
}

const instr_info* op_sstore(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Implement static mode violation in analysis.
    if (state.msg->flags & EVMC_STATIC)
        return state.exit(EVMC_STATIC_MODE_VIOLATION);

    const auto key = intx::be::store<evmc::bytes32>(state.stack.pop());
    const auto value = intx::be::store<evmc::bytes32>(state.stack.pop());
    auto status = state.host.set_storage(state.msg->destination, key, value);
    int cost = 0;
    switch (status)
    {
    case EVMC_STORAGE_UNCHANGED:
        cost = state.rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
        break;
    case EVMC_STORAGE_MODIFIED:
        cost = 5000;
        break;
    case EVMC_STORAGE_MODIFIED_AGAIN:
        cost = state.rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
        break;
    case EVMC_STORAGE_ADDED:
        cost = 20000;
        break;
    case EVMC_STORAGE_DELETED:
        cost = 5000;
        break;
    }
    if ((state.gas_left -= cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_jump(const instr_info*, execution_state& state) noexcept
{
    const auto dst = state.stack.pop();
    auto pc = -1;
    if (std::numeric_limits<int>::max() < dst ||
        (pc = find_jumpdest(*state.analysis, static_cast<int>(dst))) < 0)
        return state.exit(EVMC_BAD_JUMP_DESTINATION);

    return &state.analysis->instrs[static_cast<size_t>(pc)];
}

const instr_info* op_jumpi(const instr_info* instr, execution_state& state) noexcept
{
    if (state.stack[1] != 0)
        instr = op_jump(instr, state);
    else
    {
        state.stack.pop();
        ++instr;
    }

    // OPT: The pc must be the BEGINBLOCK (even in fallback case),
    //      so we can execute it straight away.

    state.stack.pop();
    return instr;
}

const instr_info* op_pc(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(instr->arg.number);
    return ++instr;
}

const instr_info* op_msize(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(state.memory.size());
    return ++instr;
}

const instr_info* op_gas(const instr_info* instr, execution_state& state) noexcept
{
    const auto correction = state.current_block_cost - instr->arg.number;
    const auto gas = static_cast<uint64_t>(state.gas_left + correction);
    state.stack.push(gas);
    return ++instr;
}

const instr_info* op_gasprice(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_gas_price));
    return ++instr;
}

const instr_info* op_extcodesize(const instr_info* instr, execution_state& state) noexcept
{
    auto& x = state.stack.top();
    x = state.host.get_code_size(intx::be::trunc<evmc::address>(x));
    return ++instr;
}

const instr_info* op_extcodecopy(const instr_info* instr, execution_state& state) noexcept
{
    const auto addr = intx::be::trunc<evmc::address>(state.stack.pop());
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return nullptr;

    auto dst = static_cast<size_t>(mem_index);
    auto src = max_buffer_size < input_index ? max_buffer_size : static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    auto data = s != 0 ? &state.memory[dst] : nullptr;
    auto num_bytes_copied = state.host.copy_code(addr, src, data, s);
    if (s - num_bytes_copied > 0)
        std::memset(&state.memory[dst + num_bytes_copied], 0, s - num_bytes_copied);
    return ++instr;
}

const instr_info* op_returndatasize(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(state.return_data.size());
    return ++instr;
}

const instr_info* op_returndatacopy(const instr_info* instr, execution_state& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return nullptr;

    auto dst = static_cast<size_t>(mem_index);
    auto s = static_cast<size_t>(size);

    if (state.return_data.size() < input_index)
        return state.exit(EVMC_INVALID_MEMORY_ACCESS);
    auto src = static_cast<size_t>(input_index);

    if (src + s > state.return_data.size())
        return state.exit(EVMC_INVALID_MEMORY_ACCESS);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    if (s > 0)
        std::memcpy(&state.memory[dst], &state.return_data[src], s);
    return ++instr;
}

const instr_info* op_extcodehash(const instr_info* instr, execution_state& state) noexcept
{
    auto& x = state.stack.top();
    x = intx::be::load<uint256>(state.host.get_code_hash(intx::be::trunc<evmc::address>(x)));
    return ++instr;
}

const instr_info* op_blockhash(const instr_info* instr, execution_state& state) noexcept
{
    auto& number = state.stack.top();

    const auto upper_bound = state.host.get_tx_context().block_number;
    const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    const auto n = static_cast<int64_t>(number);
    const auto header =
        (number < upper_bound && n >= lower_bound) ? state.host.get_block_hash(n) : evmc::bytes32{};
    number = intx::be::load<uint256>(header);
    return ++instr;
}

const instr_info* op_coinbase(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_coinbase));
    return ++instr;
}

const instr_info* op_timestamp(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Add tests for negative timestamp?
    const auto timestamp = static_cast<uint64_t>(state.host.get_tx_context().block_timestamp);
    state.stack.push(timestamp);
    return ++instr;
}

const instr_info* op_number(const instr_info* instr, execution_state& state) noexcept
{
    // TODO: Add tests for negative block number?
    const auto block_number = static_cast<uint64_t>(state.host.get_tx_context().block_number);
    state.stack.push(block_number);
    return ++instr;
}

const instr_info* op_difficulty(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_difficulty));
    return ++instr;
}

const instr_info* op_gaslimit(const instr_info* instr, execution_state& state) noexcept
{
    const auto block_gas_limit = static_cast<uint64_t>(state.host.get_tx_context().block_gas_limit);
    state.stack.push(block_gas_limit);
    return ++instr;
}

const instr_info* op_push_small(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(instr->arg.small_push_value);
    return ++instr;
}

const instr_info* op_push_full(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.push(*instr->arg.push_value);
    return ++instr;
}

const instr_info* op_pop(const instr_info* instr, execution_state& state) noexcept
{
    state.stack.pop();
    return ++instr;
}

template <evmc_opcode DupOp>
const instr_info* op_dup(const instr_info* instr, execution_state& state) noexcept
{
    constexpr auto index = DupOp - OP_DUP1;
    state.stack.push(state.stack[index]);
    return ++instr;
}

template <evmc_opcode SwapOp>
const instr_info* op_swap(const instr_info* instr, execution_state& state) noexcept
{
    constexpr auto index = SwapOp - OP_SWAP1 + 1;
    std::swap(state.stack.top(), state.stack[index]);
    return ++instr;
}

const instr_info* op_log(
    const instr_info* instr, execution_state& state, size_t num_topics) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return state.exit(EVMC_STATIC_MODE_VIOLATION);

    const auto offset = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, offset, size))
        return nullptr;

    const auto o = static_cast<size_t>(offset);
    const auto s = static_cast<size_t>(size);

    const auto cost = int64_t(s) * 8;
    if ((state.gas_left -= cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    auto topics = std::array<evmc::bytes32, 4>{};
    for (size_t i = 0; i < num_topics; ++i)
        topics[i] = intx::be::store<evmc::bytes32>(state.stack.pop());

    const auto data = s != 0 ? &state.memory[o] : nullptr;
    state.host.emit_log(state.msg->destination, data, s, topics.data(), num_topics);
    return ++instr;
}

template <evmc_opcode LogOp>
const instr_info* op_log(const instr_info* instr, execution_state& state) noexcept
{
    constexpr auto num_topics = LogOp - OP_LOG0;
    return op_log(instr, state, num_topics);
}

const instr_info* op_invalid(const instr_info*, execution_state& state) noexcept
{
    return state.exit(EVMC_INVALID_INSTRUCTION);
}

const instr_info* op_return(const instr_info*, execution_state& state) noexcept
{
    auto offset = state.stack[0];
    auto size = state.stack[1];

    if (!check_memory(state, offset, size))
        return nullptr;

    state.output_offset = static_cast<size_t>(offset);
    state.output_size = static_cast<size_t>(size);
    return state.exit(EVMC_SUCCESS);
}

const instr_info* op_revert(const instr_info*, execution_state& state) noexcept
{
    auto offset = state.stack[0];
    auto size = state.stack[1];

    if (!check_memory(state, offset, size))
        return nullptr;

    state.output_offset = static_cast<size_t>(offset);
    state.output_size = static_cast<size_t>(size);
    return state.exit(EVMC_REVERT);
}

template <evmc_call_kind kind>
const instr_info* op_call(const instr_info* instr, execution_state& state) noexcept
{
    const auto arg = instr->arg;
    auto gas = state.stack[0];
    const auto dst = intx::be::trunc<evmc::address>(state.stack[1]);
    auto value = state.stack[2];
    auto input_offset = state.stack[3];
    auto input_size = state.stack[4];
    auto output_offset = state.stack[5];
    auto output_size = state.stack[6];

    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack[0] = 0;

    if (!check_memory(state, input_offset, input_size))
        return nullptr;

    if (!check_memory(state, output_offset, output_size))
        return nullptr;


    auto msg = evmc_message{};
    msg.kind = kind;
    msg.flags = state.msg->flags;
    msg.value = intx::be::store<evmc::uint256be>(value);

    auto correction = state.current_block_cost - arg.number;
    auto gas_left = state.gas_left + correction;

    auto cost = 0;
    auto has_value = value != 0;

    if (has_value)
        cost += 9000;

    if constexpr (kind == EVMC_CALL)
    {
        if (has_value && state.msg->flags & EVMC_STATIC)
            return state.exit(EVMC_STATIC_MODE_VIOLATION);

        if (has_value || state.rev < EVMC_SPURIOUS_DRAGON)
        {
            if (!state.host.account_exists(dst))
                cost += 25000;
        }
    }

    if ((gas_left -= cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)
        return state.exit(EVMC_OUT_OF_GAS);

    state.return_data.clear();

    state.gas_left -= cost;
    if (state.msg->depth >= 1024)
    {
        if (has_value)
            state.gas_left += 2300;  // Return unused stipend.
        if (state.gas_left < 0)
            return state.exit(EVMC_OUT_OF_GAS);
        return ++instr;
    }

    msg.destination = dst;
    msg.sender = state.msg->destination;
    msg.value = intx::be::store<evmc::uint256be>(value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    msg.depth = state.msg->depth + 1;

    if (has_value)
    {
        const auto balance =
            intx::be::load<uint256>(state.host.get_balance(state.msg->destination));
        if (balance < value)
        {
            state.gas_left += 2300;  // Return unused stipend.
            if (state.gas_left < 0)
                return state.exit(EVMC_OUT_OF_GAS);
            return ++instr;
        }

        msg.gas += 2300;  // Add stipend.
    }

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);


    state.stack[0] = result.status_code == EVMC_SUCCESS;

    if (auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    if (has_value)
        gas_used -= 2300;

    if ((state.gas_left -= gas_used) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_delegatecall(const instr_info* instr, execution_state& state) noexcept
{
    const auto arg = instr->arg;
    auto gas = state.stack[0];
    const auto dst = intx::be::trunc<evmc::address>(state.stack[1]);
    auto input_offset = state.stack[2];
    auto input_size = state.stack[3];
    auto output_offset = state.stack[4];
    auto output_size = state.stack[5];

    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack[0] = 0;

    if (!check_memory(state, input_offset, input_size))
        return nullptr;

    if (!check_memory(state, output_offset, output_size))
        return nullptr;

    auto msg = evmc_message{};
    msg.kind = EVMC_DELEGATECALL;

    auto correction = state.current_block_cost - arg.number;
    auto gas_left = state.gas_left + correction;

    // TEST: Gas saturation for big gas values.
    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)  // TEST: gas_left vs state.gas_left.
        return state.exit(EVMC_OUT_OF_GAS);

    if (state.msg->depth >= 1024)
        return ++instr;

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

    state.stack[0] = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    if ((state.gas_left -= gas_used) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_staticcall(const instr_info* instr, execution_state& state) noexcept
{
    const auto arg = instr->arg;
    auto gas = state.stack[0];
    const auto dst = intx::be::trunc<evmc::address>(state.stack[1]);
    auto input_offset = state.stack[2];
    auto input_size = state.stack[3];
    auto output_offset = state.stack[4];
    auto output_size = state.stack[5];

    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack[0] = 0;

    if (!check_memory(state, input_offset, input_size))
        return nullptr;

    if (!check_memory(state, output_offset, output_size))
        return nullptr;

    if (state.msg->depth >= 1024)
        return ++instr;

    auto msg = evmc_message{};
    msg.kind = EVMC_CALL;
    msg.flags |= EVMC_STATIC;

    msg.depth = state.msg->depth + 1;

    auto correction = state.current_block_cost - arg.number;
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
    state.stack[0] = result.status_code == EVMC_SUCCESS;

    if (auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    auto gas_used = msg.gas - result.gas_left;

    if ((state.gas_left -= gas_used) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_create(const instr_info* instr, execution_state& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return state.exit(EVMC_STATIC_MODE_VIOLATION);

    const auto arg = instr->arg;
    auto endowment = state.stack[0];
    auto init_code_offset = state.stack[1];
    auto init_code_size = state.stack[2];

    state.stack.pop();
    state.stack.pop();
    state.stack[0] = 0;

    if (!check_memory(state, init_code_offset, init_code_size))
        return nullptr;

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return ++instr;

    if (endowment != 0)
    {
        const auto balance =
            intx::be::load<uint256>(state.host.get_balance(state.msg->destination));
        if (balance < endowment)
            return ++instr;
    }

    auto msg = evmc_message{};

    auto correction = state.current_block_cost - arg.number;
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
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        state.stack[0] = intx::be::load<uint256>(result.create_address);

    if ((state.gas_left -= msg.gas - result.gas_left) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_create2(const instr_info* instr, execution_state& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return state.exit(EVMC_STATIC_MODE_VIOLATION);

    const auto arg = instr->arg;
    auto endowment = state.stack[0];
    auto init_code_offset = state.stack[1];
    auto init_code_size = state.stack[2];
    auto salt = state.stack[3];

    state.stack.pop();
    state.stack.pop();
    state.stack.pop();
    state.stack[0] = 0;

    if (!check_memory(state, init_code_offset, init_code_size))
        return nullptr;

    auto salt_cost = num_words(static_cast<size_t>(init_code_size)) * 6;
    state.gas_left -= salt_cost;
    if (state.gas_left < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return ++instr;

    if (endowment != 0)
    {
        const auto balance =
            intx::be::load<uint256>(state.host.get_balance(state.msg->destination));
        if (balance < endowment)
            return ++instr;
    }

    auto msg = evmc_message{};

    auto correction = state.current_block_cost - arg.number;
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
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        state.stack[0] = intx::be::load<uint256>(result.create_address);

    if ((state.gas_left -= msg.gas - result.gas_left) < 0)
        return state.exit(EVMC_OUT_OF_GAS);
    return ++instr;
}

const instr_info* op_undefined(const instr_info*, execution_state& state) noexcept
{
    return state.exit(EVMC_UNDEFINED_INSTRUCTION);
}

const instr_info* op_selfdestruct(const instr_info*, execution_state& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return state.exit(EVMC_STATIC_MODE_VIOLATION);

    const auto addr = intx::be::trunc<evmc::address>(state.stack[0]);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->destination))
        {
            // After TANGERINE_WHISTLE apply additional cost of
            // sending value to a non-existing account.
            if (!state.host.account_exists(addr))
            {
                if ((state.gas_left -= 25000) < 0)
                    return state.exit(EVMC_OUT_OF_GAS);
            }
        }
    }

    state.host.selfdestruct(state.msg->destination, addr);
    return state.exit(EVMC_SUCCESS);
}

const instr_info* opx_beginblock(const instr_info* instr, execution_state& state) noexcept
{
    auto& block = instr->arg.block;

    if ((state.gas_left -= block.gas_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    if (static_cast<int>(state.stack.size()) < block.stack_req)
        return state.exit(EVMC_STACK_UNDERFLOW);

    if (static_cast<int>(state.stack.size()) + block.stack_max_growth > evm_stack::limit)
        return state.exit(EVMC_STACK_OVERFLOW);

    state.current_block_cost = block.gas_cost;
    return ++instr;
}

constexpr op_table create_op_table_frontier() noexcept
{
    auto table = op_table{};

    // First, mark all opcodes as undefined.
    for (auto& t : table)
        t = {op_undefined};

    table[OP_STOP] = {op_stop};
    table[OP_ADD] = {op_add};
    table[OP_MUL] = {op_mul};
    table[OP_SUB] = {op_sub};
    table[OP_DIV] = {op_div};
    table[OP_SDIV] = {op_sdiv};
    table[OP_MOD] = {op_mod};
    table[OP_SMOD] = {op_smod};
    table[OP_ADDMOD] = {op_addmod};
    table[OP_MULMOD] = {op_mulmod};
    table[OP_EXP] = {op_exp};
    table[OP_SIGNEXTEND] = {op_signextend};
    table[OP_LT] = {op_lt};
    table[OP_GT] = {op_gt};
    table[OP_SLT] = {op_slt};
    table[OP_SGT] = {op_sgt};
    table[OP_EQ] = {op_eq};
    table[OP_ISZERO] = {op_iszero};
    table[OP_AND] = {op_and};
    table[OP_OR] = {op_or};
    table[OP_XOR] = {op_xor};
    table[OP_NOT] = {op_not};
    table[OP_BYTE] = {op_byte};
    table[OP_SHA3] = {op_sha3};
    table[OP_ADDRESS] = {op_address};
    table[OP_BALANCE] = {op_balance};
    table[OP_ORIGIN] = {op_origin};
    table[OP_CALLER] = {op_caller};
    table[OP_CALLVALUE] = {op_callvalue};
    table[OP_CALLDATALOAD] = {op_calldataload};
    table[OP_CALLDATASIZE] = {op_calldatasize};
    table[OP_CALLDATACOPY] = {op_calldatacopy};
    table[OP_CODESIZE] = {op_codesize};
    table[OP_CODECOPY] = {op_codecopy};
    table[OP_EXTCODESIZE] = {op_extcodesize};
    table[OP_EXTCODECOPY] = {op_extcodecopy};
    table[OP_GASPRICE] = {op_gasprice};
    table[OP_BLOCKHASH] = {op_blockhash};
    table[OP_COINBASE] = {op_coinbase};
    table[OP_TIMESTAMP] = {op_timestamp};
    table[OP_NUMBER] = {op_number};
    table[OP_DIFFICULTY] = {op_difficulty};
    table[OP_GASLIMIT] = {op_gaslimit};
    table[OP_POP] = {op_pop};
    table[OP_MLOAD] = {op_mload};
    table[OP_MSTORE] = {op_mstore};
    table[OP_MSTORE8] = {op_mstore8};
    table[OP_SLOAD] = {op_sload};
    table[OP_SSTORE] = {op_sstore};
    table[OP_JUMP] = {op_jump};
    table[OP_JUMPI] = {op_jumpi};
    table[OP_PC] = {op_pc};
    table[OP_MSIZE] = {op_msize};
    table[OP_GAS] = {op_gas};
    table[OPX_BEGINBLOCK] = {opx_beginblock};  // Replaces JUMPDEST.
    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH8; ++op)
        table[op] = {op_push_small};
    for (auto op = size_t{OP_PUSH9}; op <= OP_PUSH32; ++op)
        table[op] = {op_push_full};

    table[OP_DUP1] = {op_dup<OP_DUP1>};
    table[OP_DUP2] = {op_dup<OP_DUP2>};
    table[OP_DUP3] = {op_dup<OP_DUP3>};
    table[OP_DUP4] = {op_dup<OP_DUP4>};
    table[OP_DUP5] = {op_dup<OP_DUP5>};
    table[OP_DUP6] = {op_dup<OP_DUP6>};
    table[OP_DUP7] = {op_dup<OP_DUP7>};
    table[OP_DUP8] = {op_dup<OP_DUP8>};
    table[OP_DUP9] = {op_dup<OP_DUP9>};
    table[OP_DUP10] = {op_dup<OP_DUP10>};
    table[OP_DUP11] = {op_dup<OP_DUP11>};
    table[OP_DUP12] = {op_dup<OP_DUP12>};
    table[OP_DUP13] = {op_dup<OP_DUP13>};
    table[OP_DUP14] = {op_dup<OP_DUP14>};
    table[OP_DUP15] = {op_dup<OP_DUP15>};
    table[OP_DUP16] = {op_dup<OP_DUP16>};

    table[OP_SWAP1] = {op_swap<OP_SWAP1>};
    table[OP_SWAP2] = {op_swap<OP_SWAP2>};
    table[OP_SWAP3] = {op_swap<OP_SWAP3>};
    table[OP_SWAP4] = {op_swap<OP_SWAP4>};
    table[OP_SWAP5] = {op_swap<OP_SWAP5>};
    table[OP_SWAP6] = {op_swap<OP_SWAP6>};
    table[OP_SWAP7] = {op_swap<OP_SWAP7>};
    table[OP_SWAP8] = {op_swap<OP_SWAP8>};
    table[OP_SWAP9] = {op_swap<OP_SWAP9>};
    table[OP_SWAP10] = {op_swap<OP_SWAP10>};
    table[OP_SWAP11] = {op_swap<OP_SWAP11>};
    table[OP_SWAP12] = {op_swap<OP_SWAP12>};
    table[OP_SWAP13] = {op_swap<OP_SWAP13>};
    table[OP_SWAP14] = {op_swap<OP_SWAP14>};
    table[OP_SWAP15] = {op_swap<OP_SWAP15>};
    table[OP_SWAP16] = {op_swap<OP_SWAP16>};

    table[OP_LOG0] = {op_log<OP_LOG0>};
    table[OP_LOG1] = {op_log<OP_LOG1>};
    table[OP_LOG2] = {op_log<OP_LOG2>};
    table[OP_LOG3] = {op_log<OP_LOG3>};
    table[OP_LOG4] = {op_log<OP_LOG4>};

    table[OP_CREATE] = {op_create};
    table[OP_CALL] = {op_call<EVMC_CALL>};
    table[OP_CALLCODE] = {op_call<EVMC_CALLCODE>};
    table[OP_RETURN] = {op_return};
    table[OP_INVALID] = {op_invalid};
    table[OP_SELFDESTRUCT] = {op_selfdestruct};
    return table;
}

constexpr op_table create_op_table_homestead() noexcept
{
    auto table = create_op_table_frontier();
    table[OP_DELEGATECALL] = {op_delegatecall};
    return table;
}

constexpr op_table create_op_table_byzantium() noexcept
{
    auto table = create_op_table_homestead();
    table[OP_RETURNDATASIZE] = {op_returndatasize};
    table[OP_RETURNDATACOPY] = {op_returndatacopy};
    table[OP_STATICCALL] = {op_staticcall};
    table[OP_REVERT] = {op_revert};
    return table;
}

constexpr op_table create_op_table_constantinople() noexcept
{
    auto table = create_op_table_byzantium();
    table[OP_SHL] = {op_shl};
    table[OP_SHR] = {op_shr};
    table[OP_SAR] = {op_sar};
    table[OP_EXTCODEHASH] = {op_extcodehash};
    table[OP_CREATE2] = {op_create2};
    return table;
}

constexpr op_table create_op_table_istanbul() noexcept
{
    auto table = create_op_table_constantinople();
    return table;
}

constexpr op_table op_tables[] = {
    create_op_table_frontier(),        // Frontier
    create_op_table_homestead(),       // Homestead
    create_op_table_homestead(),       // Tangerine Whistle
    create_op_table_homestead(),       // Spurious Dragon
    create_op_table_byzantium(),       // Byzantium
    create_op_table_constantinople(),  // Constantinople
    create_op_table_constantinople(),  // Petersburg
    create_op_table_istanbul(),        // Istanbul
};
static_assert(sizeof(op_tables) / sizeof(op_tables[0]) > EVMC_MAX_REVISION,
    "op table entry missing for an EVMC revision");
}  // namespace

EVMC_EXPORT const op_table& get_op_table(evmc_revision rev) noexcept
{
    return op_tables[rev];
}
}  // namespace evmone
