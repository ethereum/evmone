// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include "instruction_traits.hpp"
#include <ethash/keccak.hpp>

namespace evmone
{
constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
inline constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return (static_cast<int64_t>(size_in_bytes) + (word_size - 1)) / word_size;
}

inline bool check_memory(ExecutionState& state, const uint256& offset, uint64_t size) noexcept
{
    if (offset > max_buffer_size)
        return false;

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
            return false;

        state.memory.resize(static_cast<size_t>(new_words * word_size));
    }

    return true;
}

inline bool check_memory(ExecutionState& state, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)
        return true;

    if (size > max_buffer_size)
        return false;

    return check_memory(state, offset, static_cast<uint64_t>(size));
}

inline void add(Stack& stack) noexcept
{
    stack.top() += stack.pop();
}

inline void mul(Stack& stack) noexcept
{
    stack.top() *= stack.pop();
}

inline void sub(Stack& stack) noexcept
{
    stack[1] = stack[0] - stack[1];
    stack.pop();
}

inline void div(Stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] / v : 0;
    stack.pop();
}

inline void sdiv(Stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).quot : 0;
    stack.pop();
}

inline void mod(Stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] % v : 0;
    stack.pop();
}

inline void smod(Stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).rem : 0;
    stack.pop();
}

inline void addmod(Stack& stack) noexcept
{
    const auto x = stack.pop();
    const auto y = stack.pop();
    auto& m = stack.top();
    m = m != 0 ? intx::addmod(x, y, m) : 0;
}

inline void mulmod(Stack& stack) noexcept
{
    const auto x = stack.pop();
    const auto y = stack.pop();
    auto& m = stack.top();
    m = m != 0 ? intx::mulmod(x, y, m) : 0;
}

inline evmc_status_code exp(ExecutionState& state) noexcept
{
    const auto base = state.stack.pop();
    auto& exponent = state.stack.top();

    const auto exponent_significant_bytes =
        static_cast<int>(intx::count_significant_bytes(exponent));
    const auto exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    const auto additional_cost = exponent_significant_bytes * exponent_cost;
    if ((state.gas_left -= additional_cost) < 0)
        return EVMC_OUT_OF_GAS;

    exponent = intx::exp(base, exponent);
    return EVMC_SUCCESS;
}

inline void signextend(Stack& stack) noexcept
{
    const auto ext = stack.pop();
    auto& x = stack.top();

    if (ext < 31)
    {
        auto sign_bit = static_cast<int>(ext) * 8 + 7;
        auto sign_mask = uint256{1} << sign_bit;
        auto value_mask = sign_mask - 1;
        auto is_neg = (x & sign_mask) != 0;
        x = is_neg ? x | ~value_mask : x & value_mask;
    }
}

inline void lt(Stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = x < stack[0];
}

inline void gt(Stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = stack[0] < x;  // Arguments are swapped and < is used.
}

inline void slt(Stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = slt(x, stack[0]);
}

inline void sgt(Stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = slt(stack[0], x);  // Arguments are swapped and SLT is used.
}

inline void eq(Stack& stack) noexcept
{
    stack[1] = stack[0] == stack[1];
    stack.pop();
}

inline void iszero(Stack& stack) noexcept
{
    stack.top() = stack.top() == 0;
}

inline void and_(Stack& stack) noexcept
{
    stack.top() &= stack.pop();
}

inline void or_(Stack& stack) noexcept
{
    stack.top() |= stack.pop();
}

inline void xor_(Stack& stack) noexcept
{
    stack.top() ^= stack.pop();
}

inline void not_(Stack& stack) noexcept
{
    stack.top() = ~stack.top();
}

inline void byte(Stack& stack) noexcept
{
    const auto n = stack.pop();
    auto& x = stack.top();

    if (n > 31)
        x = 0;
    else
    {
        auto sh = (31 - static_cast<unsigned>(n)) * 8;
        auto y = x >> sh;
        x = y & 0xff;
    }
}

inline void shl(Stack& stack) noexcept
{
    stack.top() <<= stack.pop();
}

inline void shr(Stack& stack) noexcept
{
    stack.top() >>= stack.pop();
}

inline void sar(Stack& stack) noexcept
{
    if ((stack[1] & (uint256{1} << 255)) == 0)
        return shr(stack);

    constexpr auto allones = ~uint256{};

    if (stack[0] >= 256)
        stack[1] = allones;
    else
    {
        const auto shift = static_cast<unsigned>(stack[0]);
        stack[1] = (stack[1] >> shift) | (allones << (256 - shift));
    }

    stack.pop();
}


inline evmc_status_code keccak256(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    auto& size = state.stack.top();

    if (!check_memory(state, index, size))
        return EVMC_OUT_OF_GAS;

    const auto i = static_cast<size_t>(index);
    const auto s = static_cast<size_t>(size);
    const auto w = num_words(s);
    const auto cost = w * 6;
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    auto data = s != 0 ? &state.memory[i] : nullptr;
    size = intx::be::load<uint256>(ethash::keccak256(data, s));
    return EVMC_SUCCESS;
}


inline void address(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->destination));
}

inline evmc_status_code balance(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_balance(addr));
    return EVMC_SUCCESS;
}

inline void origin(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_origin));
}

inline void caller(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->sender));
}

inline void callvalue(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->value));
}

inline void calldataload(ExecutionState& state) noexcept
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
}

inline void calldatasize(ExecutionState& state) noexcept
{
    state.stack.push(state.msg->input_size);
}

inline evmc_status_code calldatacopy(ExecutionState& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.msg->input_size < input_index ? state.msg->input_size :
                                                     static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.msg->input_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return EVMC_SUCCESS;
}

inline void codesize(ExecutionState& state) noexcept
{
    state.stack.push(state.code.size());
}

inline evmc_status_code codecopy(ExecutionState& state) noexcept
{
    // TODO: Similar to calldatacopy().

    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    const auto code_size = state.code.size();
    const auto dst = static_cast<size_t>(mem_index);
    const auto src = code_size < input_index ? code_size : static_cast<size_t>(input_index);
    const auto s = static_cast<size_t>(size);
    const auto copy_size = std::min(s, code_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    // TODO: Add unit tests for each combination of conditions.
    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.code[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return EVMC_SUCCESS;
}


inline void gasprice(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_gas_price));
}

inline void basefee(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_base_fee));
}

inline evmc_status_code extcodesize(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = state.host.get_code_size(addr);
    return EVMC_SUCCESS;
}

inline evmc_status_code extcodecopy(ExecutionState& state) noexcept
{
    const auto addr = intx::be::trunc<evmc::address>(state.stack.pop());
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto src = max_buffer_size < input_index ? max_buffer_size : static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    auto data = s != 0 ? &state.memory[dst] : nullptr;
    auto num_bytes_copied = state.host.copy_code(addr, src, data, s);
    if (s - num_bytes_copied > 0)
        std::memset(&state.memory[dst + num_bytes_copied], 0, s - num_bytes_copied);

    return EVMC_SUCCESS;
}

inline void returndatasize(ExecutionState& state) noexcept
{
    state.stack.push(state.return_data.size());
}

inline evmc_status_code returndatacopy(ExecutionState& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto s = static_cast<size_t>(size);

    if (state.return_data.size() < input_index)
        return EVMC_INVALID_MEMORY_ACCESS;
    auto src = static_cast<size_t>(input_index);

    if (src + s > state.return_data.size())
        return EVMC_INVALID_MEMORY_ACCESS;

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (s > 0)
        std::memcpy(&state.memory[dst], &state.return_data[src], s);

    return EVMC_SUCCESS;
}

inline evmc_status_code extcodehash(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_code_hash(addr));
    return EVMC_SUCCESS;
}


inline void blockhash(ExecutionState& state) noexcept
{
    auto& number = state.stack.top();

    const auto upper_bound = state.host.get_tx_context().block_number;
    const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    const auto n = static_cast<int64_t>(number);
    const auto header =
        (number < upper_bound && n >= lower_bound) ? state.host.get_block_hash(n) : evmc::bytes32{};
    number = intx::be::load<uint256>(header);
}

inline void coinbase(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_coinbase));
}

inline void timestamp(ExecutionState& state) noexcept
{
    // TODO: Add tests for negative timestamp?
    const auto timestamp = static_cast<uint64_t>(state.host.get_tx_context().block_timestamp);
    state.stack.push(timestamp);
}

inline void number(ExecutionState& state) noexcept
{
    // TODO: Add tests for negative block number?
    const auto block_number = static_cast<uint64_t>(state.host.get_tx_context().block_number);
    state.stack.push(block_number);
}

inline void difficulty(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_difficulty));
}

inline void gaslimit(ExecutionState& state) noexcept
{
    const auto block_gas_limit = static_cast<uint64_t>(state.host.get_tx_context().block_gas_limit);
    state.stack.push(block_gas_limit);
}

inline void chainid(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().chain_id));
}

inline void selfbalance(ExecutionState& state) noexcept
{
    // TODO: introduce selfbalance in EVMC?
    state.stack.push(intx::be::load<uint256>(state.host.get_balance(state.msg->destination)));
}


inline void pop(Stack& stack) noexcept
{
    stack.pop();
}

inline evmc_status_code mload(ExecutionState& state) noexcept
{
    auto& index = state.stack.top();

    if (!check_memory(state, index, 32))
        return EVMC_OUT_OF_GAS;

    index = intx::be::unsafe::load<uint256>(&state.memory[static_cast<size_t>(index)]);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 32))
        return EVMC_OUT_OF_GAS;

    intx::be::unsafe::store(&state.memory[static_cast<size_t>(index)], value);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore8(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 1))
        return EVMC_OUT_OF_GAS;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(value);
    return EVMC_SUCCESS;
}

inline evmc_status_code sload(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto key = intx::be::store<evmc::bytes32>(x);

    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->destination, key) == EVMC_ACCESS_COLD)
    {
        // The warm storage access cost is already applied (from the cost table).
        // Here we need to apply additional cold storage access cost.
        constexpr auto additional_cold_sload_cost =
            instr::cold_sload_cost - instr::warm_storage_read_cost;
        if ((state.gas_left -= additional_cold_sload_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_storage(state.msg->destination, key));

    return EVMC_SUCCESS;
}

inline evmc_status_code sstore(ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    if (state.rev >= EVMC_ISTANBUL && state.gas_left <= 2300)
        return EVMC_OUT_OF_GAS;

    const auto key = intx::be::store<evmc::bytes32>(state.stack.pop());
    const auto value = intx::be::store<evmc::bytes32>(state.stack.pop());

    int cost = 0;
    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->destination, key) == EVMC_ACCESS_COLD)
        cost = instr::cold_sload_cost;

    const auto status = state.host.set_storage(state.msg->destination, key, value);

    switch (status)
    {
    case EVMC_STORAGE_UNCHANGED:
    case EVMC_STORAGE_MODIFIED_AGAIN:
        if (state.rev >= EVMC_BERLIN)
            cost += instr::warm_storage_read_cost;
        else if (state.rev == EVMC_ISTANBUL)
            cost = 800;
        else if (state.rev == EVMC_CONSTANTINOPLE)
            cost = 200;
        else
            cost = 5000;
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
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}


inline void msize(ExecutionState& state) noexcept
{
    state.stack.push(state.memory.size());
}

/// DUP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. DUP3 is dup<3>.
template <size_t N>
inline void dup(Stack& stack) noexcept
{
    static_assert(N >= 1 && N <= 16);
    stack.push(stack[N - 1]);
}

/// SWAP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. SWAP3 is swap<3>.
template <size_t N>
inline void swap(Stack& stack) noexcept
{
    static_assert(N >= 1 && N <= 16);
    std::swap(stack.top(), stack[N]);
}


template <size_t NumTopics>
inline evmc_status_code log(ExecutionState& state) noexcept
{
    static_assert(NumTopics >= 0 && NumTopics <= 4);

    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    const auto offset = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, offset, size))
        return EVMC_OUT_OF_GAS;

    const auto o = static_cast<size_t>(offset);
    const auto s = static_cast<size_t>(size);

    const auto cost = int64_t(s) * 8;
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    std::array<evmc::bytes32, NumTopics> topics;
    for (auto& topic : topics)
        topic = intx::be::store<evmc::bytes32>(state.stack.pop());

    const auto data = s != 0 ? &state.memory[o] : nullptr;
    state.host.emit_log(state.msg->destination, data, s, topics.data(), NumTopics);
    return EVMC_SUCCESS;
}


template <evmc_call_kind Kind, bool Static = false>
evmc_status_code call(ExecutionState& state) noexcept;

template <evmc_call_kind Kind>
evmc_status_code create(ExecutionState& state) noexcept;


template <evmc_status_code StatusCode>
inline void return_(ExecutionState& state) noexcept
{
    const auto offset = state.stack[0];
    const auto size = state.stack[1];

    if (!check_memory(state, offset, size))
    {
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    state.output_offset = static_cast<size_t>(offset);  // Can be garbage if size is 0.
    state.output_size = static_cast<size_t>(size);
    state.status = StatusCode;
}

inline evmc_status_code selfdestruct(ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    const auto beneficiary = intx::be::trunc<evmc::address>(state.stack[0]);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(beneficiary) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->destination))
        {
            // After TANGERINE_WHISTLE apply additional cost of
            // sending value to a non-existing account.
            if (!state.host.account_exists(beneficiary))
            {
                if ((state.gas_left -= 25000) < 0)
                    return EVMC_OUT_OF_GAS;
            }
        }
    }

    state.host.selfdestruct(state.msg->destination, beneficiary);
    return EVMC_SUCCESS;
}
}  // namespace evmone
