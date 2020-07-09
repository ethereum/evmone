// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "analysis.hpp"

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

inline void add(evm_stack& stack) noexcept
{
    stack.top() += stack.pop();
}

inline void mul(evm_stack& stack) noexcept
{
    stack.top() *= stack.pop();
}

inline void sub(evm_stack& stack) noexcept
{
    stack[1] = stack[0] - stack[1];
    stack.pop();
}

inline void div(evm_stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] / v : 0;
    stack.pop();
}

inline void sdiv(evm_stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).quot : 0;
    stack.pop();
}

inline void mod(evm_stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? stack[0] % v : 0;
    stack.pop();
}

inline void smod(evm_stack& stack) noexcept
{
    auto& v = stack[1];
    v = v != 0 ? intx::sdivrem(stack[0], v).rem : 0;
    stack.pop();
}

inline void addmod(evm_stack& stack) noexcept
{
    const auto x = stack.pop();
    const auto y = stack.pop();
    auto& m = stack.top();
    m = m != 0 ? intx::addmod(x, y, m) : 0;
}

inline void mulmod(evm_stack& stack) noexcept
{
    const auto x = stack.pop();
    const auto y = stack.pop();
    auto& m = stack.top();
    m = m != 0 ? intx::mulmod(x, y, m) : 0;
}


inline void signextend(evm_stack& stack) noexcept
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

inline void lt(evm_stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = x < stack[0];
}

inline void gt(evm_stack& stack) noexcept
{
    const auto x = stack.pop();
    stack[0] = stack[0] < x;  // TODO: Using < is faster than >.
}

inline void slt(evm_stack& stack) noexcept
{
    // TODO: Move this to intx.
    const auto x = stack.pop();
    auto& y = stack[0];
    const auto x_neg = x.hi.hi >> 63;
    const auto y_neg = y.hi.hi >> 63;
    y = ((x_neg ^ y_neg) != 0) ? x_neg : x < y;
}

inline void sgt(evm_stack& stack) noexcept
{
    const auto x = stack.pop();
    auto& y = stack[0];
    const auto x_neg = x.hi.hi >> 63;
    const auto y_neg = y.hi.hi >> 63;
    y = ((x_neg ^ y_neg) != 0) ? y_neg : y < x;
}

inline void eq(evm_stack& stack) noexcept
{
    stack[1] = stack[0] == stack[1];
    stack.pop();
}

inline void iszero(evm_stack& stack) noexcept
{
    stack.top() = stack.top() == 0;
}

inline void and_(evm_stack& stack) noexcept
{
    stack.top() &= stack.pop();
}

inline void or_(evm_stack& stack) noexcept
{
    stack.top() |= stack.pop();
}

inline void xor_(evm_stack& stack) noexcept
{
    stack.top() ^= stack.pop();
}

inline void not_(evm_stack& stack) noexcept
{
    stack.top() = ~stack.top();
}

inline void byte(evm_stack& stack) noexcept
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

inline void shl(evm_stack& stack) noexcept
{
    stack.top() <<= stack.pop();
}

inline void shr(evm_stack& stack) noexcept
{
    stack.top() >>= stack.pop();
}

inline void sar(evm_stack& stack) noexcept
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
}  // namespace evmone
