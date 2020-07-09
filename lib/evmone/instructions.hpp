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
}  // namespace evmone
