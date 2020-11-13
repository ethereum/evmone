// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/baseline.hpp>
#include <cstdint>
#include <vector>

namespace evmone::experimental
{
inline bool is_jumpdest(const std::vector<bool>& jumpdest_map, size_t index) noexcept
{
    return (index < jumpdest_map.size() && jumpdest_map[index]);
}

std::vector<bool> build_jumpdest_map_vec1(const uint8_t* code, size_t code_size);
bitset build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size);
}  // namespace evmone::experimental
