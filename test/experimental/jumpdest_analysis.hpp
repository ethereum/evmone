// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/baseline.hpp>
#include <cstdint>
#include <memory>
#include <vector>

namespace evmone::experimental
{
inline bool is_jumpdest(const std::vector<bool>& jumpdest_map, size_t index) noexcept
{
    return (index < jumpdest_map.size() && jumpdest_map[index]);
}

inline bool is_jumpdest(const uint8_t* code, size_t code_size, size_t index) noexcept
{
    return (index < code_size && code[index] == 0x5b);
}

std::vector<bool> build_jumpdest_map_vec1(const uint8_t* code, size_t code_size);
std::vector<bool> build_jumpdest_map_simd1(const uint8_t* code, size_t code_size);
bitset build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v1(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v2(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v3(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v4(const uint8_t* code, size_t code_size);
std::unique_ptr<uint8_t[]> build_internal_code_v8(const uint8_t* code, size_t code_size);
}  // namespace evmone::experimental
