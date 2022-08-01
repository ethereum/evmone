// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/evmc.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace evmone::state
{
using evmc::bytes;
using evmc::bytes_view;

class Cache
{
    static constexpr std::size_t NumPrecompiles = 10;

    std::array<std::unordered_map<uint64_t, std::optional<bytes>>, NumPrecompiles> m_cache;

public:
    Cache() noexcept;
    ~Cache() noexcept;

    std::optional<evmc::Result> find(uint8_t id, bytes_view input, int64_t gas_left) const;

    void insert(uint8_t id, bytes_view input, const evmc::Result& result);
};
}  // namespace evmone::state
