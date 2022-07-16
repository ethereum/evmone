// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_cache.hpp"

namespace evmone::state
{
namespace
{
inline uint64_t fnv1a(bytes_view v) noexcept
{
    uint64_t h = 0xcbf29ce484222325;
    for (const auto b : v)
        h = (h ^ b) * 0x100000001b3;
    return h;
}
}  // namespace

std::optional<evmc::Result> Cache::find(uint8_t id, bytes_view input, int64_t gas_left) const
{
    if (const auto& cache = m_cache.at(id); !cache.empty())
    {
        const auto input_hash = fnv1a(input);
        if (const auto it = cache.find(input_hash); it != cache.end())
        {
            if (const auto& o = it->second; !o.has_value())
                return evmc::Result{EVMC_OUT_OF_GAS};
            else
                return evmc::Result{EVMC_SUCCESS, gas_left, 0, o->data(), o->size()};
        }
    }
    return {};
}

void Cache::insert(uint8_t id, bytes_view input, const evmc::Result& result)
{
    if (id == 4)  // Do not cache "identity".
        return;
    const auto input_hash = fnv1a(input);
    std::optional<bytes> cached_output;
    if (result.status_code == EVMC_SUCCESS)
        cached_output = bytes{result.output_data, result.output_size};
    m_cache.at(id).insert({input_hash, std::move(cached_output)});
}
}  // namespace evmone::state
