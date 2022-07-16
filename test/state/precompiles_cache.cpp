// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_cache.hpp"

namespace evmone::state
{
std::optional<evmc::Result> Cache::find(PrecompileId id, bytes_view input, int64_t gas_left) const
{
    if (const auto& cache = m_cache.at(stdx::to_underlying(id)); !cache.empty())
    {
        const auto input_hash = keccak256(input);
        if (const auto it = cache.find(input_hash); it != cache.end())
        {
            if (const auto& o = it->second; !o.has_value())
                return evmc::Result{EVMC_PRECOMPILE_FAILURE};
            else
                return evmc::Result{EVMC_SUCCESS, gas_left, 0, o->data(), o->size()};
        }
    }
    return {};
}

void Cache::insert(PrecompileId id, bytes_view input, const evmc::Result& result)
{
    if (id == PrecompileId::identity)  // Do not cache "identity".
        return;
    const auto input_hash = keccak256(input);
    std::optional<bytes> cached_output;
    if (result.status_code == EVMC_SUCCESS)
        cached_output = bytes{result.output_data, result.output_size};
    m_cache.at(stdx::to_underlying(id)).insert({input_hash, std::move(cached_output)});
}
}  // namespace evmone::state
