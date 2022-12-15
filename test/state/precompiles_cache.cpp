// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#ifdef _MSC_VER
// Disable warning C4996: 'getenv': This function or variable may be unsafe.
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "precompiles_cache.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

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

Cache::Cache() noexcept
{
    const auto stub_file = std::getenv("EVMONE_PRECOMPILES_STUB");
    if (stub_file == nullptr)
        return;

    try
    {
        const auto j = nlohmann::json::parse(std::ifstream{stub_file});
        for (size_t id = 0; id < j.size(); ++id)
        {
            auto& cache = m_cache.at(id);
            for (const auto& [h_str, j_input] : j[id].items())
            {
                auto& e = cache[evmc::from_hex<hash256>(h_str).value()];
                if (!j_input.is_null())
                    e = evmc::from_hex(j_input.get<std::string>());
            }
        }
    }
    catch (...)
    {
        std::cerr << "evmone: Loading precompiles stub from '" << stub_file << "' has failed!\n";
    }
}

Cache::~Cache() noexcept
{
    const auto dump_file = std::getenv("EVMONE_PRECOMPILES_DUMP");
    if (dump_file == nullptr)
        return;

    try
    {
        nlohmann::json j;
        for (size_t id = 0; id < std::size(m_cache); ++id)
        {
            auto& q = j[id];
            for (const auto& [h, o] : m_cache[id])
            {
                auto& v = q[evmc::hex(h)];
                if (o)
                    v = evmc::hex(*o);
            }
        }
        std::ofstream{dump_file} << std::setw(2) << j << '\n';
    }
    catch (...)
    {
        std::cerr << "evmone: Dumping precompiles to '" << dump_file << "' has failed!\n";
    }
}
}  // namespace evmone::state
