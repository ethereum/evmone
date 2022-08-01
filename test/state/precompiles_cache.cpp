// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_cache.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

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

Cache::Cache() noexcept
{
    const auto stub_file = std::getenv("EVMONE_PRECOMPILES_STUB");
    if (stub_file != nullptr)
    {
        try
        {
            const auto j = nlohmann::json::parse(std::ifstream{stub_file});
            for (size_t id = 0; id < j.size(); ++id)
            {
                auto& cache = m_cache.at(id);
                for (const auto& [h_str, j_input] : j[id].items())
                {
                    const auto h = static_cast<uint64_t>(std::stoull(h_str, nullptr, 16));
                    auto& e = cache[h];
                    if (!j_input.is_null())
                        e = evmc::from_hex(j_input.get<std::string>());
                }
            }
        }
        catch (...)
        {
            std::cerr << "evmone: Loading precompiles stub from '" << stub_file
                      << "' has failed!\n";
        }
    }
}

Cache::~Cache() noexcept
{
    const auto dump_file = std::getenv("EVMONE_PRECOMPILES_DUMP");
    if (dump_file != nullptr)
    {
        try
        {
            std::ostringstream hash_s;
            nlohmann::json j;
            for (size_t id = 0; id < std::size(m_cache); ++id)
            {
                auto& q = j[id];
                for (const auto& [h, o] : m_cache[id])
                {
                    hash_s.str({});
                    hash_s << std::hex << std::setw(16) << std::setfill('0') << h;
                    auto& v = q[hash_s.str()];
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
}
}  // namespace evmone::state
