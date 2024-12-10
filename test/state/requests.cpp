// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "requests.hpp"
#include <evmone_precompiles/sha256.hpp>

namespace evmone::state
{
hash256 calculate_requests_hash(std::span<const Requests> block_requests_list)
{
    bytes requests_hash_list;
    requests_hash_list.reserve(sizeof(hash256) * block_requests_list.size());

    for (const auto& requests : block_requests_list)
    {
        // TODO recent change in the spec, uncomment for devnet-5
        //        if (requests.data.empty())
        //            continue;

        const bytes requests_bytes = static_cast<uint8_t>(requests.type) + requests.data;
        hash256 requests_hash;
        crypto::sha256(reinterpret_cast<std::byte*>(requests_hash.bytes),
            reinterpret_cast<const std::byte*>(requests_bytes.data()), requests_bytes.size());
        requests_hash_list += requests_hash;
    }

    hash256 block_requests_hash;
    crypto::sha256(reinterpret_cast<std::byte*>(block_requests_hash.bytes),
        reinterpret_cast<const std::byte*>(requests_hash_list.data()), requests_hash_list.size());
    return block_requests_hash;
}
}  // namespace evmone::state
