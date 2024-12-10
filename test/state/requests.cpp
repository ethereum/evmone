// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "requests.hpp"
#include <evmone_precompiles/sha256.hpp>

namespace evmone::state
{
namespace
{
/// The address of the deposit contract.
constexpr auto DEPOSIT_CONTRACT_ADDRESS = 0x00000000219ab540356cBB839Cbe05303d7705Fa_address;
}  // namespace

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

Requests collect_deposit_requests(std::span<const TransactionReceipt> receipts)
{
    Requests requests{.type = Requests::Type::deposit};
    for (const auto& receipt : receipts)
    {
        for (const auto& log : receipt.logs)
        {
            if (log.addr == DEPOSIT_CONTRACT_ADDRESS)
            {
                constexpr auto pubkey_offset = 32 * 5 + 32;
                constexpr auto withdrawal_credentials_offset = pubkey_offset + 64 + 32;
                constexpr auto amount_offset = withdrawal_credentials_offset + 32 + 32;
                constexpr auto signature_offset = amount_offset + 32 + 32;
                constexpr auto index_offset = signature_offset + 96 + 32;

                assert(log.data.size() == index_offset + 32);

                requests.data += log.data.substr(pubkey_offset, 48);
                requests.data += log.data.substr(withdrawal_credentials_offset, 32);
                requests.data += log.data.substr(amount_offset, 8);
                requests.data += log.data.substr(signature_offset, 96);
                requests.data += log.data.substr(index_offset, 8);
            }
        }
    }
    return requests;
}
}  // namespace evmone::state
