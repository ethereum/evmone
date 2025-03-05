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
        if (requests.data().empty())
            continue;  // Skip empty requests.

        hash256 requests_hash;
        crypto::sha256(reinterpret_cast<std::byte*>(requests_hash.bytes),
            reinterpret_cast<const std::byte*>(requests.raw_data.data()), requests.raw_data.size());
        requests_hash_list += requests_hash;
    }

    hash256 block_requests_hash;
    crypto::sha256(reinterpret_cast<std::byte*>(block_requests_hash.bytes),
        reinterpret_cast<const std::byte*>(requests_hash_list.data()), requests_hash_list.size());
    return block_requests_hash;
}

Requests collect_deposit_requests(std::span<const TransactionReceipt> receipts)
{
    Requests requests(Requests::Type::deposit);
    for (const auto& receipt : receipts)
    {
        for (const auto& log : receipt.logs)
        {
            assert(log.addr != DEPOSIT_CONTRACT_ADDRESS || !log.topics.empty());
            if (log.addr == DEPOSIT_CONTRACT_ADDRESS &&
                log.topics[0] == DEPOSIT_EVENT_SIGNATURE_HASH)
            {
                // Deposit log definition
                // https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
                // event DepositEvent(
                //     bytes pubkey,
                //     bytes withdrawal_credentials,
                //     bytes amount,
                //     bytes signature,
                //     bytes index
                // );
                //
                // In ABI every bytes array data is prepended by a word with its size.
                // Skip over first 5 words (offsets of the values) and over pubkey size.
                static constexpr auto PUBKEY_OFFSET = 32 * 5 + 32;
                static constexpr auto PUBKEY_SIZE = 48;
                // Pubkey size is 48 bytes, but is padded to word boundary, so takes 64 bytes.
                // Skip over pubkey and withdrawal credentials size.
                static constexpr auto WITHDRAWAL_CREDS_OFFSET = PUBKEY_OFFSET + 64 + 32;
                static constexpr auto WITHDRAWAL_CREDS_SIZE = 32;
                // Skip over withdrawal credentials and amount size.
                static constexpr auto AMOUNT_OFFSET = WITHDRAWAL_CREDS_OFFSET + 32 + 32;
                static constexpr auto AMOUNT_SIZE = 8;
                // Pubkey size is 8 bytes, but is padded to word boundary, so takes 32 bytes.
                // Skip over amount and signature size.
                static constexpr auto SIGNATURE_OFFSET = AMOUNT_OFFSET + 32 + 32;
                static constexpr auto SIGNATURE_SIZE = 96;
                // Skip over signature and index size.
                static constexpr auto INDEX_OFFSET = SIGNATURE_OFFSET + 96 + 32;
                static constexpr auto INDEX_SIZE = 8;

                // Index is padded to word boundary, so takes 32 bytes.
                assert(log.data.size() == INDEX_OFFSET + 32);

                requests.append({&log.data[PUBKEY_OFFSET], PUBKEY_SIZE});
                requests.append({&log.data[WITHDRAWAL_CREDS_OFFSET], WITHDRAWAL_CREDS_SIZE});
                requests.append({&log.data[AMOUNT_OFFSET], AMOUNT_SIZE});
                requests.append({&log.data[SIGNATURE_OFFSET], SIGNATURE_SIZE});
                requests.append({&log.data[INDEX_OFFSET], INDEX_SIZE});
            }
        }
    }
    return requests;
}
}  // namespace evmone::state
