// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_utils.hpp"
#include <intx/intx.hpp>
#include <vector>

namespace evmone::state
{
struct Ommer
{
    address beneficiary;  ///< Ommer block beneficiary address.
    uint32_t delta = 0;   ///< Difference between current and ommer block number.
};

struct Withdrawal
{
    uint64_t index = 0;
    uint64_t validator_index = 0;
    address recipient;
    uint64_t amount_in_gwei = 0;  ///< The amount is denominated in gwei.

    /// Returns withdrawal amount in wei.
    [[nodiscard]] intx::uint256 get_amount() const noexcept
    {
        return intx::uint256{amount_in_gwei} * 1'000'000'000;
    }
};

struct BlockInfo
{
    /// Max amount of blob gas allowed in block. It's constant now but can be dynamic in the future.
    static constexpr uint64_t MAX_BLOB_GAS_PER_BLOCK = 786432;

    int64_t number = 0;
    int64_t timestamp = 0;
    int64_t parent_timestamp = 0;
    int64_t gas_limit = 0;
    address coinbase;
    int64_t difficulty = 0;
    int64_t parent_difficulty = 0;
    hash256 parent_ommers_hash;
    bytes32 prev_randao;
    hash256 parent_beacon_block_root;

    /// The EIP-1559 base fee, since London.
    uint64_t base_fee = 0;

    /// The "blob gas used" parameter from EIP-4844
    std::optional<uint64_t> blob_gas_used;

    /// The "excess blob gas" parameter from EIP-4844
    /// for computing the blob gas price in the current block.
    std::optional<uint64_t> excess_blob_gas;

    std::vector<Ommer> ommers;
    std::vector<Withdrawal> withdrawals;
};

/// Computes the current blob gas price based on the excess blob gas.
intx::uint256 compute_blob_gas_price(uint64_t excess_blob_gas) noexcept;

/// Computes the current excess blob gas based on the parent.
uint64_t calc_excess_blob_gas(
    uint64_t parent_blob_gas_used, uint64_t parent_excess_blob_gas) noexcept;

/// Defines how to RLP-encode a Withdrawal.
[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal);
}  // namespace evmone::state
