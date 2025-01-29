// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"
#include "rlp.hpp"

namespace evmone::state
{
static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK_CANCUN = 393216;
static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK_PRAGUE = 786432;

static constexpr uint64_t MAX_BLOB_GAS_PER_BLOCK_CANCUN = 786432;
static constexpr uint64_t MAX_BLOB_GAS_PER_BLOCK_PRAGUE = 1179648;

static constexpr uint64_t BLOB_GASPRICE_UPDATE_FRACTION_CANCUN = 3338477;
static constexpr uint64_t BLOB_GASPRICE_UPDATE_FRACTION_PRAGUE = 5007716;

uint64_t max_blob_gas_per_block(evmc_revision rev) noexcept
{
    return rev >= EVMC_PRAGUE ? MAX_BLOB_GAS_PER_BLOCK_PRAGUE : MAX_BLOB_GAS_PER_BLOCK_CANCUN;
}


intx::uint256 compute_blob_gas_price(evmc_revision rev, uint64_t excess_blob_gas) noexcept
{
    /// A helper function approximating `factor * e ** (numerator / denominator)`.
    /// https://eips.ethereum.org/EIPS/eip-4844#helpers
    static constexpr auto fake_exponential = [](uint64_t factor, uint64_t numerator,
                                                 uint64_t denominator) noexcept {
        intx::uint256 i = 1;
        intx::uint256 output = 0;
        intx::uint256 numerator_accum = factor * denominator;
        const intx::uint256 numerator256 = numerator;
        while (numerator_accum > 0)
        {
            output += numerator_accum;
            // Ensure the multiplication won't overflow 256 bits.
            if (const auto p = intx::umul(numerator_accum, numerator256);
                p <= std::numeric_limits<intx::uint256>::max())
                numerator_accum = intx::uint256(p) / (denominator * i);
            else
                return std::numeric_limits<intx::uint256>::max();
            i += 1;
        }
        return output / denominator;
    };

    static constexpr auto MIN_BLOB_GASPRICE = 1;
    const uint64_t blob_gasprice_update_fraction = rev >= EVMC_PRAGUE ?
                                                       BLOB_GASPRICE_UPDATE_FRACTION_PRAGUE :
                                                       BLOB_GASPRICE_UPDATE_FRACTION_CANCUN;
    return fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, blob_gasprice_update_fraction);
}

uint64_t calc_excess_blob_gas(
    evmc_revision rev, uint64_t parent_blob_gas_used, uint64_t parent_excess_blob_gas) noexcept
{
    const auto target_blob_gas_per_block =
        rev >= EVMC_PRAGUE ? TARGET_BLOB_GAS_PER_BLOCK_PRAGUE : TARGET_BLOB_GAS_PER_BLOCK_CANCUN;
    if (parent_excess_blob_gas + parent_blob_gas_used < target_blob_gas_per_block)
        return 0;
    else
        return parent_excess_blob_gas + parent_blob_gas_used - target_blob_gas_per_block;
}

[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal)
{
    return rlp::encode_tuple(withdrawal.index, withdrawal.validator_index, withdrawal.recipient,
        withdrawal.amount_in_gwei);
}
}  // namespace evmone::state
