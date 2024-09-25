// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"
#include "rlp.hpp"

namespace evmone::state
{
intx::uint256 compute_blob_gas_price(uint64_t excess_blob_gas) noexcept
{
    /// A helper function approximating `factor * e ** (numerator / denominator)`.
    /// https://eips.ethereum.org/EIPS/eip-4844#helpers
    static constexpr auto fake_exponential = [](uint64_t factor, uint64_t numerator,
                                                 uint64_t denominator) noexcept {
        intx::uint256 i = 1;
        intx::uint256 output = 0;
        intx::uint256 numerator_accum = factor * denominator;
        while (numerator_accum > 0)
        {
            output += numerator_accum;
            numerator_accum = (numerator_accum * numerator) / (denominator * i);
            i += 1;
        }
        return output / denominator;
    };

    static constexpr auto MIN_BLOB_GASPRICE = 1;
    static constexpr auto BLOB_GASPRICE_UPDATE_FRACTION = 3338477;
    return fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION);
}

[[nodiscard]] bytes rlp_encode(const Withdrawal& withdrawal)
{
    return rlp::encode_tuple(withdrawal.index, withdrawal.validator_index, withdrawal.recipient,
        withdrawal.amount_in_gwei);
}
}  // namespace evmone::state
