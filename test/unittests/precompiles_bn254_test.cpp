// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/hex.hpp>
#include <gtest/gtest.h>
#include <intx/intx.hpp>
#include <test/state/precompiles_internal.hpp>
#include <test/utils/utils.hpp>

/// Test vectors for BN254 ecpairing precompile expecting the result to be true.
static const std::vector<std::string> positive_test_cases{
    {},                             // empty
    std::string(192 * 2, '0'),      // null pair
    std::string(192 * 2 * 2, '0'),  // two null pairs
};

TEST(bn254_ecpairing, positive_test_vectors)
{
    for (const auto& input_hex : positive_test_cases)
    {
        const auto input = evmc::from_hex(input_hex).value();
        uint8_t result[32];
        const auto [status_code, output_size] =
            evmone::state::ecpairing_execute(input.data(), input.size(), result, sizeof(result));
        EXPECT_EQ(status_code, EVMC_SUCCESS);
        EXPECT_EQ(output_size, sizeof(result));
        EXPECT_EQ(hex(evmc::bytes_view(result, sizeof(result))),
            "0000000000000000000000000000000000000000000000000000000000000001");
    }
}
