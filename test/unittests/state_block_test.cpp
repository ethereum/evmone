// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/state.hpp>

using namespace evmone::state;
using namespace intx::literals;

TEST(state_block, blob_gas_price)
{
    static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK_CANCUN = 0x60000;

    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, 0), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, 1), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, TARGET_BLOB_GAS_PER_BLOCK_CANCUN), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, TARGET_BLOB_GAS_PER_BLOCK_CANCUN * 2), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, TARGET_BLOB_GAS_PER_BLOCK_CANCUN * 7), 2);

    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, 10'000'000), 19);
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, 100'000'000), 10203769476395);

    // Close to the computation overflowing:
    EXPECT_EQ(compute_blob_gas_price(EVMC_CANCUN, 400'000'000),
        10840331274704280429132033759016842817414750029778539_u256);
}

TEST(state_block, blob_gas_price_prague)
{
    static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK_PRAGUE = 0xc0000;

    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, 0), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, 1), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, TARGET_BLOB_GAS_PER_BLOCK_PRAGUE), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, TARGET_BLOB_GAS_PER_BLOCK_PRAGUE * 2), 1);
    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, TARGET_BLOB_GAS_PER_BLOCK_PRAGUE * 7), 3);

    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, 10'000'000), 7);
    EXPECT_EQ(compute_blob_gas_price(EVMC_PRAGUE, 100'000'000), 470442149);

    // Close to the computation overflowing:
    EXPECT_EQ(
        compute_blob_gas_price(EVMC_PRAGUE, 400'000'000), 48980690787953896757236758600209812_u256);
}
