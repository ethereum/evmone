// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/state.hpp>

using namespace evmone::state;
using namespace intx;

TEST(state_block, blob_gas_price)
{
    static constexpr uint64_t TARGET_BLOB_GAS_PER_BLOCK = 0x60000;

    EXPECT_EQ(compute_blob_gas_price(0), 1);
    EXPECT_EQ(compute_blob_gas_price(1), 1);
    EXPECT_EQ(compute_blob_gas_price(TARGET_BLOB_GAS_PER_BLOCK), 1);
    EXPECT_EQ(compute_blob_gas_price(TARGET_BLOB_GAS_PER_BLOCK * 2), 1);
    EXPECT_EQ(compute_blob_gas_price(TARGET_BLOB_GAS_PER_BLOCK * 7), 2);

    EXPECT_EQ(compute_blob_gas_price(10'000'000), 19);
    EXPECT_EQ(compute_blob_gas_price(100'000'000), 10203769476395);

    // Close to the computation overflowing:
    EXPECT_EQ(compute_blob_gas_price(400'000'000),
        10840331274704280429132033759016842817414750029778539_u256);
}
