// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// This file contains EVM unit tests for the BLOBHASH instruction from EIP-4844
/// https://eips.ethereum.org/EIPS/eip-4844

#include "evm_fixture.hpp"

using namespace evmc::literals;
using namespace evmone::test;

TEST_P(evm, blobhash_undefined)
{
    rev = EVMC_SHANGHAI;
    execute(blobhash(0));
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);
}

TEST_P(evm, blobhash_empty)
{
    rev = EVMC_CANCUN;
    execute(blobhash(0) + ret_top());
    EXPECT_OUTPUT_INT(0);

    execute(blobhash(1) + ret_top());
    EXPECT_OUTPUT_INT(0);

    execute(blobhash(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32) +
            ret_top());
    EXPECT_OUTPUT_INT(0);
}

TEST_P(evm, blobhash_one)
{
    rev = EVMC_CANCUN;

    const std::array blob_hashes{
        0x01feeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed_bytes32};

    host.tx_context.blob_hashes = blob_hashes.data();
    host.tx_context.blob_hashes_count = blob_hashes.size();

    execute(blobhash(0) + ret_top());
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(output, blob_hashes[0]);

    execute(blobhash(1) + ret_top());
    EXPECT_OUTPUT_INT(0);

    execute(blobhash(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32) +
            ret_top());
    EXPECT_OUTPUT_INT(0);
}

TEST_P(evm, blobhash_two)
{
    rev = EVMC_CANCUN;

    const std::array blob_hashes{
        0x0100000000000000000000000000000000000000000000000000000000000001_bytes32,
        0x0100000000000000000000000000000000000000000000000000000000000002_bytes32};

    host.tx_context.blob_hashes = blob_hashes.data();
    host.tx_context.blob_hashes_count = blob_hashes.size();

    for (size_t i = 0; i < blob_hashes.size(); ++i)
    {
        execute(blobhash(i) + ret_top());
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_EQ(output, blob_hashes[i]);
    }

    execute(blobhash(blob_hashes.size()) + ret_top());
    EXPECT_OUTPUT_INT(0);

    execute(blobhash(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32) +
            ret_top());
    EXPECT_OUTPUT_INT(0);
}

TEST_P(evm, blobhash_invalid_hash_version)
{
    rev = EVMC_CANCUN;

    // The BLOBHASH instruction does not care about the hash version,
    // it will return whatever is in the array.
    const std::array blob_hashes{
        0x0000000000000000000000000000000000000000000000000000000000000000_bytes32,
        0x0200000000000000000000000000000000000000000000000000000000000000_bytes32};

    host.tx_context.blob_hashes = blob_hashes.data();
    host.tx_context.blob_hashes_count = blob_hashes.size();

    for (size_t i = 0; i < blob_hashes.size(); ++i)
    {
        execute(blobhash(i) + ret_top());
        EXPECT_STATUS(EVMC_SUCCESS);
        EXPECT_EQ(output, blob_hashes[i]);
    }

    execute(blobhash(blob_hashes.size()) + ret_top());
    EXPECT_OUTPUT_INT(0);

    execute(blobhash(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_bytes32) +
            ret_top());
    EXPECT_OUTPUT_INT(0);
}
