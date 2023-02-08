// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/statetest/statetest.hpp>

using namespace evmone;

static constexpr auto EmptyLogsHash =
    0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32;

TEST(statetest_logs_hash, empty_logs)
{
    EXPECT_EQ(test::logs_hash({}), EmptyLogsHash);
    EXPECT_EQ(keccak256(bytes{0xc0}), EmptyLogsHash);  // Hash of empty RLP list: 0xc0.
}

TEST(statetest_logs_hash, example1)
{
    const std::vector<state::Log> logs{
        state::Log{0x00_address, bytes{0xb0, 0xb1}, {}},
        state::Log{0xaa_address, {}, {0x01_bytes32, 0x02_bytes32}},
    };

    EXPECT_EQ(test::logs_hash(logs),
        0xb27f856c430c0266d2925d442632401e63685677a4ea009f855dee23e74488aa_bytes32);
}
