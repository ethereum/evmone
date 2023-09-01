// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gmock/gmock.h>
#include <test/state/ethash_difficulty.hpp>

using namespace evmone::state;

struct DifficultyTest  // NOLINT(clang-analyzer-optin.performance.Padding)
{
    evmc_revision rev;
    const char* name;
    int64_t block_number;
    int64_t difficulty;
    int64_t timestamp;
    int64_t parent_difficulty;
    int64_t parent_timestamp;
    bool parent_has_ommers;
};

/// Example difficulty tests from
/// https://github.com/ethereum/tests/blob/develop/DifficultyTests.
static constexpr DifficultyTest tests[] = {
    {
        EVMC_BYZANTIUM,
        "DifficultyTest1",
        0x0186a0,
        0x69702c7f2c9fad14,
        0x28d214819,
        0x6963001f28ba95c2,
        0x28d214818,
        false,
    },
    {
        EVMC_BYZANTIUM,
        "DifficultyTest1038",
        0x0dbba0,
        0x79f2cbb8c97579b0,
        0x72e440371,
        0x79f2cbb8c97579b0,
        0x72e44035d,
        true,
    },
    {
        EVMC_BERLIN,
        "DifficultyTest1",
        0x186a0,
        0x56c67d1e106966c3,
        0x63ed689e9,
        0x56bba5a95b3dff04,
        0x63ed689e8,
        false,
    },
    {
        EVMC_BERLIN,
        "DifficultyTest1040",
        0x10c8e0,
        0x68f7512123928555,
        0x617ec9fcc,
        0x68f7512123928555,
        0x617ec9fb8,
        true,
    },
};

TEST(state_difficulty, tests)
{
    for (const auto& t : tests)
    {
        const auto difficulty = calculate_difficulty(t.parent_difficulty, t.parent_has_ommers,
            t.parent_timestamp, t.timestamp, t.block_number, t.rev);
        EXPECT_EQ(difficulty, t.difficulty) << t.rev << "/" << t.name;
    }
}
