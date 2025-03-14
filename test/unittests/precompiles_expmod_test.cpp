// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/hex.hpp>
#include <gtest/gtest.h>
#include <intx/intx.hpp>
#include <test/state/precompiles_internal.hpp>
#include <test/utils/utils.hpp>

struct TestCase
{
    std::string base;
    std::string exp;
    std::string mod;
    std::string expected_result;
};

/// Test vectors for expmod precompile.
/// TODO: Currently limited to what expmod_stub can handle, but more can be added along the proper
///   implementation, e.g. {"03", "1c93", "61", "5f"}.
static const std::vector<TestCase> test_cases{
    {"", "", "", ""},
    {"", "", "00", "00"},
    {"02", "01", "03", "02"},
    {
        "03",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "0000000000000000000000000000000000000000000000000000000000000001",
    },
};

TEST(expmod, test_vectors)
{
    for (const auto& [base, exp, mod, expected_result] : test_cases)
    {
        const auto base_bytes = *evmc::from_hex(base);
        const auto exp_bytes = *evmc::from_hex(exp);
        const auto mod_bytes = *evmc::from_hex(mod);
        const auto expected_result_bytes = *evmc::from_hex(expected_result);

        evmc::bytes input(3 * 32, 0);
        input[31] = static_cast<uint8_t>(base_bytes.size());
        input[32 + 31] = static_cast<uint8_t>(exp_bytes.size());
        input[64 + 31] = static_cast<uint8_t>(mod_bytes.size());
        input += base_bytes;
        input += exp_bytes;
        input += mod_bytes;

        evmc::bytes result(expected_result_bytes.size(), 0xfe);
        const auto r =
            evmone::state::expmod_execute(input.data(), input.size(), result.data(), result.size());
        EXPECT_EQ(r.status_code, EVMC_SUCCESS);
        EXPECT_EQ(r.output_size, expected_result_bytes.size());
        EXPECT_EQ(hex(result), expected_result);
    }
}
