// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../utils/utils.hpp"
#include "eoftest.hpp"
#include <evmc/evmc.hpp>
#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace json = nlohmann;

namespace evmone::test
{

namespace
{
struct EOFValidationTest
{
    struct Case
    {
        struct Expectation
        {
            evmc_revision rev;
            bool result;
        };
        std::string name;
        evmc::bytes code;
        std::vector<Expectation> expectations;
    };
    std::unordered_map<std::string, Case> cases;
};

void from_json(const json::json& j, EOFValidationTest::Case& o)
{
    const auto op_code = evmc::from_hex(j.at("code").get<std::string>());
    if (!op_code)
        throw std::invalid_argument{"code is invalid hex string"};
    o.code = *op_code;

    for (const auto& [rev, result] : j.at("results").items())
    {
        o.expectations.push_back({to_rev(rev), result.at("result").get<bool>()});
    }
}

void from_json(const json::json& j, EOFValidationTest& o)
{
    if (!j.is_object() || j.empty())
        throw std::invalid_argument{"JSON test must be an object with single key of the test name"};

    const auto& j_t = *j.begin();  // Content is in a dict with the test name.

    for (const auto& [name, test] : j_t.at("vectors").items())
    {
        o.cases.emplace(name, test.get<EOFValidationTest::Case>());
    }
}

}  // namespace

void run_eof_test(std::istream& input)
{
    const auto test = json::json::parse(input).get<EOFValidationTest>();
    for (const auto& [name, cases] : test.cases)
    {
        for (const auto& expectation : cases.expectations)
        {
            const auto result = evmone::validate_eof(expectation.rev, cases.code);
            const bool b_result = (result == EOFValidationError::success);
            EXPECT_EQ(b_result, expectation.result)
                << name << " " << expectation.rev << " " << hex(cases.code);
        }
    }
}

}  // namespace evmone::test
