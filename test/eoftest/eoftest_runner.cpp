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
            evmc_revision rev = EVMC_OSAKA;
            bool result = false;
        };
        std::string name;
        evmc::bytes code;
        ContainerKind kind = ContainerKind::runtime;
        std::vector<Expectation> expectations;
    };
    std::string name;
    std::unordered_map<std::string, Case> cases;
};

void from_json(const json::json& j, EOFValidationTest::Case& o)
{
    const auto op_code = evmc::from_hex(j.at("code").get<std::string>());
    if (!op_code)
        throw std::invalid_argument{"code is invalid hex string"};
    o.code = *op_code;

    if (const auto it_kind = j.find("containerKind"); it_kind != j.end())
    {
        if (it_kind->get<std::string>() == "INITCODE")
            o.kind = ContainerKind::initcode;
    }

    for (const auto& [rev, result] : j.at("results").items())
    {
        o.expectations.push_back({to_rev(rev), result.at("result").get<bool>()});
    }
}

void from_json(const json::json& j, EOFValidationTest& o)
{
    if (!j.is_object() || j.empty())
        throw std::invalid_argument{"JSON test must be an object with single key of the test name"};

    for (const auto& [name, test] : j.at("vectors").items())
    {
        o.cases.emplace(name, test.get<EOFValidationTest::Case>());
    }
}

void from_json(const json::json& j, std::vector<EOFValidationTest>& o)
{
    for (const auto& elem_it : j.items())
    {
        auto test = elem_it.value().get<EOFValidationTest>();
        test.name = elem_it.key();
        o.emplace_back(std::move(test));
    }
}

std::vector<EOFValidationTest> load_eof_tests(std::istream& input)
{
    return json::json::parse(input).get<std::vector<EOFValidationTest>>();
}

}  // namespace

void run_eof_test(std::istream& input)
{
    const auto tests = evmone::test::load_eof_tests(input);
    for (const auto& test : tests)
    {
        for (const auto& [name, cases] : test.cases)
        {
            for (const auto& expectation : cases.expectations)
            {
                const auto result = evmone::validate_eof(expectation.rev, cases.kind, cases.code);
                const bool b_result = (result == EOFValidationError::success);
                EXPECT_EQ(b_result, expectation.result)
                    << name << " " << expectation.rev << " " << hex(cases.code);
            }
        }
    }
}

}  // namespace evmone::test
