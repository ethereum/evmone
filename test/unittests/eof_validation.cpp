// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"
#include <test/statetest/statetest.hpp>
#include <fstream>

namespace evmone::test
{
void eof_validation::TearDown()
{
    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        const auto& test_case = test_cases[i];
        EXPECT_EQ(evmone::validate_eof(rev, test_case.container), test_case.error)
            << "test case " << i << " " << test_case.name << "\n"
            << hex(test_case.container);
    }

    if (!export_file_path.empty())
        export_eof_validation_test();
}

void eof_validation::export_eof_validation_test()
{
    json::json j;
    auto& jt = j[export_test_name];

    auto& jvectors = jt["vectors"];
    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        const auto& test_case = test_cases[i];
        const auto case_name = test_case.name.empty() ?
                                   (std::string{export_test_name} + "_" + std::to_string(i)) :
                                   test_case.name;

        auto& jcase = jvectors[case_name];
        jcase["code"] = hex0x(test_case.container);

        auto& jresults = jcase["results"][evmc::to_string(rev)];
        if (test_case.error == EOFValidationError::success)
            jresults["result"] = true;
        else
        {
            jresults["result"] = false;
            jresults["exception"] = get_error_message(test_case.error);
        }
    }

    std::ofstream{export_file_path} << std::setw(2) << j;
}
}  // namespace evmone::test
