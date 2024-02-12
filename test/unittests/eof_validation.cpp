// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof_validation.hpp"

namespace evmone::test
{
void eof_validation::TearDown()
{
    for (const auto& test_case : test_cases)
    {
        EXPECT_EQ(evmone::validate_eof(rev, test_case.container), test_case.error)
            << test_case.name << "\n"
            << hex(test_case.container);
    }
}
}  // namespace evmone::test
