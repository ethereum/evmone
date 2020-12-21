// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include <evmone/evmone.h>

namespace evmone::test
{
namespace
{
evmc::VM advanced_vm{evmc_create_evmone(), {{"O", "2"}}};
evmc::VM baseline_vm{evmc_create_evmone(), {{"O", "0"}}};

const char* print_vm_name(const testing::TestParamInfo<evmc::VM*>& info) noexcept
{
    if (info.param == &advanced_vm)
        return "advanced";
    if (info.param == &baseline_vm)
        return "baseline";
    return "unknown";
}
}  // namespace

INSTANTIATE_TEST_SUITE_P(evmone, evm, testing::Values(&advanced_vm, &baseline_vm), print_vm_name);
}  // namespace evmone::test
