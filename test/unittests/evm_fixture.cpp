// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include <evmone/evmone.h>

namespace evmone::test
{
evmc::VM& get_vm() noexcept
{
    static auto vm = evmc::VM{evmc_create_evmone()};
    return vm;
}
}  // namespace evmone::test
