// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// @file
/// EVMC instance and entry point of evmone is defined here.
/// The file name matches the evmone.h public header.

#include "baseline.hpp"
#include "execution.hpp"
#include <evmone/evmone.h>

namespace evmone
{
namespace
{
void destroy(evmc_vm* vm) noexcept
{
    // TODO: Mark function with [[gnu:nonnull]] or add CHECK().
    delete vm;
}

constexpr evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept
{
    return EVMC_CAPABILITY_EVM1;
}

evmc_set_option_result set_option(evmc_vm* vm, char const* name, char const* value) noexcept
{
    if (name[0] == 'O' && name[1] == '\0')
    {
        if (value[0] == '0' && value[1] == '\0')  // O=0
        {
            vm->execute = evmone::baseline::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        else if (value[0] == '2' && value[1] == '\0')  // O=2
        {
            vm->execute = evmone::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        return EVMC_SET_OPTION_INVALID_VALUE;
    }
    return EVMC_SET_OPTION_INVALID_NAME;
}
}  // namespace
}  // namespace evmone

extern "C" {
EVMC_EXPORT evmc_vm* evmc_create_evmone() noexcept
{
    return new evmc_vm{
        EVMC_ABI_VERSION,
        "evmone",
        PROJECT_VERSION,
        evmone::destroy,
        evmone::execute,
        evmone::get_capabilities,
        evmone::set_option,
    };
}
}
