// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// EVMC instance and entry point of evmone is defined here.
/// The file name matches the evmone.h public header.

#include <evmone/evmone.h>
#include "execution.hpp"

extern "C" {
evmc_instance* evmc_create_evmone() noexcept
{
    static constexpr auto destroy = [](evmc_instance*) noexcept {};
    static constexpr auto get_capabilities = [](evmc_instance*) noexcept
    {
        return evmc_capabilities_flagset{EVMC_CAPABILITY_EVM1};
    };

    static auto instance = evmc_instance{
        EVMC_ABI_VERSION,
        "evmone",
        "0.1.0-alpha.0",
        destroy,
        evmone::execute,
        get_capabilities,
        /* set_tracer(): */ nullptr,
        /* set_option(): */ nullptr,
    };
    return &instance;
}
}
