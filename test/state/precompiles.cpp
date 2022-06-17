// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"

namespace evmone::state
{
using namespace evmc::literals;

std::optional<evmc::Result> call_precompile(evmc_revision rev, const evmc_message& msg) noexcept
{
    if (evmc::is_zero(msg.code_address) || msg.code_address > 0x09_address)
        return {};

    const auto id = msg.code_address.bytes[19];
    if (rev < EVMC_BYZANTIUM && id > 4)
        return {};

    if (rev < EVMC_ISTANBUL && id > 8)
        return {};

    return evmc::Result{EVMC_INTERNAL_ERROR};  // Not implemented.
}
}  // namespace evmone::state
