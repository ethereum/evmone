// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>

namespace evmone::state
{
evmc::result call_precompiled(evmc_revision rev, const evmc_message& msg) noexcept;
}
