// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>

namespace evmone
{
/// The evmone EVMC instance.
class VM : public evmc_vm
{
public:
    inline constexpr VM() noexcept;
};
}  // namespace evmone
