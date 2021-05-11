// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "tracing.hpp"
#include <evmc/evmc.h>

namespace evmone
{
/// The evmone EVMC instance.
class VM : public evmc_vm, TracerListNode
{
public:
    inline constexpr VM() noexcept;

    using TracerListNode::add_tracer;

    [[nodiscard]] VMTracer* get_tracer() const noexcept
    {
        return TracerListNode::get_next_tracer();
    }
};
}  // namespace evmone
