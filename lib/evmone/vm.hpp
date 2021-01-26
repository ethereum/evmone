// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <memory>

namespace evmone
{
struct VMTracer
{
    virtual ~VMTracer() {}

    virtual void onBeginExecution() noexcept = 0;
    virtual void onOpcode(evmc_opcode opcode) noexcept = 0;
    virtual void onEndExecution() noexcept = 0;
};

/// The evmone EVMC instance.
class VM : public evmc_vm
{
public:
    std::unique_ptr<VMTracer> tracer;

    inline constexpr VM() noexcept;
};
}  // namespace evmone
