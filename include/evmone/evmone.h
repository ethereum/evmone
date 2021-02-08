// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVMONE_H
#define EVMONE_H

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <memory>

#if __cplusplus
extern "C" {
#endif

EVMC_EXPORT struct evmc_vm* evmc_create_evmone(void) EVMC_NOEXCEPT;

#if __cplusplus
}

#include <evmc/instructions.h>

namespace evmone
{
struct VMTracer
{
    virtual ~VMTracer() {}

    virtual void onBeginExecution() noexcept = 0;
    virtual void onOpcode(evmc_opcode opcode) noexcept = 0;
    virtual void onEndExecution() noexcept = 0;
};

struct VM : evmc_vm
{
    std::unique_ptr<VMTracer> tracer;

    inline constexpr VM() noexcept;
};
}  // namespace evmone

#endif

#endif  // EVMONE_H
