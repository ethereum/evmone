// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVMONE_H
#define EVMONE_H

#include <evmc/evmc.h>
#include <evmc/utils.h>

#if __cplusplus
extern "C" {
#endif

EVMC_EXPORT struct evmc_vm* evmc_create_evmone(void) EVMC_NOEXCEPT;

#if __cplusplus
}

#include <evmc/instructions.h>

namespace evmone
{
using TracingFn = void (*)(evmc_opcode opcode) noexcept;

struct VM : evmc_vm
{
    TracingFn tracing_fn = nullptr;

    inline constexpr VM() noexcept;
};
}  // namespace evmone

#endif

#endif  // EVMONE_H
