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
#endif

namespace evmone
{
EVMC_EXPORT evmc_result execute(evmc_vm* vm, const evmc_host_interface* host,
    evmc_host_context* ctx, evmc_revision rev, const evmc_message* msg, const uint8_t* code,
    size_t code_size) noexcept;
}  // namespace evmone

#endif  // EVMONE_H
