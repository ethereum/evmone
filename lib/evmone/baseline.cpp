// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"

namespace evmone
{
evmc_result baseline_execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    (void)vm;
    (void)host;
    (void)ctx;
    (void)rev;
    (void)msg;
    (void)code;
    (void)code_size;
    evmc_result result{};
    result.status_code = EVMC_INTERNAL_ERROR;
    return result;
}
}  // namespace evmone
