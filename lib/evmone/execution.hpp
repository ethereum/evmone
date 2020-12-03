// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>

namespace evmone
{
evmc_result execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size, unsigned int repeat=1,
    bool measure_collective_time=false, bool measure_each_time=false, unsigned int instruction_to_measure=0) noexcept;
}  // namespace evmone
