// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <cstdint>

namespace evmone
{
struct instruction_metrics
{
    int16_t gas_cost = 0;
    int8_t stack_req = 0;
    int8_t stack_change = 0;
};

const instruction_metrics* get_metrics(evmc_revision rev) noexcept;
}  // namespace evmone
