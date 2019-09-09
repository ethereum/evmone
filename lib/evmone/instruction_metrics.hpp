// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <cstdint>

namespace evmone
{
enum instruction_group
{
    regular,
    terminator,
    small_push,
    large_push,
    gas_counter_user,
    pc
};

struct instruction_metrics
{
    int16_t gas_cost;
    int8_t stack_req;
    int8_t stack_change : 4;
    instruction_group group : 4;
};

const instruction_metrics* get_metrics(evmc_revision rev) noexcept;
}  // namespace evmone
