// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>
#include <intx/intx.hpp>
#include <array>
#include <cstdint>
#include <deque>
#include <vector>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

namespace evmone
{
using uint256 = intx::uint256;

using bytes32 = std::array<uint8_t, 32>;

using bytes = std::basic_string<uint8_t>;


struct block_info
{
    int64_t gas_cost = 0;
    int stack_req = 0;
    int stack_max = 0;
    int stack_diff = 0;
};

struct execution_state
{
    size_t pc = 0;
    size_t stack_ptr = 0;
    block_info block;
    uint8_t* memory;
    int64_t msize = 0;
    int64_t memory_prev_cost = 0;
    int64_t gas_left = 0;

    uint256 stack[1024];

    size_t code_size = 0;
    size_t output_offset = 0;
    size_t output_size = 0;
    evmc_status_code status = EVMC_SUCCESS;

    /// The gas cost of the current block.
    ///
    /// This is only needed to correctly calculate remaining gas for GAS instruction.
    /// TODO: Maybe this should be precomputed in analysis.
    int64_t current_block_cost = 0;

    struct code_analysis* analysis = nullptr;
    bytes return_data;
    const evmc_message* msg = nullptr;
    const uint8_t* code = nullptr;
    int64_t exp_cost = 0;
    int64_t storage_repeated_cost = 0;
    int64_t max_potential_memory;
    evmc_context* host = nullptr;
    evmc_tx_context tx_context = {};

    evmc_revision rev = {};
};


union instruction_info
{
    std::array<uint8_t, 32> push_data;
    int64_t gas_data;
};

struct code_analysis
{
    std::deque<instruction_info> instruction_data;
    std::deque<block_info> blocks;
};

code_analysis analyze(const void** labels, const block_info** blocks,
    const instruction_info** instruction_data, evmc_revision rev, const size_t code_size, const uint8_t* code, const void** jump_table) noexcept;
}  // namespace evmone