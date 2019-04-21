// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>
#include <intx/intx.hpp>
#include <array>
#include <cstdint>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

namespace evmone
{
using uint256 = intx::uint256;

using bytes32 = std::array<uint8_t, 32>;

using bytes = std::basic_string<uint8_t>;


union instruction_info
{
    std::array<uint8_t, 32> push_data;
    int64_t number;
};

struct block_info
{
    int64_t gas_cost = 0;
    int stack_req = 0;
    int stack_max = 0;
};

struct instruction
{
    const void* opcode_dest;
    block_info block_data;
    instruction_info instruction_data;
} __attribute__ ((aligned (64))); // I think gcc will do this already, but just to be sure...

struct execution_state
{
    uint256* stack_ptr;
    instruction* next_instruction;
    int64_t gas_left = 0;
    int64_t msize = 0;
    int64_t memory_prev_cost = 0;
    uint8_t* memory;
    uint256* first_stack_position; // used to check for stack depth errors
    uint256* last_stack_position;  // used to check for stack depth errors

    uint256 stack[1024];

    instruction* stop_instruction;
    size_t code_size = 0;
    size_t output_offset = 0;
    size_t output_size = 0;
    evmc_status_code status = EVMC_SUCCESS;

    /// The gas cost of the current block.
    ///
    /// This is only needed to correctly calculate remaining gas for GAS instruction.
    /// TODO: Maybe this should be precomputed in analysis.
    int64_t current_block_cost = 0;

    bytes return_data;
    const evmc_message* msg = nullptr;
    const uint8_t* code = nullptr;
    int64_t exp_cost = 0;
    int64_t storage_repeated_cost = 0;
    evmc_context* host = nullptr;
    evmc_tx_context tx_context = {};

    evmc_revision rev = {};
};

void analyze(instruction* instructions, instruction** jumpdest_map, const void** jump_table, evmc_revision rev, const uint8_t* code, const size_t code_size) noexcept;

}  // namespace evmone