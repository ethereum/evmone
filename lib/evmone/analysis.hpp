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


// Auxiliary information required to process an instruction.
// We either need 32 bytes (for push data), or a 64-bit int, but never both.
// Can use a union to save some space in our array
union instruction_info
{
    std::array<uint8_t, 32> push_data;
    int64_t number;
};

struct block_info
{
    int64_t gas_cost;
    int stack_req;
    int stack_max;
};

// Instruction holds the data required to execute an opcode.
// Padded in size to fit a cache line. Our program execution is defined by
// an array of these instructions, that we execute in order (barring jump and jumpi opcodes).
struct instruction
{
    const void* opcode_dest; // pointer to a label that we can directly use 'goto' on
    block_info block_data;   // contains basic block data (if any)
    instruction_info instruction_data; // auxiliary information for this opcode (push data etc)
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

    // This is a bit hacky. We want the fake stack to be allocated on the real stack,
    // but we don't want to call the default constructor of uint256 for every entry
    // (this was adding a few hundred microseconds to the 'empty' benchmark,
    //  and we only read stack values after we write to them).
    // It is not possible to access stack elements that have not been written to (without entering an error state),
    // so we might as well save some time and leave this array initialized with garbage.
    // But to do that, we need to instantiate an array of uint256's without calling the default constructor.
    // To do THAT, this pretends to be a char array, when in reality it is used to store uint256's
    char stack[1024 * sizeof(uint256)];

    size_t code_size_mask;
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

    execution_state() {}
};

void analyze(instruction* instructions, instruction** jumpdest_map, const void** jump_table, evmc_revision rev, const uint8_t* code, const size_t code_size) noexcept;

}  // namespace evmone