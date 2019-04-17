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

    // execution_state(size_t max_memory) noexcept {
    //     this->max_potential_memory = max_memory;
    //     this->memory = (uint8_t*)calloc(max_memory, sizeof(uint8_t));
    // };
    // ~execution_state() noexcept {
    //     free(memory);
    // }

    // uint256& item(size_t index) noexcept { return stack[stack.size() - index - 1]; }
};

union instr_argument
{
    struct
    {
        int number = 0;
        evmc_call_kind call_kind = EVMC_CALL;
    };
    const uint8_t* data;

    constexpr instr_argument() noexcept : number{}, call_kind{} {};
};

static_assert(sizeof(instr_argument) == sizeof(void*), "Incorrect size of instr_argument");

using exec_fn = void (*)(execution_state&, instr_argument arg);

using exec_fn_table = std::array<exec_fn, 256>;


struct instr_info
{
    exec_fn fn = nullptr;
    instr_argument arg;
    int block_index = -1;

    explicit constexpr instr_info(exec_fn fn) noexcept : fn{fn} {};
};


struct code_analysis
{
    std::vector<instr_info> instrs;
    std::vector<block_info> blocks;

    /// Storage for arguments' extended data.
    ///
    /// The deque container is used because pointers to its elements are not
    /// invalidated when the container grows.
    std::deque<bytes32> args_storage;

    std::vector<std::pair<int, int>> jumpdest_map;

    int find_jumpdest(int offset) noexcept;
};

code_analysis analyze(
    const exec_fn_table& fns, evmc_revision rev, const uint8_t* code, size_t code_size) noexcept;

union instruction_info
{
    std::array<uint8_t, 32> push_data;
    int64_t gas_data;
};

struct code_analysis_alt
{
    std::deque<instruction_info> instruction_data;
    std::deque<block_info> blocks;
};

code_analysis_alt analyze_alt(const void** labels, const block_info** blocks,
    const instruction_info** instruction_data, evmc_revision rev, const size_t code_size, const uint8_t* code, const void** jump_table) noexcept;

// code_analysis_alt analyze_alt(
//     void* jump_table,
//     void* labels,
//     block_info* instr_info,
//     bytes32* storage_info,
//     evmc_revision rev,
//     const uint8_t* code,
//     const size_t code_size
// ) noexcept;

}  // namespace evmone