// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.h>
#include <intx/intx.hpp>
#include <array>
#include <cstdint>
#include <deque>
#include <vector>

namespace evmone
{
using uint256 = intx::uint256;

using bytes32 = std::array<uint8_t, 32>;

struct execution_state
{
    bool run = true;
    size_t pc = 0;
    int64_t gas_left = 0;
    evmc_status_code status = EVMC_SUCCESS;

    std::vector<uint256> stack;

    std::vector<uint8_t> memory;
    int64_t memory_prev_cost = 0;
    size_t output_offset = 0;
    size_t output_size = 0;

    uint256& item(size_t index) noexcept { return stack[stack.size() - index - 1]; }
};

union instr_argument
{
    int number = -1;  // TODO: Consider initializing with zeros.
    const uint8_t* data;
};

using exec_fn = void (*)(execution_state&, instr_argument arg);

using exec_fn_table = std::array<exec_fn, 256>;

struct instr_info
{
    exec_fn fn = nullptr;
    instr_argument arg;
    int block_index = -1;

    explicit constexpr instr_info(exec_fn fn) noexcept : fn{fn} {};
};

struct block_info
{
    int64_t gas_cost = 0;
    int stack_req = 0;
    int stack_max = 0;
    int stack_diff = 0;
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

code_analysis analyze(const exec_fn_table& fns, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone
