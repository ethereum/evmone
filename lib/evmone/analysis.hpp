// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <array>
#include <cstdint>
#include <vector>

namespace evmone
{
using exec_fn = void (*)();

using exec_fn_table = std::array<exec_fn, 256>;

struct instr_info
{
    exec_fn fn;
    int extra_data_index;
};

struct block_info
{
    int64_t gas_cost;
    int stack_req;
    int stack_max;
    int stack_diff;
};

struct extra_data
{
    uint8_t bytes[32];
};

struct code_analysis
{
    std::vector<instr_info> instrs;
    std::vector<block_info> blocks;
    std::vector<extra_data> extra;
};

code_analysis analyze(const exec_fn_table& fns, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone
