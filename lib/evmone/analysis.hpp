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
    exec_fn fn = nullptr;
    int extra_data_index = -1;
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

struct extra_data
{
    uint8_t bytes[32];
};

struct code_analysis
{
    std::vector<instr_info> instrs;
    std::vector<block_info> blocks;
    std::vector<extra_data> extra;
    std::vector<std::pair<int, int>> jumpdest_map;

    int find_jumpdest(int offset) noexcept;
};

code_analysis analyze(const exec_fn_table& fns, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone
