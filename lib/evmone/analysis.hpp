// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.hpp>
#include <evmc/instructions.h>
#include <evmc/utils.h>
#include <intx/intx.hpp>
#include <array>
#include <cstdint>
#include <deque>
#include <vector>

namespace evmone
{
using uint256 = intx::uint256;

using bytes32 = std::array<uint8_t, 32>;

using bytes = std::basic_string<uint8_t>;

struct execution_state
{
    bool run = true;
    size_t pc = 0;
    int64_t gas_left = 0;
    evmc_status_code status = EVMC_SUCCESS;

    std::vector<uint256> stack;

    std::vector<uint8_t> memory;  // TODO: Use bytes.
    int64_t memory_prev_cost = 0;
    size_t output_offset = 0;
    size_t output_size = 0;

    /// The gas cost of the current block.
    ///
    /// This is only needed to correctly calculate remaining gas for GAS instruction.
    /// TODO: Maybe this should be precomputed in analysis.
    int64_t current_block_cost = 0;

    struct code_analysis* analysis = nullptr;
    bytes return_data;
    const evmc_message* msg = nullptr;
    const uint8_t* code = nullptr;
    size_t code_size = 0;

    evmc::HostContext host{nullptr};

    evmc_revision rev = {};

    uint256& item(size_t index) noexcept { return stack[stack.size() - index - 1]; }

    void exit(evmc_status_code status_code) noexcept
    {
        status = status_code;
        run = false;
    }
};

union instr_argument
{
    struct p  // A pair of fields.
    {
        int number;
        evmc_call_kind call_kind;
    } p;
    const uint8_t* data;
};

static_assert(sizeof(instr_argument) == sizeof(void*), "Incorrect size of instr_argument");

using exec_fn = void (*)(execution_state&, instr_argument arg);

/// The evmone intrinsic opcodes.
///
/// These intrinsic instructions may be injected to the code in the analysis phase.
/// They contain additional and required logic to be executed by the interpreter.
enum intrinsic_opcodes
{
    /// The BEGINBLOCK instruction.
    ///
    /// This instruction is defined as alias for JUMPDEST and replaces all JUMPDEST instructions.
    /// It is also injected at beginning of basic blocks not being the valid jump destination.
    /// It checks basic block execution requirements and terminates execution if they are not met.
    OPX_BEGINBLOCK = OP_JUMPDEST
};

using exec_fn_table = std::array<exec_fn, 256>;

struct instr_info
{
    exec_fn fn = nullptr;
    instr_argument arg;

    explicit constexpr instr_info(exec_fn f) noexcept : fn{f}, arg{} {};
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

    // TODO: Exported for unit tests. Rework unit tests?
    EVMC_EXPORT int find_jumpdest(int offset) const noexcept;
};

EVMC_EXPORT code_analysis analyze(
    const exec_fn_table& fns, evmc_revision rev, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone
