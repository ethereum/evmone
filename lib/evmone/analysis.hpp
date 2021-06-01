// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include "limits.hpp"
#include <evmc/evmc.hpp>
#include <evmc/instructions.h>
#include <evmc/utils.h>
#include <intx/intx.hpp>
#include <array>
#include <cstdint>
#include <vector>

namespace evmone
{
struct instruction;

/// Compressed information about instruction basic block.
struct block_info
{
    /// The total base gas cost of all instructions in the block.
    /// This cannot overflow, see the static_assert() below.
    uint32_t gas_cost = 0;

    static_assert(
        max_code_size * max_instruction_base_cost < std::numeric_limits<decltype(gas_cost)>::max(),
        "Potential block_info::gas_cost overflow");

    /// The stack height required to execute the block.
    /// This MAY overflow.
    int16_t stack_req = 0;

    /// The maximum stack height growth relative to the stack height at block start.
    /// This cannot overflow, see the static_assert() below.
    int16_t stack_max_growth = 0;

    static_assert(max_code_size * max_instruction_stack_increase <
                      std::numeric_limits<decltype(stack_max_growth)>::max(),
        "Potential block_info::stack_max_growth overflow");
};
static_assert(sizeof(block_info) == 8);

struct AdvancedCodeAnalysis;

/// The execution state specialized for the Advanced interpreter.
struct AdvancedExecutionState : ExecutionState
{
    /// The gas cost of the current block.
    ///
    /// This is only needed to correctly calculate the "current gas left" value.
    uint32_t current_block_cost = 0;

    /// Pointer to code analysis.
    const AdvancedCodeAnalysis* analysis = nullptr;

    using ExecutionState::ExecutionState;

    /// Terminates the execution with the given status code.
    const instruction* exit(evmc_status_code status_code) noexcept
    {
        status = status_code;
        return nullptr;
    }

    /// Resets the contents of the execution_state so that it could be reused.
    void reset(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        const uint8_t* code_ptr, size_t code_size) noexcept
    {
        ExecutionState::reset(message, revision, host_interface, host_ctx, code_ptr, code_size);
        current_block_cost = 0;
        analysis = nullptr;
    }
};

union instruction_argument
{
    int64_t number;
    const intx::uint256* push_value;
    uint64_t small_push_value;
    block_info block{};
};
static_assert(
    sizeof(instruction_argument) == sizeof(uint64_t), "Incorrect size of instruction_argument");

/// The pointer to function implementing an instruction execution.
using instruction_exec_fn = const instruction* (*)(const instruction*, AdvancedExecutionState&);

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

struct op_table_entry
{
    instruction_exec_fn fn;
    int16_t gas_cost;
    int8_t stack_req;
    int8_t stack_change;
};

using op_table = std::array<op_table_entry, 256>;

struct instruction
{
    instruction_exec_fn fn = nullptr;
    instruction_argument arg;

    explicit constexpr instruction(instruction_exec_fn f) noexcept : fn{f}, arg{} {}
};

struct AdvancedCodeAnalysis
{
    std::vector<instruction> instrs;

    /// Storage for large push values.
    std::vector<intx::uint256> push_values;

    /// The offsets of JUMPDESTs in the original code.
    /// These are values that JUMP/JUMPI receives as an argument.
    /// The elements are sorted.
    std::vector<int32_t> jumpdest_offsets;

    /// The indexes of the instructions in the generated instruction table
    /// matching the elements from jumdest_offsets.
    /// This is value to which the next instruction pointer must be set in JUMP/JUMPI.
    std::vector<int32_t> jumpdest_targets;
};

inline int find_jumpdest(const AdvancedCodeAnalysis& analysis, int offset) noexcept
{
    const auto begin = std::begin(analysis.jumpdest_offsets);
    const auto end = std::end(analysis.jumpdest_offsets);
    const auto it = std::lower_bound(begin, end, offset);
    return (it != end && *it == offset) ?
               analysis.jumpdest_targets[static_cast<size_t>(it - begin)] :
               -1;
}

EVMC_EXPORT AdvancedCodeAnalysis analyze(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept;

EVMC_EXPORT const op_table& get_op_table(evmc_revision rev) noexcept;

}  // namespace evmone
