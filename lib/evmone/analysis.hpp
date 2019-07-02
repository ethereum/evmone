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

/// The status code value indicating that the execution should continue.
/// The 0 value is used.
constexpr auto continue_status = EVMC_SUCCESS;
static_assert(continue_status == 0, "The 'continue' status is not 0");

/// The status code value indicating that the execution should be stopped.
/// The internal error (-1) is used. We could use any other negative value,
/// but using one of the constants defined by evmc_status_code avoids
/// warnings in Undefined Behavior Sanitizer.
/// The EVMC_INTERNAL_ERROR MUST NOT be used in evmone for any other case.
constexpr auto stop_status = EVMC_INTERNAL_ERROR;

/// The stack for 256-bit EVM words.
///
/// This implementation reserves memory inplace for all possible stack items (1024),
/// so this type is big. Make sure it is allocated on heap.
struct evm_stack
{
    /// The maximum number of stack items.
    static constexpr auto limit = 1024;

    /// The pointer to the top item, or below the stack bottom if stack is empty.
    uint256* top_item;

    /// The storage allocated for maximum possible number of items.
    /// This is also the pointer to the bottom item.
    ///
    /// OPT: The items are not 256-bit aligned, so access will cross a cache line.
    uint256 storage[limit];

    /// Default constructor. Sets the top_item pointer to below the stack bottom.
    [[clang::no_sanitize("bounds")]] evm_stack() noexcept : top_item{storage - 1} {}

    /// The current number of items on the stack.
    int size() noexcept { return static_cast<int>(top_item + 1 - storage); }

    /// Returns the reference to the top item.
    uint256& top() noexcept { return *top_item; }

    /// Returns the reference to the stack item on given position from the stack top.
    /// TODO: Rename to get(), at() or operator[].
    uint256& item(int index) noexcept { return *(top_item - index); }

    /// Pushes an item on the stack. The stack limit is not checked.
    void push(const uint256& item) noexcept { *++top_item = item; }

    /// Returns an item popped from the top of the stack.
    uint256 pop() noexcept { return *top_item--; }
};

struct execution_state
{
    evmc_status_code status = EVMC_SUCCESS;
    size_t pc = 0;
    int64_t gas_left = 0;

    evm_stack stack;

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

    uint256& item(int index) noexcept { return stack.item(index); }

    /// Terminates the execution with the given status code.
    void exit(evmc_status_code status_code) noexcept
    {
        // If the status_code matches the "continue" status, replace it with the "stop" status.
        // That will be revert after the execution loop terminates.
        if (status_code == continue_status)
            status_code = stop_status;
        status = status_code;
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
