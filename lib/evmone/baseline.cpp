// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "vm.hpp"
#include <evmc/instructions.h>
#include <memory>

#if defined(__GNUC__)
#define ASM_COMMENT(COMMENT) asm("# " #COMMENT)  // NOLINT(hicpp-no-assembler)
#else
#define ASM_COMMENT(COMMENT)
#endif

namespace evmone::baseline
{
CodeAnalysis analyze(const uint8_t* code, size_t code_size)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    CodeAnalysis::JumpdestMap map(code_size);  // Allocate and init bitmap with zeros.
    size_t i = 0;
    while (i < code_size)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            map[i] = true;
        ++i;
    }

    // i is the needed code size including the last push data (can be bigger than code_size).
    // Using "raw" new operator instead of std::make_unique() to get uninitialized array.
    std::unique_ptr<uint8_t[]> padded_code{new uint8_t[i + 1]};  // +1 for the final STOP.
    std::copy_n(code, code_size, padded_code.get());
    padded_code[code_size] = OP_STOP;  // Used to terminate invalid jumps, see op_jump().
    padded_code[i] = OP_STOP;  // Set final STOP at the code end - guarantees loop termination.

    // TODO: Using fixed-size padding of 33, the padded code buffer and jumpdest bitmap can be
    //       created with single allocation.

    return CodeAnalysis{std::move(padded_code), std::move(map)};
}

namespace
{
/// Checks instruction requirements before execution.
///
/// This checks:
/// - if the instruction is defined
/// - if stack height requirements are fulfilled (stack overflow, stack underflow)
/// - charges the instruction base gas cost and checks is there is any gas left.
///
/// @tparam         Op          Instruction opcode.
/// @param          cost_table  Table of base gas costs.
/// @param [in,out] gas_left    Gas left.
/// @param          stack_size  Current stack height.
/// @return  Status code with information which check has failed
///          or EVMC_SUCCESS if everything is fine.
template <evmc_opcode Op>
inline evmc_status_code check_requirements(
    const CostTable& cost_table, int64_t& gas_left, int stack_size) noexcept
{
    static_assert(
        !(instr::has_const_gas_cost(Op) && instr::gas_costs[EVMC_FRONTIER][Op] == instr::undefined),
        "undefined instructions must not be handled by check_requirements()");

    auto gas_cost = instr::gas_costs[EVMC_FRONTIER][Op];  // Init assuming const cost.
    if constexpr (!instr::has_const_gas_cost(Op))
    {
        gas_cost = cost_table[Op];  // If not, load the cost from the table.

        // Negative cost marks an undefined instruction.
        // This check must be first to produce correct error code.
        if (INTX_UNLIKELY(gas_cost < 0))
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    // Check stack requirements first. This is order is not required,
    // but it is nicer because complete gas check may need to inspect operands.
    if constexpr (instr::traits[Op].stack_height_change > 0)
    {
        static_assert(instr::traits[Op].stack_height_change == 1);
        if (INTX_UNLIKELY(stack_size == Stack::limit))
            return EVMC_STACK_OVERFLOW;
    }
    if constexpr (instr::traits[Op].stack_height_required > 0)
    {
        if (INTX_UNLIKELY(stack_size < instr::traits[Op].stack_height_required))
            return EVMC_STACK_UNDERFLOW;
    }

    if (INTX_UNLIKELY((gas_left -= gas_cost) < 0))
        return EVMC_OUT_OF_GAS;

    return EVMC_SUCCESS;
}


/// Implementation of a generic instruction "case".
#define DISPATCH_CASE(OPCODE)                                               \
    case OPCODE:                                                            \
        ASM_COMMENT(OPCODE);                                                \
        if (code_it = invoke<OPCODE>(cost_table, state, code_it); !code_it) \
            goto exit;                                                      \
        break

/// Helpers for invoking instruction implementations of different signatures.
/// @{
[[gnu::always_inline]] inline code_iterator invoke(
    void (*instr_fn)(StackTop) noexcept, ExecutionState& state, code_iterator pos) noexcept
{
    instr_fn(state.stack.top_item);
    return pos + 1;
}

[[gnu::always_inline]] inline code_iterator invoke(
    StopToken (*instr_fn)() noexcept, ExecutionState& state, code_iterator /*pos*/) noexcept
{
    state.status = instr_fn().status;
    return nullptr;
}

[[gnu::always_inline]] inline code_iterator invoke(
    evmc_status_code (*instr_fn)(StackTop, ExecutionState&) noexcept, ExecutionState& state,
    code_iterator pos) noexcept
{
    if (const auto status = instr_fn(state.stack.top_item, state); status != EVMC_SUCCESS)
    {
        state.status = status;
        return nullptr;
    }
    return pos + 1;
}

[[gnu::always_inline]] inline code_iterator invoke(
    void (*instr_fn)(StackTop, ExecutionState&) noexcept, ExecutionState& state,
    code_iterator pos) noexcept
{
    instr_fn(state.stack.top_item, state);
    return pos + 1;
}

[[gnu::always_inline]] inline code_iterator invoke(
    code_iterator (*instr_fn)(StackTop, ExecutionState&, code_iterator) noexcept,
    ExecutionState& state, code_iterator pos) noexcept
{
    return instr_fn(state.stack.top_item, state, pos);
}

[[gnu::always_inline]] inline code_iterator invoke(
    StopToken (*instr_fn)(StackTop, ExecutionState&) noexcept, ExecutionState& state,
    code_iterator /*pos*/) noexcept
{
    state.status = instr_fn(state.stack.top_item, state).status;
    return nullptr;
}
/// @}

/// A helper to invoke the instruction implementation of the given opcode Op.
template <evmc_opcode Op>
[[gnu::always_inline]] inline code_iterator invoke(
    const CostTable& cost_table, ExecutionState& state, code_iterator pos) noexcept
{
    if (const auto status = check_requirements<Op>(cost_table, state.gas_left, state.stack.size());
        status != EVMC_SUCCESS)
    {
        state.status = status;
        return nullptr;
    }
    const auto new_pos = invoke(instr::core::impl<Op>, state, pos);
    state.stack.top_item += instr::traits[Op].stack_height_change;
    return new_pos;
}

template <bool TracingEnabled>
evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    state.analysis.baseline = &analysis;  // Assign code analysis for instruction implementations.

    // Use padded code.
    state.code = {analysis.padded_code.get(), state.code.size()};

    auto* tracer = vm.get_tracer();
    if constexpr (TracingEnabled)
        tracer->notify_execution_start(state.rev, *state.msg, state.code);

    const auto& cost_table = get_baseline_cost_table(state.rev);

    const auto* const code = state.code.data();
    auto code_it = code;  // Code iterator for the interpreter loop.
    while (true)          // Guaranteed to terminate because padded code ends with STOP.
    {
        if constexpr (TracingEnabled)
        {
            const auto offset = static_cast<uint32_t>(code_it - code);
            if (offset < state.code.size())  // Skip STOP from code padding.
                tracer->notify_instruction_start(offset, state);
        }

        const auto op = *code_it;
        switch (op)
        {
#define X(OPCODE, IGNORED) DISPATCH_CASE(OPCODE);
            MAP_OPCODE_TO_IDENTIFIER
#undef X
        default:
            state.status = EVMC_UNDEFINED_INSTRUCTION;
            goto exit;
        }
    }

exit:
    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;

    assert(state.output_size != 0 || state.output_offset == 0);
    const auto result = evmc::make_result(state.status, gas_left,
        state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);

    if constexpr (TracingEnabled)
        tracer->notify_execution_end(result);

    return result;
}
}  // namespace

evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    if (INTX_UNLIKELY(vm.get_tracer() != nullptr))
        return execute<true>(vm, state, analysis);

    return execute<false>(vm, state, analysis);
}

evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto vm = static_cast<VM*>(c_vm);
    const auto jumpdest_map = analyze(code, code_size);
    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return execute(*vm, *state, jumpdest_map);
}
}  // namespace evmone::baseline
