// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "eof.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "vm.hpp"
#include <evmc/instructions.h>
#include <memory>

#ifdef NDEBUG
#define release_inline gnu::always_inline, msvc::forceinline
#else
#define release_inline
#endif

#if defined(__GNUC__)
#define ASM_COMMENT(COMMENT) asm("# " #COMMENT)  // NOLINT(hicpp-no-assembler)
#else
#define ASM_COMMENT(COMMENT)
#endif

namespace evmone::baseline
{
namespace
{
CodeAnalysis::JumpdestMap analyze_jumpdests(bytes_view code)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    CodeAnalysis::JumpdestMap map(code.size());  // Allocate and init bitmap with zeros.
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            map[i] = true;
    }

    return map;
}

std::unique_ptr<uint8_t[]> pad_code(bytes_view code)
{
    // We need at most 33 bytes of code padding: 32 for possible missing all data bytes of PUSH32
    // at the very end of the code; and one more byte for STOP to guarantee there is a terminating
    // instruction at the code end.
    constexpr auto padding = 32 + 1;

    // Using "raw" new operator instead of std::make_unique() to get uninitialized array.
    std::unique_ptr<uint8_t[]> padded_code{new uint8_t[code.size() + padding]};
    std::copy(std::begin(code), std::end(code), padded_code.get());
    std::fill_n(&padded_code[code.size()], padding, uint8_t{OP_STOP});
    return padded_code;
}


CodeAnalysis analyze_legacy(bytes_view code)
{
    // TODO: The padded code buffer and jumpdest bitmap can be created with single allocation.
    return {pad_code(code), analyze_jumpdests(code)};
}

CodeAnalysis analyze_eof1(bytes_view eof_container, const EOF1Header& header)
{
    const auto executable_code = eof_container.substr(header.code_begin(), header.code_size);
    return {executable_code.data(), analyze_jumpdests(executable_code)};
}
}  // namespace

CodeAnalysis analyze(evmc_revision rev, bytes_view code)
{
    if (rev < EVMC_SHANGHAI || !is_eof_code(code))
        return analyze_legacy(code);

    const auto eof1_header = read_valid_eof1_header(code.begin());
    return analyze_eof1(code, eof1_header);
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
/// @tparam         Op            Instruction opcode.
/// @param          cost_table    Table of base gas costs.
/// @param [in,out] gas_left      Gas left.
/// @param          stack_top     Pointer to the stack top item.
/// @param          stack_bottom  Pointer to the stack bottom.
///                               The stack height is stack_top - stack_bottom.
/// @return  Status code with information which check has failed
///          or EVMC_SUCCESS if everything is fine.
template <evmc_opcode Op>
inline evmc_status_code check_requirements(const CostTable& cost_table, int64_t& gas_left,
    const uint256* stack_top, const uint256* stack_bottom) noexcept
{
    static_assert(
        !instr::has_const_gas_cost(Op) || instr::gas_costs[EVMC_FRONTIER][Op] != instr::undefined,
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
        static_assert(instr::traits[Op].stack_height_change == 1,
            "unexpected instruction with multiple results");
        if (INTX_UNLIKELY(stack_top == stack_bottom + StackSpace::limit))
            return EVMC_STACK_OVERFLOW;
    }
    if constexpr (instr::traits[Op].stack_height_required > 0)
    {
        // Check stack underflow using pointer comparison <= (better optimization).
        static constexpr auto min_offset = instr::traits[Op].stack_height_required - 1;
        if (INTX_UNLIKELY(stack_top <= stack_bottom + min_offset))
            return EVMC_STACK_UNDERFLOW;
    }

    if (INTX_UNLIKELY((gas_left -= gas_cost) < 0))
        return EVMC_OUT_OF_GAS;

    return EVMC_SUCCESS;
}


/// The execution position.
struct Position
{
    code_iterator code_it;  ///< The position in the code.
    uint256* stack_top;     ///< The pointer to the stack top.
};

/// Helpers for invoking instruction implementations of different signatures.
/// @{
[[release_inline]] inline code_iterator invoke(
    void (*instr_fn)(StackTop) noexcept, Position pos, ExecutionState& /*state*/) noexcept
{
    instr_fn(pos.stack_top);
    return pos.code_it + 1;
}

[[release_inline]] inline code_iterator invoke(
    StopToken (*instr_fn)() noexcept, Position /*pos*/, ExecutionState& state) noexcept
{
    state.status = instr_fn().status;
    return nullptr;
}

[[release_inline]] inline code_iterator invoke(
    evmc_status_code (*instr_fn)(StackTop, ExecutionState&) noexcept, Position pos,
    ExecutionState& state) noexcept
{
    if (const auto status = instr_fn(pos.stack_top, state); status != EVMC_SUCCESS)
    {
        state.status = status;
        return nullptr;
    }
    return pos.code_it + 1;
}

[[release_inline]] inline code_iterator invoke(void (*instr_fn)(StackTop, ExecutionState&) noexcept,
    Position pos, ExecutionState& state) noexcept
{
    instr_fn(pos.stack_top, state);
    return pos.code_it + 1;
}

[[release_inline]] inline code_iterator invoke(
    code_iterator (*instr_fn)(StackTop, ExecutionState&, code_iterator) noexcept, Position pos,
    ExecutionState& state) noexcept
{
    return instr_fn(pos.stack_top, state, pos.code_it);
}

[[release_inline]] inline code_iterator invoke(
    StopToken (*instr_fn)(StackTop, ExecutionState&) noexcept, Position pos,
    ExecutionState& state) noexcept
{
    state.status = instr_fn(pos.stack_top, state).status;
    return nullptr;
}
/// @}

/// A helper to invoke the instruction implementation of the given opcode Op.
template <evmc_opcode Op>
[[release_inline]] inline Position invoke(const CostTable& cost_table, const uint256* stack_bottom,
    Position pos, ExecutionState& state) noexcept
{
    if (const auto status =
            check_requirements<Op>(cost_table, state.gas_left, pos.stack_top, stack_bottom);
        status != EVMC_SUCCESS)
    {
        state.status = status;
        return {nullptr, pos.stack_top};
    }
    const auto new_pos = invoke(instr::core::impl<Op>, pos, state);
    const auto new_stack_top = pos.stack_top + instr::traits[Op].stack_height_change;
    return {new_pos, new_stack_top};
}


template <bool TracingEnabled>
void dispatch(const CostTable& cost_table, ExecutionState& state, const uint8_t* code,
    Tracer* tracer = nullptr) noexcept
{
    const auto stack_bottom = state.stack_space.bottom();

    // Code iterator and stack top pointer for interpreter loop.
    Position position{code, stack_bottom};

    while (true)  // Guaranteed to terminate because padded code ends with STOP.
    {
        if constexpr (TracingEnabled)
        {
            const auto offset = static_cast<uint32_t>(position.code_it - code);
            const auto stack_height = static_cast<int>(position.stack_top - stack_bottom);
            if (offset < state.original_code.size())  // Skip STOP from code padding.
                tracer->notify_instruction_start(offset, position.stack_top, stack_height, state);
        }

        const auto op = *position.code_it;
        switch (op)
        {
#define ON_OPCODE(OPCODE)                                                                \
    case OPCODE:                                                                         \
        ASM_COMMENT(OPCODE);                                                             \
        if (const auto next = invoke<OPCODE>(cost_table, stack_bottom, position, state); \
            next.code_it == nullptr)                                                     \
        {                                                                                \
            return;                                                                      \
        }                                                                                \
        else                                                                             \
        {                                                                                \
            /* Update current position only when no error,                               \
               this improves compiler optimization. */                                   \
            position = next;                                                             \
        }                                                                                \
        break;

            MAP_OPCODES
#undef ON_OPCODE

        default:
            state.status = EVMC_UNDEFINED_INSTRUCTION;
            return;
        }
    }
}

#if EVMONE_CGOTO_SUPPORTED
void dispatch_cgoto(
    const CostTable& cost_table, ExecutionState& state, const uint8_t* code) noexcept
{
#pragma GCC diagnostic ignored "-Wpedantic"

    static constexpr void* cgoto_table[] = {
#define ON_OPCODE(OPCODE) &&TARGET_##OPCODE,
#undef ON_OPCODE_UNDEFINED
#define ON_OPCODE_UNDEFINED(_) &&TARGET_OP_UNDEFINED,
        MAP_OPCODES
#undef ON_OPCODE
#undef ON_OPCODE_UNDEFINED
#define ON_OPCODE_UNDEFINED ON_OPCODE_UNDEFINED_DEFAULT
    };
    static_assert(std::size(cgoto_table) == 256);

    const auto stack_bottom = state.stack_space.bottom();

    // Code iterator and stack top pointer for interpreter loop.
    Position position{code, stack_bottom};

    goto* cgoto_table[*position.code_it];

#define ON_OPCODE(OPCODE)                                                            \
    TARGET_##OPCODE : ASM_COMMENT(OPCODE);                                           \
    if (const auto next = invoke<OPCODE>(cost_table, stack_bottom, position, state); \
        next.code_it == nullptr)                                                     \
    {                                                                                \
        return;                                                                      \
    }                                                                                \
    else                                                                             \
    {                                                                                \
        /* Update current position only when no error,                               \
           this improves compiler optimization. */                                   \
        position = next;                                                             \
    }                                                                                \
    goto* cgoto_table[*position.code_it];

    MAP_OPCODES
#undef ON_OPCODE

TARGET_OP_UNDEFINED:
    state.status = EVMC_UNDEFINED_INSTRUCTION;
}
#endif
}  // namespace

evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    state.analysis.baseline = &analysis;  // Assign code analysis for instruction implementations.

    const auto code = analysis.executable_code;

    const auto& cost_table = get_baseline_cost_table(state.rev);

    auto* tracer = vm.get_tracer();
    if (INTX_UNLIKELY(tracer != nullptr))
    {
        tracer->notify_execution_start(state.rev, *state.msg, code);
        dispatch<true>(cost_table, state, code, tracer);
    }
    else
    {
#if EVMONE_CGOTO_SUPPORTED
        if (vm.cgoto)
            dispatch_cgoto(cost_table, state, code);
        else
#endif
            dispatch<false>(cost_table, state, code);
    }

    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;
    const auto gas_refund = (state.status == EVMC_SUCCESS) ? state.gas_refund : 0;

    assert(state.output_size != 0 || state.output_offset == 0);
    const auto result = evmc::make_result(state.status, gas_left, gas_refund,
        state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);

    if (INTX_UNLIKELY(tracer != nullptr))
        tracer->notify_execution_end(result);

    return result;
}

evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto vm = static_cast<VM*>(c_vm);
    const auto jumpdest_map = analyze(rev, {code, code_size});
    auto state =
        std::make_unique<ExecutionState>(*msg, rev, *host, ctx, bytes_view{code, code_size});
    return execute(*vm, *state, jumpdest_map);
}
}  // namespace evmone::baseline
