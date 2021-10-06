// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "instructions_impl_map.hpp"
#include "vm.hpp"
#include <evmc/instructions.h>
#include <memory>

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
template <evmc_opcode Op>
inline evmc_status_code check_requirements(
    const InstructionTable& instruction_table, ExecutionState& state) noexcept
{
    const auto metrics = instruction_table[Op];

    if (INTX_UNLIKELY(metrics.gas_cost == instr::undefined))
        return EVMC_UNDEFINED_INSTRUCTION;

    if (INTX_UNLIKELY((state.gas_left -= metrics.gas_cost) < 0))
        return EVMC_OUT_OF_GAS;

    const auto stack_size = state.stack.size();
    if (INTX_UNLIKELY(stack_size == Stack::limit))
    {
        if (metrics.can_overflow_stack)
            return EVMC_STACK_OVERFLOW;
    }
    else if (INTX_UNLIKELY(stack_size < metrics.stack_height_required))
        return EVMC_STACK_UNDERFLOW;

    return EVMC_SUCCESS;
}


/// Implementation of a generic instruction "case".
#define DISPATCH_CASE(OPCODE)                                                      \
    case OPCODE:                                                                   \
        if (code_it = invoke<OPCODE>(instruction_table, state, code_it); !code_it) \
            goto exit;                                                             \
        break

/// The signature of basic instructions which always succeed, e.g. ADD.
using SucceedingInstrFn = void(ExecutionState&) noexcept;
static_assert(std::is_same_v<decltype(add), SucceedingInstrFn>);

/// The signature of basic instructions which may fail.
using MayFailInstrFn = evmc_status_code(ExecutionState&) noexcept;
static_assert(std::is_same_v<decltype(exp), MayFailInstrFn>);

/// The signature of terminating instructions.
using TerminatingInstrFn = StopToken(ExecutionState&) noexcept;
static_assert(std::is_same_v<decltype(stop), TerminatingInstrFn>);

/// The signature of instructions requiring access to current code position.
using CodePositionInstrFn = code_iterator(ExecutionState&, code_iterator) noexcept;
static_assert(std::is_same_v<decltype(push<1>), CodePositionInstrFn>);
static_assert(std::is_same_v<decltype(pc), CodePositionInstrFn>);
static_assert(std::is_same_v<decltype(jump), CodePositionInstrFn>);

/// A helper to invoke instruction implementations of different signatures
/// done by template specialization.
template <typename InstrFn>
code_iterator invoke(InstrFn instr_fn, ExecutionState& state, code_iterator pos) noexcept = delete;

template <>
[[gnu::always_inline]] inline code_iterator invoke<SucceedingInstrFn*>(
    SucceedingInstrFn* instr_fn, ExecutionState& state, code_iterator pos) noexcept
{
    instr_fn(state);
    return pos + 1;
}

template <>
[[gnu::always_inline]] inline code_iterator invoke<MayFailInstrFn*>(
    MayFailInstrFn* instr_fn, ExecutionState& state, code_iterator pos) noexcept
{
    if (const auto status = instr_fn(state); status != EVMC_SUCCESS)
    {
        state.status = status;
        return nullptr;
    }
    return pos + 1;
}

template <>
[[gnu::always_inline]] inline code_iterator invoke<TerminatingInstrFn*>(
    TerminatingInstrFn* instr_fn, ExecutionState& state, code_iterator /*pos*/) noexcept
{
    state.status = instr_fn(state).status;
    return nullptr;
}

template <>
[[gnu::always_inline]] inline code_iterator invoke<CodePositionInstrFn*>(
    CodePositionInstrFn* instr_fn, ExecutionState& state, code_iterator pos) noexcept
{
    return instr_fn(state, pos);
}

/// A helper to invoke the instruction implementation of the given opcode Op.
template <evmc_opcode Op>
[[gnu::always_inline]] inline code_iterator invoke(
    const InstructionTable& instruction_table, ExecutionState& state, code_iterator pos) noexcept
{
    if (const auto status = check_requirements<Op>(instruction_table, state);
        status != EVMC_SUCCESS)
    {
        state.status = status;
        return nullptr;
    }
    return invoke(instr::impl<Op>, state, pos);
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

    const auto& instruction_table = get_baseline_instruction_table(state.rev);

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
            DISPATCH_CASE(OP_STOP);
            DISPATCH_CASE(OP_ADD);
            DISPATCH_CASE(OP_MUL);
            DISPATCH_CASE(OP_SUB);
            DISPATCH_CASE(OP_DIV);
            DISPATCH_CASE(OP_SDIV);
            DISPATCH_CASE(OP_MOD);
            DISPATCH_CASE(OP_SMOD);
            DISPATCH_CASE(OP_ADDMOD);
            DISPATCH_CASE(OP_MULMOD);
            DISPATCH_CASE(OP_EXP);
            DISPATCH_CASE(OP_SIGNEXTEND);

            DISPATCH_CASE(OP_LT);
            DISPATCH_CASE(OP_GT);
            DISPATCH_CASE(OP_SLT);
            DISPATCH_CASE(OP_SGT);
            DISPATCH_CASE(OP_EQ);
            DISPATCH_CASE(OP_ISZERO);
            DISPATCH_CASE(OP_AND);
            DISPATCH_CASE(OP_OR);
            DISPATCH_CASE(OP_XOR);
            DISPATCH_CASE(OP_NOT);
            DISPATCH_CASE(OP_BYTE);
            DISPATCH_CASE(OP_SHL);
            DISPATCH_CASE(OP_SHR);
            DISPATCH_CASE(OP_SAR);

            DISPATCH_CASE(OP_KECCAK256);

            DISPATCH_CASE(OP_ADDRESS);
            DISPATCH_CASE(OP_BALANCE);
            DISPATCH_CASE(OP_ORIGIN);
            DISPATCH_CASE(OP_CALLER);
            DISPATCH_CASE(OP_CALLVALUE);
            DISPATCH_CASE(OP_CALLDATALOAD);
            DISPATCH_CASE(OP_CALLDATASIZE);
            DISPATCH_CASE(OP_CALLDATACOPY);
            DISPATCH_CASE(OP_CODESIZE);
            DISPATCH_CASE(OP_CODECOPY);
            DISPATCH_CASE(OP_GASPRICE);
            DISPATCH_CASE(OP_EXTCODESIZE);
            DISPATCH_CASE(OP_EXTCODECOPY);
            DISPATCH_CASE(OP_RETURNDATASIZE);
            DISPATCH_CASE(OP_RETURNDATACOPY);
            DISPATCH_CASE(OP_EXTCODEHASH);
            DISPATCH_CASE(OP_BLOCKHASH);
            DISPATCH_CASE(OP_COINBASE);
            DISPATCH_CASE(OP_TIMESTAMP);
            DISPATCH_CASE(OP_NUMBER);
            DISPATCH_CASE(OP_DIFFICULTY);
            DISPATCH_CASE(OP_GASLIMIT);
            DISPATCH_CASE(OP_CHAINID);
            DISPATCH_CASE(OP_SELFBALANCE);
            DISPATCH_CASE(OP_BASEFEE);

            DISPATCH_CASE(OP_POP);
            DISPATCH_CASE(OP_MLOAD);
            DISPATCH_CASE(OP_MSTORE);
            DISPATCH_CASE(OP_MSTORE8);
            DISPATCH_CASE(OP_SLOAD);
            DISPATCH_CASE(OP_SSTORE);
            DISPATCH_CASE(OP_JUMP);
            DISPATCH_CASE(OP_JUMPI);
            DISPATCH_CASE(OP_PC);
            DISPATCH_CASE(OP_MSIZE);
            DISPATCH_CASE(OP_GAS);
            DISPATCH_CASE(OP_JUMPDEST);

            DISPATCH_CASE(OP_PUSH1);
            DISPATCH_CASE(OP_PUSH2);
            DISPATCH_CASE(OP_PUSH3);
            DISPATCH_CASE(OP_PUSH4);
            DISPATCH_CASE(OP_PUSH5);
            DISPATCH_CASE(OP_PUSH6);
            DISPATCH_CASE(OP_PUSH7);
            DISPATCH_CASE(OP_PUSH8);
            DISPATCH_CASE(OP_PUSH9);
            DISPATCH_CASE(OP_PUSH10);
            DISPATCH_CASE(OP_PUSH11);
            DISPATCH_CASE(OP_PUSH12);
            DISPATCH_CASE(OP_PUSH13);
            DISPATCH_CASE(OP_PUSH14);
            DISPATCH_CASE(OP_PUSH15);
            DISPATCH_CASE(OP_PUSH16);
            DISPATCH_CASE(OP_PUSH17);
            DISPATCH_CASE(OP_PUSH18);
            DISPATCH_CASE(OP_PUSH19);
            DISPATCH_CASE(OP_PUSH20);
            DISPATCH_CASE(OP_PUSH21);
            DISPATCH_CASE(OP_PUSH22);
            DISPATCH_CASE(OP_PUSH23);
            DISPATCH_CASE(OP_PUSH24);
            DISPATCH_CASE(OP_PUSH25);
            DISPATCH_CASE(OP_PUSH26);
            DISPATCH_CASE(OP_PUSH27);
            DISPATCH_CASE(OP_PUSH28);
            DISPATCH_CASE(OP_PUSH29);
            DISPATCH_CASE(OP_PUSH30);
            DISPATCH_CASE(OP_PUSH31);
            DISPATCH_CASE(OP_PUSH32);

            DISPATCH_CASE(OP_DUP1);
            DISPATCH_CASE(OP_DUP2);
            DISPATCH_CASE(OP_DUP3);
            DISPATCH_CASE(OP_DUP4);
            DISPATCH_CASE(OP_DUP5);
            DISPATCH_CASE(OP_DUP6);
            DISPATCH_CASE(OP_DUP7);
            DISPATCH_CASE(OP_DUP8);
            DISPATCH_CASE(OP_DUP9);
            DISPATCH_CASE(OP_DUP10);
            DISPATCH_CASE(OP_DUP11);
            DISPATCH_CASE(OP_DUP12);
            DISPATCH_CASE(OP_DUP13);
            DISPATCH_CASE(OP_DUP14);
            DISPATCH_CASE(OP_DUP15);
            DISPATCH_CASE(OP_DUP16);

            DISPATCH_CASE(OP_SWAP1);
            DISPATCH_CASE(OP_SWAP2);
            DISPATCH_CASE(OP_SWAP3);
            DISPATCH_CASE(OP_SWAP4);
            DISPATCH_CASE(OP_SWAP5);
            DISPATCH_CASE(OP_SWAP6);
            DISPATCH_CASE(OP_SWAP7);
            DISPATCH_CASE(OP_SWAP8);
            DISPATCH_CASE(OP_SWAP9);
            DISPATCH_CASE(OP_SWAP10);
            DISPATCH_CASE(OP_SWAP11);
            DISPATCH_CASE(OP_SWAP12);
            DISPATCH_CASE(OP_SWAP13);
            DISPATCH_CASE(OP_SWAP14);
            DISPATCH_CASE(OP_SWAP15);
            DISPATCH_CASE(OP_SWAP16);

            DISPATCH_CASE(OP_LOG0);
            DISPATCH_CASE(OP_LOG1);
            DISPATCH_CASE(OP_LOG2);
            DISPATCH_CASE(OP_LOG3);
            DISPATCH_CASE(OP_LOG4);

            DISPATCH_CASE(OP_CREATE);
            DISPATCH_CASE(OP_CALL);
            DISPATCH_CASE(OP_CALLCODE);
            DISPATCH_CASE(OP_RETURN);
            DISPATCH_CASE(OP_DELEGATECALL);
            DISPATCH_CASE(OP_STATICCALL);
            DISPATCH_CASE(OP_CREATE2);
            DISPATCH_CASE(OP_REVERT);
            DISPATCH_CASE(OP_INVALID);
            DISPATCH_CASE(OP_SELFDESTRUCT);

        default:
            state.status = EVMC_UNDEFINED_INSTRUCTION;
            goto exit;
        }
    }

exit:
    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;

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
