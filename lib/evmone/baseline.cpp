// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "instructions_implementations_table.hpp"
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
    padded_code[i] = OP_STOP;  // Set final STOP at the code end.

    // TODO: Using fixed-size padding of 33, the padded code buffer and jumpdest bitmap can be
    //       created with single allocation.

    return CodeAnalysis{std::move(padded_code), std::move(map)};
}

namespace
{
inline evmc_status_code check_requirements(
    const InstructionTable& instruction_table, ExecutionState& state, uint8_t op) noexcept
{
    const auto metrics = instruction_table[op];

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

/// Dispatch the instruction currently pointed by "pc".
#define DISPATCH() break  // Break out of switch statement.

#define INSTR_IMPL(OPCODE)                                                                  \
    case OPCODE:                                                                            \
        asm("# " #OPCODE);                                                                  \
        if (const auto r =                                                                  \
                instr::implementations[OPCODE](state, static_cast<size_t>(code_it - code)); \
            instr::traits[OPCODE].terminator || r.status != EVMC_SUCCESS)                   \
        {                                                                                   \
            state.status = r.status;                                                        \
            goto exit;                                                                      \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            code_it = code + r.pc;                                                          \
        }                                                                                   \
        DISPATCH();

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
        if (const auto status = check_requirements(instruction_table, state, op);
            status != EVMC_SUCCESS)
        {
            state.status = status;
            goto exit;
        }

        switch (op)
        {
            INSTR_IMPL(OP_STOP)
            INSTR_IMPL(OP_ADD)
            INSTR_IMPL(OP_MUL)
            INSTR_IMPL(OP_SUB)
            INSTR_IMPL(OP_DIV)
            INSTR_IMPL(OP_SDIV)
            INSTR_IMPL(OP_MOD)
            INSTR_IMPL(OP_SMOD)
            INSTR_IMPL(OP_ADDMOD)
            INSTR_IMPL(OP_MULMOD)
            INSTR_IMPL(OP_EXP)
            INSTR_IMPL(OP_SIGNEXTEND)

            INSTR_IMPL(OP_LT)
            INSTR_IMPL(OP_GT)
            INSTR_IMPL(OP_SLT)
            INSTR_IMPL(OP_SGT)
            INSTR_IMPL(OP_EQ)
            INSTR_IMPL(OP_ISZERO)
            INSTR_IMPL(OP_AND)
            INSTR_IMPL(OP_OR)
            INSTR_IMPL(OP_XOR)
            INSTR_IMPL(OP_NOT)
            INSTR_IMPL(OP_BYTE)
            INSTR_IMPL(OP_SHL)
            INSTR_IMPL(OP_SHR)
            INSTR_IMPL(OP_SAR)

            INSTR_IMPL(OP_KECCAK256)

            INSTR_IMPL(OP_ADDRESS)
            INSTR_IMPL(OP_BALANCE)
            INSTR_IMPL(OP_ORIGIN)
            INSTR_IMPL(OP_CALLER)
            INSTR_IMPL(OP_CALLVALUE)
            INSTR_IMPL(OP_CALLDATALOAD)
            INSTR_IMPL(OP_CALLDATASIZE)
            INSTR_IMPL(OP_CALLDATACOPY)
            INSTR_IMPL(OP_CODESIZE)
            INSTR_IMPL(OP_CODECOPY)
            INSTR_IMPL(OP_GASPRICE)
            INSTR_IMPL(OP_EXTCODESIZE)
            INSTR_IMPL(OP_EXTCODECOPY)
            INSTR_IMPL(OP_RETURNDATASIZE)
            INSTR_IMPL(OP_RETURNDATACOPY)
            INSTR_IMPL(OP_EXTCODEHASH)
            INSTR_IMPL(OP_BLOCKHASH)
            INSTR_IMPL(OP_COINBASE)
            INSTR_IMPL(OP_TIMESTAMP)
            INSTR_IMPL(OP_NUMBER)
            INSTR_IMPL(OP_DIFFICULTY)
            INSTR_IMPL(OP_GASLIMIT)
            INSTR_IMPL(OP_CHAINID)
            INSTR_IMPL(OP_SELFBALANCE)
            INSTR_IMPL(OP_BASEFEE)

            INSTR_IMPL(OP_POP)
            INSTR_IMPL(OP_MLOAD)
            INSTR_IMPL(OP_MSTORE)
            INSTR_IMPL(OP_MSTORE8)
            INSTR_IMPL(OP_SLOAD)
            INSTR_IMPL(OP_SSTORE)
            INSTR_IMPL(OP_JUMP)
            INSTR_IMPL(OP_JUMPI)
            INSTR_IMPL(OP_PC)
            INSTR_IMPL(OP_MSIZE)
            INSTR_IMPL(OP_GAS)
            INSTR_IMPL(OP_JUMPDEST)

            INSTR_IMPL(OP_PUSH1)
            INSTR_IMPL(OP_PUSH2)
            INSTR_IMPL(OP_PUSH3)
            INSTR_IMPL(OP_PUSH4)
            INSTR_IMPL(OP_PUSH5)
            INSTR_IMPL(OP_PUSH6)
            INSTR_IMPL(OP_PUSH7)
            INSTR_IMPL(OP_PUSH8)
            INSTR_IMPL(OP_PUSH9)
            INSTR_IMPL(OP_PUSH10)
            INSTR_IMPL(OP_PUSH11)
            INSTR_IMPL(OP_PUSH12)
            INSTR_IMPL(OP_PUSH13)
            INSTR_IMPL(OP_PUSH14)
            INSTR_IMPL(OP_PUSH15)
            INSTR_IMPL(OP_PUSH16)
            INSTR_IMPL(OP_PUSH17)
            INSTR_IMPL(OP_PUSH18)
            INSTR_IMPL(OP_PUSH19)
            INSTR_IMPL(OP_PUSH20)
            INSTR_IMPL(OP_PUSH21)
            INSTR_IMPL(OP_PUSH22)
            INSTR_IMPL(OP_PUSH23)
            INSTR_IMPL(OP_PUSH24)
            INSTR_IMPL(OP_PUSH25)
            INSTR_IMPL(OP_PUSH26)
            INSTR_IMPL(OP_PUSH27)
            INSTR_IMPL(OP_PUSH28)
            INSTR_IMPL(OP_PUSH29)
            INSTR_IMPL(OP_PUSH30)
            INSTR_IMPL(OP_PUSH31)
            INSTR_IMPL(OP_PUSH32)

            INSTR_IMPL(OP_DUP1)
            INSTR_IMPL(OP_DUP2)
            INSTR_IMPL(OP_DUP3)
            INSTR_IMPL(OP_DUP4)
            INSTR_IMPL(OP_DUP5)
            INSTR_IMPL(OP_DUP6)
            INSTR_IMPL(OP_DUP7)
            INSTR_IMPL(OP_DUP8)
            INSTR_IMPL(OP_DUP9)
            INSTR_IMPL(OP_DUP10)
            INSTR_IMPL(OP_DUP11)
            INSTR_IMPL(OP_DUP12)
            INSTR_IMPL(OP_DUP13)
            INSTR_IMPL(OP_DUP14)
            INSTR_IMPL(OP_DUP15)
            INSTR_IMPL(OP_DUP16)

            INSTR_IMPL(OP_SWAP1)
            INSTR_IMPL(OP_SWAP2)
            INSTR_IMPL(OP_SWAP3)
            INSTR_IMPL(OP_SWAP4)
            INSTR_IMPL(OP_SWAP5)
            INSTR_IMPL(OP_SWAP6)
            INSTR_IMPL(OP_SWAP7)
            INSTR_IMPL(OP_SWAP8)
            INSTR_IMPL(OP_SWAP9)
            INSTR_IMPL(OP_SWAP10)
            INSTR_IMPL(OP_SWAP11)
            INSTR_IMPL(OP_SWAP12)
            INSTR_IMPL(OP_SWAP13)
            INSTR_IMPL(OP_SWAP14)
            INSTR_IMPL(OP_SWAP15)
            INSTR_IMPL(OP_SWAP16)

            INSTR_IMPL(OP_LOG0)
            INSTR_IMPL(OP_LOG1)
            INSTR_IMPL(OP_LOG2)
            INSTR_IMPL(OP_LOG3)
            INSTR_IMPL(OP_LOG4)

            INSTR_IMPL(OP_CREATE)
            INSTR_IMPL(OP_CALL)
            INSTR_IMPL(OP_CALLCODE)
            INSTR_IMPL(OP_RETURN)
            INSTR_IMPL(OP_DELEGATECALL)
            INSTR_IMPL(OP_STATICCALL)
            INSTR_IMPL(OP_CREATE2)
            INSTR_IMPL(OP_REVERT)
            INSTR_IMPL(OP_INVALID)
            INSTR_IMPL(OP_SELFDESTRUCT)

        default:
            INTX_UNREACHABLE();
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
