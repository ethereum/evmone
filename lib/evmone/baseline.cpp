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

namespace evmone::baseline
{
namespace
{
CodeAnalysis analyze_jumpdests(
    const uint8_t* code, size_t code_begin, size_t code_end, evmc_opcode final_opcode)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    CodeAnalysis::JumpdestMap map(code_end);  // Allocate and init bitmap with zeros.
    size_t i = code_begin;
    while (i < code_end)
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
    std::unique_ptr<uint8_t[]> padded_code{new uint8_t[i + 1]};  // +1 for the final STOP/INVALID.
    std::copy_n(code, code_end, padded_code.get());
    // Set final STOP/INVALID at the code end.
    padded_code[i] = static_cast<uint8_t>(final_opcode);

    // TODO: Using fixed-size padding of 33, the padded code buffer and jumpdest bitmap can be
    //       created with single allocation.

    return CodeAnalysis{std::move(padded_code), std::move(map), code_begin, code_end, {}};
}


CodeAnalysis analyze_legacy(const uint8_t* code, size_t code_size)
{
    return analyze_jumpdests(code, 0, code_size, OP_STOP);
}

CodeAnalysis analyze_eof1(const uint8_t* code, const EOF1Header& header)
{
    return analyze_jumpdests(code, header.code_begin(), header.code_end(), OP_INVALID);
}

CodeAnalysis analyze_eof2(const uint8_t* code, size_t /*code_size*/, const EOF2Header& header)
{
    constexpr auto code_padding = 33;

    const auto code_begin = header.code_begin();
    const auto code_end = header.code_end();

    // Using "raw" new operator instead of std::make_unique() to get uninitialized array.
    std::unique_ptr<uint8_t[]> padded_code{new uint8_t[code_end + code_padding]};
    std::copy_n(code, code_end, padded_code.get());
    // Set final STOP/INVALID at the code end.
    std::fill_n(padded_code.get() + code_end, code_padding, uint8_t{OP_INVALID});

    // Read tables
    CodeAnalysis::TableList tables;
    tables.reserve(header.table_sizes.size());

    const auto* table_section = code + header.tables_begin();
    for (const auto table_size : header.table_sizes)
    {
        std::vector<int16_t> table;
        table.reserve(static_cast<size_t>(table_size));
        const auto* table_section_end = table_section + table_size;
        while (table_section != table_section_end)
        {
            const auto offset_hi = *(table_section);
            const auto offset_lo = *(table_section + 1);
            const int16_t offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
            table.push_back(offset);

            table_section += 2;
        }
        tables.emplace_back(std::move(table));
    }

    return CodeAnalysis{std::move(padded_code), {}, code_begin, code_end, std::move(tables)};
}
}  // namespace

CodeAnalysis analyze(evmc_revision rev, const uint8_t* code, size_t code_size)
{
    if (rev < EVMC_SHANGHAI || !is_eof_code(code, code_size))
        return analyze_legacy(code, code_size);

    const auto version = read_eof_version(code);
    if (version == 1)
    {
        const auto eof1_header = read_valid_eof1_header(code);
        return analyze_eof1(code, eof1_header);
    }

    assert(version == 2);
    const auto eof2_header = read_valid_eof2_header(code);
    return analyze_eof2(code, code_size, eof2_header);
}

namespace
{
const uint8_t* rjump(const uint8_t* pc) noexcept
{
    // Reading next 2 bytes is guaranteed to be safe by deploy-time validation.
    const auto offset_hi = *(pc + 1);
    const auto offset_lo = *(pc + 2);
    const auto offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
    return pc + 3 + offset;  // PC_post_rjump + offset
}

const uint8_t* rjumptable(ExecutionState& state, const uint8_t* pc) noexcept
{
    const auto& tables = state.analysis.baseline->tables;

    // Reading next 2 bytes is guaranteed to be safe by deploy-time validation.
    const auto table_index_hi = *(pc + 1);
    const auto table_index_lo = *(pc + 2);
    const auto table_index = static_cast<uint16_t>((table_index_hi << 8) + table_index_lo);

    // table_index is guaranteed to be within tables bounds by deploy-time validation.

    const auto index = state.stack.pop();
    if (index >= tables[table_index].size())
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;  // TODO new error code
        return pc;                                 // This value is ignored.
    }

    return pc + 3 + tables[table_index][static_cast<size_t>(index)];  // PC_post_rjumptable + offset
}

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

/// Increment "pc" and dispatch the instruction.
#define DISPATCH_NEXT() \
    ++code_it;          \
    DISPATCH()

template <bool TracingEnabled>
evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    state.analysis.baseline = &analysis;  // Assign code analysis for instruction implementations.

    // Use padded code.
    state.code = {analysis.padded_code.get(), state.code.size()};

    auto* tracer = vm.get_tracer();
    if constexpr (TracingEnabled)
        tracer->notify_execution_start(state.rev, *state.msg, state.code);

    const auto& instruction_table = analysis.code_begin == 0 ?
                                        get_baseline_legacy_instruction_table(state.rev) :
                                        get_baseline_instruction_table(state.rev);

    const auto* const code = state.code.data();
    const auto* code_it = code + analysis.code_begin;  // Code iterator for the interpreter loop.
    while (true)  // Guaranteed to terminate because padded code ends with STOP or INVALID
    {
        if constexpr (TracingEnabled)
        {
            const auto offset = static_cast<uint32_t>(code_it - code);
            if (offset < analysis.code_end)  // Skip STOP/INVALID in code padding.
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
        case OP_STOP:
            state.status = stop(state);
            goto exit;
        case OP_ADD:
            add(state);
            DISPATCH_NEXT();
        case OP_MUL:
            mul(state);
            DISPATCH_NEXT();
        case OP_SUB:
            sub(state);
            DISPATCH_NEXT();
        case OP_DIV:
            div(state);
            DISPATCH_NEXT();
        case OP_SDIV:
            sdiv(state);
            DISPATCH_NEXT();
        case OP_MOD:
            mod(state);
            DISPATCH_NEXT();
        case OP_SMOD:
            smod(state);
            DISPATCH_NEXT();
        case OP_ADDMOD:
            addmod(state);
            DISPATCH_NEXT();
        case OP_MULMOD:
            mulmod(state);
            DISPATCH_NEXT();
        case OP_EXP:
        {
            const auto status_code = exp(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_SIGNEXTEND:
            signextend(state);
            DISPATCH_NEXT();

        case OP_LT:
            lt(state);
            DISPATCH_NEXT();
        case OP_GT:
            gt(state);
            DISPATCH_NEXT();
        case OP_SLT:
            slt(state);
            DISPATCH_NEXT();
        case OP_SGT:
            sgt(state);
            DISPATCH_NEXT();
        case OP_EQ:
            eq(state);
            DISPATCH_NEXT();
        case OP_ISZERO:
            iszero(state);
            DISPATCH_NEXT();
        case OP_AND:
            and_(state);
            DISPATCH_NEXT();
        case OP_OR:
            or_(state);
            DISPATCH_NEXT();
        case OP_XOR:
            xor_(state);
            DISPATCH_NEXT();
        case OP_NOT:
            not_(state);
            DISPATCH_NEXT();
        case OP_BYTE:
            byte(state);
            DISPATCH_NEXT();
        case OP_SHL:
            shl(state);
            DISPATCH_NEXT();
        case OP_SHR:
            shr(state);
            DISPATCH_NEXT();
        case OP_SAR:
            sar(state);
            DISPATCH_NEXT();

        case OP_KECCAK256:
        {
            const auto status_code = keccak256(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }

        case OP_ADDRESS:
            address(state);
            DISPATCH_NEXT();
        case OP_BALANCE:
        {
            const auto status_code = balance(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_ORIGIN:
            origin(state);
            DISPATCH_NEXT();
        case OP_CALLER:
            caller(state);
            DISPATCH_NEXT();
        case OP_CALLVALUE:
            callvalue(state);
            DISPATCH_NEXT();
        case OP_CALLDATALOAD:
            calldataload(state);
            DISPATCH_NEXT();
        case OP_CALLDATASIZE:
            calldatasize(state);
            DISPATCH_NEXT();
        case OP_CALLDATACOPY:
        {
            const auto status_code = calldatacopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_CODESIZE:
            codesize(state);
            DISPATCH_NEXT();
        case OP_CODECOPY:
        {
            const auto status_code = codecopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_GASPRICE:
            gasprice(state);
            DISPATCH_NEXT();
        case OP_EXTCODESIZE:
        {
            const auto status_code = extcodesize(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_EXTCODECOPY:
        {
            const auto status_code = extcodecopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_RETURNDATASIZE:
            returndatasize(state);
            DISPATCH_NEXT();
        case OP_RETURNDATACOPY:
        {
            const auto status_code = returndatacopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_EXTCODEHASH:
        {
            const auto status_code = extcodehash(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_BLOCKHASH:
            blockhash(state);
            DISPATCH_NEXT();
        case OP_COINBASE:
            coinbase(state);
            DISPATCH_NEXT();
        case OP_TIMESTAMP:
            timestamp(state);
            DISPATCH_NEXT();
        case OP_NUMBER:
            number(state);
            DISPATCH_NEXT();
        case OP_DIFFICULTY:
            difficulty(state);
            DISPATCH_NEXT();
        case OP_GASLIMIT:
            gaslimit(state);
            DISPATCH_NEXT();
        case OP_CHAINID:
            chainid(state);
            DISPATCH_NEXT();
        case OP_SELFBALANCE:
            selfbalance(state);
            DISPATCH_NEXT();
        case OP_BASEFEE:
            basefee(state);
            DISPATCH_NEXT();

        case OP_POP:
            pop(state);
            DISPATCH_NEXT();
        case OP_MLOAD:
        {
            const auto status_code = mload(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_MSTORE:
        {
            const auto status_code = mstore(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_MSTORE8:
        {
            const auto status_code = mstore8(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }

        case OP_JUMP:
        {
            const auto r = jump(state, static_cast<size_t>(code_it - code));
            if (r.status != EVMC_SUCCESS)
            {
                state.status = r.status;
                goto exit;
            }
            code_it = code + r.pc;
            DISPATCH();
        }

        case OP_JUMPI:
        {
            const auto r = jumpi(state, static_cast<size_t>(code_it - code));
            if (r.status != EVMC_SUCCESS)
            {
                state.status = r.status;
                goto exit;
            }
            code_it = code + r.pc;
            DISPATCH();
        }

        case OP_PC:
            code_it = code + pc(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();

        case OP_MSIZE:
            msize(state);
            DISPATCH_NEXT();
        case OP_SLOAD:
        {
            const auto status_code = sload(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_SSTORE:
        {
            const auto status_code = sstore(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_GAS:
            gas(state);
            DISPATCH_NEXT();
        case OP_JUMPDEST:
            jumpdest(state);
            DISPATCH_NEXT();
        case OP_RJUMP:
            code_it = rjump(code_it);
            DISPATCH();
        case OP_RJUMPI:
            if (state.stack.pop() != 0)
                code_it = rjump(code_it);
            else
            {
                // skip immediate argument
                code_it += 3;
            }
            DISPATCH();
        case OP_RJUMPTABLE:
            code_it = rjumptable(state, code_it);
            if (state.status == EVMC_BAD_JUMP_DESTINATION)
                goto exit;
            DISPATCH();

        case OP_PUSH1:
            code_it = code + push<1>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH2:
            code_it = code + push<2>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH3:
            code_it = code + push<3>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH4:
            code_it = code + push<4>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH5:
            code_it = code + push<5>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH6:
            code_it = code + push<6>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH7:
            code_it = code + push<7>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH8:
            code_it = code + push<8>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH9:
            code_it = code + push<9>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH10:
            code_it = code + push<10>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH11:
            code_it = code + push<11>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH12:
            code_it = code + push<12>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH13:
            code_it = code + push<13>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH14:
            code_it = code + push<14>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH15:
            code_it = code + push<15>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH16:
            code_it = code + push<16>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH17:
            code_it = code + push<17>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH18:
            code_it = code + push<18>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH19:
            code_it = code + push<19>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH20:
            code_it = code + push<20>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH21:
            code_it = code + push<21>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH22:
            code_it = code + push<22>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH23:
            code_it = code + push<23>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH24:
            code_it = code + push<24>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH25:
            code_it = code + push<25>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH26:
            code_it = code + push<26>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH27:
            code_it = code + push<27>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH28:
            code_it = code + push<28>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH29:
            code_it = code + push<29>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH30:
            code_it = code + push<30>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH31:
            code_it = code + push<31>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();
        case OP_PUSH32:
            code_it = code + push<32>(state, static_cast<size_t>(code_it - code)).pc;
            DISPATCH();

        case OP_DUP1:
            dup<1>(state);
            DISPATCH_NEXT();
        case OP_DUP2:
            dup<2>(state);
            DISPATCH_NEXT();
        case OP_DUP3:
            dup<3>(state);
            DISPATCH_NEXT();
        case OP_DUP4:
            dup<4>(state);
            DISPATCH_NEXT();
        case OP_DUP5:
            dup<5>(state);
            DISPATCH_NEXT();
        case OP_DUP6:
            dup<6>(state);
            DISPATCH_NEXT();
        case OP_DUP7:
            dup<7>(state);
            DISPATCH_NEXT();
        case OP_DUP8:
            dup<8>(state);
            DISPATCH_NEXT();
        case OP_DUP9:
            dup<9>(state);
            DISPATCH_NEXT();
        case OP_DUP10:
            dup<10>(state);
            DISPATCH_NEXT();
        case OP_DUP11:
            dup<11>(state);
            DISPATCH_NEXT();
        case OP_DUP12:
            dup<12>(state);
            DISPATCH_NEXT();
        case OP_DUP13:
            dup<13>(state);
            DISPATCH_NEXT();
        case OP_DUP14:
            dup<14>(state);
            DISPATCH_NEXT();
        case OP_DUP15:
            dup<15>(state);
            DISPATCH_NEXT();
        case OP_DUP16:
            dup<16>(state);
            DISPATCH_NEXT();

        case OP_SWAP1:
            swap<1>(state);
            DISPATCH_NEXT();
        case OP_SWAP2:
            swap<2>(state);
            DISPATCH_NEXT();
        case OP_SWAP3:
            swap<3>(state);
            DISPATCH_NEXT();
        case OP_SWAP4:
            swap<4>(state);
            DISPATCH_NEXT();
        case OP_SWAP5:
            swap<5>(state);
            DISPATCH_NEXT();
        case OP_SWAP6:
            swap<6>(state);
            DISPATCH_NEXT();
        case OP_SWAP7:
            swap<7>(state);
            DISPATCH_NEXT();
        case OP_SWAP8:
            swap<8>(state);
            DISPATCH_NEXT();
        case OP_SWAP9:
            swap<9>(state);
            DISPATCH_NEXT();
        case OP_SWAP10:
            swap<10>(state);
            DISPATCH_NEXT();
        case OP_SWAP11:
            swap<11>(state);
            DISPATCH_NEXT();
        case OP_SWAP12:
            swap<12>(state);
            DISPATCH_NEXT();
        case OP_SWAP13:
            swap<13>(state);
            DISPATCH_NEXT();
        case OP_SWAP14:
            swap<14>(state);
            DISPATCH_NEXT();
        case OP_SWAP15:
            swap<15>(state);
            DISPATCH_NEXT();
        case OP_SWAP16:
            swap<16>(state);
            DISPATCH_NEXT();

        case OP_LOG0:
        {
            const auto status_code = log<0>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_LOG1:
        {
            const auto status_code = log<1>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_LOG2:
        {
            const auto status_code = log<2>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_LOG3:
        {
            const auto status_code = log<3>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_LOG4:
        {
            const auto status_code = log<4>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }

        case OP_CREATE:
        {
            const auto status_code = create<EVMC_CREATE>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_CALL:
        {
            const auto status_code = call<EVMC_CALL>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_CALLCODE:
        {
            const auto status_code = call<EVMC_CALLCODE>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_RETURN:
            state.status = return_<EVMC_SUCCESS>(state);
            goto exit;
        case OP_DELEGATECALL:
        {
            const auto status_code = call<EVMC_DELEGATECALL>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_STATICCALL:
        {
            const auto status_code = call<EVMC_CALL, true>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_CREATE2:
        {
            const auto status_code = create<EVMC_CREATE2>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            DISPATCH_NEXT();
        }
        case OP_REVERT:
            state.status = return_<EVMC_REVERT>(state);
            goto exit;
        case OP_INVALID:
            state.status = invalid(state);
            goto exit;
        case OP_SELFDESTRUCT:
            state.status = selfdestruct(state);
            goto exit;
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
    const auto jumpdest_map = analyze(rev, code, code_size);
    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return execute(*vm, *state, jumpdest_map);
}
}  // namespace evmone::baseline
