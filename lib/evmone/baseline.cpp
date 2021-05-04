// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
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
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            map[i] = true;
    }
    return CodeAnalysis{std::move(map)};
}

namespace
{
const uint8_t* op_jump(
    ExecutionState& state, const CodeAnalysis::JumpdestMap& jumpdest_map) noexcept
{
    const auto dst = state.stack.pop();
    if (dst >= jumpdest_map.size() || !jumpdest_map[static_cast<size_t>(dst)])
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return &state.code[0] + state.code.size();
    }

    return &state.code[static_cast<size_t>(dst)];
}

template <size_t Len>
inline const uint8_t* load_push(
    ExecutionState& state, const uint8_t* code, const uint8_t* code_end) noexcept
{
    // TODO: Also last full push can be ignored.
    if (code + Len > code_end)  // Trimmed push data can be ignored.
        return code_end;

    uint8_t buffer[Len];
    std::memcpy(buffer, code, Len);
    state.stack.push(intx::be::load<intx::uint256>(buffer));
    return code + Len;
}

template <evmc_status_code StatusCode>
inline void op_return(ExecutionState& state) noexcept
{
    const auto offset = state.stack[0];
    const auto size = state.stack[1];

    if (!check_memory(state, offset, size))
    {
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    state.output_offset = static_cast<size_t>(offset);  // Can be garbage if size is 0.
    state.output_size = static_cast<size_t>(size);
    state.status = StatusCode;
}

inline evmc_status_code check_requirements(const char* const* instruction_names,
    const evmc_instruction_metrics* instruction_metrics, ExecutionState& state, uint8_t op) noexcept
{
    const auto metrics = instruction_metrics[op];

    if (instruction_names[op] == nullptr)
        return EVMC_UNDEFINED_INSTRUCTION;

    if ((state.gas_left -= metrics.gas_cost) < 0)
        return EVMC_OUT_OF_GAS;

    const auto stack_size = state.stack.size();
    if (stack_size < metrics.stack_height_required)
        return EVMC_STACK_UNDERFLOW;
    if (stack_size + metrics.stack_height_change > evm_stack::limit)
        return EVMC_STACK_OVERFLOW;

    return EVMC_SUCCESS;
}
}  // namespace

evmc_result execute(evmc_vm* /*vm*/, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    const auto jumpdest_map = analyze(code, code_size);
    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return execute(*state, jumpdest_map);
}

evmc_result execute(ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    const auto rev = state.rev;
    const auto code = state.code.data();
    const auto code_size = state.code.size();

    const auto instruction_names = evmc_get_instruction_names_table(rev);
    const auto instruction_metrics = evmc_get_instruction_metrics_table(rev);

    const auto code_end = code + code_size;
    auto* pc = code;
    while (pc != code_end)
    {
        const auto op = *pc;

        const auto status = check_requirements(instruction_names, instruction_metrics, state, op);
        if (status != EVMC_SUCCESS)
        {
            state.status = status;
            goto exit;
        }

        switch (op)
        {
        case OP_STOP:
            goto exit;
        case OP_ADD:
            add(state.stack);
            break;
        case OP_MUL:
            mul(state.stack);
            break;
        case OP_SUB:
            sub(state.stack);
            break;
        case OP_DIV:
            div(state.stack);
            break;
        case OP_SDIV:
            sdiv(state.stack);
            break;
        case OP_MOD:
            mod(state.stack);
            break;
        case OP_SMOD:
            smod(state.stack);
            break;
        case OP_ADDMOD:
            addmod(state.stack);
            break;
        case OP_MULMOD:
            mulmod(state.stack);
            break;
        case OP_EXP:
        {
            const auto status_code = exp(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_SIGNEXTEND:
            signextend(state.stack);
            break;

        case OP_LT:
            lt(state.stack);
            break;
        case OP_GT:
            gt(state.stack);
            break;
        case OP_SLT:
            slt(state.stack);
            break;
        case OP_SGT:
            sgt(state.stack);
            break;
        case OP_EQ:
            eq(state.stack);
            break;
        case OP_ISZERO:
            iszero(state.stack);
            break;
        case OP_AND:
            and_(state.stack);
            break;
        case OP_OR:
            or_(state.stack);
            break;
        case OP_XOR:
            xor_(state.stack);
            break;
        case OP_NOT:
            not_(state.stack);
            break;
        case OP_BYTE:
            byte(state.stack);
            break;
        case OP_SHL:
            shl(state.stack);
            break;
        case OP_SHR:
            shr(state.stack);
            break;
        case OP_SAR:
            sar(state.stack);
            break;

        case OP_KECCAK256:
        {
            const auto status_code = keccak256(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }

        case OP_ADDRESS:
            address(state);
            break;
        case OP_BALANCE:
        {
            const auto status_code = balance(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_ORIGIN:
            origin(state);
            break;
        case OP_CALLER:
            caller(state);
            break;
        case OP_CALLVALUE:
            callvalue(state);
            break;
        case OP_CALLDATALOAD:
            calldataload(state);
            break;
        case OP_CALLDATASIZE:
            calldatasize(state);
            break;
        case OP_CALLDATACOPY:
        {
            const auto status_code = calldatacopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_CODESIZE:
            state.stack.push(code_size);
            break;
        case OP_CODECOPY:
        {
            const auto status_code = codecopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_GASPRICE:
            gasprice(state);
            break;
        case OP_EXTCODESIZE:
        {
            const auto status_code = extcodesize(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_EXTCODECOPY:
        {
            const auto status_code = extcodecopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_RETURNDATASIZE:
            returndatasize(state);
            break;
        case OP_RETURNDATACOPY:
        {
            const auto status_code = returndatacopy(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_EXTCODEHASH:
        {
            const auto status_code = extcodehash(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_BLOCKHASH:
            blockhash(state);
            break;
        case OP_COINBASE:
            coinbase(state);
            break;
        case OP_TIMESTAMP:
            timestamp(state);
            break;
        case OP_NUMBER:
            number(state);
            break;
        case OP_DIFFICULTY:
            difficulty(state);
            break;
        case OP_GASLIMIT:
            gaslimit(state);
            break;
        case OP_CHAINID:
            chainid(state);
            break;
        case OP_SELFBALANCE:
            selfbalance(state);
            break;

        case OP_POP:
            pop(state.stack);
            break;
        case OP_MLOAD:
        {
            const auto status_code = mload(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_MSTORE:
        {
            const auto status_code = mstore(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_MSTORE8:
        {
            const auto status_code = mstore8(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }

        case OP_JUMP:
            pc = op_jump(state, analysis.jumpdest_map);
            continue;
        case OP_JUMPI:
            if (state.stack[1] != 0)
            {
                pc = op_jump(state, analysis.jumpdest_map);
            }
            else
            {
                state.stack.pop();
                ++pc;
            }
            state.stack.pop();
            continue;

        case OP_PC:
            state.stack.push(pc - code);
            break;
        case OP_MSIZE:
            msize(state);
            break;
        case OP_SLOAD:
        {
            const auto status_code = sload(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_SSTORE:
        {
            const auto status_code = sstore(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_GAS:
            state.stack.push(state.gas_left);
            break;
        case OP_JUMPDEST:
            break;

        case OP_PUSH1:
            pc = load_push<1>(state, pc + 1, code_end);
            continue;
        case OP_PUSH2:
            pc = load_push<2>(state, pc + 1, code_end);
            continue;
        case OP_PUSH3:
            pc = load_push<3>(state, pc + 1, code_end);
            continue;
        case OP_PUSH4:
            pc = load_push<4>(state, pc + 1, code_end);
            continue;
        case OP_PUSH5:
            pc = load_push<5>(state, pc + 1, code_end);
            continue;
        case OP_PUSH6:
            pc = load_push<6>(state, pc + 1, code_end);
            continue;
        case OP_PUSH7:
            pc = load_push<7>(state, pc + 1, code_end);
            continue;
        case OP_PUSH8:
            pc = load_push<8>(state, pc + 1, code_end);
            continue;
        case OP_PUSH9:
            pc = load_push<9>(state, pc + 1, code_end);
            continue;
        case OP_PUSH10:
            pc = load_push<10>(state, pc + 1, code_end);
            continue;
        case OP_PUSH11:
            pc = load_push<11>(state, pc + 1, code_end);
            continue;
        case OP_PUSH12:
            pc = load_push<12>(state, pc + 1, code_end);
            continue;
        case OP_PUSH13:
            pc = load_push<13>(state, pc + 1, code_end);
            continue;
        case OP_PUSH14:
            pc = load_push<14>(state, pc + 1, code_end);
            continue;
        case OP_PUSH15:
            pc = load_push<15>(state, pc + 1, code_end);
            continue;
        case OP_PUSH16:
            pc = load_push<16>(state, pc + 1, code_end);
            continue;
        case OP_PUSH17:
            pc = load_push<17>(state, pc + 1, code_end);
            continue;
        case OP_PUSH18:
            pc = load_push<18>(state, pc + 1, code_end);
            continue;
        case OP_PUSH19:
            pc = load_push<19>(state, pc + 1, code_end);
            continue;
        case OP_PUSH20:
            pc = load_push<20>(state, pc + 1, code_end);
            continue;
        case OP_PUSH21:
            pc = load_push<21>(state, pc + 1, code_end);
            continue;
        case OP_PUSH22:
            pc = load_push<22>(state, pc + 1, code_end);
            continue;
        case OP_PUSH23:
            pc = load_push<23>(state, pc + 1, code_end);
            continue;
        case OP_PUSH24:
            pc = load_push<24>(state, pc + 1, code_end);
            continue;
        case OP_PUSH25:
            pc = load_push<25>(state, pc + 1, code_end);
            continue;
        case OP_PUSH26:
            pc = load_push<26>(state, pc + 1, code_end);
            continue;
        case OP_PUSH27:
            pc = load_push<27>(state, pc + 1, code_end);
            continue;
        case OP_PUSH28:
            pc = load_push<28>(state, pc + 1, code_end);
            continue;
        case OP_PUSH29:
            pc = load_push<29>(state, pc + 1, code_end);
            continue;
        case OP_PUSH30:
            pc = load_push<30>(state, pc + 1, code_end);
            continue;
        case OP_PUSH31:
            pc = load_push<31>(state, pc + 1, code_end);
            continue;
        case OP_PUSH32:
            pc = load_push<32>(state, pc + 1, code_end);
            continue;

        case OP_DUP1:
            dup<1>(state.stack);
            break;
        case OP_DUP2:
            dup<2>(state.stack);
            break;
        case OP_DUP3:
            dup<3>(state.stack);
            break;
        case OP_DUP4:
            dup<4>(state.stack);
            break;
        case OP_DUP5:
            dup<5>(state.stack);
            break;
        case OP_DUP6:
            dup<6>(state.stack);
            break;
        case OP_DUP7:
            dup<7>(state.stack);
            break;
        case OP_DUP8:
            dup<8>(state.stack);
            break;
        case OP_DUP9:
            dup<9>(state.stack);
            break;
        case OP_DUP10:
            dup<10>(state.stack);
            break;
        case OP_DUP11:
            dup<11>(state.stack);
            break;
        case OP_DUP12:
            dup<12>(state.stack);
            break;
        case OP_DUP13:
            dup<13>(state.stack);
            break;
        case OP_DUP14:
            dup<14>(state.stack);
            break;
        case OP_DUP15:
            dup<15>(state.stack);
            break;
        case OP_DUP16:
            dup<16>(state.stack);
            break;

        case OP_SWAP1:
            swap<1>(state.stack);
            break;
        case OP_SWAP2:
            swap<2>(state.stack);
            break;
        case OP_SWAP3:
            swap<3>(state.stack);
            break;
        case OP_SWAP4:
            swap<4>(state.stack);
            break;
        case OP_SWAP5:
            swap<5>(state.stack);
            break;
        case OP_SWAP6:
            swap<6>(state.stack);
            break;
        case OP_SWAP7:
            swap<7>(state.stack);
            break;
        case OP_SWAP8:
            swap<8>(state.stack);
            break;
        case OP_SWAP9:
            swap<9>(state.stack);
            break;
        case OP_SWAP10:
            swap<10>(state.stack);
            break;
        case OP_SWAP11:
            swap<11>(state.stack);
            break;
        case OP_SWAP12:
            swap<12>(state.stack);
            break;
        case OP_SWAP13:
            swap<13>(state.stack);
            break;
        case OP_SWAP14:
            swap<14>(state.stack);
            break;
        case OP_SWAP15:
            swap<15>(state.stack);
            break;
        case OP_SWAP16:
            swap<16>(state.stack);
            break;

        case OP_LOG0:
        {
            const auto status_code = log(state, 0);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_LOG1:
        {
            const auto status_code = log(state, 1);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_LOG2:
        {
            const auto status_code = log(state, 2);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_LOG3:
        {
            const auto status_code = log(state, 3);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_LOG4:
        {
            const auto status_code = log(state, 4);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }

        case OP_CREATE:
        {
            const auto status_code = create<EVMC_CREATE>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_CALL:
        {
            const auto status_code = call<EVMC_CALL>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_CALLCODE:
        {
            const auto status_code = call<EVMC_CALLCODE>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_RETURN:
            op_return<EVMC_SUCCESS>(state);
            goto exit;
        case OP_DELEGATECALL:
        {
            const auto status_code = call<EVMC_DELEGATECALL>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_STATICCALL:
        {
            const auto status_code = call<EVMC_CALL, true>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_CREATE2:
        {
            const auto status_code = create<EVMC_CREATE2>(state);
            if (status_code != EVMC_SUCCESS)
            {
                state.status = status_code;
                goto exit;
            }
            break;
        }
        case OP_REVERT:
            op_return<EVMC_REVERT>(state);
            goto exit;
        case OP_INVALID:
            state.status = EVMC_INVALID_INSTRUCTION;
            goto exit;
        case OP_SELFDESTRUCT:
            state.status = selfdestruct(state);
            goto exit;
        default:
            INTX_UNREACHABLE();
        }

        ++pc;
    }

exit:
    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;

    return evmc::make_result(state.status, gas_left,
        state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);
}
}  // namespace evmone::baseline
