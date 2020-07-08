// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include <evmc/instructions.h>
#include <memory>

namespace evmone
{
namespace
{
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

evmc_result baseline_execute(evmc_vm* /*vm*/, const evmc_host_interface* host,
    evmc_host_context* ctx, evmc_revision rev, const evmc_message* msg, const uint8_t* code,
    size_t code_size) noexcept
{
    const auto instruction_names = evmc_get_instruction_names_table(rev);
    const auto instruction_metrics = evmc_get_instruction_metrics_table(rev);

    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);

    const auto code_end = code + code_size;
    auto* pc = code;
    while (pc != code_end)
    {
        const auto op = *pc;

        const auto status = check_requirements(instruction_names, instruction_metrics, *state, op);
        if (status != EVMC_SUCCESS)
        {
            state->status = status;
            goto exit;
        }

        switch (op)
        {
        case OP_STOP:
            goto exit;
        case OP_ADD:
            add(state->stack);
            break;
        case OP_MUL:
            mul(state->stack);
            break;
        case OP_SUB:
            sub(state->stack);
            break;
        case OP_DIV:
            div(state->stack);
            break;
        case OP_SDIV:
            sdiv(state->stack);
            break;
        case OP_MOD:
            mod(state->stack);
            break;
        case OP_SMOD:
            smod(state->stack);
            break;
        case OP_ADDMOD:
            addmod(state->stack);
            break;
        case OP_MULMOD:
            mulmod(state->stack);
            break;
        case OP_SIGNEXTEND:
            signextend(state->stack);
            break;

        case OP_LT:
            lt(state->stack);
            break;
        case OP_GT:
            gt(state->stack);
            break;
        case OP_SLT:
            slt(state->stack);
            break;
        case OP_SGT:
            sgt(state->stack);
            break;
        case OP_EQ:
            eq(state->stack);
            break;
        case OP_ISZERO:
            iszero(state->stack);
            break;
        case OP_AND:
            and_(state->stack);
            break;
        case OP_OR:
            or_(state->stack);
            break;
        case OP_XOR:
            xor_(state->stack);
            break;
        case OP_NOT:
            not_(state->stack);
            break;
        case OP_BYTE:
            byte(state->stack);
            break;
        case OP_SHL:
            shl(state->stack);
            break;
        case OP_SHR:
            shr(state->stack);
            break;
        case OP_SAR:
            sar(state->stack);
            break;

        case OP_MLOAD:
        {
            const auto status_code = mload(*state);
            if (status_code != EVMC_SUCCESS)
            {
                state->status = status_code;
                goto exit;
            }
            break;
        }
        case OP_MSTORE:
        {
            const auto status_code = mstore(*state);
            if (status_code != EVMC_SUCCESS)
            {
                state->status = status_code;
                goto exit;
            }
            break;
        }
        case OP_MSTORE8:
        {
            const auto status_code = mstore8(*state);
            if (status_code != EVMC_SUCCESS)
            {
                state->status = status_code;
                goto exit;
            }
            break;
        }
        }

        ++pc;
    }

exit:
    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(state->status, gas_left,
        state->output_size != 0 ? &state->memory[state->output_offset] : nullptr,
        state->output_size);
}
}  // namespace evmone
