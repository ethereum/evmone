// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "caterpillar.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "vm.hpp"
#include <evmc/instructions.h>
#include <iostream>
#include <memory>

namespace evmone::caterpillar
{
namespace
{
template <evmc_opcode Op>
evmc_status_code cat_instr(ExecutionState& state, size_t pc) noexcept;


template <>
evmc_status_code cat_instr<OP_STOP>(ExecutionState&, size_t) noexcept
{
    return EVMC_SUCCESS;
}

template <>
evmc_status_code cat_instr<OP_RETURN>(ExecutionState& state, size_t) noexcept
{
    return_<EVMC_SUCCESS>(state);
    return EVMC_SUCCESS;
}

using InstrFn = decltype(&cat_instr<OP_STOP>);

constexpr evmc_opcode OP_UNDEFINED = static_cast<evmc_opcode>(0xEF);

constexpr auto instr_table = []() noexcept {
    std::array<InstrFn, 256> table{cat_instr<OP_STOP>, cat_instr<OP_ADD>, cat_instr<OP_MUL>,
        cat_instr<OP_SUB>, cat_instr<OP_DIV>, cat_instr<OP_SDIV>, cat_instr<OP_MOD>,
        cat_instr<OP_SMOD>, cat_instr<OP_ADDMOD>, cat_instr<OP_MULMOD>, cat_instr<OP_EXP>,
        cat_instr<OP_SIGNEXTEND>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_LT>, cat_instr<OP_GT>,
        cat_instr<OP_SLT>, cat_instr<OP_SGT>, cat_instr<OP_EQ>, cat_instr<OP_ISZERO>,
        cat_instr<OP_AND>, cat_instr<OP_OR>, cat_instr<OP_XOR>, cat_instr<OP_NOT>,
        cat_instr<OP_BYTE>, cat_instr<OP_SHL>, cat_instr<OP_SHR>, cat_instr<OP_SAR>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_KECCAK256>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_ADDRESS>, cat_instr<OP_BALANCE>, cat_instr<OP_ORIGIN>, cat_instr<OP_CALLER>,
        cat_instr<OP_CALLVALUE>, cat_instr<OP_CALLDATALOAD>, cat_instr<OP_CALLDATASIZE>,
        cat_instr<OP_CALLDATACOPY>, cat_instr<OP_CODESIZE>, cat_instr<OP_CODECOPY>,
        cat_instr<OP_GASPRICE>, cat_instr<OP_EXTCODESIZE>, cat_instr<OP_EXTCODECOPY>,
        cat_instr<OP_RETURNDATASIZE>, cat_instr<OP_RETURNDATACOPY>, cat_instr<OP_EXTCODEHASH>,
        cat_instr<OP_BLOCKHASH>, cat_instr<OP_COINBASE>, cat_instr<OP_TIMESTAMP>,
        cat_instr<OP_NUMBER>, cat_instr<OP_DIFFICULTY>, cat_instr<OP_GASLIMIT>,
        cat_instr<OP_CHAINID>, cat_instr<OP_SELFBALANCE>, cat_instr<OP_BASEFEE>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_POP>, cat_instr<OP_MLOAD>, cat_instr<OP_MSTORE>,
        cat_instr<OP_MSTORE8>, cat_instr<OP_SLOAD>, cat_instr<OP_SSTORE>, cat_instr<OP_JUMP>,
        cat_instr<OP_JUMPI>, cat_instr<OP_PC>, cat_instr<OP_MSIZE>, cat_instr<OP_GAS>,
        cat_instr<OP_JUMPDEST>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_PUSH1>, cat_instr<OP_PUSH2>,
        cat_instr<OP_PUSH3>, cat_instr<OP_PUSH4>, cat_instr<OP_PUSH5>, cat_instr<OP_PUSH6>,
        cat_instr<OP_PUSH7>, cat_instr<OP_PUSH8>, cat_instr<OP_PUSH9>, cat_instr<OP_PUSH10>,
        cat_instr<OP_PUSH11>, cat_instr<OP_PUSH12>, cat_instr<OP_PUSH13>, cat_instr<OP_PUSH14>,
        cat_instr<OP_PUSH15>, cat_instr<OP_PUSH16>, cat_instr<OP_PUSH17>, cat_instr<OP_PUSH18>,
        cat_instr<OP_PUSH19>, cat_instr<OP_PUSH20>, cat_instr<OP_PUSH21>, cat_instr<OP_PUSH22>,
        cat_instr<OP_PUSH23>, cat_instr<OP_PUSH24>, cat_instr<OP_PUSH25>, cat_instr<OP_PUSH26>,
        cat_instr<OP_PUSH27>, cat_instr<OP_PUSH28>, cat_instr<OP_PUSH29>, cat_instr<OP_PUSH30>,
        cat_instr<OP_PUSH31>, cat_instr<OP_PUSH32>, cat_instr<OP_DUP1>, cat_instr<OP_DUP2>,
        cat_instr<OP_DUP3>, cat_instr<OP_DUP4>, cat_instr<OP_DUP5>, cat_instr<OP_DUP6>,
        cat_instr<OP_DUP7>, cat_instr<OP_DUP8>, cat_instr<OP_DUP9>, cat_instr<OP_DUP10>,
        cat_instr<OP_DUP11>, cat_instr<OP_DUP12>, cat_instr<OP_DUP13>, cat_instr<OP_DUP14>,
        cat_instr<OP_DUP15>, cat_instr<OP_DUP16>, cat_instr<OP_SWAP1>, cat_instr<OP_SWAP2>,
        cat_instr<OP_SWAP3>, cat_instr<OP_SWAP4>, cat_instr<OP_SWAP5>, cat_instr<OP_SWAP6>,
        cat_instr<OP_SWAP7>, cat_instr<OP_SWAP8>, cat_instr<OP_SWAP9>, cat_instr<OP_SWAP10>,
        cat_instr<OP_SWAP11>, cat_instr<OP_SWAP12>, cat_instr<OP_SWAP13>, cat_instr<OP_SWAP14>,
        cat_instr<OP_SWAP15>, cat_instr<OP_SWAP16>, cat_instr<OP_LOG0>, cat_instr<OP_LOG1>,
        cat_instr<OP_LOG2>, cat_instr<OP_LOG3>, cat_instr<OP_LOG4>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_CREATE>, cat_instr<OP_CALL>,
        cat_instr<OP_CALLCODE>, cat_instr<OP_RETURN>, cat_instr<OP_DELEGATECALL>,
        cat_instr<OP_CREATE2>, cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_STATICCALL>,
        cat_instr<OP_UNDEFINED>, cat_instr<OP_UNDEFINED>, cat_instr<OP_REVERT>,
        cat_instr<OP_INVALID>, cat_instr<OP_SELFDESTRUCT>};
    return table;
}();

template <size_t Len>
void load_push(ExecutionState& state, const uint8_t* code) noexcept
{
    uint8_t buffer[Len];
    // This valid because code is padded with garbage to satisfy push data read pass the code end.
    std::memcpy(buffer, code, Len);
    state.stack.push(intx::be::load<intx::uint256>(buffer));
}

template <evmc_opcode Op>
evmc_status_code cat_instr(ExecutionState& state, size_t pc) noexcept
{
    // constexpr auto name = instr::traits[Op].name;
    // if constexpr (name != nullptr)
    //     std::cerr << name << std::endl;
    // else
    //     std::cerr << Op << std::endl;

    static constexpr auto tr = instr::traits[Op];

    if constexpr (const auto since = instr::is_defined_since(Op); since != EVMC_FRONTIER)
    {
        if (INTX_UNLIKELY(state.rev < since))
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    if constexpr (tr.stack_height_required > 0)
    {
        if (INTX_UNLIKELY(state.stack.size() < tr.stack_height_required))
            return EVMC_STACK_UNDERFLOW;
    }

    if constexpr (tr.stack_height_change > 0)
    {
        if (INTX_UNLIKELY(state.stack.size() == Stack::limit))
            return EVMC_STACK_OVERFLOW;
    }

    if constexpr (instr::has_const_gas_cost(Op))
    {
        if (INTX_UNLIKELY((state.gas_left -= instr::gas_costs[EVMC_FRONTIER][Op]) < 0))
            return EVMC_OUT_OF_GAS;
    }
    else
    {
        if (INTX_UNLIKELY((state.gas_left -= instr::gas_costs[state.rev][Op]) < 0))
            return EVMC_OUT_OF_GAS;
    }



    if constexpr (Op >= OP_PUSH1 && Op <= OP_PUSH32)
    {
        load_push<Op - OP_PUSH1 + 1>(state, state.code.data() + pc + 1);
        pc += Op - OP_PUSH1 + 1;
    }
    else if constexpr (Op == OP_JUMPI)
    {
        if (state.stack[1] != 0)
            pc = static_cast<size_t>(state.stack.pop()) - 1;
        else
            state.stack.pop();
        state.stack.pop();
    }
    else if constexpr (Op == OP_JUMP)
    {
        pc = static_cast<size_t>(state.stack.pop()) - 1;
    }
    else if constexpr (impls[Op] != nullptr)
    {
        const auto status = impls[Op](state);
        if (status != EVMC_SUCCESS)
            return status;
    }
    else if constexpr (Op == OP_JUMPDEST)
    {}
    else
        return EVMC_UNDEFINED_INSTRUCTION;

    ++pc;
    [[clang::musttail]] return instr_table[state.code[pc]](state, pc);
}

}  // namespace

evmc_result execute(
    const VM& /*vm*/, ExecutionState& state, const baseline::CodeAnalysis& analysis) noexcept
{
    const auto* code = analysis.padded_code.get();

    const auto first_fn = instr_table[*code];
    const auto status = first_fn(state, 0);

    const auto gas_left = (status == EVMC_SUCCESS || status == EVMC_REVERT) ? state.gas_left : 0;
    const auto result = evmc::make_result(status, gas_left,
        state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);
    return result;
}

evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto vm = static_cast<VM*>(c_vm);
    const auto jumpdest_map = baseline::analyze(code, code_size);
    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return caterpillar::execute(*vm, *state, jumpdest_map);
}

}  // namespace evmone::caterpillar
