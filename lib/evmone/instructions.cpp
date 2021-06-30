// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"
#include "analysis.hpp"
#include "instruction_traits.hpp"

namespace evmone
{
namespace
{
template <void InstrFn(Stack&)>
const instruction* op(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    InstrFn(state.stack);
    return ++instr;
}

template <void InstrFn(ExecutionState&)>
const instruction* op(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    InstrFn(state);
    return ++instr;
}

template <evmc_status_code InstrFn(ExecutionState&)>
const instruction* op(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    const auto status_code = InstrFn(state);
    if (status_code != EVMC_SUCCESS)
        return state.exit(status_code);
    return ++instr;
}

const instruction* op_stop(const instruction*, AdvancedExecutionState& state) noexcept
{
    return state.exit(EVMC_SUCCESS);
}

const instruction* op_sstore(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    const auto gas_left_correction = state.current_block_cost - instr->arg.number;
    state.gas_left += gas_left_correction;

    const auto status = sstore(state);
    if (status != EVMC_SUCCESS)
        return state.exit(status);

    if ((state.gas_left -= gas_left_correction) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    return ++instr;
}

const instruction* op_jump(const instruction*, AdvancedExecutionState& state) noexcept
{
    const auto dst = state.stack.pop();
    auto pc = -1;
    if (std::numeric_limits<int>::max() < dst ||
        (pc = find_jumpdest(*state.analysis, static_cast<int>(dst))) < 0)
        return state.exit(EVMC_BAD_JUMP_DESTINATION);

    return &state.analysis->instrs[static_cast<size_t>(pc)];
}

const instruction* op_jumpi(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    if (state.stack[1] != 0)
        instr = op_jump(instr, state);
    else
    {
        state.stack.pop();
        ++instr;
    }

    // OPT: The pc must be the BEGINBLOCK (even in fallback case),
    //      so we can execute it straight away.

    state.stack.pop();
    return instr;
}

const instruction* op_pc(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    state.stack.push(instr->arg.number);
    return ++instr;
}

const instruction* op_gas(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    const auto correction = state.current_block_cost - instr->arg.number;
    const auto gas = static_cast<uint64_t>(state.gas_left + correction);
    state.stack.push(gas);
    return ++instr;
}

const instruction* op_push_small(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    state.stack.push(instr->arg.small_push_value);
    return ++instr;
}

const instruction* op_push_full(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    state.stack.push(*instr->arg.push_value);
    return ++instr;
}

const instruction* op_invalid(const instruction*, AdvancedExecutionState& state) noexcept
{
    return state.exit(EVMC_INVALID_INSTRUCTION);
}

template <evmc_status_code status_code>
const instruction* op_return(const instruction*, AdvancedExecutionState& state) noexcept
{
    const auto offset = state.stack[0];
    const auto size = state.stack[1];

    if (!check_memory(state, offset, size))
        return state.exit(EVMC_OUT_OF_GAS);

    state.output_size = static_cast<size_t>(size);
    if (state.output_size != 0)
        state.output_offset = static_cast<size_t>(offset);
    return state.exit(status_code);
}

template <evmc_call_kind Kind, bool Static = false>
const instruction* op_call(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    const auto gas_left_correction = state.current_block_cost - instr->arg.number;
    state.gas_left += gas_left_correction;

    const auto status = call<Kind, Static>(state);
    if (status != EVMC_SUCCESS)
        return state.exit(status);

    if ((state.gas_left -= gas_left_correction) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    return ++instr;
}

template <evmc_call_kind Kind>
const instruction* op_create(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    const auto gas_left_correction = state.current_block_cost - instr->arg.number;
    state.gas_left += gas_left_correction;

    const auto status = create<Kind>(state);
    if (status != EVMC_SUCCESS)
        return state.exit(status);

    if ((state.gas_left -= gas_left_correction) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    return ++instr;
}

const instruction* op_undefined(const instruction*, AdvancedExecutionState& state) noexcept
{
    return state.exit(EVMC_UNDEFINED_INSTRUCTION);
}

const instruction* op_selfdestruct(const instruction*, AdvancedExecutionState& state) noexcept
{
    return state.exit(selfdestruct(state));
}

const instruction* opx_beginblock(const instruction* instr, AdvancedExecutionState& state) noexcept
{
    auto& block = instr->arg.block;

    if ((state.gas_left -= block.gas_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    if (static_cast<int>(state.stack.size()) < block.stack_req)
        return state.exit(EVMC_STACK_UNDERFLOW);

    if (static_cast<int>(state.stack.size()) + block.stack_max_growth > Stack::limit)
        return state.exit(EVMC_STACK_OVERFLOW);

    state.current_block_cost = block.gas_cost;
    return ++instr;
}


constexpr std::array<instruction_exec_fn, 256> instruction_implementations = []() noexcept {
    std::array<instruction_exec_fn, 256> table{};

    table[OP_STOP] = op_stop;
    table[OP_ADD] = op<add>;
    table[OP_MUL] = op<mul>;
    table[OP_SUB] = op<sub>;
    table[OP_DIV] = op<div>;
    table[OP_SDIV] = op<sdiv>;
    table[OP_MOD] = op<mod>;
    table[OP_SMOD] = op<smod>;
    table[OP_ADDMOD] = op<addmod>;
    table[OP_MULMOD] = op<mulmod>;
    table[OP_EXP] = op<exp>;
    table[OP_SIGNEXTEND] = op<signextend>;
    table[OP_LT] = op<lt>;
    table[OP_GT] = op<gt>;
    table[OP_SLT] = op<slt>;
    table[OP_SGT] = op<sgt>;
    table[OP_EQ] = op<eq>;
    table[OP_ISZERO] = op<iszero>;
    table[OP_AND] = op<and_>;
    table[OP_OR] = op<or_>;
    table[OP_XOR] = op<xor_>;
    table[OP_NOT] = op<not_>;
    table[OP_BYTE] = op<byte>;
    table[OP_SHL] = op<shl>;
    table[OP_SHR] = op<shr>;
    table[OP_SAR] = op<sar>;

    table[OP_KECCAK256] = op<keccak256>;

    table[OP_ADDRESS] = op<address>;
    table[OP_BALANCE] = op<balance>;
    table[OP_ORIGIN] = op<origin>;
    table[OP_CALLER] = op<caller>;
    table[OP_CALLVALUE] = op<callvalue>;
    table[OP_CALLDATALOAD] = op<calldataload>;
    table[OP_CALLDATASIZE] = op<calldatasize>;
    table[OP_CALLDATACOPY] = op<calldatacopy>;
    table[OP_CODESIZE] = op<codesize>;
    table[OP_CODECOPY] = op<codecopy>;
    table[OP_GASPRICE] = op<gasprice>;
    table[OP_EXTCODESIZE] = op<extcodesize>;
    table[OP_EXTCODECOPY] = op<extcodecopy>;
    table[OP_RETURNDATASIZE] = op<returndatasize>;
    table[OP_RETURNDATACOPY] = op<returndatacopy>;
    table[OP_EXTCODEHASH] = op<extcodehash>;
    table[OP_BLOCKHASH] = op<blockhash>;
    table[OP_COINBASE] = op<coinbase>;
    table[OP_TIMESTAMP] = op<timestamp>;
    table[OP_NUMBER] = op<number>;
    table[OP_DIFFICULTY] = op<difficulty>;
    table[OP_GASLIMIT] = op<gaslimit>;
    table[OP_CHAINID] = op<chainid>;
    table[OP_SELFBALANCE] = op<selfbalance>;
    table[OP_BASEFEE] = op<basefee>;

    table[OP_POP] = op<pop>;
    table[OP_MLOAD] = op<mload>;
    table[OP_MSTORE] = op<mstore>;
    table[OP_MSTORE8] = op<mstore8>;
    table[OP_SLOAD] = op<sload>;
    table[OP_SSTORE] = op_sstore;
    table[OP_JUMP] = op_jump;
    table[OP_JUMPI] = op_jumpi;
    table[OP_PC] = op_pc;
    table[OP_MSIZE] = op<msize>;
    table[OP_GAS] = op_gas;
    table[OPX_BEGINBLOCK] = opx_beginblock;

    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH8; ++op)
        table[op] = op_push_small;
    for (auto op = size_t{OP_PUSH9}; op <= OP_PUSH32; ++op)
        table[op] = op_push_full;

    table[OP_DUP1] = op<dup<1>>;
    table[OP_DUP2] = op<dup<2>>;
    table[OP_DUP3] = op<dup<3>>;
    table[OP_DUP4] = op<dup<4>>;
    table[OP_DUP5] = op<dup<5>>;
    table[OP_DUP6] = op<dup<6>>;
    table[OP_DUP7] = op<dup<7>>;
    table[OP_DUP8] = op<dup<8>>;
    table[OP_DUP9] = op<dup<9>>;
    table[OP_DUP10] = op<dup<10>>;
    table[OP_DUP11] = op<dup<11>>;
    table[OP_DUP12] = op<dup<12>>;
    table[OP_DUP13] = op<dup<13>>;
    table[OP_DUP14] = op<dup<14>>;
    table[OP_DUP15] = op<dup<15>>;
    table[OP_DUP16] = op<dup<16>>;

    table[OP_SWAP1] = op<swap<1>>;
    table[OP_SWAP2] = op<swap<2>>;
    table[OP_SWAP3] = op<swap<3>>;
    table[OP_SWAP4] = op<swap<4>>;
    table[OP_SWAP5] = op<swap<5>>;
    table[OP_SWAP6] = op<swap<6>>;
    table[OP_SWAP7] = op<swap<7>>;
    table[OP_SWAP8] = op<swap<8>>;
    table[OP_SWAP9] = op<swap<9>>;
    table[OP_SWAP10] = op<swap<10>>;
    table[OP_SWAP11] = op<swap<11>>;
    table[OP_SWAP12] = op<swap<12>>;
    table[OP_SWAP13] = op<swap<13>>;
    table[OP_SWAP14] = op<swap<14>>;
    table[OP_SWAP15] = op<swap<15>>;
    table[OP_SWAP16] = op<swap<16>>;

    table[OP_LOG0] = op<log<0>>;
    table[OP_LOG1] = op<log<1>>;
    table[OP_LOG2] = op<log<2>>;
    table[OP_LOG3] = op<log<3>>;
    table[OP_LOG4] = op<log<4>>;

    table[OP_CREATE] = op_create<EVMC_CREATE>;
    table[OP_CALL] = op_call<EVMC_CALL>;
    table[OP_CALLCODE] = op_call<EVMC_CALLCODE>;
    table[OP_RETURN] = op_return<EVMC_SUCCESS>;
    table[OP_DELEGATECALL] = op_call<EVMC_DELEGATECALL>;
    table[OP_CREATE2] = op_create<EVMC_CREATE2>;
    table[OP_STATICCALL] = op_call<EVMC_CALL, true>;
    table[OP_REVERT] = op_return<EVMC_REVERT>;
    table[OP_INVALID] = op_invalid;
    table[OP_SELFDESTRUCT] = op_selfdestruct;

    return table;
}();
}  // namespace

EVMC_EXPORT const op_table& get_op_table(evmc_revision rev) noexcept
{
    static constexpr auto op_tables = []() noexcept {
        std::array<op_table, EVMC_MAX_REVISION + 1> tables{};
        for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
        {
            auto& table = tables[r];
            for (size_t i = 0; i < table.size(); ++i)
            {
                auto& t = table[i];
                const auto gas_cost = instr::gas_costs[r][i];
                if (gas_cost == instr::undefined)
                {
                    t.fn = op_undefined;
                    t.gas_cost = 0;
                }
                else
                {
                    t.fn = instruction_implementations[i];
                    t.gas_cost = gas_cost;
                    t.stack_req = instr::traits[i].stack_height_required;
                    t.stack_change = instr::traits[i].stack_height_change;
                }
            }
        }
        return tables;
    }();

    return op_tables[rev];
}
}  // namespace evmone
