// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"
#include "analysis.hpp"

namespace evmone
{
namespace
{
template <void InstrFn(evm_stack&)>
const instruction* op(const instruction* instr, execution_state& state) noexcept
{
    InstrFn(state.stack);
    return ++instr;
}

template <void InstrFn(ExecutionState&)>
const instruction* op(const instruction* instr, execution_state& state) noexcept
{
    InstrFn(state);
    return ++instr;
}

template <evmc_status_code InstrFn(ExecutionState&)>
const instruction* op(const instruction* instr, execution_state& state) noexcept
{
    const auto status_code = InstrFn(state);
    if (status_code != EVMC_SUCCESS)
        return state.exit(status_code);
    return ++instr;
}

const instruction* op_stop(const instruction*, execution_state& state) noexcept
{
    return state.exit(EVMC_SUCCESS);
}

const instruction* op_sstore(const instruction* instr, execution_state& state) noexcept
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

const instruction* op_jump(const instruction*, execution_state& state) noexcept
{
    const auto dst = state.stack.pop();
    auto pc = -1;
    if (std::numeric_limits<int>::max() < dst ||
        (pc = find_jumpdest(*state.analysis, static_cast<int>(dst))) < 0)
        return state.exit(EVMC_BAD_JUMP_DESTINATION);

    return &state.analysis->instrs[static_cast<size_t>(pc)];
}

const instruction* op_jumpi(const instruction* instr, execution_state& state) noexcept
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

const instruction* op_pc(const instruction* instr, execution_state& state) noexcept
{
    state.stack.push(instr->arg.number);
    return ++instr;
}

const instruction* op_gas(const instruction* instr, execution_state& state) noexcept
{
    const auto correction = state.current_block_cost - instr->arg.number;
    const auto gas = static_cast<uint64_t>(state.gas_left + correction);
    state.stack.push(gas);
    return ++instr;
}

const instruction* op_push_small(const instruction* instr, execution_state& state) noexcept
{
    state.stack.push(instr->arg.small_push_value);
    return ++instr;
}

const instruction* op_push_full(const instruction* instr, execution_state& state) noexcept
{
    state.stack.push(*instr->arg.push_value);
    return ++instr;
}

template <evmc_opcode LogOp>
const instruction* op_log(const instruction* instr, execution_state& state) noexcept
{
    constexpr auto num_topics = LogOp - OP_LOG0;
    const auto status_code = log(state, num_topics);
    if (status_code != EVMC_SUCCESS)
        return state.exit(status_code);
    return ++instr;
}

const instruction* op_invalid(const instruction*, execution_state& state) noexcept
{
    return state.exit(EVMC_INVALID_INSTRUCTION);
}

template <evmc_status_code status_code>
const instruction* op_return(const instruction*, execution_state& state) noexcept
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
const instruction* op_call(const instruction* instr, execution_state& state) noexcept
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
const instruction* op_create(const instruction* instr, execution_state& state) noexcept
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

const instruction* op_undefined(const instruction*, execution_state& state) noexcept
{
    return state.exit(EVMC_UNDEFINED_INSTRUCTION);
}

const instruction* op_selfdestruct(const instruction*, execution_state& state) noexcept
{
    return state.exit(selfdestruct(state));
}

const instruction* opx_beginblock(const instruction* instr, execution_state& state) noexcept
{
    auto& block = instr->arg.block;

    if ((state.gas_left -= block.gas_cost) < 0)
        return state.exit(EVMC_OUT_OF_GAS);

    if (static_cast<int>(state.stack.size()) < block.stack_req)
        return state.exit(EVMC_STACK_UNDERFLOW);

    if (static_cast<int>(state.stack.size()) + block.stack_max_growth > evm_stack::limit)
        return state.exit(EVMC_STACK_OVERFLOW);

    state.current_block_cost = block.gas_cost;
    return ++instr;
}

constexpr op_table create_op_table_frontier() noexcept
{
    auto table = op_table{};

    // First, mark all opcodes as undefined.
    for (auto& t : table)
        t = {op_undefined, 0, 0, 0};

    table[OP_STOP] = {op_stop, 0, 0, 0};
    table[OP_ADD] = {op<add>, 3, 2, -1};
    table[OP_MUL] = {op<mul>, 5, 2, -1};
    table[OP_SUB] = {op<sub>, 3, 2, -1};
    table[OP_DIV] = {op<div>, 5, 2, -1};
    table[OP_SDIV] = {op<sdiv>, 5, 2, -1};
    table[OP_MOD] = {op<mod>, 5, 2, -1};
    table[OP_SMOD] = {op<smod>, 5, 2, -1};
    table[OP_ADDMOD] = {op<addmod>, 8, 3, -2};
    table[OP_MULMOD] = {op<mulmod>, 8, 3, -2};
    table[OP_EXP] = {op<exp>, 10, 2, -1};
    table[OP_SIGNEXTEND] = {op<signextend>, 5, 2, -1};
    table[OP_LT] = {op<lt>, 3, 2, -1};
    table[OP_GT] = {op<gt>, 3, 2, -1};
    table[OP_SLT] = {op<slt>, 3, 2, -1};
    table[OP_SGT] = {op<sgt>, 3, 2, -1};
    table[OP_EQ] = {op<eq>, 3, 2, -1};
    table[OP_ISZERO] = {op<iszero>, 3, 1, 0};
    table[OP_AND] = {op<and_>, 3, 2, -1};
    table[OP_OR] = {op<or_>, 3, 2, -1};
    table[OP_XOR] = {op<xor_>, 3, 2, -1};
    table[OP_NOT] = {op<not_>, 3, 1, 0};
    table[OP_BYTE] = {op<byte>, 3, 2, -1};
    table[OP_SHA3] = {op<sha3>, 30, 2, -1};
    table[OP_ADDRESS] = {op<address>, 2, 0, 1};
    table[OP_BALANCE] = {op<balance>, 20, 1, 0};
    table[OP_ORIGIN] = {op<origin>, 2, 0, 1};
    table[OP_CALLER] = {op<caller>, 2, 0, 1};
    table[OP_CALLVALUE] = {op<callvalue>, 2, 0, 1};
    table[OP_CALLDATALOAD] = {op<calldataload>, 3, 1, 0};
    table[OP_CALLDATASIZE] = {op<calldatasize>, 2, 0, 1};
    table[OP_CALLDATACOPY] = {op<calldatacopy>, 3, 3, -3};
    table[OP_CODESIZE] = {op<codesize>, 2, 0, 1};
    table[OP_CODECOPY] = {op<codecopy>, 3, 3, -3};
    table[OP_GASPRICE] = {op<gasprice>, 2, 0, 1};
    table[OP_EXTCODESIZE] = {op<extcodesize>, 20, 1, 0};
    table[OP_EXTCODECOPY] = {op<extcodecopy>, 20, 4, -4};
    table[OP_BLOCKHASH] = {op<blockhash>, 20, 1, 0};
    table[OP_COINBASE] = {op<coinbase>, 2, 0, 1};
    table[OP_TIMESTAMP] = {op<timestamp>, 2, 0, 1};
    table[OP_NUMBER] = {op<number>, 2, 0, 1};
    table[OP_DIFFICULTY] = {op<difficulty>, 2, 0, 1};
    table[OP_GASLIMIT] = {op<gaslimit>, 2, 0, 1};
    table[OP_POP] = {op<pop>, 2, 1, -1};
    table[OP_MLOAD] = {op<mload>, 3, 1, 0};
    table[OP_MSTORE] = {op<mstore>, 3, 2, -2};
    table[OP_MSTORE8] = {op<mstore8>, 3, 2, -2};
    table[OP_SLOAD] = {op<sload>, 50, 1, 0};
    table[OP_SSTORE] = {op_sstore, 0, 2, -2};
    table[OP_JUMP] = {op_jump, 8, 1, -1};
    table[OP_JUMPI] = {op_jumpi, 10, 2, -2};
    table[OP_PC] = {op_pc, 2, 0, 1};
    table[OP_MSIZE] = {op<msize>, 2, 0, 1};
    table[OP_GAS] = {op_gas, 2, 0, 1};
    table[OPX_BEGINBLOCK] = {opx_beginblock, 1, 0, 0};  // Replaces JUMPDEST.

    for (auto op = size_t{OP_PUSH1}; op <= OP_PUSH8; ++op)
        table[op] = {op_push_small, 3, 0, 1};
    for (auto op = size_t{OP_PUSH9}; op <= OP_PUSH32; ++op)
        table[op] = {op_push_full, 3, 0, 1};

    table[OP_DUP1] = {op<dup<OP_DUP1>>, 3, 1, 1};
    table[OP_DUP2] = {op<dup<OP_DUP2>>, 3, 2, 1};
    table[OP_DUP3] = {op<dup<OP_DUP3>>, 3, 3, 1};
    table[OP_DUP4] = {op<dup<OP_DUP4>>, 3, 4, 1};
    table[OP_DUP5] = {op<dup<OP_DUP5>>, 3, 5, 1};
    table[OP_DUP6] = {op<dup<OP_DUP6>>, 3, 6, 1};
    table[OP_DUP7] = {op<dup<OP_DUP7>>, 3, 7, 1};
    table[OP_DUP8] = {op<dup<OP_DUP8>>, 3, 8, 1};
    table[OP_DUP9] = {op<dup<OP_DUP9>>, 3, 9, 1};
    table[OP_DUP10] = {op<dup<OP_DUP10>>, 3, 10, 1};
    table[OP_DUP11] = {op<dup<OP_DUP11>>, 3, 11, 1};
    table[OP_DUP12] = {op<dup<OP_DUP12>>, 3, 12, 1};
    table[OP_DUP13] = {op<dup<OP_DUP13>>, 3, 13, 1};
    table[OP_DUP14] = {op<dup<OP_DUP14>>, 3, 14, 1};
    table[OP_DUP15] = {op<dup<OP_DUP15>>, 3, 15, 1};
    table[OP_DUP16] = {op<dup<OP_DUP16>>, 3, 16, 1};

    table[OP_SWAP1] = {op<swap<OP_SWAP1>>, 3, 2, 0};
    table[OP_SWAP2] = {op<swap<OP_SWAP2>>, 3, 3, 0};
    table[OP_SWAP3] = {op<swap<OP_SWAP3>>, 3, 4, 0};
    table[OP_SWAP4] = {op<swap<OP_SWAP4>>, 3, 5, 0};
    table[OP_SWAP5] = {op<swap<OP_SWAP5>>, 3, 6, 0};
    table[OP_SWAP6] = {op<swap<OP_SWAP6>>, 3, 7, 0};
    table[OP_SWAP7] = {op<swap<OP_SWAP7>>, 3, 8, 0};
    table[OP_SWAP8] = {op<swap<OP_SWAP8>>, 3, 9, 0};
    table[OP_SWAP9] = {op<swap<OP_SWAP9>>, 3, 10, 0};
    table[OP_SWAP10] = {op<swap<OP_SWAP10>>, 3, 11, 0};
    table[OP_SWAP11] = {op<swap<OP_SWAP11>>, 3, 12, 0};
    table[OP_SWAP12] = {op<swap<OP_SWAP12>>, 3, 13, 0};
    table[OP_SWAP13] = {op<swap<OP_SWAP13>>, 3, 14, 0};
    table[OP_SWAP14] = {op<swap<OP_SWAP14>>, 3, 15, 0};
    table[OP_SWAP15] = {op<swap<OP_SWAP15>>, 3, 16, 0};
    table[OP_SWAP16] = {op<swap<OP_SWAP16>>, 3, 17, 0};

    table[OP_LOG0] = {op_log<OP_LOG0>, 1 * 375, 2, -2};
    table[OP_LOG1] = {op_log<OP_LOG1>, 2 * 375, 3, -3};
    table[OP_LOG2] = {op_log<OP_LOG2>, 3 * 375, 4, -4};
    table[OP_LOG3] = {op_log<OP_LOG3>, 4 * 375, 5, -5};
    table[OP_LOG4] = {op_log<OP_LOG4>, 5 * 375, 6, -6};

    table[OP_CREATE] = {op_create<EVMC_CREATE>, 32000, 3, -2};
    table[OP_CALL] = {op_call<EVMC_CALL>, 40, 7, -6};
    table[OP_CALLCODE] = {op_call<EVMC_CALLCODE>, 40, 7, -6};
    table[OP_RETURN] = {op_return<EVMC_SUCCESS>, 0, 2, -2};
    table[OP_INVALID] = {op_invalid, 0, 0, 0};
    table[OP_SELFDESTRUCT] = {op_selfdestruct, 0, 1, -1};
    return table;
}

constexpr op_table create_op_table_homestead() noexcept
{
    auto table = create_op_table_frontier();
    table[OP_DELEGATECALL] = {op_call<EVMC_DELEGATECALL>, 40, 6, -5};
    return table;
}

constexpr op_table create_op_table_tangerine_whistle() noexcept
{
    auto table = create_op_table_homestead();
    table[OP_BALANCE].gas_cost = 400;
    table[OP_EXTCODESIZE].gas_cost = 700;
    table[OP_EXTCODECOPY].gas_cost = 700;
    table[OP_SLOAD].gas_cost = 200;
    table[OP_CALL].gas_cost = 700;
    table[OP_CALLCODE].gas_cost = 700;
    table[OP_DELEGATECALL].gas_cost = 700;
    table[OP_SELFDESTRUCT].gas_cost = 5000;
    return table;
}

constexpr op_table create_op_table_byzantium() noexcept
{
    auto table = create_op_table_tangerine_whistle();
    table[OP_RETURNDATASIZE] = {op<returndatasize>, 2, 0, 1};
    table[OP_RETURNDATACOPY] = {op<returndatacopy>, 3, 3, -3};
    table[OP_STATICCALL] = {op_call<EVMC_CALL, true>, 700, 6, -5};
    table[OP_REVERT] = {op_return<EVMC_REVERT>, 0, 2, -2};
    return table;
}

constexpr op_table create_op_table_constantinople() noexcept
{
    auto table = create_op_table_byzantium();
    table[OP_SHL] = {op<shl>, 3, 2, -1};
    table[OP_SHR] = {op<shr>, 3, 2, -1};
    table[OP_SAR] = {op<sar>, 3, 2, -1};
    table[OP_EXTCODEHASH] = {op<extcodehash>, 400, 1, 0};
    table[OP_CREATE2] = {op_create<EVMC_CREATE2>, 32000, 4, -3};
    return table;
}

constexpr op_table create_op_table_istanbul() noexcept
{
    auto table = create_op_table_constantinople();
    table[OP_BALANCE] = {op<balance>, 700, 1, 0};
    table[OP_CHAINID] = {op<chainid>, 2, 0, 1};
    table[OP_EXTCODEHASH] = {op<extcodehash>, 700, 1, 0};
    table[OP_SELFBALANCE] = {op<selfbalance>, 5, 0, 1};
    table[OP_SLOAD] = {op<sload>, 800, 1, 0};
    return table;
}

constexpr op_table op_tables[] = {
    create_op_table_frontier(),           // Frontier
    create_op_table_homestead(),          // Homestead
    create_op_table_tangerine_whistle(),  // Tangerine Whistle
    create_op_table_tangerine_whistle(),  // Spurious Dragon
    create_op_table_byzantium(),          // Byzantium
    create_op_table_constantinople(),     // Constantinople
    create_op_table_constantinople(),     // Petersburg
    create_op_table_istanbul(),           // Istanbul
    create_op_table_istanbul(),           // Berlin
};
static_assert(sizeof(op_tables) / sizeof(op_tables[0]) > EVMC_MAX_REVISION,
    "op table entry missing for an EVMC revision");
}  // namespace

EVMC_EXPORT const op_table& get_op_table(evmc_revision rev) noexcept
{
    return op_tables[rev];
}
}  // namespace evmone
