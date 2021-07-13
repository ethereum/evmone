// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "instructions.hpp"

namespace evmone::instr
{
/// Wraps the basic instruction implementation to InstrFn signature.
template <evmc_status_code Fn(ExecutionState&) noexcept>
inline InstrResult wrap(ExecutionState& state, size_t pc) noexcept
{
    return {Fn(state), pc + 1};
}

/// The table of pointers to core instruction implementations.
constexpr std::array<InstrFn*, 256> implementations = []() noexcept {
    std::array<InstrFn*, 256> table{};

    table[OP_STOP] = wrap<stop>;
    table[OP_ADD] = wrap<add>;
    table[OP_MUL] = wrap<mul>;
    table[OP_SUB] = wrap<sub>;
    table[OP_DIV] = wrap<div>;
    table[OP_SDIV] = wrap<sdiv>;
    table[OP_MOD] = wrap<mod>;
    table[OP_SMOD] = wrap<smod>;
    table[OP_ADDMOD] = wrap<addmod>;
    table[OP_MULMOD] = wrap<mulmod>;
    table[OP_EXP] = wrap<exp>;
    table[OP_SIGNEXTEND] = wrap<signextend>;

    table[OP_LT] = wrap<lt>;
    table[OP_GT] = wrap<gt>;
    table[OP_SLT] = wrap<slt>;
    table[OP_SGT] = wrap<sgt>;
    table[OP_EQ] = wrap<eq>;
    table[OP_ISZERO] = wrap<iszero>;
    table[OP_AND] = wrap<and_>;
    table[OP_OR] = wrap<or_>;
    table[OP_XOR] = wrap<xor_>;
    table[OP_NOT] = wrap<not_>;
    table[OP_BYTE] = wrap<byte>;
    table[OP_SHL] = wrap<shl>;
    table[OP_SHR] = wrap<shr>;
    table[OP_SAR] = wrap<sar>;

    table[OP_KECCAK256] = wrap<keccak256>;

    table[OP_ADDRESS] = wrap<address>;
    table[OP_BALANCE] = wrap<balance>;
    table[OP_ORIGIN] = wrap<origin>;
    table[OP_CALLER] = wrap<caller>;
    table[OP_CALLVALUE] = wrap<callvalue>;
    table[OP_CALLDATALOAD] = wrap<calldataload>;
    table[OP_CALLDATASIZE] = wrap<calldatasize>;
    table[OP_CALLDATACOPY] = wrap<calldatacopy>;
    table[OP_CODESIZE] = wrap<codesize>;
    table[OP_CODECOPY] = wrap<codecopy>;
    table[OP_GASPRICE] = wrap<gasprice>;
    table[OP_EXTCODESIZE] = wrap<extcodesize>;
    table[OP_EXTCODECOPY] = wrap<extcodecopy>;
    table[OP_RETURNDATASIZE] = wrap<returndatasize>;
    table[OP_RETURNDATACOPY] = wrap<returndatacopy>;
    table[OP_EXTCODEHASH] = wrap<extcodehash>;

    table[OP_BLOCKHASH] = wrap<blockhash>;
    table[OP_COINBASE] = wrap<coinbase>;
    table[OP_TIMESTAMP] = wrap<timestamp>;
    table[OP_NUMBER] = wrap<number>;
    table[OP_DIFFICULTY] = wrap<difficulty>;
    table[OP_GASLIMIT] = wrap<gaslimit>;
    table[OP_CHAINID] = wrap<chainid>;
    table[OP_SELFBALANCE] = wrap<selfbalance>;
    table[OP_BASEFEE] = wrap<basefee>;

    table[OP_POP] = wrap<pop>;
    table[OP_MLOAD] = wrap<mload>;
    table[OP_MSTORE] = wrap<mstore>;
    table[OP_MSTORE8] = wrap<mstore8>;
    table[OP_SLOAD] = wrap<sload>;
    table[OP_SSTORE] = wrap<sstore>;
    table[OP_JUMP] = jump;
    table[OP_JUMPI] = jumpi;
    table[OP_PC] = pc;
    table[OP_MSIZE] = wrap<msize>;
    table[OP_GAS] = wrap<gas>;
    table[OP_JUMPDEST] = wrap<jumpdest>;

    table[OP_PUSH1] = push<1>;
    table[OP_PUSH2] = push<2>;
    table[OP_PUSH3] = push<3>;
    table[OP_PUSH4] = push<4>;
    table[OP_PUSH4] = push<4>;
    table[OP_PUSH5] = push<5>;
    table[OP_PUSH6] = push<6>;
    table[OP_PUSH7] = push<7>;
    table[OP_PUSH8] = push<8>;
    table[OP_PUSH9] = push<9>;
    table[OP_PUSH10] = push<10>;
    table[OP_PUSH11] = push<11>;
    table[OP_PUSH12] = push<12>;
    table[OP_PUSH13] = push<13>;
    table[OP_PUSH14] = push<14>;
    table[OP_PUSH15] = push<15>;
    table[OP_PUSH16] = push<16>;
    table[OP_PUSH17] = push<17>;
    table[OP_PUSH18] = push<18>;
    table[OP_PUSH19] = push<19>;
    table[OP_PUSH20] = push<20>;
    table[OP_PUSH21] = push<21>;
    table[OP_PUSH22] = push<22>;
    table[OP_PUSH23] = push<23>;
    table[OP_PUSH24] = push<24>;
    table[OP_PUSH25] = push<25>;
    table[OP_PUSH26] = push<26>;
    table[OP_PUSH27] = push<27>;
    table[OP_PUSH28] = push<28>;
    table[OP_PUSH29] = push<29>;
    table[OP_PUSH30] = push<30>;
    table[OP_PUSH31] = push<31>;
    table[OP_PUSH32] = push<32>;

    table[OP_DUP1] = wrap<dup<1>>;
    table[OP_DUP2] = wrap<dup<2>>;
    table[OP_DUP3] = wrap<dup<3>>;
    table[OP_DUP4] = wrap<dup<4>>;
    table[OP_DUP5] = wrap<dup<5>>;
    table[OP_DUP6] = wrap<dup<6>>;
    table[OP_DUP7] = wrap<dup<7>>;
    table[OP_DUP8] = wrap<dup<8>>;
    table[OP_DUP9] = wrap<dup<9>>;
    table[OP_DUP10] = wrap<dup<10>>;
    table[OP_DUP11] = wrap<dup<11>>;
    table[OP_DUP12] = wrap<dup<12>>;
    table[OP_DUP13] = wrap<dup<13>>;
    table[OP_DUP14] = wrap<dup<14>>;
    table[OP_DUP15] = wrap<dup<15>>;
    table[OP_DUP16] = wrap<dup<16>>;

    table[OP_SWAP1] = wrap<swap<1>>;
    table[OP_SWAP2] = wrap<swap<2>>;
    table[OP_SWAP3] = wrap<swap<3>>;
    table[OP_SWAP4] = wrap<swap<4>>;
    table[OP_SWAP5] = wrap<swap<5>>;
    table[OP_SWAP6] = wrap<swap<6>>;
    table[OP_SWAP7] = wrap<swap<7>>;
    table[OP_SWAP8] = wrap<swap<8>>;
    table[OP_SWAP9] = wrap<swap<9>>;
    table[OP_SWAP10] = wrap<swap<10>>;
    table[OP_SWAP11] = wrap<swap<11>>;
    table[OP_SWAP12] = wrap<swap<12>>;
    table[OP_SWAP13] = wrap<swap<13>>;
    table[OP_SWAP14] = wrap<swap<14>>;
    table[OP_SWAP15] = wrap<swap<15>>;
    table[OP_SWAP16] = wrap<swap<16>>;

    table[OP_LOG0] = wrap<log<0>>;
    table[OP_LOG1] = wrap<log<1>>;
    table[OP_LOG2] = wrap<log<2>>;
    table[OP_LOG3] = wrap<log<3>>;
    table[OP_LOG4] = wrap<log<4>>;

    table[OP_CREATE] = wrap<create<EVMC_CREATE>>;
    table[OP_CALL] = wrap<call<EVMC_CALL>>;
    table[OP_CALLCODE] = wrap<call<EVMC_CALLCODE>>;
    table[OP_RETURN] = wrap<return_<EVMC_SUCCESS>>;
    table[OP_DELEGATECALL] = wrap<call<EVMC_DELEGATECALL>>;
    table[OP_CREATE2] = wrap<create<EVMC_CREATE2>>;
    table[OP_STATICCALL] = wrap<call<EVMC_CALL, true>>;
    table[OP_REVERT] = wrap<return_<EVMC_REVERT>>;
    table[OP_INVALID] = wrap<invalid>;
    table[OP_SELFDESTRUCT] = wrap<selfdestruct>;

    return table;
}();
}  // namespace evmone::instr
