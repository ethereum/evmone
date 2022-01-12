// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "instructions.hpp"

namespace evmone::instr
{

/// Maps an opcode to the function with the instruction implementation.
template <evmc_opcode Op>
constexpr auto impl = nullptr;  // Default template specialization, should not be used.

// clang-format off
template <> constexpr auto impl<OP_STOP> = stop;
template <> constexpr auto impl<OP_ADD> = add;
template <> constexpr auto impl<OP_MUL> = mul;
template <> constexpr auto impl<OP_SUB> = sub;
template <> constexpr auto impl<OP_DIV> = div;
template <> constexpr auto impl<OP_SDIV> = sdiv;
template <> constexpr auto impl<OP_MOD> = mod;
template <> constexpr auto impl<OP_SMOD> = smod;
template <> constexpr auto impl<OP_ADDMOD> = addmod;
template <> constexpr auto impl<OP_MULMOD> = mulmod;
template <> constexpr auto impl<OP_EXP> = exp;
template <> constexpr auto impl<OP_SIGNEXTEND> = signextend;
template <> constexpr auto impl<OP_LT> = lt;
template <> constexpr auto impl<OP_GT> = gt;
template <> constexpr auto impl<OP_SLT> = slt;
template <> constexpr auto impl<OP_SGT> = sgt;
template <> constexpr auto impl<OP_EQ> = eq;
template <> constexpr auto impl<OP_ISZERO> = iszero;
template <> constexpr auto impl<OP_AND> = and_;
template <> constexpr auto impl<OP_OR> = or_;
template <> constexpr auto impl<OP_XOR> = xor_;
template <> constexpr auto impl<OP_NOT> = not_;
template <> constexpr auto impl<OP_BYTE> = byte;
template <> constexpr auto impl<OP_SHL> = shl;
template <> constexpr auto impl<OP_SHR> = shr;
template <> constexpr auto impl<OP_SAR> = sar;
template <> constexpr auto impl<OP_KECCAK256> = keccak256;
template <> constexpr auto impl<OP_ADDRESS> = address;
template <> constexpr auto impl<OP_BALANCE> = balance;
template <> constexpr auto impl<OP_ORIGIN> = origin;
template <> constexpr auto impl<OP_CALLER> = caller;
template <> constexpr auto impl<OP_CALLVALUE> = callvalue;
template <> constexpr auto impl<OP_CALLDATALOAD> = calldataload;
template <> constexpr auto impl<OP_CALLDATASIZE> = calldatasize;
template <> constexpr auto impl<OP_CALLDATACOPY> = calldatacopy;
template <> constexpr auto impl<OP_CODESIZE> = codesize;
template <> constexpr auto impl<OP_CODECOPY> = codecopy;
template <> constexpr auto impl<OP_GASPRICE> = gasprice;
template <> constexpr auto impl<OP_EXTCODESIZE> = extcodesize;
template <> constexpr auto impl<OP_EXTCODECOPY> = extcodecopy;
template <> constexpr auto impl<OP_RETURNDATASIZE> = returndatasize;
template <> constexpr auto impl<OP_RETURNDATACOPY> = returndatacopy;
template <> constexpr auto impl<OP_EXTCODEHASH> = extcodehash;
template <> constexpr auto impl<OP_BLOCKHASH> = blockhash;
template <> constexpr auto impl<OP_COINBASE> = coinbase;
template <> constexpr auto impl<OP_TIMESTAMP> = timestamp;
template <> constexpr auto impl<OP_NUMBER> = number;
template <> constexpr auto impl<OP_DIFFICULTY> = difficulty;
template <> constexpr auto impl<OP_GASLIMIT> = gaslimit;
template <> constexpr auto impl<OP_CHAINID> = chainid;
template <> constexpr auto impl<OP_SELFBALANCE> = selfbalance;
template <> constexpr auto impl<OP_BASEFEE> = basefee;
template <> constexpr auto impl<OP_POP> = pop;
template <> constexpr auto impl<OP_MLOAD> = mload;
template <> constexpr auto impl<OP_MSTORE> = mstore;
template <> constexpr auto impl<OP_MSTORE8> = mstore8;
template <> constexpr auto impl<OP_SLOAD> = sload;
template <> constexpr auto impl<OP_SSTORE> = sstore;
template <> constexpr auto impl<OP_JUMP> = jump;
template <> constexpr auto impl<OP_JUMPI> = jumpi;
template <> constexpr auto impl<OP_PC> = pc;
template <> constexpr auto impl<OP_MSIZE> = msize;
template <> constexpr auto impl<OP_GAS> = gas;
template <> constexpr auto impl<OP_JUMPDEST> = jumpdest;
template <> constexpr auto impl<OP_PUSH1> = push<1>;
template <> constexpr auto impl<OP_PUSH2> = push<2>;
template <> constexpr auto impl<OP_PUSH3> = push<3>;
template <> constexpr auto impl<OP_PUSH4> = push<4>;
template <> constexpr auto impl<OP_PUSH5> = push<5>;
template <> constexpr auto impl<OP_PUSH6> = push<6>;
template <> constexpr auto impl<OP_PUSH7> = push<7>;
template <> constexpr auto impl<OP_PUSH8> = push<8>;
template <> constexpr auto impl<OP_PUSH9> = push<9>;
template <> constexpr auto impl<OP_PUSH10> = push<10>;
template <> constexpr auto impl<OP_PUSH11> = push<11>;
template <> constexpr auto impl<OP_PUSH12> = push<12>;
template <> constexpr auto impl<OP_PUSH13> = push<13>;
template <> constexpr auto impl<OP_PUSH14> = push<14>;
template <> constexpr auto impl<OP_PUSH15> = push<15>;
template <> constexpr auto impl<OP_PUSH16> = push<16>;
template <> constexpr auto impl<OP_PUSH17> = push<17>;
template <> constexpr auto impl<OP_PUSH18> = push<18>;
template <> constexpr auto impl<OP_PUSH19> = push<19>;
template <> constexpr auto impl<OP_PUSH20> = push<20>;
template <> constexpr auto impl<OP_PUSH21> = push<21>;
template <> constexpr auto impl<OP_PUSH22> = push<22>;
template <> constexpr auto impl<OP_PUSH23> = push<23>;
template <> constexpr auto impl<OP_PUSH24> = push<24>;
template <> constexpr auto impl<OP_PUSH25> = push<25>;
template <> constexpr auto impl<OP_PUSH26> = push<26>;
template <> constexpr auto impl<OP_PUSH27> = push<27>;
template <> constexpr auto impl<OP_PUSH28> = push<28>;
template <> constexpr auto impl<OP_PUSH29> = push<29>;
template <> constexpr auto impl<OP_PUSH30> = push<30>;
template <> constexpr auto impl<OP_PUSH31> = push<31>;
template <> constexpr auto impl<OP_PUSH32> = push<32>;
template <> constexpr auto impl<OP_DUP1> = dup<1>;
template <> constexpr auto impl<OP_DUP2> = dup<2>;
template <> constexpr auto impl<OP_DUP3> = dup<3>;
template <> constexpr auto impl<OP_DUP4> = dup<4>;
template <> constexpr auto impl<OP_DUP5> = dup<5>;
template <> constexpr auto impl<OP_DUP6> = dup<6>;
template <> constexpr auto impl<OP_DUP7> = dup<7>;
template <> constexpr auto impl<OP_DUP8> = dup<8>;
template <> constexpr auto impl<OP_DUP9> = dup<9>;
template <> constexpr auto impl<OP_DUP10> = dup<10>;
template <> constexpr auto impl<OP_DUP11> = dup<11>;
template <> constexpr auto impl<OP_DUP12> = dup<12>;
template <> constexpr auto impl<OP_DUP13> = dup<13>;
template <> constexpr auto impl<OP_DUP14> = dup<14>;
template <> constexpr auto impl<OP_DUP15> = dup<15>;
template <> constexpr auto impl<OP_DUP16> = dup<16>;
template <> constexpr auto impl<OP_SWAP1> = swap<1>;
template <> constexpr auto impl<OP_SWAP2> = swap<2>;
template <> constexpr auto impl<OP_SWAP3> = swap<3>;
template <> constexpr auto impl<OP_SWAP4> = swap<4>;
template <> constexpr auto impl<OP_SWAP5> = swap<5>;
template <> constexpr auto impl<OP_SWAP6> = swap<6>;
template <> constexpr auto impl<OP_SWAP7> = swap<7>;
template <> constexpr auto impl<OP_SWAP8> = swap<8>;
template <> constexpr auto impl<OP_SWAP9> = swap<9>;
template <> constexpr auto impl<OP_SWAP10> = swap<10>;
template <> constexpr auto impl<OP_SWAP11> = swap<11>;
template <> constexpr auto impl<OP_SWAP12> = swap<12>;
template <> constexpr auto impl<OP_SWAP13> = swap<13>;
template <> constexpr auto impl<OP_SWAP14> = swap<14>;
template <> constexpr auto impl<OP_SWAP15> = swap<15>;
template <> constexpr auto impl<OP_SWAP16> = swap<16>;
template <> constexpr auto impl<OP_LOG0> = log<0>;
template <> constexpr auto impl<OP_LOG1> = log<1>;
template <> constexpr auto impl<OP_LOG2> = log<2>;
template <> constexpr auto impl<OP_LOG3> = log<3>;
template <> constexpr auto impl<OP_LOG4> = log<4>;
template <> constexpr auto impl<OP_CREATE> = create;
template <> constexpr auto impl<OP_CALL> = call;
template <> constexpr auto impl<OP_CALLCODE> = callcode;
template <> constexpr auto impl<OP_RETURN> = return_;
template <> constexpr auto impl<OP_DELEGATECALL> = delegatecall;
template <> constexpr auto impl<OP_CREATE2> = create2;
template <> constexpr auto impl<OP_STATICCALL> = staticcall;
template <> constexpr auto impl<OP_INVALID> = invalid;
template <> constexpr auto impl<OP_REVERT> = revert;
template <> constexpr auto impl<OP_SELFDESTRUCT> = selfdestruct;
// clang-format on
}  // namespace evmone::instr
