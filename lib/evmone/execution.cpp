// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"
#include "constants.hpp"
#include "memory.hpp"
#include "opcodes.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

#include <math.h>
#include <iostream>


#define UPDATE_MEMORY()                                \
    {                                                  \
        auto w = state.msize >> 5;                     \
        auto new_cost = 3 * w + (w * w >> 9);          \
        auto cost = new_cost - state.memory_prev_cost; \
        state.memory_prev_cost = new_cost;             \
        state.gas_left -= cost;                        \
    }

// this macro is called to dispatch to the subsequent instruction in our transaction.
// The aspiration is that the CPU can figure out what we're up to, and avoid a pipeline stall...
#define DISPATCH() goto**(void**)++state.next_instruction;

#define CHECK_BLOCK()                                                                           \
    {                                                                                           \
        auto block = state.next_instruction->block_data;                                        \
        state.gas_left -= block.gas_cost;                                                       \
        if (__builtin_expect((state.gas_left < 0) ||                                            \
                                 (state.stack_ptr - block.stack_req < &state.stack[0] ||        \
                                     (state.stack_ptr + block.stack_max > &state.stack[1023])), \
                0))                                                                             \
        {                                                                                       \
            if (state.gas_left < 0)                                                             \
            {                                                                                   \
                state.status = EVMC_OUT_OF_GAS;                                                 \
            }                                                                                   \
            else if (state.stack_ptr - block.stack_req < &state.stack[0])                       \
            {                                                                                   \
                state.status = EVMC_STACK_UNDERFLOW;                                            \
            }                                                                                   \
            else if (state.stack_ptr + block.stack_max > &state.stack[1023])                    \
            {                                                                                   \
                state.status = EVMC_STACK_OVERFLOW;                                             \
            }                                                                                   \
            goto op_stop_dest;                                                                  \
        }                                                                                       \
        state.current_block_cost = block.gas_cost;                                              \
    }


namespace evmone
{
namespace
{
}  // namespace

const void** interpret(
    instruction* instructions, instruction** jumpdest_map, execution_state& state) noexcept
{
    static const void* jump_tables[JUMP_TABLE_SIZE] = {
        /* 0x00 */ &&op_stop_dest,
        /* 0x01 */ &&op_add_dest,
        /* 0x02 */ &&op_mul_dest,
        /* 0x03 */ &&op_sub_dest,
        /* 0x04 */ &&op_div_dest,
        /* 0x05 */ &&op_sdiv_dest,
        /* 0x06 */ &&op_mod_dest,
        /* 0x07 */ &&op_smod_dest,
        /* 0x08 */ &&op_addmod_dest,
        /* 0x09 */ &&op_mulmod_dest,
        /* 0x0a */ &&op_exp_dest,
        /* 0x0b */ &&op_signextend_dest,
        /* 0x0c */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0x10 */ &&op_lt_dest,
        /* 0x11 */ &&op_gt_dest,
        /* 0x12 */ &&op_slt_dest,
        /* 0x13 */ &&op_sgt_dest,
        /* 0x14 */ &&op_eq_dest,
        /* 0x15 */ &&op_iszero_dest,
        /* 0x16 */ &&op_and_dest,
        /* 0x17 */ &&op_or_dest,
        /* 0x18 */ &&op_xor_dest,
        /* 0x19 */ &&op_not_dest,
        /* 0x1a */ &&op_byte_dest,
        /* 0x1b */ &&op_shl_dest,
        /* 0x1c */ &&op_shr_dest,
        /* 0x1d */ &&op_sar_dest,
        /* 0x1e */ &&op_undefined_dest,
        /* 0x1f */ &&op_undefined_dest,
        /* 0x20 */ &&op_sha3_dest,
        /* 0x21 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0x30 */ &&op_address_dest,
        /* 0x31 */ &&op_balance_dest,
        /* 0x32 */ &&op_origin_dest,
        /* 0x33 */ &&op_caller_dest,
        /* 0x34 */ &&op_callvalue_dest,
        /* 0x35 */ &&op_calldataload_dest,
        /* 0x36 */ &&op_calldatasize_dest,
        /* 0x37 */ &&op_calldatacopy_dest,
        /* 0x38 */ &&op_codesize_dest,
        /* 0x39 */ &&op_codecopy_dest,
        /* 0x3a */ &&op_gasprice_dest,
        /* 0x3b */ &&op_extcodesize_dest,
        /* 0x3c */ &&op_extcodecopy_dest,
        /* 0x3d */ &&op_returndatasize_dest,
        /* 0x3e */ &&op_returndatacopy_dest,
        /* 0x3f */ &&op_extcodehash_dest,
        /* 0x40 */ &&op_blockhash_dest,
        /* 0x41 */ &&op_coinbase_dest,
        /* 0x42 */ &&op_timestamp_dest,
        /* 0x43 */ &&op_number_dest,
        /* 0x44 */ &&op_difficulty_dest,
        /* 0x45 */ &&op_gaslimit_dest,
        /* 0x46 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0x50 */ &&op_pop_dest,
        /* 0x51 */ &&op_mload_dest,
        /* 0x52 */ &&op_mstore_dest,
        /* 0x53 */ &&op_mstore8_dest,
        /* 0x54 */ &&op_sload_dest,
        /* 0x55 */ &&op_sstore_dest,
        /* 0x56 */ &&op_jump_dest,
        /* 0x57 */ &&op_jumpi_dest,
        /* 0x58 */ &&op_pc_dest,
        /* 0x59 */ &&op_msize_dest,
        /* 0x5a */ &&op_gas_dest,
        /* 0x5b */ &&op_jumpdest_dest,
        /* 0x5c */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0x60 */ &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        &&op_push_dest,
        /* 0x80 */ &&op_dup1_dest,
        &&op_dup2_dest,
        &&op_dup3_dest,
        &&op_dup4_dest,
        &&op_dup5_dest,
        &&op_dup6_dest,
        &&op_dup7_dest,
        &&op_dup8_dest,
        &&op_dup9_dest,
        &&op_dup10_dest,
        &&op_dup11_dest,
        &&op_dup12_dest,
        &&op_dup13_dest,
        &&op_dup14_dest,
        &&op_dup15_dest,
        &&op_dup16_dest,
        /* 0x90 */ &&op_swap1_dest,
        &&op_swap2_dest,
        &&op_swap3_dest,
        &&op_swap4_dest,
        &&op_swap5_dest,
        &&op_swap6_dest,
        &&op_swap7_dest,
        &&op_swap8_dest,
        &&op_swap9_dest,
        &&op_swap10_dest,
        &&op_swap11_dest,
        &&op_swap12_dest,
        &&op_swap13_dest,
        &&op_swap14_dest,
        &&op_swap15_dest,
        &&op_swap16_dest,
        /* 0xa0 */ &&op_log0_dest,
        &&op_log1_dest,
        &&op_log2_dest,
        &&op_log3_dest,
        &&op_log4_dest,
        /* 0xa5 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xb5 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xc5 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xd5 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xe5 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xf0 */ &&op_create_dest,
        /* 0xf1 */ &&op_call_dest,
        /* 0xf2 */ &&op_callcode_dest,
        /* 0xf3 */ &&op_return_dest,
        /* 0xf4 */ &&op_delegatecall_dest,
        /* 0xf5 */ &&op_create2_dest,
        /* 0xf6 */ &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        &&op_undefined_dest,
        /* 0xfa */ &&op_staticcall_dest,
        /* 0xfb */ &&op_undefined_dest,
        /* 0xfc */ &&op_undefined_dest,
        /* 0xfd */ &&op_revert_dest,
        /* 0xfe */ &&op_invalid_dest,
        /* 0xff */ &&op_selfdestruct_dest,
        /* 0x100 */ &&op_stop_dest_no_check,
        /* 0x101 */ &&op_add_dest_no_check,
        /* 0x102 */ &&op_mul_dest_no_check,
        /* 0x103 */ &&op_sub_dest_no_check,
        /* 0x104 */ &&op_div_dest_no_check,
        /* 0x105 */ &&op_sdiv_dest_no_check,
        /* 0x106 */ &&op_mod_dest_no_check,
        /* 0x107 */ &&op_smod_dest_no_check,
        /* 0x108 */ &&op_addmod_dest_no_check,
        /* 0x109 */ &&op_mulmod_dest_no_check,
        /* 0x10a */ &&op_exp_dest_no_check,
        /* 0x10b */ &&op_signextend_dest_no_check,
        /* 0x10c */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x110 */ &&op_lt_dest_no_check,
        /* 0x111 */ &&op_gt_dest_no_check,
        /* 0x112 */ &&op_slt_dest_no_check,
        /* 0x113 */ &&op_sgt_dest_no_check,
        /* 0x114 */ &&op_eq_dest_no_check,
        /* 0x115 */ &&op_iszero_dest_no_check,
        /* 0x116 */ &&op_and_dest_no_check,
        /* 0x117 */ &&op_or_dest_no_check,
        /* 0x118 */ &&op_xor_dest_no_check,
        /* 0x119 */ &&op_not_dest_no_check,
        /* 0x11a */ &&op_byte_dest_no_check,
        /* 0x11b */ &&op_shl_dest_no_check,
        /* 0x11c */ &&op_shr_dest_no_check,
        /* 0x11d */ &&op_sar_dest_no_check,
        /* 0x11e */ &&op_undefined_dest_no_check,
        /* 0x11f */ &&op_undefined_dest_no_check,
        /* 0x120 */ &&op_sha3_dest_no_check,
        /* 0x121 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x130 */ &&op_address_dest_no_check,
        /* 0x131 */ &&op_balance_dest_no_check,
        /* 0x132 */ &&op_origin_dest_no_check,
        /* 0x133 */ &&op_caller_dest_no_check,
        /* 0x134 */ &&op_callvalue_dest_no_check,
        /* 0x135 */ &&op_calldataload_dest_no_check,
        /* 0x136 */ &&op_calldatasize_dest_no_check,
        /* 0x137 */ &&op_calldatacopy_dest_no_check,
        /* 0x138 */ &&op_codesize_dest_no_check,
        /* 0x139 */ &&op_codecopy_dest_no_check,
        /* 0x13a */ &&op_gasprice_dest_no_check,
        /* 0x13b */ &&op_extcodesize_dest_no_check,
        /* 0x13c */ &&op_extcodecopy_dest_no_check,
        /* 0x13d */ &&op_returndatasize_dest_no_check,
        /* 0x13e */ &&op_returndatacopy_dest_no_check,
        /* 0x13f */ &&op_extcodehash_dest_no_check,
        /* 0x140 */ &&op_blockhash_dest_no_check,
        /* 0x141 */ &&op_coinbase_dest_no_check,
        /* 0x142 */ &&op_timestamp_dest_no_check,
        /* 0x143 */ &&op_number_dest_no_check,
        /* 0x144 */ &&op_difficulty_dest_no_check,
        /* 0x145 */ &&op_gaslimit_dest_no_check,
        /* 0x146 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x150 */ &&op_pop_dest_no_check,
        /* 0x151 */ &&op_mload_dest_no_check,
        /* 0x152 */ &&op_mstore_dest_no_check,
        /* 0x153 */ &&op_mstore8_dest_no_check,
        /* 0x154 */ &&op_sload_dest_no_check,
        /* 0x155 */ &&op_sstore_dest_no_check,
        /* 0x156 */ &&op_jump_dest_no_check,
        /* 0x157 */ &&op_jumpi_dest_no_check,
        /* 0x158 */ &&op_pc_dest_no_check,
        /* 0x159 */ &&op_msize_dest_no_check,
        /* 0x15a */ &&op_gas_dest_no_check,
        /* 0x15b */ &&op_jumpdest_dest_no_check,
        /* 0x15c */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x160 */ &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        &&op_push_dest_no_check,
        /* 0x180 */ &&op_dup1_dest_no_check,
        &&op_dup2_dest_no_check,
        &&op_dup3_dest_no_check,
        &&op_dup4_dest_no_check,
        &&op_dup5_dest_no_check,
        &&op_dup6_dest_no_check,
        &&op_dup7_dest_no_check,
        &&op_dup8_dest_no_check,
        &&op_dup9_dest_no_check,
        &&op_dup10_dest_no_check,
        &&op_dup11_dest_no_check,
        &&op_dup12_dest_no_check,
        &&op_dup13_dest_no_check,
        &&op_dup14_dest_no_check,
        &&op_dup15_dest_no_check,
        &&op_dup16_dest_no_check,
        /* 0x190 */ &&op_swap1_dest_no_check,
        &&op_swap2_dest_no_check,
        &&op_swap3_dest_no_check,
        &&op_swap4_dest_no_check,
        &&op_swap5_dest_no_check,
        &&op_swap6_dest_no_check,
        &&op_swap7_dest_no_check,
        &&op_swap8_dest_no_check,
        &&op_swap9_dest_no_check,
        &&op_swap10_dest_no_check,
        &&op_swap11_dest_no_check,
        &&op_swap12_dest_no_check,
        &&op_swap13_dest_no_check,
        &&op_swap14_dest_no_check,
        &&op_swap15_dest_no_check,
        &&op_swap16_dest_no_check,
        /* 0x1a0 */ &&op_log0_dest_no_check,
        &&op_log1_dest_no_check,
        &&op_log2_dest_no_check,
        &&op_log3_dest_no_check,
        &&op_log4_dest_no_check,
        /* 0x1a5 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1b5 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1c5 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1d5 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1e5 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1f0 */ &&op_create_dest_no_check,
        /* 0x1f1 */ &&op_call_dest_no_check,
        /* 0x1f2 */ &&op_callcode_dest_no_check,
        /* 0x1f3 */ &&op_return_dest_no_check,
        /* 0x1f4 */ &&op_delegatecall_dest_no_check,
        /* 0x1f5 */ &&op_create2_dest_no_check,
        /* 0x1f6 */ &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        &&op_undefined_dest_no_check,
        /* 0x1fa */ &&op_staticcall_dest_no_check,
        /* 0x1fb */ &&op_undefined_dest_no_check,
        /* 0x1fc */ &&op_undefined_dest_no_check,
        /* 0x1fd */ &&op_revert_dest_no_check,
        /* 0x1fe */ &&op_invalid_dest_no_check,
        /* 0x1ff */ &&op_selfdestruct_dest_no_check,
        /* 0x200 */ &&op_staticviolation_dest,
    };

    // If we haven't computed our jump labels yet, return our jump tables
    if (instructions == nullptr)
    {
        return jump_tables;
    };

    // This really shouldn't happen, but in case we cannot allocate enough memory, throw an error
    if (state.memory == nullptr)
    {
        state.status = EVMC_REJECTED;
        state.next_instruction = state.stop_instruction;
    }

    // hon hon hon
    goto**(void**)state.next_instruction;

op_add_dest:
    CHECK_BLOCK();
op_add_dest_no_check:
    op_add(state);
    DISPATCH();
op_mul_dest:
    CHECK_BLOCK();
op_mul_dest_no_check:
    op_mul(state);
    DISPATCH();
op_sub_dest:
    CHECK_BLOCK();
op_sub_dest_no_check:
    op_sub(state);
    DISPATCH();
op_div_dest:
    CHECK_BLOCK();
op_div_dest_no_check:
    op_div(state);
    DISPATCH();
op_sdiv_dest:
    CHECK_BLOCK();
op_sdiv_dest_no_check:
    op_sdiv(state);
    DISPATCH();
op_mod_dest:
    CHECK_BLOCK();
op_mod_dest_no_check:
    op_mod(state);
    DISPATCH();
op_smod_dest:
    CHECK_BLOCK();
op_smod_dest_no_check:
    op_smod(state);
    DISPATCH();
op_addmod_dest:
    CHECK_BLOCK();
op_addmod_dest_no_check:
    op_addmod(state);
    DISPATCH();
op_mulmod_dest:
    CHECK_BLOCK();
op_mulmod_dest_no_check:
    op_mulmod(state);
    DISPATCH();
op_exp_dest:
    CHECK_BLOCK();
op_exp_dest_no_check:
    op_exp(state);
    DISPATCH();
op_signextend_dest:
    CHECK_BLOCK();
op_signextend_dest_no_check:
    op_signextend(state);
    DISPATCH();
op_lt_dest:
    CHECK_BLOCK();
op_lt_dest_no_check:
    op_lt(state);
    DISPATCH();
op_gt_dest:
    CHECK_BLOCK();
op_gt_dest_no_check:
    op_gt(state);
    DISPATCH();
op_slt_dest:
    CHECK_BLOCK();
op_slt_dest_no_check:
    op_slt(state);
    DISPATCH();
op_sgt_dest:
    CHECK_BLOCK();
op_sgt_dest_no_check:
    op_sgt(state);
    DISPATCH();
op_eq_dest:
    CHECK_BLOCK();
op_eq_dest_no_check:
    op_eq(state);
    DISPATCH();
op_iszero_dest:
    CHECK_BLOCK();
op_iszero_dest_no_check:
    op_iszero(state);
    DISPATCH();
op_and_dest:
    CHECK_BLOCK();
op_and_dest_no_check:
    op_and(state);
    DISPATCH();
op_or_dest:
    CHECK_BLOCK();
op_or_dest_no_check:
    op_or(state);
    DISPATCH();
op_xor_dest:
    CHECK_BLOCK();
op_xor_dest_no_check:
    op_xor(state);
    DISPATCH();
op_not_dest:
    CHECK_BLOCK();
op_not_dest_no_check:
    op_not(state);
    DISPATCH();
op_byte_dest:
    CHECK_BLOCK();
op_byte_dest_no_check:
    op_byte(state);
    DISPATCH();
op_shl_dest:
    CHECK_BLOCK();
op_shl_dest_no_check:
    op_shl(state);
    DISPATCH();
op_shr_dest:
    CHECK_BLOCK();
op_shr_dest_no_check:
    op_shr(state);
    DISPATCH();
op_sar_dest:
    CHECK_BLOCK();
op_sar_dest_no_check:
    op_sar(state);
    DISPATCH();
op_sha3_dest:
    CHECK_BLOCK();
op_sha3_dest_no_check:
    op_sha3(state);
    DISPATCH();
op_address_dest:
    CHECK_BLOCK();
op_address_dest_no_check:
    op_address(state);
    DISPATCH();
op_balance_dest:
    CHECK_BLOCK();
op_balance_dest_no_check:
    op_balance(state);
    DISPATCH();
op_origin_dest:
    CHECK_BLOCK();
op_origin_dest_no_check:
    op_origin(state);
    DISPATCH();
op_caller_dest:
    CHECK_BLOCK();
op_caller_dest_no_check:
    op_caller(state);
    DISPATCH();
op_callvalue_dest:
    CHECK_BLOCK();
op_callvalue_dest_no_check:
    op_callvalue(state);
    DISPATCH();
op_calldataload_dest:
    CHECK_BLOCK();
op_calldataload_dest_no_check:
    op_calldataload(state);
    DISPATCH();
op_calldatasize_dest:
    CHECK_BLOCK();
op_calldatasize_dest_no_check:
    op_calldatasize(state);
    DISPATCH();
op_calldatacopy_dest:
    CHECK_BLOCK();
op_calldatacopy_dest_no_check:
    op_calldatacopy(state);
    DISPATCH();
op_codesize_dest:
    CHECK_BLOCK();
op_codesize_dest_no_check:
    op_codesize(state);
    DISPATCH();
op_codecopy_dest:
    CHECK_BLOCK();
op_codecopy_dest_no_check:
    op_codecopy(state);
    DISPATCH();
op_gasprice_dest:
    CHECK_BLOCK();
op_gasprice_dest_no_check:
    op_gasprice(state);
    DISPATCH();
op_extcodesize_dest:
    CHECK_BLOCK();
op_extcodesize_dest_no_check:
    op_extcodesize(state);
    DISPATCH();
op_extcodecopy_dest:
    CHECK_BLOCK();
op_extcodecopy_dest_no_check:
    op_extcodecopy(state);
    DISPATCH();
op_returndatasize_dest:
    CHECK_BLOCK();
op_returndatasize_dest_no_check:
    op_returndatasize(state);
    DISPATCH();
op_returndatacopy_dest:
    CHECK_BLOCK();
op_returndatacopy_dest_no_check:
    op_returndatacopy(state);
    DISPATCH();
op_extcodehash_dest:
    CHECK_BLOCK();
op_extcodehash_dest_no_check:
    op_extcodehash(state);
    DISPATCH();
op_blockhash_dest:
    CHECK_BLOCK();
op_blockhash_dest_no_check:
    op_blockhash(state);
    DISPATCH();
op_coinbase_dest:
    CHECK_BLOCK();
op_coinbase_dest_no_check:
    op_coinbase(state);
    DISPATCH();
op_timestamp_dest:
    CHECK_BLOCK();
op_timestamp_dest_no_check:
    op_timestamp(state);
    DISPATCH();
op_number_dest:
    CHECK_BLOCK();
op_number_dest_no_check:
    op_number(state);
    DISPATCH();
op_difficulty_dest:
    CHECK_BLOCK();
op_difficulty_dest_no_check:
    op_difficulty(state);
    DISPATCH();
op_gaslimit_dest:
    CHECK_BLOCK();
op_gaslimit_dest_no_check:
    op_gaslimit(state);
    DISPATCH();
op_pop_dest:
    CHECK_BLOCK();
op_pop_dest_no_check:
    op_pop(state);
    DISPATCH();
op_mload_dest:
    CHECK_BLOCK();
op_mload_dest_no_check:
    op_mload(state);
    DISPATCH();
op_mstore_dest:
    CHECK_BLOCK();
op_mstore_dest_no_check:
    op_mstore(state);
    DISPATCH();
op_mstore8_dest:
    CHECK_BLOCK();
op_mstore8_dest_no_check:
    op_mstore8(state);
    DISPATCH();
op_sload_dest:
    CHECK_BLOCK();
op_sload_dest_no_check:
    op_sload(state);
    DISPATCH();
op_sstore_dest:
    CHECK_BLOCK();
op_sstore_dest_no_check:
    op_sstore(state);
    DISPATCH();
op_jump_dest:
    CHECK_BLOCK();
op_jump_dest_no_check:
    op_jump(state, jumpdest_map);
    DISPATCH();
op_jumpi_dest:
    CHECK_BLOCK();
op_jumpi_dest_no_check:
    op_jumpi(state, jumpdest_map);
    DISPATCH();
op_pc_dest:
    CHECK_BLOCK();
op_pc_dest_no_check:
    op_pc(state);
    DISPATCH();
op_msize_dest:
    CHECK_BLOCK();
op_msize_dest_no_check:
    op_msize(state);
    DISPATCH();
op_gas_dest:
    CHECK_BLOCK();
op_gas_dest_no_check:
    op_gas(state, state.next_instruction->instruction_data);
    DISPATCH();
op_jumpdest_dest:
    CHECK_BLOCK();
op_jumpdest_dest_no_check:
    op_jumpdest(state);
    DISPATCH();

/**
 * push
 **/
op_push_dest:
    CHECK_BLOCK();
op_push_dest_no_check:
    op_push(state);
    DISPATCH();

/**
 * dup
 **/
op_dup1_dest:
    CHECK_BLOCK();
op_dup1_dest_no_check:
    op_dup1(state);
    DISPATCH();
op_dup2_dest:
    CHECK_BLOCK();
op_dup2_dest_no_check:
    op_dup2(state);
    DISPATCH();
op_dup3_dest:
    CHECK_BLOCK();
op_dup3_dest_no_check:
    op_dup3(state);
    DISPATCH();
op_dup4_dest:
    CHECK_BLOCK();
op_dup4_dest_no_check:
    op_dup4(state);
    DISPATCH();
op_dup5_dest:
    CHECK_BLOCK();
op_dup5_dest_no_check:
    op_dup5(state);
    DISPATCH();
op_dup6_dest:
    CHECK_BLOCK();
op_dup6_dest_no_check:
    op_dup6(state);
    DISPATCH();
op_dup7_dest:
    CHECK_BLOCK();
op_dup7_dest_no_check:
    op_dup7(state);
    DISPATCH();
op_dup8_dest:
    CHECK_BLOCK();
op_dup8_dest_no_check:
    op_dup8(state);
    DISPATCH();
op_dup9_dest:
    CHECK_BLOCK();
op_dup9_dest_no_check:
    op_dup9(state);
    DISPATCH();
op_dup10_dest:
    CHECK_BLOCK();
op_dup10_dest_no_check:
    op_dup10(state);
    DISPATCH();
op_dup11_dest:
    CHECK_BLOCK();
op_dup11_dest_no_check:
    op_dup11(state);
    DISPATCH();
op_dup12_dest:
    CHECK_BLOCK();
op_dup12_dest_no_check:
    op_dup12(state);
    DISPATCH();

op_dup13_dest:
    CHECK_BLOCK();
op_dup13_dest_no_check:
    op_dup13(state);
    DISPATCH();
op_dup14_dest:
    CHECK_BLOCK();
op_dup14_dest_no_check:
    op_dup14(state);
    DISPATCH();
op_dup15_dest:
    CHECK_BLOCK();
op_dup15_dest_no_check:
    op_dup15(state);
    DISPATCH();
op_dup16_dest:
    CHECK_BLOCK();
op_dup16_dest_no_check:
    op_dup16(state);
    DISPATCH();

/**
 * swap
 **/
op_swap1_dest:
    CHECK_BLOCK();
op_swap1_dest_no_check:
    op_swap1(state);
    DISPATCH();
op_swap2_dest:
    CHECK_BLOCK();
op_swap2_dest_no_check:
    op_swap2(state);
    DISPATCH();
op_swap3_dest:
    CHECK_BLOCK();
op_swap3_dest_no_check:
    op_swap3(state);
    DISPATCH();
op_swap4_dest:
    CHECK_BLOCK();
op_swap4_dest_no_check:
    op_swap4(state);
    DISPATCH();
op_swap5_dest:
    CHECK_BLOCK();
op_swap5_dest_no_check:
    op_swap5(state);
    DISPATCH();
op_swap6_dest:
    CHECK_BLOCK();
op_swap6_dest_no_check:
    op_swap6(state);
    DISPATCH();
op_swap7_dest:
    CHECK_BLOCK();
op_swap7_dest_no_check:
    op_swap7(state);
    DISPATCH();
op_swap8_dest:
    CHECK_BLOCK();
op_swap8_dest_no_check:
    op_swap8(state);
    DISPATCH();
op_swap9_dest:
    CHECK_BLOCK();
op_swap9_dest_no_check:
    op_swap9(state);
    DISPATCH();
op_swap10_dest:
    CHECK_BLOCK();
op_swap10_dest_no_check:
    op_swap10(state);
    DISPATCH();
op_swap11_dest:
    CHECK_BLOCK();
op_swap11_dest_no_check:
    op_swap11(state);
    DISPATCH();
op_swap12_dest:
    CHECK_BLOCK();
op_swap12_dest_no_check:
    op_swap12(state);
    DISPATCH();
op_swap13_dest:
    CHECK_BLOCK();
op_swap13_dest_no_check:
    op_swap13(state);
    DISPATCH();
op_swap14_dest:
    CHECK_BLOCK();
op_swap14_dest_no_check:
    op_swap14(state);
    DISPATCH();
op_swap15_dest:
    CHECK_BLOCK();
op_swap15_dest_no_check:
    op_swap15(state);
    DISPATCH();
op_swap16_dest:
    CHECK_BLOCK();
op_swap16_dest_no_check:
    op_swap16(state);
    DISPATCH();
op_log0_dest:
    CHECK_BLOCK();
op_log0_dest_no_check:
    op_log0(state);
    DISPATCH();
op_log1_dest:
    CHECK_BLOCK();
op_log1_dest_no_check:
    op_log1(state);
    DISPATCH();
op_log2_dest:
    CHECK_BLOCK();
op_log2_dest_no_check:
    op_log2(state);
    DISPATCH();
op_log3_dest:
    CHECK_BLOCK();
op_log3_dest_no_check:
    op_log3(state);
    DISPATCH();
op_log4_dest:
    CHECK_BLOCK();
op_log4_dest_no_check:
    op_log4(state);
    DISPATCH();
op_create_dest:
    CHECK_BLOCK();
op_create_dest_no_check:
    op_create(state, state.next_instruction->instruction_data);
    DISPATCH();
op_call_dest:
    CHECK_BLOCK();
op_call_dest_no_check:
    op_call(state, state.next_instruction->instruction_data);
    DISPATCH();
op_callcode_dest:
    CHECK_BLOCK();
op_callcode_dest_no_check:
    op_callcode(state, state.next_instruction->instruction_data);
    DISPATCH();
op_return_dest:
    CHECK_BLOCK();
op_return_dest_no_check:
    op_return(state);
    goto op_stop_dest;
op_delegatecall_dest:
    CHECK_BLOCK();
op_delegatecall_dest_no_check:
    op_delegatecall(state, state.next_instruction->instruction_data);
    DISPATCH();
op_create2_dest:
    CHECK_BLOCK();
op_create2_dest_no_check:
    op_create2(state, state.next_instruction->instruction_data);
    DISPATCH();
op_staticcall_dest:
    CHECK_BLOCK();
op_staticcall_dest_no_check:
    op_staticcall(state, state.next_instruction->instruction_data);
    DISPATCH();
op_revert_dest:
op_revert_dest_no_check:
    op_revert(state);
    goto op_stop_dest;
op_invalid_dest:
op_invalid_dest_no_check:
    state.status = EVMC_INVALID_INSTRUCTION;
    goto op_stop_dest;
op_selfdestruct_dest:
op_selfdestruct_dest_no_check:
    op_selfdestruct(state);
    goto op_stop_dest;
op_undefined_dest:
op_undefined_dest_no_check:
    state.status = EVMC_UNDEFINED_INSTRUCTION;
    goto op_stop_dest;
op_staticviolation_dest:
    state.status = EVMC_STATIC_MODE_VIOLATION;
op_stop_dest:
op_stop_dest_no_check:
    return nullptr;
}

void** create_op_table_istanbul() noexcept
{
    static execution_state dummy_state = execution_state();
    const void** table = interpret(nullptr, nullptr, dummy_state);
    static void* istanbul[JUMP_TABLE_SIZE];
    memcpy(&istanbul, table, sizeof(void*) * JUMP_TABLE_SIZE);
    return istanbul;
}

void** create_op_table_petersburg() noexcept
{
    void** table = create_op_table_istanbul();
    static void* petersburg[JUMP_TABLE_SIZE];
    memcpy(&petersburg, table, sizeof(void*) * JUMP_TABLE_SIZE);
    return petersburg;
}

void** create_op_table_constantinople() noexcept
{
    void** table = create_op_table_petersburg();
    static void* constantinople[JUMP_TABLE_SIZE];
    memcpy(&constantinople, table, sizeof(void*) * JUMP_TABLE_SIZE);
    return constantinople;
}

void** create_op_table_byzantium() noexcept
{
    void** table = create_op_table_constantinople();
    static void* byzantium[JUMP_TABLE_SIZE];
    memcpy(&byzantium, table, sizeof(void*) * JUMP_TABLE_SIZE);
    byzantium[OP_SHL] = byzantium[UNDEFINED_INDEX];
    byzantium[OP_SHR] = byzantium[UNDEFINED_INDEX];
    byzantium[OP_SAR] = byzantium[UNDEFINED_INDEX];
    byzantium[OP_EXTCODEHASH] = byzantium[UNDEFINED_INDEX];
    byzantium[OP_CREATE2] = byzantium[UNDEFINED_INDEX];
    byzantium[JUMP_TABLE_CHECK_BOUNDARY + OP_SHL] = byzantium[UNDEFINED_INDEX];
    byzantium[JUMP_TABLE_CHECK_BOUNDARY + OP_SHR] = byzantium[UNDEFINED_INDEX];
    byzantium[JUMP_TABLE_CHECK_BOUNDARY + OP_SAR] = byzantium[UNDEFINED_INDEX];
    byzantium[JUMP_TABLE_CHECK_BOUNDARY + OP_EXTCODEHASH] = byzantium[UNDEFINED_INDEX];
    byzantium[JUMP_TABLE_CHECK_BOUNDARY + OP_CREATE2] = byzantium[UNDEFINED_INDEX];
    return byzantium;
}

void** create_op_table_homestead() noexcept
{
    void** table = create_op_table_byzantium();
    static void* homestead[JUMP_TABLE_SIZE];
    memcpy(&homestead, table, sizeof(void*) * JUMP_TABLE_SIZE);
    homestead[OP_RETURNDATASIZE] = homestead[UNDEFINED_INDEX];
    homestead[OP_RETURNDATACOPY] = homestead[UNDEFINED_INDEX];
    homestead[OP_STATICCALL] = homestead[UNDEFINED_INDEX];
    homestead[OP_REVERT] = homestead[UNDEFINED_INDEX];
    homestead[JUMP_TABLE_CHECK_BOUNDARY + OP_RETURNDATASIZE] = homestead[UNDEFINED_INDEX];
    homestead[JUMP_TABLE_CHECK_BOUNDARY + OP_RETURNDATACOPY] = homestead[UNDEFINED_INDEX];
    homestead[JUMP_TABLE_CHECK_BOUNDARY + OP_STATICCALL] = homestead[UNDEFINED_INDEX];
    homestead[JUMP_TABLE_CHECK_BOUNDARY + OP_REVERT] = homestead[UNDEFINED_INDEX];
    return homestead;
}

void** create_op_table_frontier() noexcept
{
    void** table = create_op_table_homestead();
    static void* frontier[JUMP_TABLE_SIZE];
    memcpy(&frontier, table, sizeof(void*) * JUMP_TABLE_SIZE);
    frontier[OP_DELEGATECALL] = frontier[UNDEFINED_INDEX];
    frontier[JUMP_TABLE_CHECK_BOUNDARY + OP_DELEGATECALL] = frontier[UNDEFINED_INDEX];
    return frontier;
}

void add_static_violations(const void** table) noexcept
{
    table[OP_SSTORE] = table[STATIC_VIOLATION_INDEX];
    table[OP_LOG0] = table[STATIC_VIOLATION_INDEX];
    table[OP_LOG1] = table[STATIC_VIOLATION_INDEX];
    table[OP_LOG2] = table[STATIC_VIOLATION_INDEX];
    table[OP_LOG3] = table[STATIC_VIOLATION_INDEX];
    table[OP_LOG4] = table[STATIC_VIOLATION_INDEX];
    table[OP_CREATE] = table[STATIC_VIOLATION_INDEX];
    table[OP_CREATE2] = table[STATIC_VIOLATION_INDEX];
    table[OP_SELFDESTRUCT] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_SSTORE] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_LOG0] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_LOG1] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_LOG2] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_LOG3] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_LOG4] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_CREATE] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_CREATE2] = table[STATIC_VIOLATION_INDEX];
    table[JUMP_TABLE_CHECK_BOUNDARY + OP_SELFDESTRUCT] = table[STATIC_VIOLATION_INDEX];
}

constexpr auto num_revisions = int{EVMC_MAX_REVISION + 1};
static const void* op_table[num_revisions * 2][JUMP_TABLE_SIZE] = {};

const auto op_table_initialized = []() noexcept
{
    void** frontier = create_op_table_frontier();
    void** homestead = create_op_table_homestead();
    void** byzantium = create_op_table_byzantium();
    void** constantinople = create_op_table_constantinople();
    void** petersburg = create_op_table_petersburg();
    void** istanbul = create_op_table_istanbul();

    memcpy(&op_table[EVMC_FRONTIER], frontier, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_HOMESTEAD], homestead, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_TANGERINE_WHISTLE], homestead, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_SPURIOUS_DRAGON], homestead, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_BYZANTIUM], byzantium, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_CONSTANTINOPLE], constantinople, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_CONSTANTINOPLE2], petersburg, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[EVMC_ISTANBUL], istanbul, sizeof(void*) * JUMP_TABLE_SIZE);

    memcpy(&op_table[num_revisions + EVMC_FRONTIER], frontier, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_HOMESTEAD], homestead, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_TANGERINE_WHISTLE], homestead,
        sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_SPURIOUS_DRAGON], homestead,
        sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_BYZANTIUM], byzantium, sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_CONSTANTINOPLE], constantinople,
        sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_CONSTANTINOPLE2], petersburg,
        sizeof(void*) * JUMP_TABLE_SIZE);
    memcpy(&op_table[num_revisions + EVMC_ISTANBUL], istanbul, sizeof(void*) * JUMP_TABLE_SIZE);
    for (size_t i = 0; i < num_revisions; i++)
    {
        add_static_violations(op_table[num_revisions + i]);
    }
    return true;
}
();


evmc_result execute(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
    // If this is a static call, fish out a different jump table that will trigger an error
    // for non-static methods
    auto jump_table_index = msg->flags & EVMC_STATIC ? rev + num_revisions : rev;
    const void* temp_table[JUMP_TABLE_SIZE];
    memcpy(temp_table, op_table[jump_table_index], sizeof(void*) * JUMP_TABLE_SIZE);
    // Compute the maximum amount of memory this transaction can potentially consume.
    // This currently tops out at ~8MB, which is low enough to just allocate and zero out,
    // instead of dealing with memory paging overheads
    execution_state state;
    state.tx_context = ctx->host->get_tx_context(ctx);
    std::tie(state.memory, state.max_potential_memory) =
        evmone::memory::get_tx_memory_ptr(std::min(msg->gas, state.tx_context.block_gas_limit));

    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = ctx;
    state.gas_left = msg->gas;
    state.rev = rev;
    state.exp_cost = rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    state.storage_repeated_cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
    state.msize = 0;
    state.stack_ptr = &state.stack[0];

    instruction* jumpdest_map[code_size + 2] = {nullptr};
    instruction instructions[code_size + 2];

    analyze(instructions, jumpdest_map, rev, code_size, code, temp_table);

    state.stop_instruction = &instructions[code_size];
    state.next_instruction = &instructions[0];

    interpret(instructions, jumpdest_map, state);

    evmc_result result{};

    result.status_code = state.status;

    if (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
        result.gas_left = state.gas_left;


    if (state.output_size > 0)
    {
        result.output_size = state.output_size;
        auto output_data = static_cast<uint8_t*>(std::malloc(result.output_size));
        std::memcpy(output_data, &state.memory[state.output_offset], result.output_size);
        result.output_data = output_data;
        result.release = [](const evmc_result* result) noexcept
        {
            std::free(const_cast<uint8_t*>(result->output_data));
        };
    }
    evmone::memory::clean_up(state.msize);
    return result;
}
}  // namespace evmone
