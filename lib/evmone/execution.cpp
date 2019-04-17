// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"
#include "opcodes.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

#include <math.h>
#include <iostream>


#define DISPATCH() \
    if (blocks[++state.pc] != nullptr) \
    { \
    CHECK_BLOCK(); \

#define DISPATCH_PUSH() \
    if (blocks[state.pc] != nullptr) \
    { \
    CHECK_BLOCK(); \

#define CHECK_BLOCK() \
    { \
        auto block = *blocks[state.pc]; \
        state.gas_left -= block.gas_cost; \
        if (__builtin_expect(state.gas_left < 0, 0)) \
        { \
            state.status = EVMC_OUT_OF_GAS; \
            goto op_stop_dest; \
        } \
        else if (__builtin_expect(static_cast<int>(state.stack_ptr) < block.stack_req, 0)) \
        { \
            state.status = EVMC_STACK_UNDERFLOW; \
            goto op_stop_dest; \
        } \
        else if (__builtin_expect(static_cast<int>(state.stack_ptr) + block.stack_max > 1024, 0)) \
        { \
            state.status = EVMC_STACK_OVERFLOW; \
            goto op_stop_dest; \
        } \
        state.current_block_cost = block.gas_cost; \
    }\
    } \
    goto *labels[state.pc];

#define CHECK_BLOCK_B() \
    state.next_instruction = labels[state.pc]; \
    if (state.block != nullptr) \
    { \
        state.gas_left -= state.block->gas_cost; \
        if (__builtin_expect(state.gas_left < 0, 0)) \
        { \
            state.status = EVMC_OUT_OF_GAS; \
            state.next_instruction = &&op_stop_dest; \
        } \
        else if (__builtin_expect(static_cast<int>(state.stack_ptr) < state.block->stack_req, 0)) \
        { \
            state.status = EVMC_STACK_UNDERFLOW; \
            state.next_instruction = &&op_stop_dest; \
        } \
        else if (__builtin_expect(static_cast<int>(state.stack_ptr) + state.block->stack_max > 1024, 0)) \
        { \
            state.status = EVMC_STACK_OVERFLOW; \
            state.next_instruction = &&op_stop_dest; \
        } \
        state.current_block_cost = state.block->gas_cost; \
    } \
    goto *state.next_instruction;


#define DISPATCH_B() state.block = blocks[++state.pc]; CHECK_BLOCK();
#define DISPATCH_PUSH_B() state.block = blocks[state.pc]; CHECK_BLOCK();

namespace evmone
{
namespace
{
}  // namespace

// #define DISPATCH() check_block(state, blocks[++state.pc]);
//     goto *labels[state.pc];

// #define DISPATCH_PUSH() check_block(state, blocks[state.pc]);
//     goto *labels[state.pc];

// struct opcode_tables
// {
//     void* tables[4][256];
// };

struct opcode_table
{
    void* table[256];
};

opcode_table interpret(const void** labels, execution_state& state, const block_info** blocks, const instruction_info** instruction_data)
{
    static const opcode_table jump_tables = { .table = {
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
        /* 0x0c */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x21 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x46 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x5c */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0x60 */ &&op_push1_dest, &&op_push2_dest, &&op_push3_dest, &&op_push4_dest, &&op_push5_dest, &&op_push6_dest, &&op_push7_dest, &&op_push8_dest, &&op_push9_dest, &&op_push10_dest, &&op_push11_dest, &&op_push12_dest, &&op_push13_dest, &&op_push14_dest, &&op_push15_dest, &&op_push16_dest, &&op_push17_dest, &&op_push18_dest, &&op_push19_dest, &&op_push20_dest, &&op_push21_dest, &&op_push22_dest, &&op_push23_dest, &&op_push24_dest, &&op_push25_dest, &&op_push26_dest, &&op_push27_dest, &&op_push28_dest, &&op_push29_dest, &&op_push30_dest, &&op_push31_dest, &&op_push32_dest,
        /* 0x80 */ &&op_dup1_dest, &&op_dup2_dest, &&op_dup3_dest, &&op_dup4_dest, &&op_dup5_dest, &&op_dup6_dest, &&op_dup7_dest, &&op_dup8_dest, &&op_dup9_dest, &&op_dup10_dest, &&op_dup11_dest, &&op_dup12_dest, &&op_dup13_dest, &&op_dup14_dest, &&op_dup15_dest, &&op_dup16_dest,
        /* 0x90 */ &&op_swap1_dest, &&op_swap2_dest, &&op_swap3_dest, &&op_swap4_dest, &&op_swap5_dest, &&op_swap6_dest, &&op_swap7_dest, &&op_swap8_dest, &&op_swap9_dest, &&op_swap10_dest, &&op_swap11_dest, &&op_swap12_dest, &&op_swap13_dest, &&op_swap14_dest, &&op_swap15_dest, &&op_swap16_dest,
        /* 0xa0 */ &&op_log0_dest, &&op_log1_dest, &&op_log2_dest, &&op_log3_dest, &&op_log4_dest,
        /* 0xa5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xb5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xc5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xd5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xe5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xf0 */ &&op_create_dest,
        /* 0xf1 */ &&op_call_dest,
        /* 0xf2 */ &&op_callcode_dest,
        /* 0xf3 */ &&op_return_dest,
        /* 0xf4 */ &&op_delegatecall_dest,
        /* 0xf5 */ &&op_create2_dest,
        /* 0xf6 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xfa */ &&op_staticcall_dest,
        /* 0xfb */ &&op_undefined_dest,
        /* 0xfc */ &&op_undefined_dest,
        /* 0xfd */ &&op_revert_dest,
        /* 0xfe */ &&op_invalid_dest,
        /* 0xff */ &&op_selfdestruct_dest
        }
    };

    // If we haven't computed our jump labels yet, set *labels to point to the jump table, and return
    if (labels == nullptr)
    {
        return jump_tables;
    };
    // state.block = blocks[state.pc];

    DISPATCH_PUSH();
    
    op_add_dest:
        op_add(state);
        DISPATCH();

    op_mul_dest:
        op_mul(state);
        DISPATCH();

    op_sub_dest:
        op_sub(state);
        DISPATCH();

    op_div_dest:
        op_div(state);
        DISPATCH();

    op_sdiv_dest:
        op_sdiv(state);
        DISPATCH();

    op_mod_dest:
        op_mod(state);
        DISPATCH();

    op_smod_dest:
        op_smod(state);
        DISPATCH();

    op_addmod_dest:
        op_addmod(state);
        DISPATCH();

    op_mulmod_dest:
        op_mulmod(state);
        DISPATCH();

    op_exp_dest:
        op_exp(state);
        DISPATCH();

    op_signextend_dest:
        op_signextend(state);
        DISPATCH();

    op_lt_dest:
        op_lt(state);
        DISPATCH();

    op_gt_dest:
        op_gt(state);
        DISPATCH();

    op_slt_dest:
        op_slt(state);
        DISPATCH();

    op_sgt_dest:
        op_sgt(state);
        DISPATCH();

    op_eq_dest:
        op_eq(state);
        DISPATCH();

    op_iszero_dest:
        op_iszero(state);
        DISPATCH();

    op_and_dest:
        op_and(state);
        DISPATCH();

    op_or_dest:
        op_or(state);
        DISPATCH();

    op_xor_dest:
        op_xor(state);
        DISPATCH();

    op_not_dest:
        op_not(state);
        DISPATCH();

    op_byte_dest:
        op_byte(state);
        DISPATCH();

    op_shl_dest:
        op_shl(state);
        DISPATCH();

    op_shr_dest:
        op_shr(state);
        DISPATCH();

    op_sar_dest:
        op_sar(state);
        DISPATCH();

    op_sha3_dest:
        op_sha3(state);
        DISPATCH();

    op_address_dest:
        op_address(state);
        DISPATCH();

    op_balance_dest:
        op_balance(state);
        DISPATCH();

    op_origin_dest:
        op_origin(state);
        DISPATCH();

    op_caller_dest:
        op_caller(state);
        DISPATCH();

    op_callvalue_dest:
        op_callvalue(state);
        DISPATCH();

    op_calldataload_dest:
        op_calldataload(state);
        DISPATCH();

    op_calldatasize_dest:
        op_calldatasize(state);
        DISPATCH();

    op_calldatacopy_dest:
        op_calldatacopy(state);
        DISPATCH();

    op_codesize_dest:
        op_codesize(state);
        DISPATCH();

    op_codecopy_dest:
        op_codecopy(state);
        DISPATCH();

    op_gasprice_dest:
        op_gasprice(state);
        DISPATCH();

    op_extcodesize_dest:
        op_extcodesize(state);
        DISPATCH();

    op_extcodecopy_dest:
        op_extcodecopy(state);
        DISPATCH();

    op_returndatasize_dest:
        op_returndatasize(state);
        DISPATCH();

    op_returndatacopy_dest:
        op_returndatacopy(state);
        DISPATCH();

    op_extcodehash_dest:
        op_extcodehash(state);
        DISPATCH();

    op_blockhash_dest:
        op_blockhash(state);
        DISPATCH();

    op_coinbase_dest:
        op_coinbase(state);
        DISPATCH();

    op_timestamp_dest:
        op_timestamp(state);
        DISPATCH();

    op_number_dest:
        op_number(state);
        DISPATCH();

    op_difficulty_dest:
        op_difficulty(state);
        DISPATCH();

    op_gaslimit_dest:
        op_gaslimit(state);
        DISPATCH();

    op_pop_dest:
        op_pop(state);
        DISPATCH();
    op_mload_dest:
        op_mload(state);
        DISPATCH();

    op_mstore_dest:
        op_mstore(state);
        DISPATCH();

    op_mstore8_dest:
        op_mstore8(state);
        DISPATCH();

    op_sload_dest:
        op_sload(state);
        DISPATCH();

    op_sstore_dest:
        op_sstore(state);
        DISPATCH();

    op_jump_dest:
        op_jump(state);
        DISPATCH_PUSH();

    op_jumpi_dest:
        op_jumpi(state);
        DISPATCH_PUSH();

    op_pc_dest:
        op_pc(state);
        DISPATCH();

    op_msize_dest:
        op_msize(state);
        DISPATCH();

    op_gas_dest:
        op_gas(state, *instruction_data[state.pc]);
        DISPATCH();

    op_jumpdest_dest:
        op_jumpdest(state);
        DISPATCH();

    /**
     * push
    **/
    op_push1_dest:
        op_push1(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push2_dest:
        op_push2(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push3_dest:
        op_push3(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push4_dest:
        op_push4(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push5_dest:
        op_push5(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push6_dest:
        op_push6(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push7_dest:
        op_push7(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push8_dest:
        op_push8(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push9_dest:
        op_push9(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push10_dest:
        op_push10(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push11_dest:
        op_push11(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push12_dest:
        op_push12(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push13_dest:
        op_push13(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push14_dest:
        op_push14(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push15_dest:
        op_push15(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push16_dest:
        op_push16(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push17_dest:
        op_push17(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push18_dest:
        op_push18(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push19_dest:
        op_push19(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push20_dest:
        op_push20(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push21_dest:
        op_push21(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push22_dest:
        op_push22(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push23_dest:
        op_push23(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push24_dest:
        op_push24(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push25_dest:
        op_push25(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push26_dest:
        op_push26(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push27_dest:
        op_push27(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push28_dest:
        op_push28(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push29_dest:
        op_push29(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push30_dest:
        op_push30(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push31_dest:
        op_push31(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push32_dest:
        op_push32(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    /**
     * dup
    **/
    op_dup1_dest:
        op_dup1(state);
        DISPATCH();

    op_dup2_dest:
        op_dup2(state);
        DISPATCH();

    op_dup3_dest:
        op_dup3(state);
        DISPATCH();
    
    op_dup4_dest:
        op_dup4(state);
        DISPATCH();
    
    op_dup5_dest:
        op_dup5(state);
        DISPATCH();
    
    op_dup6_dest:
        op_dup6(state);
        DISPATCH();
    
    op_dup7_dest:
        op_dup7(state);
        DISPATCH();
    
    op_dup8_dest:
        op_dup8(state);
        DISPATCH();
    
    op_dup9_dest:
        op_dup9(state);
        DISPATCH();
    
    op_dup10_dest:
        op_dup10(state);
        DISPATCH();

    op_dup11_dest:
        op_dup11(state);
        DISPATCH();

    op_dup12_dest:
        op_dup12(state);
        DISPATCH();

    op_dup13_dest:
        op_dup13(state);
        DISPATCH();

    op_dup14_dest:
        op_dup14(state);
        DISPATCH();

    op_dup15_dest:
        op_dup15(state);
        DISPATCH();

    op_dup16_dest:
        op_dup16(state);
        DISPATCH();

    /**
     * swap
    **/
    op_swap1_dest:
        op_swap1(state);
        DISPATCH();

    op_swap2_dest:
        op_swap2(state);
        DISPATCH();

    op_swap3_dest:
        op_swap3(state);
        DISPATCH();
    
    op_swap4_dest:
        op_swap4(state);
        DISPATCH();
    
    op_swap5_dest:
        op_swap5(state);
        DISPATCH();
    
    op_swap6_dest:
        op_swap6(state);
        DISPATCH();
    
    op_swap7_dest:
        op_swap7(state);
        DISPATCH();
    
    op_swap8_dest:
        op_swap8(state);
        DISPATCH();
    
    op_swap9_dest:
        op_swap9(state);
        DISPATCH();
    
    op_swap10_dest:
        op_swap10(state);
        DISPATCH();

    op_swap11_dest:
        op_swap11(state);
        DISPATCH();

    op_swap12_dest:
        op_swap12(state);
        DISPATCH();

    op_swap13_dest:
        op_swap13(state);
        DISPATCH();

    op_swap14_dest:
        op_swap14(state);
        DISPATCH();

    op_swap15_dest:
        op_swap15(state);
        DISPATCH();

    op_swap16_dest:
        op_swap16(state);
        DISPATCH();

    op_log0_dest:
        op_log0(state);
        DISPATCH();

    op_log1_dest:
        op_log1(state);
        DISPATCH();
  
    op_log2_dest:
        op_log2(state);
        DISPATCH();

    op_log3_dest:
        op_log3(state);
        DISPATCH();

    op_log4_dest:
        op_log4(state);
        DISPATCH();

    op_create_dest:
        op_create(state, *instruction_data[state.pc]);
        DISPATCH();

    op_call_dest:
        op_call(state, *instruction_data[state.pc]);
        DISPATCH();

    op_callcode_dest:
        op_callcode(state, *instruction_data[state.pc]);
        DISPATCH();

    op_return_dest:
        op_return(state);
        goto op_stop_dest;

    op_delegatecall_dest:
        op_delegatecall(state, *instruction_data[state.pc]);
        DISPATCH();

    op_create2_dest:
        op_create2(state, *instruction_data[state.pc]);
        DISPATCH();

    op_staticcall_dest:
        op_staticcall(state, *instruction_data[state.pc]);
        DISPATCH();

    op_revert_dest:
        op_revert(state);
        goto op_stop_dest;

    op_invalid_dest:
        state.status = EVMC_INVALID_INSTRUCTION;
        goto op_stop_dest;

    op_selfdestruct_dest:
        op_selfdestruct(state);
        goto op_stop_dest;

    op_undefined_dest:
        state.status = EVMC_UNDEFINED_INSTRUCTION;
        goto op_stop_dest;

    // op_staticviolation_dest:
    //    state.status = EVMC_STATIC_MODE_VIOLATION;
        // fallthrough

    op_stop_dest:
    return jump_tables;
}

static execution_state dummy_state = execution_state();

opcode_table create_op_table_istanbul() noexcept
{
    static opcode_table table = interpret(nullptr, dummy_state, nullptr, nullptr);
    return table;
}

opcode_table create_op_table_petersburg() noexcept
{
    return create_op_table_istanbul();
}

opcode_table create_op_table_constantinople() noexcept
{
    return create_op_table_petersburg();
}

opcode_table create_op_table_byzantium() noexcept
{
    static opcode_table table = create_op_table_constantinople();
    table.table[OP_SHL] = table.table[0];
    table.table[OP_SHR] = table.table[0];
    table.table[OP_SAR] = table.table[0];
    table.table[OP_EXTCODEHASH] = table.table[0];
    table.table[OP_CREATE2] = table.table[0];
    return table;
}

opcode_table create_op_table_homestead() noexcept
{
    static opcode_table table = create_op_table_byzantium();
    table.table[OP_RETURNDATASIZE] = table.table[0];
    table.table[OP_RETURNDATACOPY] = table.table[0];
    table.table[OP_STATICCALL] = table.table[0];
    table.table[OP_REVERT] = table.table[0];
    return table;
}

opcode_table create_op_table_frontier() noexcept
{
    static opcode_table table = create_op_table_homestead();
    table.table[OP_DELEGATECALL] = table.table[0];
    return table;
}

constexpr auto num_revisions = int{EVMC_MAX_REVISION + 1};
static const void* op_table[num_revisions][256] = {};

const auto op_table_initialized = []() noexcept
{
    static void** frontier = create_op_table_frontier().table;
    static void** homestead = create_op_table_homestead().table;
    static void** byzantium = create_op_table_byzantium().table;
    static void** constantinople = create_op_table_constantinople().table;
    static void** petersburg = create_op_table_petersburg().table;
    static void** istanbul = create_op_table_istanbul().table;
    std::cout << "running memcpy" << std::endl;
    memcpy(&op_table[EVMC_FRONTIER], frontier, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_HOMESTEAD], homestead, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_TANGERINE_WHISTLE], homestead, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_SPURIOUS_DRAGON], homestead, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_BYZANTIUM], byzantium, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_CONSTANTINOPLE], constantinople, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_CONSTANTINOPLE2], petersburg, sizeof(void*) * 256);
    memcpy(&op_table[EVMC_ISTANBUL], istanbul, sizeof(void*) * 256);
    return true;
}
();


evmc_result execute(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
    size_t max_memory = 40000;
    execution_state state;
    state.max_potential_memory = max_memory;
    // TODO fix this :/
    // std::cout << "msg gas = " << (size_t)msg->gas << std::endl;
    // std::cout << "max memory = " << (size_t)max_memory << std::endl;
    state.memory = (uint8_t*)calloc(max_memory + 32, sizeof(uint8_t));
    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = ctx;
    state.gas_left = msg->gas;
    state.rev = rev;
    state.exp_cost = rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    state.storage_repeated_cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
    state.msize = 0;


    // opcode_tables jump_tables = interpret(nullptr, state, nullptr, nullptr);
    // const void** jump_table = get_function_table(rev);
    // switch (rev) {
    //     case EVMC_FRONTIER: {
    //         jump_table = &jump_tables.tables[0][0];
    //         break;
    //     }
    //     case EVMC_TANGERINE_WHISTLE:
    //     case EVMC_SPURIOUS_DRAGON:
    //     case EVMC_HOMESTEAD: {
    //         jump_table = &jump_tables.tables[1][0];
    //         break;
    //     };
    //     case EVMC_BYZANTIUM: {
    //         jump_table = &jump_tables.tables[2][0];
    //         break;
    //     };
    //     case EVMC_CONSTANTINOPLE:
    //         [[fallthrough]]
    //     case EVMC_CONSTANTINOPLE2:
    //         [[fallthrough]]
    //     case EVMC_ISTANBUL:
    //         jump_table = &jump_tables.tables[3][0];
    //         break;
    //     default:
    //         jump_table = &jump_tables.tables[3][0];
    //         break;
    // };

    const void* labels[code_size + 2];
    const block_info* blocks[code_size + 2];
    const instruction_info* instruction_data[code_size];

    code_analysis_alt analysis_alt = analyze_alt(
        labels, blocks, instruction_data, rev, code_size, code, op_table[rev]
    );

    if (state.memory == nullptr)
    {
        // ??!??!!!?
        state.status = EVMC_REJECTED;
        state.pc = state.code_size;
    }
    else
    {
        interpret(labels, state, blocks, instruction_data);
    }

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
    free(state.memory);
    state.memory = nullptr;
    return result;
}

evmc_result execute_old(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
        // TODO ensure this call succeeds?
    // compute maximum amount of memory this call can consume
    // auto gas_limit = ctx->host->get_tx_context(ctx).block_gas_limit;
    // std::cout << "gas limit ?" << gas_limit << std::endl;
    // int64_t w = (int64_t)(((long double)std::sqrt(2359296 + 2048 * (long double)gas_limit)) / 2);
    // size_t max_memory = (32 * (size_t)w) + 32;
    // std::cout << "max_memory = " << max_memory << std::endl;



    size_t max_memory = 40000;
    // 3.w + w.w / 512 - g = 0
    // 1536.w + w.w - 512.g = 0
    
    // w = (-1536 + sqrt(2,359,296 + 2048 * g))/ 2;
    // auto temp = std::max(int64_t(msg->gas), int64_t(100000));
    // int64_t w = (int64_t)(((long double)std::sqrt(2359296 + 2048 * (long double)temp)) / 2);
    // size_t max_memory = (32 * w) + 32;
    //size_t max_memory = 100000;
    execution_state state;
    state.max_potential_memory = max_memory;
    // TODO fix this :/
    // std::cout << "msg gas = " << (size_t)msg->gas << std::endl;
    // std::cout << "max memory = " << (size_t)max_memory << std::endl;
    state.memory = (uint8_t*)calloc(max_memory + 32, sizeof(uint8_t));
    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = ctx;
    state.gas_left = msg->gas;
    state.rev = rev;
    state.exp_cost = rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    state.storage_repeated_cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
    state.msize = 0;
    const void* jump_table[256] = {
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
        /* 0x0c */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x21 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x46 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
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
        /* 0x5c */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0x60 */ &&op_push1_dest, &&op_push2_dest, &&op_push3_dest, &&op_push4_dest, &&op_push5_dest, &&op_push6_dest, &&op_push7_dest, &&op_push8_dest, &&op_push9_dest, &&op_push10_dest, &&op_push11_dest, &&op_push12_dest, &&op_push13_dest, &&op_push14_dest, &&op_push15_dest, &&op_push16_dest, &&op_push17_dest, &&op_push18_dest, &&op_push19_dest, &&op_push20_dest, &&op_push21_dest, &&op_push22_dest, &&op_push23_dest, &&op_push24_dest, &&op_push25_dest, &&op_push26_dest, &&op_push27_dest, &&op_push28_dest, &&op_push29_dest, &&op_push30_dest, &&op_push31_dest, &&op_push32_dest,
        /* 0x80 */ &&op_dup1_dest, &&op_dup2_dest, &&op_dup3_dest, &&op_dup4_dest, &&op_dup5_dest, &&op_dup6_dest, &&op_dup7_dest, &&op_dup8_dest, &&op_dup9_dest, &&op_dup10_dest, &&op_dup11_dest, &&op_dup12_dest, &&op_dup13_dest, &&op_dup14_dest, &&op_dup15_dest, &&op_dup16_dest,
        /* 0x90 */ &&op_swap1_dest, &&op_swap2_dest, &&op_swap3_dest, &&op_swap4_dest, &&op_swap5_dest, &&op_swap6_dest, &&op_swap7_dest, &&op_swap8_dest, &&op_swap9_dest, &&op_swap10_dest, &&op_swap11_dest, &&op_swap12_dest, &&op_swap13_dest, &&op_swap14_dest, &&op_swap15_dest, &&op_swap16_dest,
        /* 0xa0 */ &&op_log0_dest, &&op_log1_dest, &&op_log2_dest, &&op_log3_dest, &&op_log4_dest,
        /* 0xa5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xb5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xc5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xd5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xe5 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xf0 */ &&op_create_dest,
        /* 0xf1 */ &&op_call_dest,
        /* 0xf2 */ &&op_callcode_dest,
        /* 0xf3 */ &&op_return_dest,
        /* 0xf4 */ &&op_delegatecall_dest,
        /* 0xf5 */ &&op_create2_dest,
        /* 0xf6 */ &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest, &&op_undefined_dest,
        /* 0xfa */ &&op_staticcall_dest,
        /* 0xfb */ &&op_undefined_dest,
        /* 0xfc */ &&op_undefined_dest,
        /* 0xfd */ &&op_revert_dest,
        /* 0xfe */ &&op_invalid_dest,
        /* 0xff */ &&op_selfdestruct_dest,
    };

    switch (rev) {
        case EVMC_FRONTIER: {
            jump_table[OP_DELEGATECALL] = &&op_undefined_dest;
            [[fallthrough]];
        }
        case EVMC_TANGERINE_WHISTLE:
        case EVMC_SPURIOUS_DRAGON:
        case EVMC_HOMESTEAD: {
            jump_table[OP_RETURNDATASIZE] = &&op_undefined_dest;
            jump_table[OP_RETURNDATACOPY] = &&op_undefined_dest;
            jump_table[OP_STATICCALL] = &&op_undefined_dest;
            jump_table[OP_REVERT] = &&op_undefined_dest;
            [[fallthrough]];
        };
        case EVMC_BYZANTIUM: {
            jump_table[OP_SHL] = &&op_undefined_dest;
            jump_table[OP_SHR] = &&op_undefined_dest;
            jump_table[OP_SAR] = &&op_undefined_dest;
            jump_table[OP_EXTCODEHASH] = &&op_undefined_dest;
            jump_table[OP_CREATE2] = &&op_undefined_dest;
            [[fallthrough]];
        };
        case EVMC_CONSTANTINOPLE:
            [[fallthrough]]
        case EVMC_CONSTANTINOPLE2:
            [[fallthrough]]
        case EVMC_ISTANBUL:
            break;
    };
    // TODO, encode this into opcodes so that our tables can be constant
    if (state.msg->flags & EVMC_STATIC)
    {
        jump_table[OP_SSTORE] = &&op_staticviolation_dest;
        jump_table[OP_LOG0] = &&op_staticviolation_dest;
        jump_table[OP_LOG1] = &&op_staticviolation_dest;
        jump_table[OP_LOG2] = &&op_staticviolation_dest;
        jump_table[OP_LOG3] = &&op_staticviolation_dest;
        jump_table[OP_LOG4] = &&op_staticviolation_dest;
        jump_table[OP_CREATE] = &&op_staticviolation_dest;
        jump_table[OP_CREATE2] = &&op_staticviolation_dest;
        jump_table[OP_SELFDESTRUCT] = &&op_staticviolation_dest;
    }
    const void* labels[code_size + 2];
    const block_info* blocks[code_size + 2];
    const instruction_info* instruction_data[code_size];

    code_analysis_alt analysis_alt = analyze_alt(
        labels, &blocks[0], &instruction_data[0], rev, code_size, code, jump_table
    );

    if (state.memory == nullptr)
    {
        // ??!??!!!?
        state.status = EVMC_REJECTED;
        state.pc = state.code_size;
    }
    // state.block = blocks[state.pc];
    DISPATCH_PUSH();
    
    op_add_dest:
        op_add(state);
        DISPATCH();

    op_mul_dest:
        op_mul(state);
        DISPATCH();

    op_sub_dest:
        op_sub(state);
        DISPATCH();

    op_div_dest:
        op_div(state);
        DISPATCH();

    op_sdiv_dest:
        op_sdiv(state);
        DISPATCH();

    op_mod_dest:
        op_mod(state);
        DISPATCH();

    op_smod_dest:
        op_smod(state);
        DISPATCH();

    op_addmod_dest:
        op_addmod(state);
        DISPATCH();

    op_mulmod_dest:
        op_mulmod(state);
        DISPATCH();

    op_exp_dest:
        op_exp(state);
        DISPATCH();

    op_signextend_dest:
        op_signextend(state);
        DISPATCH();

    op_lt_dest:
        op_lt(state);
        DISPATCH();

    op_gt_dest:
        op_gt(state);
        DISPATCH();

    op_slt_dest:
        op_slt(state);
        DISPATCH();

    op_sgt_dest:
        op_sgt(state);
        DISPATCH();

    op_eq_dest:
        op_eq(state);
        DISPATCH();

    op_iszero_dest:
        op_iszero(state);
        DISPATCH();

    op_and_dest:
        op_and(state);
        DISPATCH();

    op_or_dest:
        op_or(state);
        DISPATCH();

    op_xor_dest:
        op_xor(state);
        DISPATCH();

    op_not_dest:
        op_not(state);
        DISPATCH();

    op_byte_dest:
        op_byte(state);
        DISPATCH();

    op_shl_dest:
        op_shl(state);
        DISPATCH();

    op_shr_dest:
        op_shr(state);
        DISPATCH();

    op_sar_dest:
        op_sar(state);
        DISPATCH();

    op_sha3_dest:
        op_sha3(state);
        DISPATCH();

    op_address_dest:
        op_address(state);
        DISPATCH();

    op_balance_dest:
        op_balance(state);
        DISPATCH();

    op_origin_dest:
        op_origin(state);
        DISPATCH();

    op_caller_dest:
        op_caller(state);
        DISPATCH();

    op_callvalue_dest:
        op_callvalue(state);
        DISPATCH();

    op_calldataload_dest:
        op_calldataload(state);
        DISPATCH();

    op_calldatasize_dest:
        op_calldatasize(state);
        DISPATCH();

    op_calldatacopy_dest:
        op_calldatacopy(state);
        DISPATCH();

    op_codesize_dest:
        op_codesize(state);
        DISPATCH();

    op_codecopy_dest:
        op_codecopy(state);
        DISPATCH();

    op_gasprice_dest:
        op_gasprice(state);
        DISPATCH();

    op_extcodesize_dest:
        op_extcodesize(state);
        DISPATCH();

    op_extcodecopy_dest:
        op_extcodecopy(state);
        DISPATCH();

    op_returndatasize_dest:
        op_returndatasize(state);
        DISPATCH();

    op_returndatacopy_dest:
        op_returndatacopy(state);
        DISPATCH();

    op_extcodehash_dest:
        op_extcodehash(state);
        DISPATCH();

    op_blockhash_dest:
        op_blockhash(state);
        DISPATCH();

    op_coinbase_dest:
        op_coinbase(state);
        DISPATCH();

    op_timestamp_dest:
        op_timestamp(state);
        DISPATCH();

    op_number_dest:
        op_number(state);
        DISPATCH();

    op_difficulty_dest:
        op_difficulty(state);
        DISPATCH();

    op_gaslimit_dest:
        op_gaslimit(state);
        DISPATCH();

    op_pop_dest:
        op_pop(state);
        DISPATCH();
    op_mload_dest:
        op_mload(state);
        DISPATCH();

    op_mstore_dest:
        op_mstore(state);
        DISPATCH();

    op_mstore8_dest:
        op_mstore8(state);
        DISPATCH();

    op_sload_dest:
        op_sload(state);
        DISPATCH();

    op_sstore_dest:
        op_sstore(state);
        DISPATCH();

    op_jump_dest:
        op_jump(state);
        DISPATCH_PUSH();

    op_jumpi_dest:
        op_jumpi(state);
        DISPATCH_PUSH();

    op_pc_dest:
        op_pc(state);
        DISPATCH();

    op_msize_dest:
        op_msize(state);
        DISPATCH();

    op_gas_dest:
        op_gas(state, *instruction_data[state.pc]);
        DISPATCH();

    op_jumpdest_dest:
        op_jumpdest(state);
        DISPATCH();

    /**
     * push
    **/
    op_push1_dest:
        op_push1(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push2_dest:
        op_push2(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push3_dest:
        op_push3(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push4_dest:
        op_push4(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push5_dest:
        op_push5(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push6_dest:
        op_push6(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push7_dest:
        op_push7(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push8_dest:
        op_push8(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push9_dest:
        op_push9(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();
    
    op_push10_dest:
        op_push10(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push11_dest:
        op_push11(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push12_dest:
        op_push12(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push13_dest:
        op_push13(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push14_dest:
        op_push14(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push15_dest:
        op_push15(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push16_dest:
        op_push16(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push17_dest:
        op_push17(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push18_dest:
        op_push18(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push19_dest:
        op_push19(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push20_dest:
        op_push20(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push21_dest:
        op_push21(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push22_dest:
        op_push22(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push23_dest:
        op_push23(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push24_dest:
        op_push24(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push25_dest:
        op_push25(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push26_dest:
        op_push26(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push27_dest:
        op_push27(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push28_dest:
        op_push28(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push29_dest:
        op_push29(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push30_dest:
        op_push30(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push31_dest:
        op_push31(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    op_push32_dest:
        op_push32(state, *instruction_data[state.pc]);
        DISPATCH_PUSH();

    /**
     * dup
    **/
    op_dup1_dest:
        op_dup1(state);
        DISPATCH();

    op_dup2_dest:
        op_dup2(state);
        DISPATCH();

    op_dup3_dest:
        op_dup3(state);
        DISPATCH();
    
    op_dup4_dest:
        op_dup4(state);
        DISPATCH();
    
    op_dup5_dest:
        op_dup5(state);
        DISPATCH();
    
    op_dup6_dest:
        op_dup6(state);
        DISPATCH();
    
    op_dup7_dest:
        op_dup7(state);
        DISPATCH();
    
    op_dup8_dest:
        op_dup8(state);
        DISPATCH();
    
    op_dup9_dest:
        op_dup9(state);
        DISPATCH();
    
    op_dup10_dest:
        op_dup10(state);
        DISPATCH();

    op_dup11_dest:
        op_dup11(state);
        DISPATCH();

    op_dup12_dest:
        op_dup12(state);
        DISPATCH();

    op_dup13_dest:
        op_dup13(state);
        DISPATCH();

    op_dup14_dest:
        op_dup14(state);
        DISPATCH();

    op_dup15_dest:
        op_dup15(state);
        DISPATCH();

    op_dup16_dest:
        op_dup16(state);
        DISPATCH();

    /**
     * swap
    **/
    op_swap1_dest:
        op_swap1(state);
        DISPATCH();

    op_swap2_dest:
        op_swap2(state);
        DISPATCH();

    op_swap3_dest:
        op_swap3(state);
        DISPATCH();
    
    op_swap4_dest:
        op_swap4(state);
        DISPATCH();
    
    op_swap5_dest:
        op_swap5(state);
        DISPATCH();
    
    op_swap6_dest:
        op_swap6(state);
        DISPATCH();
    
    op_swap7_dest:
        op_swap7(state);
        DISPATCH();
    
    op_swap8_dest:
        op_swap8(state);
        DISPATCH();
    
    op_swap9_dest:
        op_swap9(state);
        DISPATCH();
    
    op_swap10_dest:
        op_swap10(state);
        DISPATCH();

    op_swap11_dest:
        op_swap11(state);
        DISPATCH();

    op_swap12_dest:
        op_swap12(state);
        DISPATCH();

    op_swap13_dest:
        op_swap13(state);
        DISPATCH();

    op_swap14_dest:
        op_swap14(state);
        DISPATCH();

    op_swap15_dest:
        op_swap15(state);
        DISPATCH();

    op_swap16_dest:
        op_swap16(state);
        DISPATCH();

    op_log0_dest:
        op_log0(state);
        DISPATCH();

    op_log1_dest:
        op_log1(state);
        DISPATCH();
  
    op_log2_dest:
        op_log2(state);
        DISPATCH();

    op_log3_dest:
        op_log3(state);
        DISPATCH();

    op_log4_dest:
        op_log4(state);
        DISPATCH();

    op_create_dest:
        op_create(state, *instruction_data[state.pc]);
        DISPATCH();

    op_call_dest:
        op_call(state, *instruction_data[state.pc]);
        DISPATCH();

    op_callcode_dest:
        op_callcode(state, *instruction_data[state.pc]);
        DISPATCH();

    op_return_dest:
        op_return(state);
        goto op_stop_dest;

    op_delegatecall_dest:
        op_delegatecall(state, *instruction_data[state.pc]);
        DISPATCH();

    op_create2_dest:
        op_create2(state, *instruction_data[state.pc]);
        DISPATCH();

    op_staticcall_dest:
        op_staticcall(state, *instruction_data[state.pc]);
        DISPATCH();

    op_revert_dest:
        op_revert(state);
        goto op_stop_dest;

    op_invalid_dest:
        state.status = EVMC_INVALID_INSTRUCTION;
        goto op_stop_dest;

    op_selfdestruct_dest:
        op_selfdestruct(state);
        goto op_stop_dest;

    op_undefined_dest:
        state.status = EVMC_UNDEFINED_INSTRUCTION;
        goto op_stop_dest;

    op_staticviolation_dest:
        state.status = EVMC_STATIC_MODE_VIOLATION;
        // fallthrough

    op_stop_dest:

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
    free(state.memory);
    state.memory = nullptr;
    return result;
}

}  // namespace evmone
