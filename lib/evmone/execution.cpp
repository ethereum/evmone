// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"
#include "opcodes.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

namespace evmone
{
namespace
{
bool is_terminator(uint8_t c) noexcept
{
    return c == OP_JUMP || c == OP_JUMPI || c == OP_STOP || c == OP_RETURN || c == OP_REVERT ||
        c == OP_SELFDESTRUCT;
}

bytes32 init_zero_bytes() noexcept
{
    bytes32 data;
    for (auto& b : data)
        b = 0;
    return data;
}
static const bytes32 zero_bytes = init_zero_bytes();

}  // namespace

evmc_result execute(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
    auto* instr_table = evmc_get_instruction_metrics_table(rev);
    // bytes32 zero_bytes;

    execution_state state;
    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = ctx;
    state.gas_left = msg->gas;
    state.rev = rev;
    state.exp_cost = rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    state.storage_repeated_cost = rev == EVMC_CONSTANTINOPLE ? 200 : 5000;
    state.max_code_size = 0xffffffff; // TODO FIX THIS
    void* jump_table[259] = {
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
    void* labels[code_size + 1];
    block_info* blocks[code_size + 1];
    instruction_info* instruction_data[code_size];
    code_analysis_alt analysis_alt;

    block_info* block = nullptr;

    /* so, apparently this is valid...
    size_t test_label = *static_cast<size_t*>(&&op_stop_dest);
    goto *&test_label;
    */
    for (size_t i = 0; i < code_size; ++i)
    {
        uint8_t c = code[i];
        labels[i] = jump_table[c];
        if (!block || (c == OP_JUMPDEST)) {
            block = &analysis_alt.blocks.emplace_back();
            blocks[i] = block;
        } else {
            blocks[i] = nullptr;
        }
        auto metrics = instr_table[c];
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - block->stack_diff;
        block->stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, block->stack_diff);
        if (c >= OP_PUSH1 && c <= OP_PUSH32)
        {
            ++i;
            size_t push_size = size_t(c - OP_PUSH1 + 1);
            size_t leading_zeroes = size_t(32 - push_size);
            analysis_alt.instruction_data.emplace_back();
            instruction_info& instruction = analysis_alt.instruction_data.back();
            memcpy(&instruction.push_data[0], &zero_bytes, 32);
            memcpy(&instruction.push_data[leading_zeroes], code + i, push_size);
            instruction_data[i - 1] = &instruction;
            i += push_size - 1;
        }
        else if (c == OP_GAS || c == OP_DELEGATECALL || c == OP_CALL || c == OP_CALLCODE ||
                 c == OP_STATICCALL || c == OP_CREATE || c == OP_CREATE2)
        {
            // instruction_info* instruction = &analysis_alt.instruction_data.emplace_back();
            // instruction->gas_data = block->gas_cost;
            analysis_alt.instruction_data.emplace_back();
            instruction_info& instruction = analysis_alt.instruction_data.back();
            instruction.gas_data = block->gas_cost;
            instruction_data[i] = &instruction;
        }
        else if (is_terminator(c))
        {
            instruction_data[i] = nullptr;
            block = nullptr;
        }
        else
        {
            instruction_data[i] = nullptr;
        }
    }
    blocks[code_size] = nullptr;
    labels[code_size] = &&op_stop_dest;
    // op_stop_dest is a label. This is... of 'void' type?
    // dereferencing op_stop_dest TWICE gets us to a void pointer*
    // members of this array are of void pointer* type
    // which are then referenced again to get to a label
    // sooo. 1st dereference = memory location of label
    // 2nd dereference = memory location of memory location of label
    // referencing the 2nd dereference layer gives us the memory location of label
    // referencing this reference gets us back to the label itself??

    // label = position in the program counter we need to jump to
    // dereference of label = position in memory where this label is stored
    // 2nd dereference = memory location of memory where label location is stored
    // goto op_stop_dest;
    check_block(state, blocks[state.pc]);
    goto *labels[state.pc];
    // oh crud
    op_add_dest:
        op_add(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_mul_dest:
        op_mul(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sub_dest:
        op_sub(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_div_dest:
        op_div(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sdiv_dest:
        op_sdiv(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_mod_dest:
        op_mod(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_smod_dest:
        op_smod(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_addmod_dest:
        op_addmod(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_mulmod_dest:
        op_mulmod(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_exp_dest:
        op_exp(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_signextend_dest:
        op_signextend(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_lt_dest:
        op_lt(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_gt_dest:
        op_gt(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_slt_dest:
        op_slt(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sgt_dest:
        op_sgt(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_eq_dest:
        op_eq(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_iszero_dest:
        op_iszero(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_and_dest:
        op_and(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_or_dest:
        op_or(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_xor_dest:
        op_xor(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_not_dest:
        op_not(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_byte_dest:
        op_byte(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_shl_dest:
        op_shl(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_shr_dest:
        op_shr(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sar_dest:
        op_sar(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sha3_dest:
        op_sha3(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_address_dest:
        op_address(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_balance_dest:
        op_balance(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_origin_dest:
        op_origin(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_caller_dest:
        op_caller(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_callvalue_dest:
        op_callvalue(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_calldataload_dest:
        op_calldataload(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_calldatasize_dest:
        op_calldatasize(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_calldatacopy_dest:
        op_calldatacopy(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_codesize_dest:
        op_codesize(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_codecopy_dest:
        op_codecopy(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_gasprice_dest:
        op_gasprice(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_extcodesize_dest:
        op_extcodesize(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_extcodecopy_dest:
        op_extcodecopy(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_returndatasize_dest:
        op_returndatasize(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_returndatacopy_dest:
        op_returndatacopy(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_extcodehash_dest:
        op_extcodehash(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_blockhash_dest:
        op_blockhash(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_coinbase_dest:
        op_coinbase(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_timestamp_dest:
        op_timestamp(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_number_dest:
        op_number(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_difficulty_dest:
        op_difficulty(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_gaslimit_dest:
        op_gaslimit(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_pop_dest:
        op_pop(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
        
    op_mload_dest:
        op_mload(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_mstore_dest:
        op_mstore(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_mstore8_dest:
        op_mstore8(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sload_dest:
        op_sload(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_sstore_dest:
        op_sstore(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_jump_dest:
        op_jump(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_jumpi_dest:
        op_jumpi(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_pc_dest:
        op_pc(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_msize_dest:
        op_msize(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_gas_dest:
        op_gas(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_jumpdest_dest:
        op_jumpdest(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    /**
     * push
    **/
    op_push1_dest:
        op_push1(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push2_dest:
        op_push2(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push3_dest:
        op_push3(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push4_dest:
        op_push4(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push5_dest:
        op_push5(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push6_dest:
        op_push6(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push7_dest:
        op_push7(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push8_dest:
        op_push8(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push9_dest:
        op_push9(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_push10_dest:
        op_push10(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push11_dest:
        op_push11(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push12_dest:
        op_push12(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push13_dest:
        op_push13(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push14_dest:
        op_push14(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push15_dest:
        op_push15(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push16_dest:
        op_push16(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push17_dest:
        op_push17(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push18_dest:
        op_push18(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push19_dest:
        op_push19(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push20_dest:
        op_push20(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push21_dest:
        op_push21(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push22_dest:
        op_push22(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push23_dest:
        op_push23(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push24_dest:
        op_push24(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push25_dest:
        op_push25(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push26_dest:
        op_push26(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push27_dest:
        op_push27(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push28_dest:
        op_push28(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push29_dest:
        op_push29(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push30_dest:
        op_push30(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push31_dest:
        op_push31(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_push32_dest:
        op_push32(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    /**
     * dup
    **/
    op_dup1_dest:
        op_dup1(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup2_dest:
        op_dup2(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup3_dest:
        op_dup3(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup4_dest:
        op_dup4(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup5_dest:
        op_dup5(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup6_dest:
        op_dup6(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup7_dest:
        op_dup7(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup8_dest:
        op_dup8(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup9_dest:
        op_dup9(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_dup10_dest:
        op_dup10(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup11_dest:
        op_dup11(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup12_dest:
        op_dup12(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup13_dest:
        op_dup13(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup14_dest:
        op_dup14(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup15_dest:
        op_dup15(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_dup16_dest:
        op_dup16(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    /**
     * swap
    **/
    op_swap1_dest:
        op_swap1(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap2_dest:
        op_swap2(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap3_dest:
        op_swap3(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap4_dest:
        op_swap4(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap5_dest:
        op_swap5(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap6_dest:
        op_swap6(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap7_dest:
        op_swap7(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap8_dest:
        op_swap8(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap9_dest:
        op_swap9(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
    
    op_swap10_dest:
        op_swap10(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap11_dest:
        op_swap11(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap12_dest:
        op_swap12(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap13_dest:
        op_swap13(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap14_dest:
        op_swap14(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap15_dest:
        op_swap15(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_swap16_dest:
        op_swap16(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_log0_dest:
        op_log0(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_log1_dest:
        op_log1(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];
  
    op_log2_dest:
        op_log2(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_log3_dest:
        op_log3(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_log4_dest:
        op_log4(state);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_create_dest:
        op_create(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_call_dest:
        op_call(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_callcode_dest:
        op_call(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_return_dest:
        op_return(state);
        goto *labels[state.pc];

    op_delegatecall_dest:
        op_delegatecall(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_create2_dest:
        op_create2(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_staticcall_dest:
        op_staticcall(state, *instruction_data[state.pc]);
        check_block(state, blocks[state.pc]);
        goto *labels[state.pc];

    op_revert_dest:
        op_revert(state);
        goto *labels[state.pc];

    op_invalid_dest:
        state.status = EVMC_INVALID_INSTRUCTION;
        goto op_stop_dest;

    op_selfdestruct_dest:
        op_selfdestruct(state);
        goto *labels[state.pc];

    op_undefined_dest:
        state.status = EVMC_UNDEFINED_INSTRUCTION;
        goto op_stop_dest;
    op_staticviolation_dest:
        state.status = EVMC_STATIC_MODE_VIOLATION;
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

    return result;

/*
    while (state.run)
    {
        void* jumpdest = labels[state.pc];
        goto foo;
        goto *jumpdest;
        foo:
        auto& instr = blocks[state.pc]
        if (instr.block_index >= 0)
        {
            auto& block = analysis.blocks[static_cast<size_t>(instr.block_index)];
            state.gas_left -= block.gas_cost;
            // we assume this statement is not triggered, to avoid
            // pipeline stalls when the program is running
            if (__builtin_expect(state.gas_left < 0, 0))
            {
                state.status = EVMC_OUT_OF_GAS;
                break;
            }
            // (see above)
            if (__builtin_expect(static_cast<int>(state.stack_ptr) < block.stack_req, 0))
            {
                state.status = EVMC_STACK_UNDERFLOW;
                break;
            }
            // (see above)
            if (__builtin_expect(static_cast<int>(state.stack_ptr) + block.stack_max > 1024, 0))
            {
                state.status = EVMC_STACK_OVERFLOW;
                break;
            }

            state.current_block_cost = block.gas_cost;
        }

        // goto jumpdest;
        // Advance the PC not to allow jump opcodes to overwrite it.
        ++state.pc;
        instr.fn(state, instr.arg);
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

    return result; */
}

}  // namespace evmone
