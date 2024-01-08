// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles_evm.hpp"
#include "ecc_evm.hpp"
#include "utils.hpp"

namespace evmmax::evm
{
using namespace evmmax::evm::utils;

bytecode add(const uint256& mod, const uint256& b3, field_inv_f inv) noexcept
{
    using namespace evmc::literals;

    const auto mod_size = sizeof(mod);

    // mod, x1, y1, x2, y2, b3
    auto code_init = calldatacopy(push(0), push(0), push(mod_size * 4));
    const auto x1_mem_offset = 0;
    const auto x2_mem_offset = mod_size * 2;
    const auto mod_mem_offset = mod_size * 4;
    const auto b3_mem_offset = mod_size * 5;

    // Check that point x1 is not inf.
    code_init += mload(x1_mem_offset);
    code_init += mload(x1_mem_offset + mod_size);
    code_init += bytecode(OP_OR);
    code_init += push(0xFFFF);
    const auto if1_end_placeholder_start = code_init.size() - 2;
    code_init += bytecode(OP_JUMPI);
    code_init += ret(x2_mem_offset, mod_size * 2);
    code_init += bytecode(OP_JUMPDEST);
    intx::be::unsafe::store(
        &code_init[if1_end_placeholder_start], static_cast<uint16_t>(code_init.size() - 1));

    // Check that point x2 is not inf.
    code_init += mload(x2_mem_offset);
    code_init += mload(x2_mem_offset + mod_size);
    code_init += bytecode(OP_OR);
    code_init += push(0xFFFF);
    const auto if2_end_placeholder_start = code_init.size() - 2;
    code_init += bytecode(OP_JUMPI);
    code_init += ret(x1_mem_offset, mod_size * 2);
    code_init += bytecode(OP_JUMPDEST);
    intx::be::unsafe::store(
        &code_init[if2_end_placeholder_start], static_cast<uint16_t>(code_init.size() - 1));

    // Store mod and b3 in memory
    code_init += mstore(mod_mem_offset, push(mod));
    code_init += mstore(b3_mem_offset, push(b3));

    SlotRegister reg;

    // Store 1 to use it to initialize value slot 1.
    // TODO: Idea: EVMMAX can potentially have this slot pre-initialized on `setupx`
    code_init += mstore(mod_size * 6, push(1));

    auto code = storex(1, mod_size * 6, 1);  // Init slot 1 to value 1.

    // Reserve slots for result
    Scope scope(reg);
    const auto x3_idx = scope.new_slot();
    const auto y3_idx = scope.new_slot();
    const auto z3_idx = scope.new_slot();

    {
        Scope scope1(reg);
        const auto x1_idx = scope1.new_slot();
        const auto y1_idx = scope1.new_slot();
        const auto z1_idx = scope1.new_slot();
        const auto x2_idx = scope1.new_slot();
        const auto y2_idx = scope1.new_slot();
        const auto z2_idx = scope1.new_slot();
        const auto b3_idx = scope1.new_slot();

        code += storex(2, x1_mem_offset, x1_idx) + copy_values(1, z1_idx);  // [x1, y1, 1]
        code += storex(2, x2_mem_offset, x2_idx) +
                copy_values<1>({1}, {z2_idx});     // [x1, y1, 1, x2, y2, 1]
        code += storex(1, b3_mem_offset, b3_idx);  // Store

        ecc::add(code, scope1, x1_idx, y1_idx, z1_idx, x2_idx, y2_idx, z2_idx, b3_idx, x3_idx,
            y3_idx, z3_idx);
    }
    {
        Scope scope2(reg);
        const auto z_inv_idx = scope2.new_slot();

        code += inv(scope2, z3_idx, z_inv_idx);

        code += mulmodx(x3_idx, x3_idx, z_inv_idx);
        code += mulmodx(y3_idx, y3_idx, z_inv_idx);
    }
    ////////////////////////////////////////////////////////

    code += loadx(2, x3_idx, 0);
    // return loaded result
    code += ret(0, mod_size * 2);

    return code_init + setupx(reg.max_slots_used(), mod_size, mod_mem_offset, 1) + code;
}

bytecode mul(const uint256& mod, const uint256& b3, field_inv_f inv) noexcept
{
    const auto mod_size = sizeof(mod);

    auto code = calldatacopy(push(0), push(0), push(mod_size * 3));

    const auto x_mem_offset = 0;
    const auto c_mem_offset = mod_size * 2;
    const auto mod_mem_offset = mod_size * 3;
    const auto b3_mem_offset = mod_size * 4;

    // Check that point x is not inf.
    code += mload(x_mem_offset);
    code += mload(x_mem_offset + mod_size);
    code += bytecode(OP_OR);
    code += push(0xFFFF);
    const auto if1_end_placeholder_start = code.size() - 2;
    code += bytecode(OP_JUMPI);
    code += ret(x_mem_offset, mod_size * 2);
    code += bytecode(OP_JUMPDEST);
    intx::be::unsafe::store(
        &code[if1_end_placeholder_start], static_cast<uint16_t>(code.size() - 1));

    // Check that c is not 0.
    code += mload(c_mem_offset);
    code += push(0xFFFF);
    const auto if2_end_placeholder_start = code.size() - 2;
    code += bytecode(OP_JUMPI);
    code += mstore(0, push(0));
    code += mstore(mod_size, push(0));
    code += ret(0, mod_size * 2);
    code += bytecode(OP_JUMPDEST);
    intx::be::unsafe::store(
        &code[if2_end_placeholder_start], static_cast<uint16_t>(code.size() - 1));

    // Store mod and b3 in memory
    code += mstore(mod_mem_offset, push(mod));
    code += mstore(b3_mem_offset, push(b3));

    code += setupx(0xFF, mod_size, mod_mem_offset, 1);
    const auto num_slots_placeholder_start = code.size() - 8;

    SlotRegister reg;

    // Store 1 to use it to initialize value slot 1.
    // TODO: Idea: EVMMAX can potentially have this slot pre-initialized on `setupx`
    code += mstore(mod_size * 5, push(1));
    code += storex(1, mod_size * 5, 1);  // Init slot 1 to value 1.

    Scope scope(reg);
    const auto px_idx = scope.new_slot();
    const auto py_idx = scope.new_slot();
    const auto pz_idx = scope.new_slot();

    {
        Scope scope0(scope);
        const auto qx_idx = scope0.new_slot();
        const auto qy_idx = scope0.new_slot();
        const auto qz_idx = scope0.new_slot();
        const auto b3_idx = scope0.new_slot();

        code += storex(2, x_mem_offset, qx_idx) + copy_values(1, qz_idx);  // [x1, y1, 1]
        code += storex(1, b3_mem_offset, b3_idx);

        code += mload(push(c_mem_offset));  // c on stack is required by `ecmul`

        ecc::mul(code, scope0, qx_idx, qy_idx, qz_idx, b3_idx, px_idx, py_idx, pz_idx);
    }
    const auto pz_inv_idx = scope.new_slot();

    code += inv(scope, pz_idx, pz_inv_idx);

    code += mulmodx(px_idx, px_idx, pz_inv_idx);
    code += mulmodx(py_idx, py_idx, pz_inv_idx);

    code += loadx(2, px_idx, 0);
    // return loaded result
    code += ret(0, mod_size * 2);

    code[num_slots_placeholder_start] = reg.max_slots_used();

    return code;
}

}  // namespace evmmax::evm
