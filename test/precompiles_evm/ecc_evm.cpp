// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "ecc_evm.hpp"

namespace evmmax::evm::ecc
{
// using namespace evmc::literals;
using namespace intx;

void add(bytecode& code, const Scope& parent_scope, uint8_t x1_idx, uint8_t y1_idx, uint8_t z1_idx,
    uint8_t x2_idx, uint8_t y2_idx, uint8_t z2_idx, uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx,
    uint8_t rz_idx) noexcept
{
    auto const x3_idx = rx_idx;
    auto const y3_idx = ry_idx;
    auto const z3_idx = rz_idx;

    // Point addition in projective space.
    Scope scope(parent_scope);
    const auto t0_idx = scope.new_slot();
    const auto t1_idx = scope.new_slot();
    const auto t2_idx = scope.new_slot();
    const auto t3_idx = scope.new_slot();
    const auto t4_idx = scope.new_slot();

    code += mulmodx(t0_idx, x1_idx, x2_idx);  // 1
    code += mulmodx(t1_idx, y1_idx, y2_idx);  // 2
    code += mulmodx(t2_idx, z1_idx, z2_idx);  // 3
    code += addmodx(t3_idx, x1_idx, y1_idx);  // 4
    code += addmodx(t4_idx, x2_idx, y2_idx);  // 5
    code += mulmodx(t3_idx, t3_idx, t4_idx);  // 6
    code += addmodx(t4_idx, t0_idx, t1_idx);  // 7
    code += submodx(t3_idx, t3_idx, t4_idx);  // 8
    code += addmodx(t4_idx, y1_idx, z1_idx);  // 9
    code += addmodx(x3_idx, y2_idx, z2_idx);  // 10
    code += mulmodx(t4_idx, t4_idx, x3_idx);  // 11
    code += addmodx(x3_idx, t1_idx, t2_idx);  // 12
    code += submodx(t4_idx, t4_idx, x3_idx);  // 13
    code += addmodx(x3_idx, x1_idx, z1_idx);  // 14
    code += addmodx(y3_idx, x2_idx, z2_idx);  // 15
    code += mulmodx(x3_idx, x3_idx, y3_idx);  // 16
    code += addmodx(y3_idx, t0_idx, t2_idx);  // 17
    code += submodx(y3_idx, x3_idx, y3_idx);  // 18
    code += addmodx(x3_idx, t0_idx, t0_idx);  // 19
    code += addmodx(t0_idx, x3_idx, t0_idx);  // 20
    code += mulmodx(t2_idx, b3_idx, t2_idx);  // 21
    code += addmodx(z3_idx, t1_idx, t2_idx);  // 22
    code += submodx(t1_idx, t1_idx, t2_idx);  // 23
    code += mulmodx(y3_idx, b3_idx, y3_idx);  // 24
    code += mulmodx(x3_idx, t4_idx, y3_idx);  // 25
    code += mulmodx(t2_idx, t3_idx, t1_idx);  // 26
    code += submodx(x3_idx, t2_idx, x3_idx);  // 27
    code += mulmodx(y3_idx, y3_idx, t0_idx);  // 28
    code += mulmodx(t1_idx, t1_idx, z3_idx);  // 29
    code += addmodx(y3_idx, t1_idx, y3_idx);  // 30
    code += mulmodx(t0_idx, t0_idx, t3_idx);  // 31
    code += mulmodx(z3_idx, z3_idx, t4_idx);  // 32
    code += addmodx(z3_idx, z3_idx, t0_idx);  // 33
}

void dbl(bytecode& code, const Scope& parent_scope, uint8_t x_idx, uint8_t y_idx, uint8_t z_idx,
    uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx, uint8_t rz_idx) noexcept
{
    const auto x3_idx = rx_idx;
    const auto y3_idx = ry_idx;
    const auto z3_idx = rz_idx;

    Scope scope(parent_scope);

    const auto t0_idx = scope.new_slot();
    const auto t1_idx = scope.new_slot();
    const auto t2_idx = scope.new_slot();

    code += mulmodx(t0_idx, y_idx, y_idx);    // 1
    code += addmodx(z3_idx, t0_idx, t0_idx);  // 2
    code += addmodx(z3_idx, z3_idx, z3_idx);  // 3
    code += addmodx(z3_idx, z3_idx, z3_idx);  // 4
    code += mulmodx(t1_idx, y_idx, z_idx);    // 5
    code += mulmodx(t2_idx, z_idx, z_idx);    // 6
    code += mulmodx(t2_idx, b3_idx, t2_idx);  // 7
    code += mulmodx(x3_idx, t2_idx, z3_idx);  // 8
    code += addmodx(y3_idx, t0_idx, t2_idx);  // 9
    code += mulmodx(z3_idx, t1_idx, z3_idx);  // 10
    code += addmodx(t1_idx, t2_idx, t2_idx);  // 11
    code += addmodx(t2_idx, t1_idx, t2_idx);  // 12
    code += submodx(t0_idx, t0_idx, t2_idx);  // 13
    code += mulmodx(y3_idx, t0_idx, y3_idx);  // 14
    code += addmodx(y3_idx, x3_idx, y3_idx);  // 15
    code += mulmodx(t1_idx, x_idx, y_idx);    // 16
    code += mulmodx(x3_idx, t0_idx, t1_idx);  // 17
    code += addmodx(x3_idx, x3_idx, x3_idx);  // 18
}

void mul(bytecode& code, const Scope& parent_scope, uint8_t x_idx, uint8_t y_idx, uint8_t z_idx,
    uint8_t b3_idx, uint8_t rx_idx, uint8_t ry_idx, uint8_t rz_idx) noexcept
{
    const auto px_idx = rx_idx;
    const auto py_idx = ry_idx;
    const auto pz_idx = rz_idx;

    // Initialize p to [0, 1, 0] (infinity)
    code += copy_values(0, px_idx);
    code += copy_values(1, py_idx);
    code += copy_values(0, pz_idx);

    {
        Scope scope0(parent_scope);

        const auto qx_idx = scope0.new_slot();
        const auto qy_idx = scope0.new_slot();
        const auto qz_idx = scope0.new_slot();

        code += copy_values({x_idx, y_idx, z_idx}, {qx_idx, qy_idx, qz_idx});

        code +=
            push(0x8000000000000000000000000000000000000000000000000000000000000000_u256);  // mask

        // Loop 0. Find first significant bit
        code += bytecode(OP_JUMPDEST);
        const auto loop0_begin_label = code.size() - 1;

        code += iszero(bytecode(OP_DUP1));  // dup c and check if != 0
        code += push(0xFFFF);
        const auto loop1_end_placeholder_start_0 = code.size() - 2;
        code += bytecode(OP_JUMPI);

        code += bytecode(OP_DUP2) + bytecode(OP_DUP2);  // dup c and mask
        code += bytecode(OP_AND) + OP_DUP1;  // check if c && mask != 0. if so jump to loop1
        code += push(0xFFFF);
        const auto loop1_begin_placeholder_start = code.size() - 2;
        code += bytecode(OP_JUMPI);
        code += bytecode(OP_POP);
        code += bytecode(OP_DUP1) + push(1) + bytecode(OP_SHR);  // shift right c by 1 bit
        code += bytecode(OP_SWAP1) + OP_POP;  // swap shifted c with original and pop the original c
        code += push(loop0_begin_label) + bytecode(OP_JUMP);  // jump to loop 0 start

        // Loop 1 start computation.
        code += bytecode(OP_JUMPDEST);
        const auto loop1_begin_label = code.size() - 1;
        intx::be::unsafe::store(
            &code[loop1_begin_placeholder_start], static_cast<uint16_t>(loop1_begin_label));

        code += push(0xffff);
        const auto else0_placeholder_start = code.size() - 2;
        code += bytecode(OP_JUMPI);

        const auto tx_idx = scope0.new_slot();
        const auto ty_idx = scope0.new_slot();
        const auto tz_idx = scope0.new_slot();

        add(code, Scope(scope0), qx_idx, qy_idx, qz_idx, px_idx, py_idx, pz_idx, b3_idx, tx_idx,
            ty_idx, tz_idx);

        code += copy_values({tx_idx, ty_idx, tz_idx}, {qx_idx, qy_idx, qz_idx});

        dbl(code, Scope(scope0), px_idx, py_idx, pz_idx, b3_idx, tx_idx, ty_idx, tz_idx);

        code += copy_values({tx_idx, ty_idx, tz_idx}, {px_idx, py_idx, pz_idx});

        code += push(0xffff);
        const auto else0_end_placeholder_start = code.size() - 2;
        code += bytecode(OP_JUMP);

        code += bytecode(OP_JUMPDEST);
        intx::be::unsafe::store(
            &code[else0_placeholder_start], static_cast<uint16_t>(code.size() - 1));

        add(code, Scope(scope0), qx_idx, qy_idx, qz_idx, px_idx, py_idx, pz_idx, b3_idx, tx_idx,
            ty_idx, tz_idx);

        code += copy_values({tx_idx, ty_idx, tz_idx}, {px_idx, py_idx, pz_idx});

        dbl(code, Scope(scope0), qx_idx, qy_idx, qz_idx, b3_idx, tx_idx, ty_idx, tz_idx);

        code += copy_values({tx_idx, ty_idx, tz_idx}, {qx_idx, qy_idx, qz_idx});

        code += bytecode(OP_JUMPDEST);
        intx::be::unsafe::store(
            &code[else0_end_placeholder_start], static_cast<uint16_t>(code.size() - 1));

        code += bytecode(OP_DUP1) + push(1) + bytecode(OP_SHR);  // shift right mask by 1 bit
        code += bytecode(OP_SWAP1) +
                OP_POP;  // swap shifted mask with original and pop the original mask
        code += iszero(bytecode(OP_DUP1));  // dup mask and check if != 0
        code += push(0xFFFF);
        const auto loop1_end_placeholder_start_1 = code.size() - 2;
        code += bytecode(OP_JUMPI);

        code += bytecode(OP_DUP2) + bytecode(OP_DUP2);  // dup c and mask
        code += bytecode(OP_AND);

        code += jump(push(loop1_begin_label));

        code += bytecode(OP_JUMPDEST);  // End of function
        intx::be::unsafe::store(
            &code[loop1_end_placeholder_start_0], static_cast<uint16_t>(code.size() - 1));
        intx::be::unsafe::store(
            &code[loop1_end_placeholder_start_1], static_cast<uint16_t>(code.size() - 1));

        code += bytecode(OP_POP);  // Clear stack
    }
}

}  // namespace evmmax::evm::ecc
