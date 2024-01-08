// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "bn254_evm.hpp"
#include "precompiles_evm.hpp"
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

namespace evmmax::evm::bn254
{
namespace
{
evmc::Result execute(int64_t gas, const bytecode& code, bytes_view input = {}) noexcept
{
    const evmc_message msg = {
        .gas = gas,
        .input_data = input.data(),
        .input_size = input.size(),
    };

    const evmc_revision rev = EVMC_PRAGUE;

    evmc::MockedHost host;

    if constexpr (rev >= EVMC_BERLIN)  // Add EIP-2929 tweak.
    {
        host.access_account(msg.sender);
        host.access_account(msg.recipient);
    }

    evmc::VM vm{evmc_create_evmone()};

    return vm.execute(host, rev, msg, code.data(), code.size());
}

bytecode field_inv(const Scope& parent_scope, uint8_t x_idx, uint8_t r_idx) noexcept
{
    auto code = bytecode{};

    // Inversion computation
    // Allocate Temporaries.
    Scope scope(parent_scope);
    const auto t0_idx = scope.new_slot();
    const auto t1_idx = scope.new_slot();
    const auto t2_idx = scope.new_slot();
    const auto t3_idx = scope.new_slot();
    const auto t4_idx = scope.new_slot();
    const auto t5_idx = scope.new_slot();
    const auto t6_idx = scope.new_slot();
    const auto t7_idx = scope.new_slot();
    const auto t8_idx = scope.new_slot();
    const auto t9_idx = scope.new_slot();
    const auto t10_idx = scope.new_slot();
    const auto t11_idx = scope.new_slot();
    const auto t12_idx = scope.new_slot();
    const auto t13_idx = scope.new_slot();
    const auto t14_idx = scope.new_slot();
    const auto t15_idx = scope.new_slot();
    const auto t16_idx = scope.new_slot();
    const auto t17_idx = scope.new_slot();
    const auto t18_idx = scope.new_slot();
    const auto t19_idx = scope.new_slot();
    const auto t20_idx = scope.new_slot();
    const auto t21_idx = scope.new_slot();
    const auto z_idx = r_idx;

    // Step 1: t8 = x^0x2
    code += mulmodx(t8_idx, x_idx, x_idx);

    // Step 2: t15 = x^0x3
    code += mulmodx(t15_idx, x_idx, t8_idx);

    // Step 3: z = x^0x5
    code += mulmodx(z_idx, t8_idx, t15_idx);

    // Step 4: t1 = x^0x6
    code += mulmodx(t1_idx, x_idx, z_idx);

    // Step 5: t3 = x^0x8
    code += mulmodx(t3_idx, t8_idx, t1_idx);

    // Step 6: t9 = x^0xd
    code += mulmodx(t9_idx, z_idx, t3_idx);

    // Step 7: t6 = x^0x12
    code += mulmodx(t6_idx, z_idx, t9_idx);

    // Step 8: t19 = x^0x13
    code += mulmodx(t19_idx, x_idx, t6_idx);

    // Step 9: t0 = x^0x14
    code += mulmodx(t0_idx, x_idx, t19_idx);

    // Step 10: t20 = x^0x17
    code += mulmodx(t20_idx, t15_idx, t0_idx);

    // Step 11: t2 = x^0x1c
    code += mulmodx(t2_idx, z_idx, t20_idx);

    // Step 12: t17 = x^0x20
    code += mulmodx(t17_idx, t9_idx, t19_idx);

    // Step 13: t4 = x^0x23
    code += mulmodx(t4_idx, t15_idx, t17_idx);

    // Step 14: t14 = x^0x2b
    code += mulmodx(t14_idx, t3_idx, t4_idx);

    // Step 15: t12 = x^0x2f
    code += mulmodx(t12_idx, t19_idx, t2_idx);

    // Step 16: t16 = x^0x41
    code += mulmodx(t16_idx, t6_idx, t12_idx);

    // Step 17: t18 = x^0x53
    code += mulmodx(t18_idx, t6_idx, t16_idx);

    // Step 18: t3 = x^0x5b
    code += mulmodx(t3_idx, t3_idx, t18_idx);

    // Step 19: t5 = x^0x61
    code += mulmodx(t5_idx, t1_idx, t3_idx);

    // Step 20: t0 = x^0x75
    code += mulmodx(t0_idx, t0_idx, t5_idx);

    // Step 21: t10 = x^0x91
    code += mulmodx(t10_idx, t2_idx, t0_idx);

    // Step 22: t7 = x^0x95
    code += mulmodx(t7_idx, t17_idx, t0_idx);

    // Step 23: t11 = x^0xb5
    code += mulmodx(t11_idx, t17_idx, t7_idx);

    // Step 24: t13 = x^0xbb
    code += mulmodx(t13_idx, t1_idx, t11_idx);

    // Step 25: t21 = x^0xc1
    code += mulmodx(t21_idx, t1_idx, t13_idx);

    // Step 26: t2 = x^0xc3
    code += mulmodx(t2_idx, t8_idx, t21_idx);

    // Step 27: t6 = x^0xd3
    code += mulmodx(t6_idx, t6_idx, t21_idx);

    // Step 28: t17 = x^0xe1
    code += mulmodx(t17_idx, t17_idx, t21_idx);

    // Step 29: t8 = x^0xe3
    code += mulmodx(t8_idx, t8_idx, t17_idx);

    // Step 30: t1 = x^0xe7
    code += mulmodx(t1_idx, t1_idx, t17_idx);

    // Step 38: t21 = x^0xc100
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t21_idx, t21_idx, t21_idx);

    // Step 39: t21 = x^0xc191
    code += mulmodx(t21_idx, t10_idx, t21_idx);

    // Step 49: t21 = x^0x3064400
    for (int i = 0; i < 10; ++i)
        code += mulmodx(t21_idx, t21_idx, t21_idx);

    // Step 50: t21 = x^0x30644e7
    code += mulmodx(t21_idx, t1_idx, t21_idx);

    // Step 57: t21 = x^0x183227380
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t21_idx, t21_idx, t21_idx);

    // Step 58: t20 = x^0x183227397
    code += mulmodx(t20_idx, t20_idx, t21_idx);

    // Step 67: t20 = x^0x30644e72e00
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t20_idx, t20_idx, t20_idx);

    // Step 68: t19 = x^0x30644e72e13
    code += mulmodx(t19_idx, t19_idx, t20_idx);

    // Step 75: t19 = x^0x1832273970980
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t19_idx, t19_idx, t19_idx);

    // Step 76: t19 = x^0x183227397098d
    code += mulmodx(t19_idx, t9_idx, t19_idx);

    // Step 90: t19 = x^0x60c89ce5c2634000
    for (int i = 0; i < 14; ++i)
        code += mulmodx(t19_idx, t19_idx, t19_idx);

    // Step 91: t18 = x^0x60c89ce5c2634053
    code += mulmodx(t18_idx, t18_idx, t19_idx);

    // Step 100: t18 = x^0xc19139cb84c680a600
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t18_idx, t18_idx, t18_idx);

    // Step 101: t17 = x^0xc19139cb84c680a6e1
    code += mulmodx(t17_idx, t17_idx, t18_idx);

    // Step 109: t17 = x^0xc19139cb84c680a6e100
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t17_idx, t17_idx, t17_idx);

    // Step 110: t16 = x^0xc19139cb84c680a6e141
    code += mulmodx(t16_idx, t16_idx, t17_idx);

    // Step 120: t16 = x^0x30644e72e131a029b850400
    for (int i = 0; i < 10; ++i)
        code += mulmodx(t16_idx, t16_idx, t16_idx);

    // Step 121: t16 = x^0x30644e72e131a029b85045b
    code += mulmodx(t16_idx, t3_idx, t16_idx);

    // Step 126: t16 = x^0x60c89ce5c263405370a08b60
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t16_idx, t16_idx, t16_idx);

    // Step 127: t16 = x^0x60c89ce5c263405370a08b6d
    code += mulmodx(t16_idx, t9_idx, t16_idx);

    // Step 135: t16 = x^0x60c89ce5c263405370a08b6d00
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t16_idx, t16_idx, t16_idx);

    // Step 136: t15 = x^0x60c89ce5c263405370a08b6d03
    code += mulmodx(t15_idx, t15_idx, t16_idx);

    // Step 148: t15 = x^0x60c89ce5c263405370a08b6d03000
    for (int i = 0; i < 12; ++i)
        code += mulmodx(t15_idx, t15_idx, t15_idx);

    // Step 149: t14 = x^0x60c89ce5c263405370a08b6d0302b
    code += mulmodx(t14_idx, t14_idx, t15_idx);

    // Step 161: t14 = x^0x60c89ce5c263405370a08b6d0302b000
    for (int i = 0; i < 12; ++i)
        code += mulmodx(t14_idx, t14_idx, t14_idx);

    // Step 162: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb
    code += mulmodx(t13_idx, t13_idx, t14_idx);

    // Step 170: t13 = x^0x60c89ce5c263405370a08b6d0302b0bb00
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t13_idx, t13_idx, t13_idx);

    // Step 171: t12 = x^0x60c89ce5c263405370a08b6d0302b0bb2f
    code += mulmodx(t12_idx, t12_idx, t13_idx);

    // Step 185: t12 = x^0x183227397098d014dc2822db40c0ac2ecbc000
    for (int i = 0; i < 14; ++i)
        code += mulmodx(t12_idx, t12_idx, t12_idx);

    // Step 186: t11 = x^0x183227397098d014dc2822db40c0ac2ecbc0b5
    code += mulmodx(t11_idx, t11_idx, t12_idx);

    // Step 195: t11 = x^0x30644e72e131a029b85045b68181585d97816a00
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t11_idx, t11_idx, t11_idx);

    // Step 196: t10 = x^0x30644e72e131a029b85045b68181585d97816a91
    code += mulmodx(t10_idx, t10_idx, t11_idx);

    // Step 201: t10 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d5220
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t10_idx, t10_idx, t10_idx);

    // Step 202: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d
    code += mulmodx(t9_idx, t9_idx, t10_idx);

    // Step 214: t9 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d000
    for (int i = 0; i < 12; ++i)
        code += mulmodx(t9_idx, t9_idx, t9_idx);

    // Step 215: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e3
    code += mulmodx(t8_idx, t8_idx, t9_idx);

    // Step 223: t8 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e300
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t8_idx, t8_idx, t8_idx);

    // Step 224: t7 = x^0x60c89ce5c263405370a08b6d0302b0bb2f02d522d0e395
    code += mulmodx(t7_idx, t7_idx, t8_idx);

    // Step 235: t7 = x^0x30644e72e131a029b85045b68181585d97816a916871ca800
    for (int i = 0; i < 11; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 236: t6 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3
    code += mulmodx(t6_idx, t6_idx, t7_idx);

    // Step 243: t6 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e546980
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t6_idx, t6_idx, t6_idx);

    // Step 244: t5 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e1
    code += mulmodx(t5_idx, t5_idx, t6_idx);

    // Step 255: t5 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0800
    for (int i = 0; i < 11; ++i)
        code += mulmodx(t5_idx, t5_idx, t5_idx);

    // Step 256: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823
    code += mulmodx(t4_idx, t4_idx, t5_idx);

    // Step 268: t4 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f0823000
    for (int i = 0; i < 12; ++i)
        code += mulmodx(t4_idx, t4_idx, t4_idx);

    // Step 269: t3 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b
    code += mulmodx(t3_idx, t3_idx, t4_idx);

    // Step 278: t3 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b600
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 279: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 287: t2 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c300
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 288: t1 = x^0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7
    code += mulmodx(t1_idx, t1_idx, t2_idx);

    // Step 295: t1 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f380
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t1_idx, t1_idx, t1_idx);

    // Step 296: t0 = x^0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f5
    code += mulmodx(t0_idx, t0_idx, t1_idx);

    // Step 302: t0 = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd40
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 303: z = x^0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
    code += mulmodx(z_idx, z_idx, t0_idx);

    return code;
}
}  // namespace

const bytecode& generate_add() noexcept
{
    static const auto add_bytecode = evmmax::evm::add(evmmax::bn254::FieldPrime, 9_u256, field_inv);
    return add_bytecode;
}

const bytecode& generate_mul() noexcept
{
    static const auto mul_bytecode = evmmax::evm::mul(evmmax::bn254::FieldPrime, 9_u256, field_inv);
    return mul_bytecode;
}

Point add(const Point& pt1, const Point& pt2) noexcept
{
    const auto& add_bytecode = generate_add();

    static const auto mod_size = sizeof(evmmax::bn254::FieldPrime);

    uint8_t calldata[4 * mod_size];  // x1, y1, x2, y2
    intx::be::unsafe::store(&calldata[0], pt1.x);
    intx::be::unsafe::store(&calldata[1 * mod_size], pt1.y);
    intx::be::unsafe::store(&calldata[2 * mod_size], pt2.x);
    intx::be::unsafe::store(&calldata[3 * mod_size], pt2.y);

    if (const auto res = execute(1000, add_bytecode, {calldata, mod_size * 4});
        res.status_code == EVMC_SUCCESS && res.output_size == 2 * mod_size)
    {
        return {intx::be::unsafe::load<uint256>(res.output_data),
            intx::be::unsafe::load<uint256>(res.output_data + mod_size)};
    }
    else
        return {};
}

Point mul(const Point& pt, const uint256& c) noexcept
{
    const auto& mul_bytecode = generate_mul();

    static const auto mod_size = sizeof(evmmax::bn254::FieldPrime);

    uint8_t calldata[3 * mod_size];  // x1, y1, s
    intx::be::unsafe::store(&calldata[0], pt.x);
    intx::be::unsafe::store(&calldata[1 * mod_size], pt.y);
    intx::be::unsafe::store(&calldata[2 * mod_size], c);

    if (const auto res = execute(100000, mul_bytecode, {calldata, mod_size * 3});
        res.status_code == EVMC_SUCCESS && res.output_size == 2 * mod_size)
    {
        return {intx::be::unsafe::load<uint256>(res.output_data),
            intx::be::unsafe::load<uint256>(res.output_data + mod_size)};
    }
    else
        return {};
}
}  // namespace evmmax::evm::bn254
