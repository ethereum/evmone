// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include <evmmax/evmmax.hpp>
#include <gtest/gtest.h>
#include <array>

using namespace intx;
using namespace evmmax;
using namespace evmc::literals;
using evmone::test::evm;

TEST_P(evm, evmmax_32bytes_modulus_test)
{
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 7
    auto code = mstore(0, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setupx(3, 32, 0);
    // value 3
    code += mstore(32, 0x03);
    // value 6
    code += mstore(64, 0x06);
    // num values
    // values offset
    // store values
    code += storex(2, 32, 0);
    // ADDMODX for values in slots 0 and 1 save result in slot 2
    code += addmodx(2, 1, 0);
    // MULMODX for values in slots 1 and 2 save result in slot 2
    code += mulmodx(2, 2, 1);
    // SUBMODX for values in slots 1 and 2 save result in slot 2
    code += submodx(2, 2, 1);
    // load values from slot 2 into EVM memory
    code += loadx(1, 2, 96);
    // return loaded result
    code += ret(96, 32);

    execute(1000, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);
    EXPECT_OUTPUT_INT(6);
}

TEST_P(evm, evmmax_1byte_modulus_test)
{
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 7
    auto code = mstore8(0, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setupx(3, 1, 0);
    // value 3
    code += mstore8(8, 0x03);
    // value 6
    code += mstore8(16, 0x06);
    // num values
    // values offset
    // store values
    code += storex(2, 1, 0);
    // ADDMODX for values in slots 0 and 1 save result in slot 2
    code += addmodx(2, 1, 0);
    // MULMODX for values in slots 1 and 2 save result in slot 2
    code += mulmodx(2, 2, 1);
    // SUBMODX for values in slots 1 and 2 save result in slot 2
    code += submodx(2, 2, 1);
    // load values from slot 2 into EVM memory
    code += loadx(1, 2, 17);
    // return loaded result
    code += ret(17, 8);

    execute(1000, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 8);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "0000000000000006");
}

TEST_P(evm, evmmax_2byte_modulus_test)
{
    if (is_advanced())
        return;

    rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 263 (0x0107)
    auto code = mstore8(0, 0x01);
    code += mstore8(1, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setupx(3, 2, 0);
    // value 258
    code += mstore8(8, 0x01);
    code += mstore8(9, 0x02);
    // value 254
    code += mstore8(16, 0x00);
    code += mstore8(17, 0xfe);
    // num values
    // values offset
    // store values
    code += storex(2, 2, 0);
    // ADDMODX for values in slots 0 and 1 save result in slot 2
    code += addmodx(2, 1, 0);  // 258 + 254 = 249 mod 263
    // MULMODX for values in slots 1 and 2 save result in slot 2
    code += mulmodx(2, 2, 1);  // 249 * 254 = 126 mod 263
    // SUBMODX for values in slots 1 and 2 save result in slot 2
    code += submodx(2, 2, 1);  // 126 - 254 = 135 mod 263
    // load values from slot 2 into EVM memory
    code += loadx(1, 2, 18);
    // return loaded result
    code += ret(18, 8);

    execute(1000, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 8);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "0000000000000087");
}

// Advanced test cases. ecadd(bn254), ecmul(bn254) and ecrecovery(seckp256k1)
namespace
{
struct SlotsScope;

struct ValueSlotsRegister
{
private:
    friend struct SlotsScope;

    std::vector<bool> vals;

    [[nodiscard]] uint8_t register_slot() noexcept
    {
        if (const auto it = std::find(vals.begin(), vals.end(), false); it != vals.end())
        {
            *it = true;
            return static_cast<uint8_t>(std::distance(vals.begin(), it));
        }
        else
        {
            assert(vals.size() < 256);
            vals.push_back(true);
            return static_cast<uint8_t>(vals.size() - 1);
        }
    }

    void unregister_slot(uint8_t slot_idx) noexcept
    {
        if (slot_idx < vals.size())
            vals[slot_idx] = false;
        else
            assert(false);  // Invalid slot idx
    }

public:
    explicit ValueSlotsRegister() noexcept
    {
        // Assumption that slot 0 keeps value 0 and slot 1 keeps value 1 (in Montgomery form).
        // Never write to these slots.
        (void)register_slot();
        (void)register_slot();
    }
    [[nodiscard]] uint8_t max_slots_used() const { return static_cast<uint8_t>(vals.size()); }
};

struct SlotsScope
{
private:
    std::set<uint8_t> slots;
    ValueSlotsRegister& value_slots_register;

public:
    explicit SlotsScope(ValueSlotsRegister& vs_reg) noexcept : value_slots_register(vs_reg) {}
    explicit SlotsScope(const SlotsScope& outer_scope) noexcept
      : value_slots_register(outer_scope.value_slots_register)
    {}

    [[nodiscard]] uint8_t register_slot() noexcept
    {
        const auto new_slot = value_slots_register.register_slot();
        slots.insert(new_slot);
        return new_slot;
    }

    virtual ~SlotsScope() noexcept
    {
        for (const auto& slot : slots)
            value_slots_register.unregister_slot(slot);
    }
};

template <size_t NUM_VALUES>
[[nodiscard]] bytecode copy_values(
    const std::array<uint8_t, NUM_VALUES>& inputs, const std::array<uint8_t, NUM_VALUES>& outputs)
{
    // Slot 0 stores 0 value by convention.
    auto code = bytecode{};

    for (size_t i = 0; i < NUM_VALUES; ++i)
    {
        if (inputs[i] != outputs[i])
            code += addmodx(outputs[i], inputs[i], 0);
    }

    return code;
}

template <size_t NUM_INPUTS, size_t NUM_OUTPUTS>
struct EVMMAXFunction
{
    std::array<uint8_t, NUM_INPUTS> input_ids;
    std::array<uint8_t, NUM_OUTPUTS> output_ids;
    std::vector<size_t> func_offset_placeholders_start;

    using bytecode_gen_fn = void (*)(bytecode& code, const SlotsScope& scope,
        const std::array<uint8_t, NUM_INPUTS>& inputs_ids,
        const std::array<uint8_t, NUM_OUTPUTS>& outputs_ids);

    bytecode_gen_fn gen_code_func;

    explicit EVMMAXFunction(SlotsScope& scope, bytecode_gen_fn bytecode_gen_func) noexcept
      : gen_code_func(bytecode_gen_func)
    {
        std::generate(
            input_ids.begin(), input_ids.end(), [&scope] { return scope.register_slot(); });

        std::generate(
            output_ids.begin(), output_ids.end(), [&scope] { return scope.register_slot(); });
    }

    bytecode gen_call(size_t call_offset_in_code) noexcept
    {
        auto code = bytecode{};

        // push return destination to the stack. `0xFFFF` is a placeholder to be filled later
        code += push(0xFFFF);
        const auto ret_offset_placeholder_start = code.size() - 2;
        // jump to beg of the function code. `0xFFFF` is a placeholder for function body offset in
        // the code
        code += push(0xFFFF) + OP_JUMP;
        const auto func_loc_placeholder_start_offset = code.size() - 3;
        // return destination
        const auto ret_destination_offset = code.size();
        code += bytecode(OP_JUMPDEST);

        // fill return destination placeholder
        intx::be::unsafe::store(&code[ret_offset_placeholder_start],
            static_cast<uint16_t>(call_offset_in_code + ret_destination_offset));

        func_offset_placeholders_start.push_back(
            call_offset_in_code + func_loc_placeholder_start_offset);
        return code;
    }

    void finalize(SlotsScope& scope, bytecode& code) const
    {
        const auto func_offset_in_code = code.size();
        assert(func_offset_in_code <= std::numeric_limits<uint16_t>::max());
        for (const auto& p_start : func_offset_placeholders_start)
        {
            if (p_start + 1 < code.size())
                intx::be::unsafe::store(&code[p_start], static_cast<uint16_t>(func_offset_in_code));
            else
                throw std::runtime_error("invalid code size");
        }

        code += bytecode(OP_JUMPDEST);
        // sanitizer error: "error: variable 's' of type 'SlotsScope' can be declared 'const'"
        SlotsScope s(scope);  // NOLINT(misc-const-correctness)
        gen_code_func(code, s, input_ids, output_ids);
        code += bytecode(OP_JUMP);
    }
};

constexpr auto BN254Mod = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_u256;

void ecadd(bytecode& code, const SlotsScope& scope, const std::array<uint8_t, 7>& inputs,
    const std::array<uint8_t, 3>& outputs);

void dbl(bytecode& code, const SlotsScope& scope, const std::array<uint8_t, 4>& inputs,
    const std::array<uint8_t, 3>& outputs);

void ecmul(bytecode& code, const SlotsScope& scope, const std::array<uint8_t, 4>& inputs,
    const std::array<uint8_t, 3>& outputs);

void field_inv_bn254(bytecode& code, const SlotsScope& scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr);

void field_inv_secp256k1(bytecode& code, const SlotsScope& scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr);

void scalar_inv_secp256k1(bytecode& code, const SlotsScope& scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr);

void calculate_y(bytecode& code, const SlotsScope& scope, const std::array<uint8_t, 2>& x_idx_arr,
    const std::array<uint8_t, 1>& dst_idx_arr);

}  // namespace

TEST_P(evm, exec_bn254_ecadd_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    // vm.set_option("trace", "0");

    constexpr auto size = sizeof(uint256);

    const auto x1 = 0x0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2_u256;
    const auto y1 = 0x16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba_u256;
    const auto x2 = 0x1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc286_u256;
    const auto y2 = 0x0217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4_u256;

    uint8_t calldata[6 * size];  // mod, x1, y1, x2, y2, b3
    intx::be::unsafe::store(&calldata[0], BN254Mod);
    intx::be::unsafe::store(&calldata[size], x1);
    intx::be::unsafe::store(&calldata[2 * size], y1);
    intx::be::unsafe::store(&calldata[3 * size], x2);
    intx::be::unsafe::store(&calldata[4 * size], y2);
    intx::be::unsafe::store(&calldata[5 * size], 9_u256);

    ValueSlotsRegister vs_reg;
    SlotsScope scope(vs_reg);

    // Reserve slots for result
    const auto x3_idx = scope.register_slot();
    const auto y3_idx = scope.register_slot();
    const auto z3_idx = scope.register_slot();

    // Stores inputs in evm memory and `1` to load it as `z` coordinates of the inputs in projective
    // space
    auto code_init = calldatacopy(push(0), push(0), push(size * 6)) + mstore(size * 6, push(1));

    auto code = bytecode{};
    code += storex(1, size * 6, 1);  // Init slot 1 to value 1.
    {
        SlotsScope scope1(vs_reg);
        const auto x1_idx = scope1.register_slot();
        const auto y1_idx = scope1.register_slot();
        const auto z1_idx = scope1.register_slot();
        const auto x2_idx = scope1.register_slot();
        const auto y2_idx = scope1.register_slot();
        const auto z2_idx = scope1.register_slot();
        const auto b3_idx = scope1.register_slot();

        code += storex(2, size, x1_idx) + copy_values<1>({1}, {z1_idx});  // [x1, y1, 1]
        code +=
            storex(2, size * 3, x2_idx) + copy_values<1>({1}, {z2_idx});  // [x1, y1, 1, x2, y2, 1]
        code += storex(1, size * 5, b3_idx);                              // Store

        {
            const SlotsScope s(vs_reg);
            ecadd(code, s, {x1_idx, y1_idx, z1_idx, x2_idx, y2_idx, z2_idx, b3_idx},
                {x3_idx, y3_idx, z3_idx});
        }
    }
    {
        SlotsScope scope2(vs_reg);
        const auto z_inv_idx = scope2.register_slot();

        {
            const SlotsScope s(vs_reg);
            field_inv_bn254(code, s, {z3_idx}, {z_inv_idx});
        }

        code += mulmodx(x3_idx, x3_idx, z_inv_idx);
        code += mulmodx(y3_idx, y3_idx, z_inv_idx);
    }
    ////////////////////////////////////////////////////////

    code += loadx(2, x3_idx, size * 6);
    // return loaded result
    code += ret(size * 6, size * 2);

    execute(
        1000, code_init + setupx(vs_reg.max_slots_used(), size, 0) + code, {calldata, size * 6});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, size * 2);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "1f4d1d80177b1377743d1901f70d7389be7f7a35a35bfd234a8aaee615b88c49018683193ae021a2f8920fed18"
        "6cde5d9b1365116865281ccf884c1f28b1df8f");
}

TEST_P(evm, exec_bn254_ecadd_function_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    // vm.set_option("trace", "0");

    constexpr auto size = sizeof(uint256);

    const auto x1 = 0x0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2_u256;
    const auto y1 = 0x16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba_u256;
    const auto x2 = 0x1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc286_u256;
    const auto y2 = 0x0217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4_u256;

    uint8_t calldata[6 * size];  // mod, x1, y1, x2, y2, b3
    intx::be::unsafe::store(&calldata[0], BN254Mod);
    intx::be::unsafe::store(&calldata[size], x1);
    intx::be::unsafe::store(&calldata[2 * size], y1);
    intx::be::unsafe::store(&calldata[3 * size], x2);
    intx::be::unsafe::store(&calldata[4 * size], y2);
    intx::be::unsafe::store(&calldata[5 * size], 9_u256);

    ValueSlotsRegister vs_reg;
    SlotsScope scope(vs_reg);
    // Reserve slots to store calculated results in them.

    EVMMAXFunction<7, 3> bn254_ecadd_f(scope, ecadd);
    EVMMAXFunction<1, 1> field_inv_f(scope, field_inv_bn254);

    auto code = calldatacopy(push(0), push(0), push(size * 6)) + mstore(size * 6, push(1)) +
                setupx(0xFF, size, 0);
    const auto num_slots_placeholder_start = code.size() - 6;
    code += storex(1, size * 6, 1);  // Init slot 1 to value 1.

    code += storex(2, size, bn254_ecadd_f.input_ids[0]) +
            copy_values<1>({1}, {bn254_ecadd_f.input_ids[2]});  // [x1, y1, 1]
    code += storex(2, size * 3, bn254_ecadd_f.input_ids[3]) +
            copy_values<1>({1}, {bn254_ecadd_f.input_ids[5]});  // [x1, y1, 1, x2, y2, 1]
    code += storex(1, size * 5, bn254_ecadd_f.input_ids[6]);

    code += bn254_ecadd_f.gen_call(code.size());

    code += copy_values({bn254_ecadd_f.output_ids[2]}, field_inv_f.input_ids);

    code += field_inv_f.gen_call(code.size());

    code += mulmodx(
        bn254_ecadd_f.output_ids[0], bn254_ecadd_f.output_ids[0], field_inv_f.output_ids[0]);
    code += mulmodx(
        bn254_ecadd_f.output_ids[1], bn254_ecadd_f.output_ids[1], field_inv_f.output_ids[0]);
    ////////////////////////////////////////////////////////

    code += loadx(2, bn254_ecadd_f.output_ids[0], size * 6);
    // return loaded result
    code += ret(size * 6, size * 2);

    bn254_ecadd_f.finalize(scope, code);
    field_inv_f.finalize(scope, code);

    code[num_slots_placeholder_start] = vs_reg.max_slots_used();

    execute(1000, code, {calldata, size * 6});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, size * 2);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "1f4d1d80177b1377743d1901f70d7389be7f7a35a35bfd234a8aaee615b88c49018683193ae021a2f8920fed18"
        "6cde5d9b1365116865281ccf884c1f28b1df8f");
}

TEST_P(evm, exec_bn254_ecmul_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    // vm.set_option("trace", "0");

    constexpr auto size = sizeof(uint256);

    const auto x = 0x025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb_u256;
    const auto y = 0x2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e_u256;
    const auto c = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3_u256;

    //    const auto x = 0x0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2_u256;
    //    const auto y = 0x16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba_u256;
    //    const auto c = 0x0000000000000000000000000000000000000000000000000000000000000003_u256;

    uint8_t calldata[5 * size];  // mod, x, y, c, b3
    intx::be::unsafe::store(&calldata[0], BN254Mod);
    intx::be::unsafe::store(&calldata[size], x);
    intx::be::unsafe::store(&calldata[2 * size], y);
    intx::be::unsafe::store(&calldata[3 * size], c);
    intx::be::unsafe::store(&calldata[4 * size], 9_u256);

    auto code = calldatacopy(push(0), push(0), push(size * 5)) + mstore(size * 5, push(1)) +
                setupx(0xFF, size, 0);
    const auto num_slots_placeholder_start = code.size() - 6;
    code += storex(1, size * 5, 1);  // Store 1 in slot 1

    ValueSlotsRegister vs_reg;
    SlotsScope scope(vs_reg);
    const auto px_idx = scope.register_slot();
    const auto py_idx = scope.register_slot();
    const auto pz_idx = scope.register_slot();

    {
        SlotsScope scope0(scope);
        const auto qx_idx = scope0.register_slot();
        const auto qy_idx = scope0.register_slot();
        const auto qz_idx = scope0.register_slot();
        const auto b3_idx = scope0.register_slot();

        code += storex(2, size, qx_idx) + copy_values<1>({1}, {qz_idx});  // [x1, y1, 1]
        code += storex(1, size * 4, b3_idx);

        code += mload(push(3 * size));  // c on stack is required by `ecmul`

        ecmul(code, scope0, {qx_idx, qy_idx, qz_idx, b3_idx}, {px_idx, py_idx, pz_idx});
    }
    const auto pz_inv_idx = scope.register_slot();

    field_inv_bn254(code, scope, {pz_idx}, {pz_inv_idx});

    code += mulmodx(px_idx, px_idx, pz_inv_idx);
    code += mulmodx(py_idx, py_idx, pz_inv_idx);

    code += loadx(2, px_idx, size * 7);
    // return loaded result
    code += ret(size * 7, size * 2);

    code[num_slots_placeholder_start] = vs_reg.max_slots_used();

    execute(100000, code, {calldata, size * 5});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, size * 2);
    //    EXPECT_EQ(hex({result.output_data, result.output_size}),
    //        "1f4d1d80177b1377743d1901f70d7389be7f7a35a35bfd234a8aaee615b88c49018683193ae021a2f8920fed18"
    //        "6cde5d9b1365116865281ccf884c1f28b1df8f");

    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "14789d0d4a730b354403b5fac948113739e276c23e0258d8596ee72f9cd9d3230af18a63153e0ec25ff9f2951d"
        "d3fa90ed0197bfef6e2a1a62b5095b9d2b4a27");
}

TEST_P(evm, exec_secp256k1_ecrecovery_test)
{
    using namespace evmone::test;

    if (evm::is_advanced())
        return;

    evm::rev = EVMC_PRAGUE;  /// TODO: Use EVMC_EVMMAX

    // vm.set_option("trace", "0");

    constexpr auto size = sizeof(uint256);

    const auto hash = 0x18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c_bytes32;
    const auto r = 0x7af9e73057870458f03c143483bc5fcb6f39d01c9b26d28ed9f3fe23714f6628_u256;
    const auto s = 0x3134a4ba8fafe11b351a720538398a5635e235c0b3258dce19942000731079ec_u256;
    const auto parity = false;

    constexpr auto Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_u256;

    constexpr auto FieldPrime =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_u256;

    constexpr auto calldata_size = 6 * size;
    uint8_t calldata[calldata_size];  // Order, FieldPrime, hash, r, s, parity
    auto calldata_ptr = &calldata[0];

    intx::be::unsafe::store(calldata_ptr, Order);
    const auto order_offset = static_cast<size_t>(calldata_ptr - &calldata[0]);
    calldata_ptr += sizeof(Order);

    intx::be::unsafe::store(calldata_ptr, FieldPrime);
    const auto prime_field_offset = static_cast<size_t>(calldata_ptr - &calldata[0]);
    calldata_ptr += sizeof(FieldPrime);

    memcpy(calldata_ptr, hash.bytes, sizeof(hash.bytes));
    const auto hash_offset = static_cast<size_t>(calldata_ptr - &calldata[0]);
    calldata_ptr += sizeof(hash.bytes);

    intx::be::unsafe::store(calldata_ptr, r);
    const auto r_offset = static_cast<size_t>(calldata_ptr - &calldata[0]);
    calldata_ptr += sizeof(r);

    intx::be::unsafe::store(calldata_ptr, s);
    calldata_ptr += sizeof(s);

    intx::be::unsafe::store(calldata_ptr, static_cast<uint256>(parity));
    const auto parity_offset = static_cast<size_t>(calldata_ptr - &calldata[0]);

    auto code = calldatacopy(push(0), push(0), push(calldata_size));
    auto free_mem_offset = calldata_size;
    code += setupx(0xFF, size, order_offset);
    const auto order_num_slots_placeholder_start = code.size() - 6;

    size_t u1_mem_offset = 0;
    size_t u2_mem_offset = 0;

    {
        ValueSlotsRegister vs_reg;
        SlotsScope scope(vs_reg);
        const auto hash_idx = scope.register_slot();
        const auto z_idx =
            hash_idx;  // TODO: "Convert hash e to z field element by doing z = e % n."
        const auto r_idx = scope.register_slot();
        const auto s_idx = scope.register_slot();

        code += storex(3, hash_offset, hash_idx);

        const auto r_inv_idx = scope.register_slot();
        scalar_inv_secp256k1(code, scope, {r_idx}, {r_inv_idx});

        const auto z_neg_idx = scope.register_slot();
        code += submodx(z_neg_idx, 0, z_idx);

        const auto u1_idx = scope.register_slot();
        code += mulmodx(u1_idx, z_neg_idx, r_inv_idx);

        const auto u2_idx = scope.register_slot();
        code += mulmodx(u2_idx, s_idx, r_inv_idx);

        code += loadx(1, u1_idx, free_mem_offset);
        u1_mem_offset = free_mem_offset;
        free_mem_offset += size;

        code += loadx(1, u2_idx, free_mem_offset);
        u2_mem_offset = free_mem_offset;
        free_mem_offset += size;

        code[order_num_slots_placeholder_start] = vs_reg.max_slots_used();
    }
    {
        ValueSlotsRegister vs_reg;
        SlotsScope scope(vs_reg);

        const auto r_idx = scope.register_slot();

        code += setupx(0xFF, size, prime_field_offset);
        const auto prime_field_num_slots_placeholder_start = code.size() - 6;

        code += storex(1, r_offset, r_idx);

        code += mstore(free_mem_offset, push(0x7_u256));
        const auto B_idx = scope.register_slot();
        code += storex(1, free_mem_offset, B_idx);
        free_mem_offset += size;

        const auto y_idx = scope.register_slot();
        code += mload(parity_offset);
        calculate_y(code, scope, {r_idx, B_idx}, {y_idx});

        code += mstore(free_mem_offset, 1);
        const auto _1_idx = scope.register_slot();
        code += storex(1, free_mem_offset, _1_idx);
        code += storex(1, free_mem_offset, 1);
        free_mem_offset += size;

        code += mstore(free_mem_offset, 7 * 3);
        const auto B3_idx = scope.register_slot();
        code += storex(1, free_mem_offset, B3_idx);
        free_mem_offset += size;

        code += mstore(free_mem_offset,
            push(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256));
        const auto Gx_idx = scope.register_slot();
        code += storex(1, free_mem_offset, Gx_idx);
        free_mem_offset += size;

        code += mstore(free_mem_offset,
            push(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256));
        const auto Gy_idx = scope.register_slot();
        code += storex(1, free_mem_offset, Gy_idx);
        free_mem_offset += size;

        code += mload(u1_mem_offset);

        const auto T1x_idx = scope.register_slot();
        const auto T1y_idx = scope.register_slot();
        const auto T1z_idx = scope.register_slot();
        ecmul(code, scope, {Gx_idx, Gy_idx, _1_idx, B3_idx}, {T1x_idx, T1y_idx, T1z_idx});

        const auto T2x_idx = scope.register_slot();
        const auto T2y_idx = scope.register_slot();
        const auto T2z_idx = scope.register_slot();
        code += mload(u2_mem_offset);
        ecmul(code, scope, {r_idx, y_idx, _1_idx, B3_idx}, {T2x_idx, T2y_idx, T2z_idx});

        const auto pqx_idx = scope.register_slot();
        const auto pqy_idx = scope.register_slot();
        const auto pqz_idx = scope.register_slot();
        ecadd(code, scope, {T1x_idx, T1y_idx, T1z_idx, T2x_idx, T2y_idx, T2z_idx, B3_idx},
            {pqx_idx, pqy_idx, pqz_idx});

        const auto pqz_inv_idx = scope.register_slot();
        field_inv_secp256k1(code, scope, {pqz_idx}, {pqz_inv_idx});

        code += mulmodx(pqx_idx, pqx_idx, pqz_inv_idx);
        code += mulmodx(pqy_idx, pqy_idx, pqz_inv_idx);

        code[prime_field_num_slots_placeholder_start] = vs_reg.max_slots_used();

        code += loadx(2, pqx_idx, free_mem_offset);

        // return loaded result
        code += ret(free_mem_offset, size * 2);
    }

    execute(100000, code, {calldata, calldata_size});

    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, size * 2);

    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "43ec87f8ee6f58605d947dac51b5e4cfe26705f509e5dad058212aadda180835"
        "90ebad786ce091f5af1719bf30ee236a4e6ce8a7ab6c36a16c93c6177aa109df");
}

namespace
{
void ecadd(bytecode& code, const SlotsScope& outer_scope, const std::array<uint8_t, 7>& inputs,
    const std::array<uint8_t, 3>& outputs)
{
    auto const x3_idx = outputs[0];
    auto const y3_idx = outputs[1];
    auto const z3_idx = outputs[2];

    const auto x1_idx = inputs[0];
    const auto y1_idx = inputs[1];
    const auto z1_idx = inputs[2];
    const auto x2_idx = inputs[3];
    const auto y2_idx = inputs[4];
    const auto z2_idx = inputs[5];
    const auto b3_idx = inputs[6];

    // Point addition in projective space.
    SlotsScope scope(outer_scope);
    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();
    const auto t3_idx = scope.register_slot();
    const auto t4_idx = scope.register_slot();

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

void dbl(bytecode& code, const SlotsScope& outer_scope, const std::array<uint8_t, 4>& inputs,
    const std::array<uint8_t, 3>& outputs)
{
    const auto rx_idx = outputs[0];
    const auto ry_idx = outputs[1];
    const auto rz_idx = outputs[2];

    const auto x_idx = inputs[0];
    const auto y_idx = inputs[1];
    const auto z_idx = inputs[2];
    const auto b3_idx = inputs[3];

    const auto x3_idx = rx_idx;
    const auto y3_idx = ry_idx;
    const auto z3_idx = rz_idx;

    SlotsScope scope(outer_scope);

    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();

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

void ecmul(bytecode& code, const SlotsScope& outer_scope, const std::array<uint8_t, 4>& inputs,
    const std::array<uint8_t, 3>& outputs)
{
    const auto px_idx = outputs[0];
    const auto py_idx = outputs[1];
    const auto pz_idx = outputs[2];

    // Initialize p to [0, 1, 0] (infinity)
    code += copy_values<1>({0}, {px_idx});
    code += copy_values<1>({1}, {py_idx});
    code += copy_values<1>({0}, {pz_idx});

    {
        SlotsScope scope0(outer_scope);

        const auto qx_idx = scope0.register_slot();
        const auto qy_idx = scope0.register_slot();
        const auto qz_idx = scope0.register_slot();
        const auto b3_idx = scope0.register_slot();

        code += copy_values(inputs, {qx_idx, qy_idx, qz_idx, b3_idx});

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

        const auto rx_idx = scope0.register_slot();
        const auto ry_idx = scope0.register_slot();
        const auto rz_idx = scope0.register_slot();

        ecadd(code, SlotsScope(scope0), {qx_idx, qy_idx, qz_idx, px_idx, py_idx, pz_idx, b3_idx},
            {rx_idx, ry_idx, rz_idx});

        code += copy_values<3>({rx_idx, ry_idx, rz_idx}, {qx_idx, qy_idx, qz_idx});

        dbl(code, SlotsScope(scope0), {px_idx, py_idx, pz_idx, b3_idx}, {rx_idx, ry_idx, rz_idx});

        code += copy_values<3>({rx_idx, ry_idx, rz_idx}, {px_idx, py_idx, pz_idx});

        code += push(0xffff);
        const auto else0_end_placeholder_start = code.size() - 2;
        code += bytecode(OP_JUMP);

        code += bytecode(OP_JUMPDEST);
        intx::be::unsafe::store(
            &code[else0_placeholder_start], static_cast<uint16_t>(code.size() - 1));

        ecadd(code, SlotsScope(scope0), {qx_idx, qy_idx, qz_idx, px_idx, py_idx, pz_idx, b3_idx},
            {rx_idx, ry_idx, rz_idx});

        code += copy_values<3>({rx_idx, ry_idx, rz_idx}, {px_idx, py_idx, pz_idx});

        dbl(code, SlotsScope(scope0), {qx_idx, qy_idx, qz_idx, b3_idx}, {rx_idx, ry_idx, rz_idx});

        code += copy_values<3>({rx_idx, ry_idx, rz_idx}, {qx_idx, qy_idx, qz_idx});

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

void field_inv_bn254(bytecode& code, const SlotsScope& outer_scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr)
{
    const auto x_idx = x_idx_arr[0];
    const auto dst_idx = dst_idx_arr[0];

    // Inversion computation
    // Allocate Temporaries.
    SlotsScope scope(outer_scope);
    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();
    const auto t3_idx = scope.register_slot();
    const auto t4_idx = scope.register_slot();
    const auto t5_idx = scope.register_slot();
    const auto t6_idx = scope.register_slot();
    const auto t7_idx = scope.register_slot();
    const auto t8_idx = scope.register_slot();
    const auto t9_idx = scope.register_slot();
    const auto t10_idx = scope.register_slot();
    const auto t11_idx = scope.register_slot();
    const auto t12_idx = scope.register_slot();
    const auto t13_idx = scope.register_slot();
    const auto t14_idx = scope.register_slot();
    const auto t15_idx = scope.register_slot();
    const auto t16_idx = scope.register_slot();
    const auto t17_idx = scope.register_slot();
    const auto t18_idx = scope.register_slot();
    const auto t19_idx = scope.register_slot();
    const auto t20_idx = scope.register_slot();
    const auto t21_idx = scope.register_slot();
    const auto z_idx = dst_idx;

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
}

void field_inv_secp256k1(bytecode& code, const SlotsScope& outer_scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr)
{
    // Computes modular exponentiation
    // x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d
    // Operations: 255 squares 15 multiplies
    // Generated by github.com/mmcloughlin/addchain v0.4.0.
    //   addchain search 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d
    //     > secp256k1_field_inv.acc
    //   addchain gen -tmpl expmod.tmpl secp256k1_field_inv.acc
    //     > secp256k1_field_inv.cpp
    //
    // Exponentiation computation is derived from the addition chain:
    //
    // _10     = 2*1
    // _100    = 2*_10
    // _101    = 1 + _100
    // _111    = _10 + _101
    // _1110   = 2*_111
    // _111000 = _1110 << 2
    // _111111 = _111 + _111000
    // i13     = _111111 << 4 + _1110
    // x12     = i13 << 2 + _111
    // x22     = x12 << 10 + i13 + 1
    // i29     = 2*x22
    // i31     = i29 << 2
    // i54     = i31 << 22 + i31
    // i122    = (i54 << 20 + i29) << 46 + i54
    // x223    = i122 << 110 + i122 + _111
    // i269    = ((x223 << 23 + x22) << 7 + _101) << 3
    // return    _101 + i269

    const auto z_idx = dst_idx_arr[0];
    const auto x_idx = x_idx_arr[0];

    // Allocate Temporaries.
    SlotsScope scope(outer_scope);
    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();
    const auto t3_idx = scope.register_slot();
    const auto t4_idx = scope.register_slot();

    // Step 1: t0 = x^0x2
    code += mulmodx(t0_idx, x_idx, x_idx);

    // Step 2: z = x^0x4
    code += mulmodx(z_idx, t0_idx, t0_idx);

    // Step 3: z = x^0x5
    code += mulmodx(z_idx, x_idx, z_idx);

    // Step 4: t1 = x^0x7
    code += mulmodx(t1_idx, t0_idx, z_idx);

    // Step 5: t0 = x^0xe
    code += mulmodx(t0_idx, t1_idx, t1_idx);

    // Step 7: t2 = x^0x38
    code += mulmodx(t2_idx, t0_idx, t0_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 8: t2 = x^0x3f
    code += mulmodx(t2_idx, t1_idx, t2_idx);

    // Step 12: t2 = x^0x3f0
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 13: t0 = x^0x3fe
    code += mulmodx(t0_idx, t0_idx, t2_idx);

    // Step 15: t2 = x^0xff8
    code += mulmodx(t2_idx, t0_idx, t0_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 16: t2 = x^0xfff
    code += mulmodx(t2_idx, t1_idx, t2_idx);

    // Step 26: t2 = x^0x3ffc00
    for (int i = 0; i < 10; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 27: t0 = x^0x3ffffe
    code += mulmodx(t0_idx, t0_idx, t2_idx);

    // Step 28: t0 = x^0x3fffff
    code += mulmodx(t0_idx, x_idx, t0_idx);

    // Step 29: t3 = x^0x7ffffe
    code += mulmodx(t3_idx, t0_idx, t0_idx);

    // Step 31: t2 = x^0x1fffff8
    code += mulmodx(t2_idx, t3_idx, t3_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 53: t4 = x^0x7ffffe000000
    code += mulmodx(t4_idx, t2_idx, t2_idx);
    for (int i = 1; i < 22; ++i)
        code += mulmodx(t4_idx, t4_idx, t4_idx);

    // Step 54: t2 = x^0x7ffffffffff8
    code += mulmodx(t2_idx, t2_idx, t4_idx);

    // Step 74: t4 = x^0x7ffffffffff800000
    code += mulmodx(t4_idx, t2_idx, t2_idx);
    for (int i = 1; i < 20; ++i)
        code += mulmodx(t4_idx, t4_idx, t4_idx);

    // Step 75: t3 = x^0x7fffffffffffffffe
    code += mulmodx(t3_idx, t3_idx, t4_idx);

    // Step 121: t3 = x^0x1ffffffffffffffff800000000000
    for (int i = 0; i < 46; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 122: t2 = x^0x1fffffffffffffffffffffffffff8
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 232: t3 = x^0x7ffffffffffffffffffffffffffe0000000000000000000000000000
    code += mulmodx(t3_idx, t2_idx, t2_idx);
    for (int i = 1; i < 110; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 233: t2 = x^0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffff8
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 234: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    code += mulmodx(t1_idx, t1_idx, t2_idx);

    // Step 257: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        code += mulmodx(t1_idx, t1_idx, t1_idx);

    // Step 258: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    code += mulmodx(t0_idx, t0_idx, t1_idx);

    // Step 265: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff80
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 266: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff85
    code += mulmodx(t0_idx, z_idx, t0_idx);

    // Step 269: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc28
    for (int i = 0; i < 3; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 270: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d
    code += mulmodx(z_idx, z_idx, t0_idx);
}

void scalar_inv_secp256k1(bytecode& code, const SlotsScope& outer_scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr)
{
    // Computes modular exponentiation
    // x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f
    // Operations: 253 squares 40 multiplies
    // Generated by github.com/mmcloughlin/addchain v0.4.0.
    //   addchain search 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f
    //     > secp256k1_scalar_inv.acc
    //   addchain gen -tmpl expmod.tmpl secp256k1_scalar_inv.acc
    //     > secp256k1_scalar_inv.cpp
    //
    // Exponentiation computation is derived from the addition chain:
    //
    // _10       = 2*1
    // _11       = 1 + _10
    // _101      = _10 + _11ķ
    // _111      = _10 + _101
    // _1001     = _10 + _111
    // _1011     = _10 + _1001
    // _1101     = _10 + _1011
    // _110100   = _1101 << 2
    // _111111   = _1011 + _110100
    // _1111110  = 2*_111111
    // _1111111  = 1 + _1111110
    // _11111110 = 2*_1111111
    // _11111111 = 1 + _11111110
    // i17       = _11111111 << 3
    // i19       = i17 << 2
    // i20       = 2*i19
    // i21       = 2*i20
    // i39       = (i21 << 7 + i20) << 9 + i21
    // i73       = (i39 << 6 + i19) << 26 + i39
    // x127      = (i73 << 4 + i17) << 60 + i73 + _1111111
    // i154      = ((x127 << 5 + _1011) << 3 + _101) << 4
    // i166      = ((_101 + i154) << 4 + _111) << 5 + _1101
    // i181      = ((i166 << 2 + _11) << 5 + _111) << 6
    // i193      = ((_1101 + i181) << 5 + _1011) << 4 + _1101
    // i214      = ((i193 << 3 + 1) << 6 + _101) << 10
    // i230      = ((_111 + i214) << 4 + _111) << 9 + _11111111
    // i247      = ((i230 << 5 + _1001) << 6 + _1011) << 4
    // i261      = ((_1101 + i247) << 5 + _11) << 6 + _1101
    // i283      = ((i261 << 10 + _1101) << 4 + _1001) << 6
    // return      (1 + i283) << 8 + _111111

    SlotsScope scope(outer_scope);
    const auto x_idx = x_idx_arr[0];
    const auto z_idx = dst_idx_arr[0];

    // Allocate Temporaries.
    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();
    const auto t3_idx = scope.register_slot();
    const auto t4_idx = scope.register_slot();
    const auto t5_idx = scope.register_slot();
    const auto t6_idx = scope.register_slot();
    const auto t7_idx = scope.register_slot();
    const auto t8_idx = scope.register_slot();
    const auto t9_idx = scope.register_slot();
    const auto t10_idx = scope.register_slot();
    const auto t11_idx = scope.register_slot();
    const auto t12_idx = scope.register_slot();

    // Step 1: z = x^0x2
    code += mulmodx(z_idx, x_idx, x_idx);

    // Step 2: t2 = x^0x3
    code += mulmodx(t2_idx, x_idx, z_idx);

    // Step 3: t6 = x^0x5
    code += mulmodx(t6_idx, z_idx, t2_idx);

    // Step 4: t5 = x^0x7
    code += mulmodx(t5_idx, z_idx, t6_idx);

    // Step 5: t0 = x^0x9
    code += mulmodx(t0_idx, z_idx, t5_idx);

    // Step 6: t3 = x^0xb
    code += mulmodx(t3_idx, z_idx, t0_idx);

    // Step 7: t1 = x^0xd
    code += mulmodx(t1_idx, z_idx, t3_idx);

    // Step 9: z = x^0x34
    code += mulmodx(z_idx, t1_idx, t1_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(z_idx, z_idx, z_idx);

    // Step 10: z = x^0x3f
    code += mulmodx(z_idx, t3_idx, z_idx);

    // Step 11: t4 = x^0x7e
    code += mulmodx(t4_idx, z_idx, z_idx);

    // Step 12: t7 = x^0x7f
    code += mulmodx(t7_idx, x_idx, t4_idx);

    // Step 13: t4 = x^0xfe
    code += mulmodx(t4_idx, t7_idx, t7_idx);

    // Step 14: t4 = x^0xff
    code += mulmodx(t4_idx, x_idx, t4_idx);

    // Step 17: t9 = x^0x7f8
    code += mulmodx(t9_idx, t4_idx, t4_idx);
    for (int i = 1; i < 3; ++i)
        code += mulmodx(t9_idx, t9_idx, t9_idx);

    // Step 19: t10 = x^0x1fe0
    code += mulmodx(t10_idx, t9_idx, t9_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t10_idx, t10_idx, t10_idx);

    // Step 20: t11 = x^0x3fc0
    code += mulmodx(t11_idx, t10_idx, t10_idx);

    // Step 21: t8 = x^0x7f80
    code += mulmodx(t8_idx, t11_idx, t11_idx);

    // Step 28: t12 = x^0x3fc000
    code += mulmodx(t12_idx, t8_idx, t8_idx);
    for (int i = 1; i < 7; ++i)
        code += mulmodx(t12_idx, t12_idx, t12_idx);

    // Step 29: t11 = x^0x3fffc0
    code += mulmodx(t11_idx, t11_idx, t12_idx);

    // Step 38: t11 = x^0x7fff8000
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t11_idx, t11_idx, t11_idx);

    // Step 39: t8 = x^0x7fffff80
    code += mulmodx(t8_idx, t8_idx, t11_idx);

    // Step 45: t11 = x^0x1fffffe000
    code += mulmodx(t11_idx, t8_idx, t8_idx);
    for (int i = 1; i < 6; ++i)
        code += mulmodx(t11_idx, t11_idx, t11_idx);

    // Step 46: t10 = x^0x1fffffffe0
    code += mulmodx(t10_idx, t10_idx, t11_idx);

    // Step 72: t10 = x^0x7fffffff80000000
    for (int i = 0; i < 26; ++i)
        code += mulmodx(t10_idx, t10_idx, t10_idx);

    // Step 73: t8 = x^0x7fffffffffffff80
    code += mulmodx(t8_idx, t8_idx, t10_idx);

    // Step 77: t10 = x^0x7fffffffffffff800
    code += mulmodx(t10_idx, t8_idx, t8_idx);
    for (int i = 1; i < 4; ++i)
        code += mulmodx(t10_idx, t10_idx, t10_idx);

    // Step 78: t9 = x^0x7fffffffffffffff8
    code += mulmodx(t9_idx, t9_idx, t10_idx);

    // Step 138: t9 = x^0x7fffffffffffffff8000000000000000
    for (int i = 0; i < 60; ++i)
        code += mulmodx(t9_idx, t9_idx, t9_idx);

    // Step 139: t8 = x^0x7fffffffffffffffffffffffffffff80
    code += mulmodx(t8_idx, t8_idx, t9_idx);

    // Step 140: t7 = x^0x7fffffffffffffffffffffffffffffff
    code += mulmodx(t7_idx, t7_idx, t8_idx);

    // Step 145: t7 = x^0xfffffffffffffffffffffffffffffffe0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 146: t7 = x^0xfffffffffffffffffffffffffffffffeb
    code += mulmodx(t7_idx, t3_idx, t7_idx);

    // Step 149: t7 = x^0x7fffffffffffffffffffffffffffffff58
    for (int i = 0; i < 3; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 150: t7 = x^0x7fffffffffffffffffffffffffffffff5d
    code += mulmodx(t7_idx, t6_idx, t7_idx);

    // Step 154: t7 = x^0x7fffffffffffffffffffffffffffffff5d0
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 155: t7 = x^0x7fffffffffffffffffffffffffffffff5d5
    code += mulmodx(t7_idx, t6_idx, t7_idx);

    // Step 159: t7 = x^0x7fffffffffffffffffffffffffffffff5d50
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 160: t7 = x^0x7fffffffffffffffffffffffffffffff5d57
    code += mulmodx(t7_idx, t5_idx, t7_idx);

    // Step 165: t7 = x^0xfffffffffffffffffffffffffffffffebaae0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 166: t7 = x^0xfffffffffffffffffffffffffffffffebaaed
    code += mulmodx(t7_idx, t1_idx, t7_idx);

    // Step 168: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb4
    for (int i = 0; i < 2; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 169: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb7
    code += mulmodx(t7_idx, t2_idx, t7_idx);

    // Step 174: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 175: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e7
    code += mulmodx(t7_idx, t5_idx, t7_idx);

    // Step 181: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9c0
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 182: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd
    code += mulmodx(t7_idx, t1_idx, t7_idx);

    // Step 187: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739a0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 188: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739ab
    code += mulmodx(t7_idx, t3_idx, t7_idx);

    // Step 192: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739ab0
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 193: t7 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd
    code += mulmodx(t7_idx, t1_idx, t7_idx);

    // Step 196: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e8
    for (int i = 0; i < 3; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 197: t7 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9
    code += mulmodx(t7_idx, x_idx, t7_idx);

    // Step 203: t7 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a40
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t7_idx, t7_idx, t7_idx);

    // Step 204: t6 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a45
    code += mulmodx(t6_idx, t6_idx, t7_idx);

    // Step 214: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e91400
    for (int i = 0; i < 10; ++i)
        code += mulmodx(t6_idx, t6_idx, t6_idx);

    // Step 215: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e91407
    code += mulmodx(t6_idx, t5_idx, t6_idx);

    // Step 219: t6 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e914070
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t6_idx, t6_idx, t6_idx);

    // Step 220: t5 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e914077
    code += mulmodx(t5_idx, t5_idx, t6_idx);

    // Step 229: t5 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280ee00
    for (int i = 0; i < 9; ++i)
        code += mulmodx(t5_idx, t5_idx, t5_idx);

    // Step 230: t4 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff
    code += mulmodx(t4_idx, t4_idx, t5_idx);

    // Step 235: t4 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t4_idx, t4_idx, t4_idx);

    // Step 236: t4 = x^0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe9
    code += mulmodx(t4_idx, t0_idx, t4_idx);

    // Step 242: t4 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa40
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t4_idx, t4_idx, t4_idx);

    // Step 243: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4b
    code += mulmodx(t3_idx, t3_idx, t4_idx);

    // Step 247: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4b0
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 248: t3 = x^0x1fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4bd
    code += mulmodx(t3_idx, t1_idx, t3_idx);

    // Step 253: t3 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a0
    for (int i = 0; i < 5; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 254: t2 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 260: t2 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8c0
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 261: t2 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd
    code += mulmodx(t2_idx, t1_idx, t2_idx);

    // Step 271: t2 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a33400
    for (int i = 0; i < 10; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 272: t1 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d
    code += mulmodx(t1_idx, t1_idx, t2_idx);

    // Step 276: t1 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d0
    for (int i = 0; i < 4; ++i)
        code += mulmodx(t1_idx, t1_idx, t1_idx);

    // Step 277: t0 = x^0x3fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d9
    code += mulmodx(t0_idx, t0_idx, t1_idx);

    // Step 283: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03640
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 284: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641
    code += mulmodx(t0_idx, x_idx, t0_idx);

    // Step 292: t0 = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364100
    for (int i = 0; i < 8; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 293: z = x^0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f
    code += mulmodx(z_idx, z_idx, t0_idx);
}

void field_sqrt(bytecode& code, const SlotsScope& outer_scope,
    const std::array<uint8_t, 1>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr)
{
    // Computes modular exponentiation
    // x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    // Operations: 253 squares 13 multiplies
    // Main part generated by github.com/mmcloughlin/addchain v0.4.0.
    //   addchain search 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    //     > secp256k1_sqrt.acc
    //   addchain gen -tmpl expmod.tmpl secp256k1_sqrt.acc
    //     > secp256k1_sqrt.cpp
    //
    // Exponentiation computation is derived from the addition chain:
    //
    // _10      = 2*1
    // _11      = 1 + _10
    // _1100    = _11 << 2
    // _1111    = _11 + _1100
    // _11110   = 2*_1111
    // _11111   = 1 + _11110
    // _1111100 = _11111 << 2
    // _1111111 = _11 + _1111100
    // x11      = _1111111 << 4 + _1111
    // x22      = x11 << 11 + x11
    // x27      = x22 << 5 + _11111
    // x54      = x27 << 27 + x27
    // x108     = x54 << 54 + x54
    // x216     = x108 << 108 + x108
    // x223     = x216 << 7 + _1111111
    // return     ((x223 << 23 + x22) << 6 + _11) << 2

    const auto x_idx = x_idx_arr[0];
    const auto z_idx = dst_idx_arr[0];

    SlotsScope scope(outer_scope);
    // Allocate Temporaries.
    const auto t0_idx = scope.register_slot();
    const auto t1_idx = scope.register_slot();
    const auto t2_idx = scope.register_slot();
    const auto t3_idx = scope.register_slot();


    // Step 1: z = x^0x2
    code += mulmodx(z_idx, x_idx, x_idx);

    // Step 2: z = x^0x3
    code += mulmodx(z_idx, x_idx, z_idx);

    // Step 4: t0 = x^0xc
    code += mulmodx(t0_idx, z_idx, z_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 5: t0 = x^0xf
    code += mulmodx(t0_idx, z_idx, t0_idx);

    // Step 6: t1 = x^0x1e
    code += mulmodx(t1_idx, t0_idx, t0_idx);

    // Step 7: t2 = x^0x1f
    code += mulmodx(t2_idx, x_idx, t1_idx);

    // Step 9: t1 = x^0x7c
    code += mulmodx(t1_idx, t2_idx, t2_idx);
    for (int i = 1; i < 2; ++i)
        code += mulmodx(t1_idx, t1_idx, t1_idx);

    // Step 10: t1 = x^0x7f
    code += mulmodx(t1_idx, z_idx, t1_idx);

    // Step 14: t3 = x^0x7f0
    code += mulmodx(t3_idx, t1_idx, t1_idx);
    for (int i = 1; i < 4; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 15: t0 = x^0x7ff
    code += mulmodx(t0_idx, t0_idx, t3_idx);

    // Step 26: t3 = x^0x3ff800
    code += mulmodx(t3_idx, t0_idx, t0_idx);
    for (int i = 1; i < 11; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 27: t0 = x^0x3fffff
    code += mulmodx(t0_idx, t0_idx, t3_idx);

    // Step 32: t3 = x^0x7ffffe0
    code += mulmodx(t3_idx, t0_idx, t0_idx);
    for (int i = 1; i < 5; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 33: t2 = x^0x7ffffff
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 60: t3 = x^0x3ffffff8000000
    code += mulmodx(t3_idx, t2_idx, t2_idx);
    for (int i = 1; i < 27; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 61: t2 = x^0x3fffffffffffff
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 115: t3 = x^0xfffffffffffffc0000000000000
    code += mulmodx(t3_idx, t2_idx, t2_idx);
    for (int i = 1; i < 54; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 116: t2 = x^0xfffffffffffffffffffffffffff
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 224: t3 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
    code += mulmodx(t3_idx, t2_idx, t2_idx);
    for (int i = 1; i < 108; ++i)
        code += mulmodx(t3_idx, t3_idx, t3_idx);

    // Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
    code += mulmodx(t2_idx, t2_idx, t3_idx);

    // Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
    for (int i = 0; i < 7; ++i)
        code += mulmodx(t2_idx, t2_idx, t2_idx);

    // Step 233: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    code += mulmodx(t1_idx, t1_idx, t2_idx);

    // Step 256: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
    for (int i = 0; i < 23; ++i)
        code += mulmodx(t1_idx, t1_idx, t1_idx);

    // Step 257: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
    code += mulmodx(t0_idx, t0_idx, t1_idx);

    // Step 263: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc0
    for (int i = 0; i < 6; ++i)
        code += mulmodx(t0_idx, t0_idx, t0_idx);

    // Step 264: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc3
    code += mulmodx(z_idx, z_idx, t0_idx);

    // Step 266: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    for (int i = 0; i < 2; ++i)
        code += mulmodx(z_idx, z_idx, z_idx);

    // TODO: Handle this case too.
    //    if (m.mul(z, z) != x)
    //        return std::nullopt;  // Computed value is not the square root.
}

void calculate_y(bytecode& code, const SlotsScope& outer_scope,
    const std::array<uint8_t, 2>& x_idx_arr, const std::array<uint8_t, 1>& dst_idx_arr)
{
    const auto x_idx = x_idx_arr[0];
    const auto B_idx = x_idx_arr[1];
    const auto y_idx = dst_idx_arr[0];

    SlotsScope scope(outer_scope);
    const auto x3_idx = scope.register_slot();

    code += mulmodx(x3_idx, x_idx, x_idx);
    code += mulmodx(x3_idx, x3_idx, x_idx);
    code += addmodx(x3_idx, x3_idx, B_idx);

    field_sqrt(code, scope, {x3_idx}, {y_idx});

    const auto size = sizeof(uint256);

    code += loadx(1, y_idx, size * 15);
    code += mload(size * 15) + push(1) + OP_AND;
    code += bytecode(OP_EQ) + push(0xFFFF);
    const auto if_end_placeholder_start = code.size() - 2;
    code += bytecode(OP_JUMPI);
    code += submodx(y_idx, 0, y_idx);
    code += bytecode(OP_JUMPDEST);
    intx::be::unsafe::store(
        &code[if_end_placeholder_start], static_cast<uint16_t>(code.size() - 1));
}

}  // namespace
