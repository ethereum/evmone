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
using namespace evmone::test;
using evmone::test::evm;

TEST_P(evm, evmmax_32bytes_modulus_test)
{
    // vm.set_option("trace", "1");
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 7
    auto code = mstore(0, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setmodx(3, 32, 0);
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

    rev = EVMC_EXPERIMENTAL;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 7
    auto code = mstore8(0, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setmodx(3, 1, 0);
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

    rev = EVMC_EXPERIMENTAL;  /// TODO: Use EVMC_EVMMAX
    // Modulus == 263 (0x0107)
    auto code = mstore8(0, 0x01);
    code += mstore8(1, 0x07);
    // 3 values slots
    // Modulus size in bytes
    // Modulus offset in EVM memory
    // Modulus ID
    code += setmodx(3, 2, 0);
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

static const auto expmod_code =
    "ef000101002802000a013e001100430027004700290017002f0042006204000000008000170204000603000009010200090201000801010006010100030100000902010007060100093660608110e101335f3560203591604035928381840101606001821415e1011860208106e1010e602080601f850104029283602080601f88010402602080601f860104029387602085069482602083069181818a88602084069a0101e300068160608c819d8491e100c250379901888199848c0191e100ab503787019501908084870191e10093503782019460208287e3000891033560011617e100768260038787986001809996819897968297e30001958d92849e94869395899760ffe300039c909ee300099be30009818a86c2c60000030001818881c26002c2c402000200010001c502000200000001e300069284600285c1c05fc281c26002c2c502000000020001c30000010002000160015f82c1f3949091e30009f360200390015fe0ff6460200390015fe0ff4c60200390015fe0ff355f80fd5f80fd5f80fd8181e300048082938093e30002e30003e4919060208106e1003760209004905f905f91838310e100065050505050e4600190602084028601519081841c176020850287015282610100031b920191e0ffd25f80fd602061010060ff8301040280e3000691602060018061010080850494061b9201028284010352e45f9160208106e1003b602090045f818110e10004505050e46020810283015180e100085060019001e0ffe3816001809396500183036101000290e3000590019390e0ffdf5f80fd5f5f916101008310e10004509050e460018116e1000f60018091811c920192019190e0ffde509050e4604051908115e100068101604052e49050606090e0fff2600190602081049080e30006915f81811115e1000c50508280910382015381c2e4805f602087930286015201e0ffdf9060209004905f905f838110e1000550509050e46020810282015180e100085060019001e0ffe26001819492940390169017e100086001809290e0ffe25050505fe460019150610100866020959496c05fc283e3000704905f828110e1000c505050e3000660018082c1e460208102820151600160ff1b80e10009505060019001e0ffd5c501000100010001818116e1000760011c80e0ffdfc501000100000001e0ffee"_hex;

TEST_P(evm, evmmax_expmod_odd)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("histogram", "1");

    vm.set_option("trace", "1");
    uint8_t calldata[6 * sizeof(uint256)];
    intx::be::unsafe::store(calldata, 32_u256);
    intx::be::unsafe::store(&calldata[32], 32_u256);
    intx::be::unsafe::store(&calldata[2 * 32], 32_u256);
    intx::be::unsafe::store(&calldata[3 * 32], 2_u256);
    intx::be::unsafe::store(&calldata[4 * 32], 5_u256);
    intx::be::unsafe::store(&calldata[5 * 32], 9_u256);

    execute(60000, expmod_code, {calldata, 6 * sizeof(uint256)});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "0000000000000000000000000000000000000000000000000000000000000005");
}

TEST_P(evm, evmmax_expmod_pow2)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("histogram", "1");

    vm.set_option("trace", "1");
    uint8_t calldata[6 * sizeof(uint256)];
    intx::be::unsafe::store(calldata, 32_u256);
    intx::be::unsafe::store(&calldata[32], 32_u256);
    intx::be::unsafe::store(&calldata[2 * 32], 32_u256);
    intx::be::unsafe::store(&calldata[3 * 32], 3_u256);
    intx::be::unsafe::store(&calldata[4 * 32], 5_u256);
    intx::be::unsafe::store(&calldata[5 * 32], 8_u256);

    execute(60000, expmod_code, {calldata, 6 * sizeof(uint256)});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "0000000000000000000000000000000000000000000000000000000000000003");
}

TEST_P(evm, evmmax_expmod_even)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("histogram", "1");

    vm.set_option("trace", "1");
    uint8_t calldata[6 * sizeof(uint256)];
    intx::be::unsafe::store(calldata, 32_u256);
    intx::be::unsafe::store(&calldata[32], 32_u256);
    intx::be::unsafe::store(&calldata[2 * 32], 32_u256);
    intx::be::unsafe::store(&calldata[3 * 32], 3_u256);
    intx::be::unsafe::store(&calldata[4 * 32], 7_u256);
    intx::be::unsafe::store(&calldata[5 * 32], 10_u256);

    execute(60000, expmod_code, {calldata, 6 * sizeof(uint256)});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "0000000000000000000000000000000000000000000000000000000000000007");
}
