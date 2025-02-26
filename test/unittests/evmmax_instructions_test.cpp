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


TEST_P(evm, evmmax_expmod)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("histogram", "1");

    const auto code =
        "ef000101001c02000700df0081002b002900170041008a04000000008000100204000d010200070101000601010003020100070501000a60603610e100d55f356020356040359181810190838201606001361415e100b9601f8316e100af601f840160051c92601f810160051c938560608683601f870160051c0101e30004938582601f821660200387013780868601968301602088013785019501601f82166020038601378084e30005601f1936013560011617e1004e90600184958195938294e30001939183838a899b94969be3000695e30006936003c281c26002c2c402000200010001c502000200000001c502000200010001c5020002000300016001600282c1f3939190e30006f35f80fd5f80fd5f80fd5f601f8316e100768260051c5f818110e1003b508293925f505f905f90846101000392848310e1000b5050505050e300029090e46001908360051b830180519182891c179052841b920191e0ffd58060059492941b82015180e1000b5060019001929092e0ffa66001919350e300035f198486030160081b019290e0ffde5f80fd6020600160fd1b0360ff820160031c1680e300049160018060ff83161b9160081c0160051b8284010352e45f5f916101008310e10004509050e460018116e1000f60018091811c920192019190e0ffde509050e4604051908115e100068101604052e49050606090e0fff29060051c905f905f838110e1000550509050e48060051b82015180e100085060019001e0ffe25f93919319810190169017e100086001809290e0ffe25050505fe46101008560019395c05fc28260051c83e30004905f81811115e1005f5050600190815f19868301015381c260051c905f828110e1000c505050e3000460018082c1e48060051b820151600160ff1b80e10009505060019001e0ffd5c501000100010001818116e1000760011c80e0ffdfc501000100000001e0ffee805f60019260051b85015201e0ff8b"_hex;

    vm.set_option("trace", "1");
    uint8_t calldata[6 * sizeof(uint256)];
    intx::be::unsafe::store(calldata, 32_u256);
    intx::be::unsafe::store(&calldata[32], 32_u256);
    intx::be::unsafe::store(&calldata[2 * 32], 32_u256);
    intx::be::unsafe::store(&calldata[3 * 32], 2_u256);
    intx::be::unsafe::store(&calldata[4 * 32], 5_u256);
    intx::be::unsafe::store(&calldata[5 * 32], 9_u256);

    execute(60000, code, {calldata, 6 * sizeof(uint256)});
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 32);
    EXPECT_EQ(hex({result.output_data, result.output_size}),
        "0000000000000000000000000000000000000000000000000000000000000005");
}
