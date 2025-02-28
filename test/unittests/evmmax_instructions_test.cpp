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

// Code generated with customized solidity version from test/evmmax-precompiles/expmod.yul
static const auto expmod_code =
    "ef000101003402000d00ee002d002b00270074004e0046001600a500170031004100ab04000000008000180102000602020006020200040204000d020100060201000701010003010100040101000301000009020100070501000860605f356020359080e30001509082818501e30002949093604035920101e3000293848083e3000b601f1936013560011617e100b260018086868686868083e3000495929891949086918a99878c83838de3000c99e3000c81896003c2c60000030001818781c26002c2c402000200010001c502000200000001e3000395909183871415e1003a505090600385879596938660028196e300099584038601c1c05fc281c26002c2c502000000020001c30000010002000180e3000960015f82c1f3879550956003918694939782e300099083038097825e9582e3000991825e9550959192e0ffa0938493e3000cf3601f8116908090825f93e1000c50606082e3000993840137e49150915060018260051c0190602003915fe0ffe0601f8216918091835f94e1000a5082e3000993840137e49250925060018160051c0191602003925fe0ffe2600160ff1b905116e1000e8090e3000990600160ff1b8252e46020900180e300099060018252e4908082e3000582928292601f8116e1006060051c905f905f90846101000392848310e1003250505050506020600160fd1b0360ff820160031c169081e300099060018060ff83161b9160081c0160051b838301035290e46001908360051b830180519182891c179052841b920191e0ffae5f80fd601f8216e100448160051c91601f19910101905f915f828110e10004505050e48151928315e10009505050e300079001e491936001919350610100900193601f1990019201919091e0ffcb5f80fd90601f8116e1003b60051c90905f915f828110e10004505050e48151928315e10009505050e300089001e4919360019193506101006020910194019201919091e0ffcd5f80fd8015e1000c805f039016e3000860ff03e450610100e48015e1009b5f908060801c15e100878060c01c15e100738060e01c15e1005f8060f01c15e1004b8060f81c15e100378060fc1c15e100238060fe1c15e1000f60ff1c15e10001e460019001e0fff890600290019060021be0ffe590600490019060041be0ffd190600890019060081be0ffbd90601090019060101be0ffa990602090019060201be0ff9590604090019060401be0ff819050608090811be0ff6f50610100e4604051908115e100068101604052e49050606090e0fff26001908060051c9080e30009915f81811115e1000e505082905f19908301015381c2e4805f869260051b86015201e0ffdd9060051c905f905f838110e1000550509050e48060051b82015180e100085060019001e0ffe25f93919319810190169017e100086001809290e0ffe25050505fe4610100856001939495c05fc282e3000a8160051c9181e300066020600160fd1b038160031c16820151600181e3000860ff031b80e10054505060019060081c01828110e1000c505050e3000960018082c1e48060051b820151600160ff1b80e10009505060019001e0ffd5c501000100010001818116e1000760011c80e0ffdfc501000100000001e0ffeec501000100010001818116e1000760011c80e0ff94c501000100000001e0ffee"_hex;

TEST_P(evm, evmmax_expmod_odd)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
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
