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
        "ef000101001002000400670017002f0062040000000080000a0101000301000009060100093660608110e1005c5f3560203590604035928383830101606001901415e1004160208206e100378282820101e3000191816060939381818637018183850191818184370192858383019485376020360335600116e10001008594e30003f35f80fd5f80fd5f80fd604051908115e100068101604052e49050606090e0fff2600190602081049080e30001915f81811115e1000c50508280910382015381c2e4805f602087930286015201e0ffdf60019150610100866020959496c05fc283e30002045f818110e1000c505050e3000160018082c1e4600160ff1b806020830285015191e10009505060019001e0ffd4c501000100010001818116e1000760011c80e0ffdfc501000100000001e0ffee"_hex;

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
