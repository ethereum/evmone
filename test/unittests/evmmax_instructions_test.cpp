// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"
#include <evmmax/evmmax.hpp>
#include <gtest/gtest.h>
#include <test/evmmax-precompiles/ntt.hpp>
#include <test/evmmax-precompiles/poseidon.hpp>
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
    code += setmodx(3, 256, 0);
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
    code += setmodx(3, 8, 0);
    // value 3
    code += mstore8(1, 0x03);
    // value 6
    code += mstore8(2, 0x06);
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
    code += ret(17, 1);

    execute(1000, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "06");
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
    code += setmodx(3, 9, 0);
    // value 258
    code += mstore8(2, 0x01);
    code += mstore8(3, 0x02);
    // value 254
    code += mstore8(4, 0x00);
    code += mstore8(5, 0xfe);
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
    code += ret(18, 2);

    execute(1000, code);
    EXPECT_EQ(result.status_code, EVMC_SUCCESS);

    ASSERT_EQ(result.output_size, 2);
    EXPECT_EQ(hex({result.output_data, result.output_size}), "0087");
}


TEST_P(evm, evmmax_poseidon_hash)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    // vm.set_option("histogram", "1");

    for (const auto& code : {
             create_poseidon_hash_bytecode(),
             create_poseidon_hash_bytecode_datacopy(),
             create_poseidon_hash_bytecode_vectorized(),
             create_poseidon_hash_bytecode_vectorized_datacopy(),
         })
    {
        // std::cout << hex(code) << std::endl;

        //    vm.set_option("trace", "1");
        uint8_t calldata[2 * sizeof(uint256)];
        intx::be::unsafe::store(calldata, 2_u256);
        intx::be::unsafe::store(&calldata[32], 1_u256);

        // std::cout << hex({calldata, 64}) << std::endl;

        execute(6000, code, {calldata, 64});
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        ASSERT_EQ(result.output_size, 32);
        EXPECT_EQ(hex({result.output_data, result.output_size}),
            "1576c555b70c9b778666e91d600fdc6d73f30aeed2f6adc5360d6a052259775a");
    }
}

namespace
{
std::array<uint16_t, 512> f_12289_512 = {5072, 8090, 3251, 4761, 259, 10870, 1822, 9635, 5563, 5405,
    3608, 11161, 294, 3226, 1677, 3462, 1785, 5110, 12000, 9790, 7452, 906, 2811, 5750, 8453, 5570,
    5461, 3876, 9416, 2202, 1440, 5014, 11755, 5161, 10296, 12009, 10171, 762, 9795, 5892, 2884,
    6733, 9129, 3340, 1423, 1335, 4953, 7012, 6458, 1816, 10030, 7817, 7748, 729, 11021, 5222, 2349,
    8945, 3140, 2398, 2129, 10243, 5994, 1556, 9535, 9028, 4646, 11899, 12083, 1198, 10295, 9255,
    9749, 5497, 11392, 4049, 10550, 11244, 8646, 596, 7640, 5203, 6058, 10422, 2769, 2784, 7348,
    6243, 1093, 6640, 11396, 6726, 2822, 6098, 3015, 12175, 7507, 9182, 8089, 2086, 6267, 1242,
    8082, 2546, 4720, 4335, 10936, 368, 2080, 7503, 11523, 2520, 1058, 8929, 773, 5836, 11288, 696,
    5564, 10372, 1651, 10698, 3574, 1320, 5700, 4578, 10861, 2374, 10233, 6116, 318, 5994, 5322,
    5558, 5276, 5494, 8935, 5439, 4989, 10624, 1941, 6114, 10181, 5860, 10009, 10573, 919, 3650,
    5539, 12058, 3204, 4697, 2973, 6653, 3769, 11981, 6095, 1801, 4735, 281, 2774, 896, 6530, 4436,
    2023, 8922, 638, 5135, 9951, 2169, 138, 3770, 2404, 596, 5005, 43, 2811, 9260, 361, 5893, 4499,
    12094, 4258, 1530, 10634, 8281, 3924, 11571, 10972, 2128, 8886, 5940, 4747, 6567, 4002, 8715,
    11384, 2133, 910, 3965, 12200, 10022, 11833, 2774, 7570, 10516, 2318, 7897, 754, 11516, 7309,
    677, 4652, 3835, 4237, 7288, 10272, 11569, 5574, 496, 5151, 2371, 10489, 11654, 5160, 11469,
    2002, 5790, 7262, 4514, 4185, 1678, 11862, 1077, 11158, 9803, 7047, 5967, 518, 8277, 6452, 7011,
    10680, 10674, 2879, 8136, 2122, 9113, 11702, 12127, 10159, 10528, 6382, 268, 1662, 11568, 10474,
    1650, 5405, 8010, 158, 10765, 7669, 5126, 378, 4824, 2246, 6048, 6482, 3401, 3533, 1227, 9056,
    10721, 6168, 5591, 1709, 5382, 10322, 119, 10952, 7398, 1089, 8054, 5386, 169, 6123, 10320,
    6528, 835, 7537, 9583, 8088, 3305, 2600, 253, 1600, 3917, 5067, 2609, 11206, 9971, 3542, 5237,
    8032, 9302, 11116, 8318, 5113, 5532, 4116, 6302, 4835, 10887, 10584, 3121, 10898, 2566, 862,
    3682, 4542, 4687, 11756, 7591, 8933, 11449, 7425, 11949, 12144, 12150, 11117, 3893, 6760, 2474,
    5608, 4600, 5257, 10302, 9479, 3669, 10474, 6024, 5116, 1694, 10068, 8696, 2952, 7950, 9815,
    10984, 1793, 1432, 4982, 2747, 11624, 5523, 12102, 11454, 9363, 11238, 6786, 89, 11561, 5191,
    8371, 9858, 2443, 9511, 6935, 3466, 2413, 7184, 2220, 7969, 8114, 2676, 8155, 4700, 1526, 6990,
    6560, 2175, 5996, 8774, 7979, 5700, 7978, 9105, 5002, 6389, 3717, 9257, 11191, 5401, 3788, 650,
    6862, 2963, 5464, 2379, 9247, 8596, 378, 6691, 10332, 5180, 11576, 2738, 4240, 3689, 10220,
    11791, 1200, 589, 106, 1977, 84, 3611, 10622, 4478, 5077, 8266, 8542, 9452, 7064, 195, 2368,
    10009, 5252, 4472, 7469, 2963, 2665, 7070, 7021, 11234, 4248, 8827, 3998, 3065, 2318, 8337,
    6739, 9458, 10469, 6657, 6753, 1705, 5488, 9437, 9681, 9990, 11040, 2338, 10791, 3418, 3245,
    9798, 6672, 1776, 9627, 7953, 3630, 1393, 10813, 10636, 11431, 11199, 4470, 6058, 4495, 8943,
    3211, 10085, 10482, 6176, 3616, 1869, 8294, 827, 678, 10921, 2834, 8347, 8421, 4431, 2225, 161,
    12040, 6115, 1045, 10236, 9898, 6315, 11291, 2307, 7319, 1994, 7858, 7642, 3512, 3911, 8390,
    8500, 6477, 11285, 1243, 9359, 7980, 2372, 2816, 7228};

std::array<uint16_t, 512> f_ntt_12289_512 = {10406, 8420, 7776, 8647, 10107, 8228, 7297, 10926,
    3501, 2935, 5129, 11962, 11156, 7609, 5154, 4684, 6430, 1265, 6357, 3401, 6791, 8683, 4150,
    6869, 5276, 11240, 10820, 2599, 3575, 6090, 2327, 7449, 10091, 9704, 11656, 4069, 7297, 7382,
    9016, 6444, 2730, 2043, 6340, 10818, 8527, 11287, 1102, 1748, 9946, 6134, 2976, 10774, 10666,
    5691, 3048, 6671, 8045, 3556, 1089, 8304, 4370, 11489, 8073, 4755, 4853, 6204, 7435, 3393, 24,
    4613, 7291, 6435, 2621, 7546, 5170, 3705, 10596, 11556, 2428, 6800, 2986, 4187, 7548, 7817,
    6539, 3005, 7208, 10928, 9103, 7881, 10402, 1551, 9587, 2165, 864, 632, 2952, 4156, 10531, 5509,
    8327, 9065, 8828, 4986, 9864, 9108, 73, 4106, 11242, 9938, 4492, 8637, 11733, 3703, 2008, 2753,
    117, 6927, 2865, 6034, 7921, 8773, 9773, 10340, 8925, 738, 946, 4220, 11973, 5415, 4128, 2641,
    1471, 7941, 490, 2136, 6012, 11934, 8917, 2605, 10911, 11443, 928, 6518, 3974, 4893, 3891, 2259,
    11676, 6130, 329, 255, 11945, 8037, 2198, 315, 11299, 7401, 8709, 10369, 3488, 1900, 11744,
    11590, 6646, 1652, 3312, 6933, 8649, 4685, 9678, 4752, 8316, 10381, 9676, 9141, 4635, 9180,
    12064, 10873, 8257, 9911, 2382, 4883, 8228, 5847, 11638, 1147, 3037, 2888, 6620, 9557, 4215,
    3682, 1695, 2415, 1, 8500, 7772, 4423, 2128, 10125, 10654, 9608, 8433, 5888, 3570, 10442, 1398,
    10647, 10178, 8011, 6003, 10642, 6574, 11955, 388, 6790, 2276, 10788, 3681, 6790, 12053, 5536,
    8043, 178, 7422, 3232, 9286, 3057, 2121, 6122, 9891, 5716, 331, 9675, 5674, 6883, 8454, 3976,
    11542, 7637, 4716, 7188, 8560, 4665, 3266, 3368, 1710, 7479, 7936, 4930, 9127, 9169, 4726, 6618,
    11753, 11431, 10184, 1175, 8050, 10558, 10354, 7200, 2334, 7912, 11452, 8292, 8855, 9157, 10078,
    9383, 6904, 2353, 12064, 8558, 5560, 2003, 7173, 12123, 5068, 6525, 4572, 5887, 8825, 11302,
    7893, 9685, 3244, 8457, 2686, 10712, 3250, 851, 10945, 11544, 4826, 11341, 7494, 2428, 4188,
    8754, 2972, 9687, 9913, 676, 156, 10861, 12139, 3158, 165, 2129, 2657, 2755, 2708, 11352, 5258,
    7384, 5308, 5440, 10059, 8614, 7221, 10502, 8790, 6124, 3431, 952, 7358, 1631, 3066, 9394, 5138,
    7157, 5884, 2687, 10259, 5053, 9079, 6092, 553, 7807, 3130, 5141, 1200, 10240, 6394, 6360, 8349,
    9027, 9947, 6386, 615, 2091, 3541, 4074, 3468, 992, 4103, 10906, 5105, 8278, 701, 4334, 1823,
    6151, 4983, 4684, 8924, 2912, 10295, 3715, 6561, 3702, 1992, 9406, 2175, 2279, 8603, 7267, 3744,
    1442, 534, 4119, 7014, 8352, 7391, 5106, 10284, 9061, 4553, 2421, 10066, 6373, 4668, 5490, 1189,
    10698, 2365, 3736, 8108, 5851, 11733, 10118, 694, 7199, 9614, 6897, 1502, 1734, 5064, 11541,
    3216, 9593, 7139, 9974, 9886, 3964, 1288, 6216, 8357, 9460, 11530, 898, 4678, 3334, 2415, 9454,
    1628, 352, 1588, 9287, 5350, 9565, 104, 9041, 8817, 4233, 9566, 5327, 1208, 4537, 1141, 4929,
    5687, 1424, 942, 5266, 5443, 2389, 7962, 469, 11823, 9818, 4662, 8858, 4439, 7273, 9993, 6357,
    1814, 7332, 1307, 7394, 10094, 4717, 10879, 3500, 63, 3945, 11660, 8270, 9140, 5362, 12014,
    6845, 7187, 9343, 4754, 8062, 8744, 10365, 6450, 4492, 7748, 10390, 9713, 11143, 4370, 5462,
    10072, 7694, 1672, 11895, 1263, 8632, 10679, 8134, 9211, 10825, 9325, 2776, 5248, 130, 1364,
    3280, 5997, 8689, 1304, 840, 7365, 7458};


}  // namespace

TEST_P(evm, ntt)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("validate_eof", "1");
    //    vm.set_option("histogram", "1");
    //    vm.set_option("trace", "1");

    uint8_t calldata[2 * 512 * 2];
    uint8_t result_data[2 * 512];

    for (size_t i = 0; i < f_12289_512.size(); ++i)
    {
        intx::be::unsafe::store(&calldata[i * 2], f_12289_512[i]);
        intx::be::unsafe::store(&result_data[i * 2], f_ntt_12289_512[i]);
    }

    for (const auto& code : {create_nttfw_bytecode()})
    {
        std::cout << hex(code) << std::endl;
        // std::cout << code.size() << std::endl;

        execute(30000, code, {calldata, 2 * 512});
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        size_t log_idx = 0;
        for (const auto& l : this->host.recorded_logs)
        {
            std::cout << "log " << log_idx << std::endl;
            for (size_t i = 0; i < l.data.size(); i = i + 2)
                std::cout << i / 2 << ": " << intx::be::unsafe::load<uint16_t>(l.data.data() + i)
                          << std::endl;

            log_idx++;
        }

        ASSERT_EQ(result.output_size, 2 * 512);
        EXPECT_EQ(hex({result.output_data, result.output_size}), hex({result_data, 2 * 512}));
    }
}

TEST_P(evm, ntt_shuffle)
{
    if (is_advanced())
        return;

    rev = EVMC_EXPERIMENTAL;
    vm.set_option("validate_eof", "1");
    // vm.set_option("trace", "1");

    {
        uint8_t calldata[2 * 64];
        uint8_t result_data[2 * 64];

        std::array<uint16_t, 64> test_data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
            60, 61, 62, 63};

        std::array<uint16_t, 64> expected_result = {0, 4, 1, 5, 2, 6, 3, 7, 8, 12, 9, 13, 10, 14,
            11, 15, 16, 20, 17, 21, 18, 22, 19, 23, 24, 28, 25, 29, 26, 30, 27, 31, 32, 36, 33, 37,
            34, 38, 35, 39, 40, 44, 41, 45, 42, 46, 43, 47, 48, 52, 49, 53, 50, 54, 51, 55, 56, 60,
            57, 61, 58, 62, 59, 63};

        for (size_t i = 0; i < 64; ++i)
        {
            intx::be::unsafe::store(&calldata[i * 2], test_data[i]);
            intx::be::unsafe::store(&result_data[i * 2], expected_result[i]);
        }

        const auto code = create_shuffle_bytecode_test(64, 8);

        execute(50000, code, {calldata, 2 * 64});
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        ASSERT_EQ(result.output_size, 2 * 64);
        EXPECT_EQ(hex({result.output_data, result.output_size}), hex({result_data, 2 * 64}));
    }
}

TEST_P(evm, ntt_spread)
{
    {
        if (is_advanced())
            return;
        rev = EVMC_EXPERIMENTAL;
        vm.set_option("validate_eof", "1");

        uint8_t calldata[2 * 64];
        uint8_t result_data[2 * 64];

        std::array<uint16_t, 8> test_data = {0, 1, 2, 3, 4, 5, 6, 7};

        std::array<uint16_t, 8 * 4> expected_result = {0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3,
            3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7};

        for (size_t i = 0; i < 8; ++i)
            intx::be::unsafe::store(&calldata[i * 2], test_data[i]);

        for (size_t i = 0; i < 8 * 4; ++i)
            intx::be::unsafe::store(&result_data[i * 2], expected_result[i]);

        const auto code = create_spread_bytecode_test(8, 4);

        execute(50000, code, {calldata, 2 * 8});
        EXPECT_EQ(result.status_code, EVMC_SUCCESS);

        ASSERT_EQ(result.output_size, 2 * 4 * 8);
        EXPECT_EQ(hex({result.output_data, result.output_size}), hex({result_data, 2 * 4 * 8}));
    }
}
