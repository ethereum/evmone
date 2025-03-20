#include "ntt.hpp"
#include <evmmax/evmmax.hpp>
#include <iostream>

using namespace evmone::test;
using namespace intx;

namespace
{
const std::array<uint16_t, 1024> psi_rev = {1, 1479, 4043, 7143, 5736, 4134, 1305, 722, 1646, 1212,
    6429, 9094, 3504, 8747, 9744, 8668, 4591, 6561, 5023, 6461, 10938, 4978, 6512, 8961, 11340,
    9664, 9650, 4821, 563, 9314, 2744, 3006, 1000, 4320, 12208, 3091, 9326, 4896, 2366, 9238, 11563,
    7678, 1853, 140, 1635, 9521, 11112, 4255, 7203, 10963, 9088, 9275, 790, 955, 11119, 2319, 9542,
    4846, 3135, 3712, 9995, 11227, 3553, 7484, 544, 5791, 11950, 2468, 11267, 9, 9447, 11809, 10616,
    8011, 7300, 6958, 1381, 2525, 4177, 8705, 2837, 5374, 4354, 130, 2396, 4452, 3296, 8340, 12171,
    9813, 2197, 5067, 11336, 3748, 5767, 827, 3284, 2881, 5092, 10200, 10276, 9000, 9048, 11560,
    10593, 10861, 334, 2426, 4632, 5755, 11029, 4388, 10530, 3707, 3694, 7110, 11934, 3382, 2548,
    8058, 4890, 6378, 9558, 3932, 5542, 12144, 3459, 3637, 1663, 1777, 1426, 7635, 2704, 5291, 7351,
    8653, 9140, 160, 12286, 7852, 2166, 8374, 7370, 12176, 3364, 10600, 9018, 4057, 2174, 7917,
    2847, 7875, 7094, 9509, 10805, 4895, 2305, 5042, 4053, 9644, 3985, 7384, 476, 3531, 420, 6730,
    2178, 1544, 9273, 243, 9289, 11618, 3136, 5191, 8889, 9890, 9103, 6882, 10163, 1630, 11136,
    2884, 8241, 10040, 3247, 9603, 2969, 3978, 6957, 3510, 9919, 9424, 7575, 8146, 1537, 12047,
    8585, 2678, 5019, 545, 7404, 1017, 10657, 7205, 10849, 8526, 3066, 12262, 11244, 2859, 2481,
    7277, 2912, 5698, 354, 7428, 390, 11516, 3778, 8456, 442, 2401, 5101, 11222, 4976, 10682, 875,
    3780, 7278, 11287, 5088, 4284, 6022, 9302, 2437, 3646, 10102, 9723, 6039, 9867, 11854, 7952,
    10911, 1912, 11796, 8193, 9908, 5444, 9041, 1207, 5277, 1168, 11885, 4645, 1065, 2143, 3957,
    2839, 10162, 151, 11858, 1579, 2505, 5906, 52, 3174, 1323, 2766, 3336, 6055, 6415, 677, 3445,
    7509, 4698, 5057, 12097, 10968, 10240, 4912, 5241, 9369, 3127, 4169, 3482, 787, 6821, 11279,
    12231, 241, 11286, 3532, 11404, 6008, 10333, 7280, 2844, 3438, 8077, 975, 5681, 8812, 142, 1105,
    4080, 421, 3602, 6221, 4624, 6212, 3263, 8689, 5886, 4782, 5594, 3029, 4213, 504, 605, 9987,
    2033, 8291, 10367, 8410, 11316, 11035, 10930, 5435, 3710, 6196, 6950, 5446, 8301, 468, 11973,
    11907, 6152, 4948, 11889, 10561, 6153, 6427, 3643, 5415, 56, 9090, 5206, 6760, 1702, 10302,
    11635, 3565, 5315, 8214, 7373, 4324, 10120, 11767, 5079, 3262, 11011, 2344, 6715, 1973, 5925,
    1018, 3514, 11248, 7500, 7822, 5537, 4749, 8500, 12142, 5456, 7840, 6844, 8429, 7753, 1050,
    6118, 3818, 9606, 1190, 5876, 2281, 2031, 5333, 8298, 8320, 12133, 2767, 453, 6381, 418, 3772,
    5429, 4774, 1293, 7552, 2361, 1843, 9259, 4115, 218, 2908, 8855, 8760, 2882, 10484, 1954, 2051,
    2447, 6147, 576, 3963, 1858, 7535, 3315, 11863, 2925, 347, 3757, 1975, 10596, 3009, 174, 11566,
    9551, 5868, 2655, 6554, 1512, 11939, 5383, 10474, 9087, 7796, 6920, 10232, 6374, 1483, 49,
    11026, 1489, 2500, 10706, 5942, 1404, 11964, 11143, 948, 4049, 3728, 1159, 5990, 652, 5766,
    6190, 11994, 4016, 4077, 2919, 3762, 6328, 7183, 10695, 1962, 7991, 8960, 12121, 9597, 7105,
    1200, 6122, 9734, 3956, 1360, 6119, 5297, 3054, 6803, 9166, 1747, 5919, 4433, 3834, 5257, 683,
    2459, 8633, 12225, 9786, 9341, 6507, 1566, 11454, 6224, 3570, 8049, 3150, 1319, 4046, 11580,
    1958, 7967, 2078, 1112, 11231, 8210, 11367, 441, 1826, 9363, 9118, 4489, 3708, 3238, 11153,
    3449, 7080, 1092, 3359, 3205, 8024, 8611, 10361, 11825, 2068, 10900, 4404, 346, 3163, 8257,
    7449, 6127, 12164, 11749, 10763, 4222, 8051, 11677, 8921, 8062, 7228, 11071, 11851, 3515, 9011,
    5993, 6877, 8080, 1536, 10568, 4103, 9860, 11572, 8700, 1373, 2982, 3448, 11946, 4538, 1908,
    4727, 11081, 1866, 7078, 10179, 716, 10125, 6873, 1705, 2450, 11475, 416, 10224, 5826, 7725,
    8794, 1756, 4145, 8755, 8328, 5063, 4176, 8524, 10771, 2461, 2275, 8022, 5653, 6693, 6302,
    11710, 3889, 212, 6323, 9175, 2769, 5734, 1176, 5508, 11014, 4860, 11164, 11158, 10844, 11841,
    1014, 7508, 7365, 10962, 3607, 5232, 8347, 12221, 10029, 7723, 5836, 3200, 1535, 9572, 60, 7784,
    10032, 10872, 5676, 3087, 6454, 7406, 3975, 7326, 8545, 2528, 3056, 5845, 5588, 11877, 5102,
    1255, 506, 10897, 5784, 9615, 2212, 3338, 9013, 1178, 9513, 6811, 8778, 10347, 3408, 1165, 2575,
    10453, 425, 11897, 10104, 377, 4578, 375, 1620, 1038, 11366, 6085, 4167, 6092, 2231, 2800,
    12096, 1522, 2151, 8946, 8170, 5002, 12269, 7681, 5163, 10545, 1314, 2894, 3654, 11951, 3947,
    9834, 6599, 7350, 7174, 1248, 2442, 8330, 6492, 6330, 10141, 5724, 10964, 1945, 1029, 8945,
    6691, 10397, 3624, 6825, 4906, 4670, 512, 7735, 11295, 9389, 12050, 1804, 1403, 6195, 7100, 406,
    10602, 7021, 12143, 8914, 9998, 7954, 3393, 8464, 8054, 7376, 8761, 11667, 1737, 4499, 5672,
    8307, 9342, 11653, 5609, 4605, 2689, 180, 8151, 5219, 1409, 204, 6780, 9806, 2054, 1344, 9247,
    463, 8882, 3981, 1468, 4475, 7043, 3017, 1236, 9168, 4705, 2600, 11232, 4739, 4251, 1226, 6771,
    11925, 2360, 3028, 5216, 11839, 10345, 11711, 5368, 11779, 7628, 2622, 6903, 8929, 7605, 7154,
    12226, 8481, 8619, 2373, 7302, 10891, 9199, 826, 5043, 5789, 8787, 6671, 10631, 9224, 1506,
    7806, 5703, 4719, 11538, 6389, 11379, 4693, 9951, 11872, 9996, 6138, 8820, 4443, 8871, 7186,
    10398, 1802, 10734, 1590, 4411, 1223, 2334, 2946, 6828, 2637, 4510, 881, 365, 10362, 1015, 7250,
    6742, 2485, 904, 24, 10918, 11009, 11675, 980, 11607, 5082, 7699, 5207, 8239, 844, 7087, 3221,
    8016, 8452, 2595, 5289, 6627, 567, 2941, 1406, 2633, 6940, 2945, 3232, 11996, 3769, 7434, 3944,
    8190, 6759, 5604, 11024, 9282, 10118, 8809, 9169, 6184, 6643, 6086, 8753, 5370, 8348, 8536,
    1282, 3572, 9457, 2021, 4730, 3229, 1706, 3929, 5054, 3154, 9004, 7929, 12282, 1936, 8566,
    11444, 11520, 5526, 50, 216, 767, 3805, 4153, 10076, 1279, 11424, 9617, 5170, 12100, 3116,
    10080, 1763, 3815, 1734, 1350, 5832, 8420, 4423, 1530, 1694, 10036, 10421, 9559, 5411, 4820,
    1160, 9195, 7771, 2840, 9811, 4194, 9270, 7315, 4565, 7211, 10506, 944, 7519, 7002, 8620, 7624,
    6883, 3020, 5673, 5410, 1251, 10499, 7014, 2035, 11249, 6164, 10407, 8176, 12217, 10447, 3840,
    2712, 4834, 2828, 4352, 1241, 4378, 3451, 4094, 3045, 5781, 9646, 11194, 7592, 8711, 8823,
    10588, 7785, 11511, 2626, 530, 10808, 9332, 9349, 2046, 8972, 9757, 8957, 12150, 3268, 3795,
    1849, 6513, 4523, 4301, 457, 8, 8835, 3758, 8071, 4390, 10013, 982, 2593, 879, 9687, 10388,
    11787, 7171, 6063, 8496, 8443, 1573, 5969, 4649, 9360, 6026, 1030, 11823, 10608, 8468, 11415,
    9988, 5650, 12119, 648, 12139, 2307, 8000, 11498, 9855, 9416, 2827, 9754, 11169, 21, 6481};

[[maybe_unused]] bytecode generate_internal_nttfw(size_t a_ptr, size_t at_ptr, uint8_t size,
    uint8_t S_slot, uint8_t slot_range_first, [[maybe_unused]] uint8_t slot_range_last)
{
    assert(slot_range_first + 3 * size <= slot_range_last);

    bytecode res;
    const uint8_t a_start_slot = slot_range_first;
    res += storex(size, a_ptr, a_start_slot);
    const uint8_t at_start_slot = a_start_slot + size;
    res += storex(size, at_ptr, at_start_slot);

    const uint8_t V_slot_start = at_start_slot + size;

    // V := at * S
    res += mulmodx(V_slot_start, 1, at_start_slot, 1, S_slot, 0, size);

    // at = a - V
    res += submodx(at_start_slot, 1, a_start_slot, 1, V_slot_start, 1, size);

    // a = a + V
    res += addmodx(a_start_slot, 1, a_start_slot, 1, V_slot_start, 1, size);

    res += loadx(size, a_start_slot, a_ptr);
    res += loadx(size, at_start_slot, at_ptr);

    return res;
}

bytecode generate_shuffle_bytecode(uint8_t input_slot_start, uint8_t output_slot_start,
    uint8_t zero_slot, uint8_t window_size, uint8_t num_windows)
{
    bytecode res;

    for (uint8_t k = 0; k < window_size / 2; ++k)
    {
        res += addmodx(output_slot_start + 2 * k, window_size, input_slot_start + k, window_size,
            zero_slot, 0, num_windows);
        res += addmodx(output_slot_start + 2 * k + 1, window_size,
            input_slot_start + (window_size / 2) + k, window_size, zero_slot, 0, num_windows);
    }

    return res;
}

bytecode generate_unshuffle_bytecode(uint8_t input_slot_start, uint8_t output_slot_start,
    uint8_t zero_slot, uint8_t window_size, uint8_t num_windows)
{
    bytecode res;

    for (uint8_t k = 0; k < window_size / 2; ++k)
    {
        res += addmodx(output_slot_start + k, window_size, input_slot_start + 2 * k, window_size,
            zero_slot, 0, num_windows);
        res += addmodx(output_slot_start + (window_size / 2) + k, window_size,
            input_slot_start + 2 * k + 1, window_size, zero_slot, 0, num_windows);
    }

    return res;
}

bytecode generate_spread_bytecode(uint8_t input_slot_start, uint8_t output_slot_start,
    uint8_t zero_slot, uint8_t window_size, uint8_t num_windows)
{
    bytecode res;

    for (uint8_t k = 0; k < window_size; ++k)
    {
        res += addmodx(
            output_slot_start + k, window_size, input_slot_start, 1, zero_slot, 0, num_windows);
    }

    return res;
}

[[maybe_unused]] bytecode log_evmmax(uint8_t start_slot, uint8_t num_slots, size_t free_mem_ptr)
{
    bytecode res;
    res += loadx(num_slots, start_slot, free_mem_ptr);
    res += log0(free_mem_ptr, num_slots * 2);

    return res;
}

[[maybe_unused]] bytecode generate_internal_nttfw_small_t(size_t a_ptr, uint8_t slot_range_first,
    [[maybe_unused]] uint8_t slot_range_last, size_t psi_rev_mem_ptr, uint8_t zero_slot,
    uint8_t window_size)
{
    constexpr uint8_t MAX_BUCKET_SIZE = 64;
    constexpr uint8_t VALUE_SIZE = 2;
    const uint8_t num_windows = MAX_BUCKET_SIZE / window_size;
    bytecode res;

    for (size_t j = 0; j < 512; j += MAX_BUCKET_SIZE)
    {
        // store input elements to [slot_range_first + 64, slot_range_first + 128)
        const uint8_t a_tmp_slot_start = slot_range_first + MAX_BUCKET_SIZE;
        res += storex(MAX_BUCKET_SIZE, a_ptr + VALUE_SIZE * j, a_tmp_slot_start);

        // shuffle input
        const uint8_t a_slot_start = slot_range_first;
        res += generate_shuffle_bytecode(
            a_tmp_slot_start, a_slot_start, zero_slot, window_size, num_windows);

        // load psi
        // reuse slots. tmp not needed any longer.
        const uint8_t psi_rev_slot_start = a_tmp_slot_start + MAX_BUCKET_SIZE / 2;
        res += storex(num_windows,
            psi_rev_mem_ptr + (512 / window_size) * VALUE_SIZE + (j / window_size) * VALUE_SIZE,
            psi_rev_slot_start);

        // spread psi
        const uint8_t psi_rev_spreaded_slot_start = a_tmp_slot_start;
        res += generate_spread_bytecode(psi_rev_slot_start, psi_rev_spreaded_slot_start, zero_slot,
            window_size / 2, num_windows);

        // res += log_evmmax(psi_rev_spreaded_slot_start, 32, 10 * 1024);
        // multiply V = at * S
        const uint8_t V_slot_start = psi_rev_spreaded_slot_start + (window_size / 2) * num_windows;
        res += mulmodx(V_slot_start, 1, a_slot_start + 1, 2, psi_rev_spreaded_slot_start, 1,
            MAX_BUCKET_SIZE / 2);

        // at = a - V
        res += submodx(a_slot_start + 1, 2, a_slot_start, 2, V_slot_start, 1, MAX_BUCKET_SIZE / 2);

        // a = a + V
        res += addmodx(a_slot_start, 2, a_slot_start, 2, V_slot_start, 1, MAX_BUCKET_SIZE / 2);

        // unshuffle input
        res += generate_unshuffle_bytecode(
            a_slot_start, a_tmp_slot_start, zero_slot, window_size, num_windows);

        // res += log_evmmax(a_tmp_slot_start, 64, 10 * 1024);

        res += loadx(MAX_BUCKET_SIZE, a_tmp_slot_start, a_ptr + 2 * j);
    }

    return res;
}

bytecode generate_nttfw(size_t a_ptr, size_t size, uint8_t S_slot, size_t psi_rev_mem_ptr,
    uint8_t slot_range_first, uint8_t slot_range_last)
{
    bytecode res;
    size_t m = 1;
    size_t t = size;
    constexpr auto VALUE_SIZE = 2;

    while (m < size)
    {
        t = t >> 1;

        constexpr size_t max_bucket_size = 64;
        if (t > 2)
        {
            // res += log0(a_ptr, 128);
            for (size_t i = 0; i < m; i++)
            {
                res += storex(1, psi_rev_mem_ptr + (m + i) * 2, S_slot);

                size_t j1 = (i * t) << 1;
                size_t j2 = j1 + t - 1;

                for (size_t j = j1; j < j2 + 1; j += max_bucket_size)
                {
                    res += generate_internal_nttfw(a_ptr + j * VALUE_SIZE,
                        a_ptr + (t + j) * VALUE_SIZE,
                        static_cast<uint8_t>(std::min(t, max_bucket_size)), S_slot,
                        slot_range_first, slot_range_last);
                }
            }

            // res += log0(a_ptr, 128);
        }
        else if (t == 2)  // t == 2 Can be tested for t in a range [2, k].
                          // It looks now that for t == 4 it's slower
        {
            // res += log0(a_ptr, 128);
            //  zero last slot
            const uint8_t zero_slot = slot_range_last;
            res += submodx(zero_slot, 0, zero_slot, 0, zero_slot, 0, 1);

            assert(2 * t <= std::numeric_limits<uint8_t>::max());
            res += generate_internal_nttfw_small_t(a_ptr, slot_range_first, slot_range_last - 1,
                psi_rev_mem_ptr, zero_slot, static_cast<uint8_t>(2 * t));

            // res += log0(a_ptr, 128);
        }
        else  // t == 1
        {
            // res += log0(a_ptr, 128);
            for (size_t j = 0; j < 512; j += max_bucket_size)
            {
                // store `a` 64 elements
                const uint8_t a_slot_start = slot_range_first;
                res += storex(max_bucket_size, a_ptr + VALUE_SIZE * j, a_slot_start);

                // store S 32 elements
                const uint8_t pri_res_slot_start = a_slot_start + max_bucket_size;
                res += storex(max_bucket_size / 2,
                    psi_rev_mem_ptr + 256 * VALUE_SIZE + (j / 2) * VALUE_SIZE, pri_res_slot_start);

                // multiply V = at * S
                const uint8_t V_slot_start = pri_res_slot_start + max_bucket_size / 2;
                res += mulmodx(V_slot_start, 1, a_slot_start + 1, 2, pri_res_slot_start, 1,
                    max_bucket_size / 2);

                // at = a - V
                res += submodx(
                    a_slot_start + 1, 2, a_slot_start, 2, V_slot_start, 1, max_bucket_size / 2);

                // a = a + V
                res +=
                    addmodx(a_slot_start, 2, a_slot_start, 2, V_slot_start, 1, max_bucket_size / 2);

                res += loadx(max_bucket_size, a_slot_start, a_ptr + 2 * j);
            }

            // res += log0(a_ptr, 2 * 512);
        }

        m = m << 1;
    }

    res = res + OP_RETF;

    return res;
}
}  // namespace

bytecode create_shuffle_bytecode_test(size_t input_size, uint8_t window_size)
{
    bytecode res = {};

    size_t mem_ptr = 0;
    res += mstore8(mem_ptr, push(12289_u256 >> 8));
    res += mstore8(mem_ptr + 1, push(12289_u256));
    const size_t mod_ptr = mem_ptr;
    res += setmodx(256, 14, mod_ptr);
    mem_ptr += 2;

    const auto VALUE_SIZE = 2;
    res += calldatacopy(mem_ptr, 0, input_size * VALUE_SIZE);
    constexpr uint8_t zero_slot = 255;
    res += submodx(zero_slot, 0, zero_slot, 0, zero_slot, 0, 1);
    const size_t a_ptr = mem_ptr;

    res += storex(input_size, a_ptr, 0);

    res += generate_shuffle_bytecode(0, static_cast<uint8_t>(input_size), zero_slot, window_size,
        static_cast<uint8_t>(input_size / window_size));

    res += loadx(input_size, input_size, a_ptr);

    res += ret(a_ptr, input_size * VALUE_SIZE);

    return eof_bytecode(res, 3);
}

bytecode create_spread_bytecode_test(size_t input_size, uint8_t window_size)
{
    bytecode res = {};

    size_t mem_ptr = 0;
    res += mstore8(mem_ptr, push(12289_u256 >> 8));
    res += mstore8(mem_ptr + 1, push(12289_u256));
    const size_t mod_ptr = mem_ptr;
    res += setmodx(256, 14, mod_ptr);
    mem_ptr += 2;

    const auto VALUE_SIZE = 2;
    res += calldatacopy(mem_ptr, 0, input_size * VALUE_SIZE);
    constexpr uint8_t zero_slot = 255;
    res += submodx(zero_slot, 0, zero_slot, 0, zero_slot, 0, 1);
    const size_t a_ptr = mem_ptr;

    res += storex(input_size, a_ptr, 0);

    res += generate_spread_bytecode(0, static_cast<uint8_t>(input_size), zero_slot, window_size,
        static_cast<uint8_t>(input_size));

    res += loadx(input_size * window_size, input_size, a_ptr);

    res += ret(a_ptr, input_size * window_size * VALUE_SIZE);

    return eof_bytecode(res, 3);
}

bytecode create_nttfw_bytecode()
{
    // Create data section with psi values
    bytecode data = {};
    data.resize(2 * psi_rev.size());

    for (size_t i = 0; i < psi_rev.size(); ++i)
        intx::be::unsafe::store(&data[i * 2], psi_rev[i]);

    bytecode res;
    size_t mem_ptr = 0;

    // Store modulus
    res += mstore8(mem_ptr, push(12289_u256 >> 8));
    res += mstore8(mem_ptr + 1, push(12289_u256));
    const size_t mod_ptr = mem_ptr;
    res += setmodx(256, 14, mod_ptr);
    mem_ptr += 2;

    uint8_t first_available_slot = 0;
    const auto INPUT_SIZE = 512;
    const auto VALUE_SIZE = 2;
    // Load call data to evmmax registers
    res += calldatacopy(mem_ptr, 0, INPUT_SIZE * VALUE_SIZE);
    const size_t a_ptr = mem_ptr;
    mem_ptr += INPUT_SIZE * VALUE_SIZE;

    res += datacopy(mem_ptr, 0, 2 * psi_rev.size());
    const auto psi_rev_mem_ptr = mem_ptr;

    res += callf(1);

    res += ret(a_ptr, INPUT_SIZE * VALUE_SIZE);

    auto container = eof_bytecode(res, 3);

    uint8_t S_slot = first_available_slot++;

    container.code(
        generate_nttfw(a_ptr, INPUT_SIZE, S_slot, psi_rev_mem_ptr, first_available_slot, 255), 0, 0,
        3);

    return container.data(data);
}
