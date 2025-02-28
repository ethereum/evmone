// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/bytes.hpp>
#include <evmone_precompiles/bls.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>
#include <array>

using evmone::test::operator""_hex;

namespace
{
/// G1 group point at infinity.
const auto G1_inf = evmc::bytes(128, 0);
/// G1 subgroup generator.
const auto G1_1 =
    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"_hex;
/// G1 subgroup example point (maybe [2]G1_1?).
const auto G1_2 =
    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21"_hex;
/// G1 subgroup example point (maybe [3]G1_1?).
const auto G1_3 =
    "000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025"_hex;

/// G2 group point at infinity.
const auto G2_inf = evmc::bytes(256, 0);
/// G2 subgroup generator.
const auto G2_1 =
    "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"_hex;
/// Negation of G2 subgroup generator.
const auto G2_m1 =
    "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed"_hex;

const auto RESULT_ONE = "0000000000000000000000000000000000000000000000000000000000000001"_hex;
const auto RESULT_ZERO = "0000000000000000000000000000000000000000000000000000000000000000"_hex;
}  // namespace

TEST(bls, g1_add)
{
    const auto x0 =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"_hex;
    const auto y0 =
        "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"_hex;
    const auto x1 =
        "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"_hex;
    const auto y1 =
        "00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21"_hex;

    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::g1_add(rx, ry, x0.data(), y0.data(), x1.data(), y1.data()));

    const auto expected_x =
        "000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d"_hex;
    const auto expected_y =
        "0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g1_add_not_on_curve)
{
    {
        const auto x0 =
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6ba"_hex;
        const auto y0 =
            "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"_hex;
        const auto x1 =
            "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"_hex;
        const auto y1 =
            "00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21"_hex;

        uint8_t rx[64];
        uint8_t ry[64];

        EXPECT_FALSE(
            evmone::crypto::bls::g1_add(rx, ry, x0.data(), y0.data(), x1.data(), y1.data()));
    }
    {
        const auto x0 =
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"_hex;
        const auto y0 =
            "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"_hex;
        const auto x1 =
            "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"_hex;
        const auto y1 =
            "00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a22"_hex;

        uint8_t rx[64];
        uint8_t ry[64];

        EXPECT_FALSE(
            evmone::crypto::bls::g1_add(rx, ry, x0.data(), y0.data(), x1.data(), y1.data()));
    }
}

TEST(bls, g1_mul)
{
    const auto x =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"_hex;
    const auto y =
        "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"_hex;
    const auto c = "0000000000000000000000000000000000000000000000000000000000000002"_hex;

    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::g1_mul(rx, ry, x.data(), y.data(), c.data()));

    const auto expected_x =
        "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"_hex;
    const auto expected_y =
        "00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g2_add)
{
    const auto x0 =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"_hex;
    const auto y0 =
        "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"_hex;
    const auto x1 =
        "00000000000000000000000000000000103121a2ceaae586d240843a398967325f8eb5a93e8fea99b62b9f88d8556c80dd726a4b30e84a36eeabaf3592937f2700000000000000000000000000000000086b990f3da2aeac0a36143b7d7c824428215140db1bb859338764cb58458f081d92664f9053b50b3fbd2e4723121b68"_hex;
    const auto y1 =
        "000000000000000000000000000000000f9e7ba9a86a8f7624aa2b42dcc8772e1af4ae115685e60abc2c9b90242167acef3d0be4050bf935eed7c3b6fc7ba77e000000000000000000000000000000000d22c3652d0dc6f0fc9316e14268477c2049ef772e852108d269d9c38dba1d4802e8dae479818184c08f9a569d878451"_hex;

    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::g2_add(rx, ry, x0.data(), y0.data(), x1.data(), y1.data()));

    const auto expected_x =
        "000000000000000000000000000000000b54a8a7b08bd6827ed9a797de216b8c9057b3a9ca93e2f88e7f04f19accc42da90d883632b9ca4dc38d013f71ede4db00000000000000000000000000000000077eba4eecf0bd764dce8ed5f45040dd8f3b3427cb35230509482c14651713282946306247866dfe39a8e33016fcbe52"_hex;
    const auto expected_y =
        "0000000000000000000000000000000014e60a76a29ef85cbd69f251b9f29147b67cfe3ed2823d3f9776b3a0efd2731941d47436dc6d2b58d9e65f8438bad073000000000000000000000000000000001586c3c910d95754fef7a732df78e279c3d37431c6a2b77e67a00c7c130a8fcd4d19f159cbeb997a178108fffffcbd20"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g2_mul)
{
    const auto x =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"_hex;
    const auto y =
        "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"_hex;
    const auto c = "0000000000000000000000000000000000000000000000000000000000000002"_hex;

    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::g2_mul(rx, ry, x.data(), y.data(), c.data()));

    const auto expected_x =
        "000000000000000000000000000000001638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053000000000000000000000000000000000a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"_hex;
    const auto expected_y =
        "000000000000000000000000000000000468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899000000000000000000000000000000000f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g1_msm)
{
    using namespace evmc::literals;
    auto input =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f17"
        "1bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e"
        "30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000"
        "00000000000000000000000000000000000000000000000002"_hex;
    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::g1_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"_hex;
    const auto expected_y =
        "00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g1_msm_inf_0)
{
    using namespace evmc::literals;
    auto input =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000000"_hex;
    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::g1_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"_hex;
    const auto expected_y =
        "00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g1_msm_inf_2)
{
    using namespace evmc::literals;
    auto input =
        "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"_hex;
    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::g1_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"_hex;
    const auto expected_y =
        "00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g2_msm)
{
    using namespace evmc::literals;
    auto input =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0000000000000000000000000000000000000000000000000000000000000002"_hex;
    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::g2_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000001638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053000000000000000000000000000000000a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"_hex;
    const auto expected_y =
        "000000000000000000000000000000000468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899000000000000000000000000000000000f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g2_msm_inf_0)
{
    using namespace evmc::literals;
    auto input =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0000000000000000000000000000000000000000000000000000000000000000"_hex;
    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::g2_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000001638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053000000000000000000000000000000000a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"_hex;
    const auto expected_y =
        "000000000000000000000000000000000468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899000000000000000000000000000000000f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, g2_msm_inf_2)
{
    using namespace evmc::literals;
    auto input =
        "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"_hex;
    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::g2_msm(rx, ry, input.data(), input.size()));

    const auto expected_x =
        "000000000000000000000000000000001638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053000000000000000000000000000000000a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"_hex;
    const auto expected_y =
        "000000000000000000000000000000000468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899000000000000000000000000000000000f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, map_fp_to_g1)
{
    using namespace evmc::literals;
    auto input =
        "00000000000000000000000000000000156c8a6a2c184569d69a76be144b5cdc5141d2d2ca4fe341f011e25e3969c55ad9e9b9ce2eb833c81a908e5fa4ac5f03"_hex;
    uint8_t rx[64];
    uint8_t ry[64];

    EXPECT_TRUE(evmone::crypto::bls::map_fp_to_g1(rx, ry, input.data()));

    const auto expected_x =
        "00000000000000000000000000000000184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba"_hex;
    const auto expected_y =
        "0000000000000000000000000000000004407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, map_fp2_to_g2)
{
    using namespace evmc::literals;
    auto input =
        "0000000000000000000000000000000007355d25caf6e7f2f0cb2812ca0e513bd026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b040000000000000000000000000000000002829ce3c021339ccb5caf3e187f6370e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c"_hex;
    uint8_t rx[128];
    uint8_t ry[128];

    EXPECT_TRUE(evmone::crypto::bls::map_fp2_to_g2(rx, ry, input.data()));

    const auto expected_x =
        "0000000000000000000000000000000000e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb700000000000000000000000000000000126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b"_hex;
    const auto expected_y =
        "000000000000000000000000000000000caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42000000000000000000000000000000001498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d"_hex;

    EXPECT_EQ(evmc::bytes_view(rx, sizeof rx), expected_x);
    EXPECT_EQ(evmc::bytes_view(ry, sizeof ry), expected_y);
}

TEST(bls, paring_check_three_pairs_correct)
{
    // proves e(1, 1) * e(x, 1) * e(y, -1) == 1, i.e. x + 1 = y
    const auto input = (G1_1 + G2_1) + (G1_2 + G2_1) + (G1_3 + G2_m1);
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, std::size(r)), RESULT_ONE);
}

TEST(bls, paring_check_two_pairs_incorrect)
{
    const auto input = (G1_1 + G2_1) + (G1_2 + G2_m1);
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, std::size(r)), RESULT_ZERO);
}

TEST(bls, paring_check_one_pair_g1_inf)
{
    const auto input = G1_inf + G2_1;
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, sizeof r), RESULT_ONE);
}

TEST(bls, paring_check_one_pair_g2_inf)
{
    const auto input = G1_1 + G2_inf;
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, sizeof r), RESULT_ONE);
}

TEST(bls, paring_check_two_pairs_g1_inf)
{
    const auto input = (G1_1 + G2_1) + (G1_inf + G2_1);
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, sizeof r), RESULT_ONE);
}

TEST(bls, paring_check_two_pairs_g2_inf)
{
    const auto input = (G1_1 + G2_inf) + (G1_2 + G2_1);
    uint8_t r[32];
    EXPECT_TRUE(evmone::crypto::bls::pairing_check(r, input.data(), input.size()));
    EXPECT_EQ(evmc::bytes_view(r, sizeof r), RESULT_ONE);
}
