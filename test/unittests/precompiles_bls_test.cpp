// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/bytes.hpp>
#include <evmone_precompiles/bls.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>
#include <array>

using evmone::test::operator""_hex;

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
