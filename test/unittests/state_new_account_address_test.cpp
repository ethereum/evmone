// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/host.hpp>

using namespace evmc;
using namespace evmc::literals;

inline constexpr uint64_t nonces[] = {0, 1, 0x80, 0xffffffffffffffff};
inline constexpr address senders[] = {
    0x00_address, 0x01_address, 0x8000000000000000000000000000000000000000_address};

TEST(state_new_account_address, create)
{
    constexpr auto addr = evmone::state::compute_create_address;

    auto s = senders[0];
    EXPECT_EQ(addr(s, nonces[0]), 0xbd770416a3345f91e4b34576cb804a576fa48eb1_address);
    EXPECT_EQ(addr(s, nonces[3]), 0x1262d73ea59d3a661bf8751d16cf1a5377149e75_address);

    s = senders[1];
    EXPECT_EQ(addr(s, nonces[0]), 0x522b3294e6d06aa25ad0f1b8891242e335d3b459_address);
    EXPECT_EQ(addr(s, nonces[1]), 0x535b3d7a252fa034ed71f0c53ec0c6f784cb64e1_address);
    EXPECT_EQ(addr(s, nonces[2]), 0x09c1ef8f55c61b94e8b92a55d0891d408a991e18_address);
    EXPECT_EQ(addr(s, nonces[3]), 0x001567239734aeadea21023c2a7c0d9bb9ae4af9_address);

    s = senders[2];
    EXPECT_EQ(addr(s, nonces[0]), 0x3cb1045aee4a06f522ea2b69e4f3d21ed3c135d1_address);
    EXPECT_EQ(addr(s, nonces[3]), 0xe1aa03e4a7b6991d69aff8ece53ceafdf347082e_address);

    const auto beacon_roots1 = addr(0xb20a608c624Ca5003905aA834De7156C68b2E1d0_address, 0);
    EXPECT_EQ(beacon_roots1, 0x00000000219ab540356cbb839cbe05303d7705fa_address);

    const auto beacon_roots2 = addr(0x0B799C86a49DEeb90402691F1041aa3AF2d3C875_address, 0);
    EXPECT_EQ(beacon_roots2, 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address);
}

TEST(state_new_account_address, create2)
{
    constexpr auto addr = evmone::state::compute_create2_address;
    constexpr auto z0 = 0x00_bytes32;
    constexpr auto z1 = 0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0_bytes32;
    const auto i0 = bytes{};
    const auto i1 = bytes{0xFE};

    EXPECT_EQ(addr(senders[0], z0, i0), 0xe33c0c7f7df4809055c3eba6c09cfe4baf1bd9e0_address);
    EXPECT_EQ(addr(senders[2], z0, i1), 0x3517dea701ed18fc4a99dc111c5946e1f1541dad_address);
    EXPECT_EQ(addr(senders[1], z1, i0), 0x7be1c1cb3b8298f21c56add66defce03e2d32604_address);
    EXPECT_EQ(addr(senders[2], z1, i1), 0x8f459e65c8f00a9c0c0493de7b0c61c3c27f7384_address);
}
