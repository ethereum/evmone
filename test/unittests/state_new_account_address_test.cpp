// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/host.hpp>

using namespace evmc;
using namespace evmc::literals;
inline constexpr auto addr = evmone::state::compute_new_account_address;

inline constexpr uint64_t nonces[] = {0, 1, 0x80, 0xffffffffffffffff};
inline constexpr address senders[] = {
    0x00_address, 0x01_address, 0x8000000000000000000000000000000000000000_address};
inline const bytes init_codes[] = {bytes{}, bytes{0xFE}};
inline constexpr bytes32 salts[] = {
    0x00_bytes32, 0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0_bytes32};

TEST(state_new_account_address, create)
{
    for (const auto& ic : init_codes)  // Init-code doesn't affect CREATE.
    {
        auto s = senders[0];
        EXPECT_EQ(addr(s, nonces[0], {}, ic), 0xbd770416a3345f91e4b34576cb804a576fa48eb1_address);
        EXPECT_EQ(addr(s, nonces[3], {}, ic), 0x1262d73ea59d3a661bf8751d16cf1a5377149e75_address);

        s = senders[1];
        EXPECT_EQ(addr(s, nonces[0], {}, ic), 0x522b3294e6d06aa25ad0f1b8891242e335d3b459_address);
        EXPECT_EQ(addr(s, nonces[1], {}, ic), 0x535b3d7a252fa034ed71f0c53ec0c6f784cb64e1_address);
        EXPECT_EQ(addr(s, nonces[2], {}, ic), 0x09c1ef8f55c61b94e8b92a55d0891d408a991e18_address);
        EXPECT_EQ(addr(s, nonces[3], {}, ic), 0x001567239734aeadea21023c2a7c0d9bb9ae4af9_address);

        s = senders[2];
        EXPECT_EQ(addr(s, nonces[0], {}, ic), 0x3cb1045aee4a06f522ea2b69e4f3d21ed3c135d1_address);
        EXPECT_EQ(addr(s, nonces[3], {}, ic), 0xe1aa03e4a7b6991d69aff8ece53ceafdf347082e_address);

        const auto beacon_deposit_address =
            addr(0xb20a608c624Ca5003905aA834De7156C68b2E1d0_address, 0, {}, ic);
        EXPECT_EQ(beacon_deposit_address, 0x00000000219ab540356cbb839cbe05303d7705fa_address);
    }
}

TEST(state_new_account_address, create2)
{
    for (const auto n : nonces)  // Nonce doesn't affect CREATE2.
    {
        EXPECT_EQ(addr(senders[0], n, salts[0], init_codes[0]),
            0xe33c0c7f7df4809055c3eba6c09cfe4baf1bd9e0_address);

        EXPECT_EQ(addr(senders[2], n, salts[0], init_codes[1]),
            0x3517dea701ed18fc4a99dc111c5946e1f1541dad_address);

        EXPECT_EQ(addr(senders[1], n, salts[1], init_codes[0]),
            0x7be1c1cb3b8298f21c56add66defce03e2d32604_address);

        EXPECT_EQ(addr(senders[2], n, salts[1], init_codes[1]),
            0x8f459e65c8f00a9c0c0493de7b0c61c3c27f7384_address);
    }
}
