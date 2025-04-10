// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone_precompiles/blake2b.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>
#include <array>
#include <cstring>

using evmone::crypto::blake2b_compress;

// Initialization Vector.
// https://datatracker.ietf.org/doc/html/rfc7693#appendix-C.2
constexpr std::array<uint64_t, 8> blake2b_iv{
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};

TEST(blake2b_compress, reference_test)
{
    // The reference test from the RFC.
    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    // with some extensions by modifying the "rounds" and "last" values.

    using evmone::test::hex;

    auto h_init = blake2b_iv;
    h_init[0] ^= 0x01010000 ^ /*outlen = */ 64;

    const std::string_view data = "abc";
    uint64_t m[16]{};
    std::memcpy(m, data.data(), data.size());

    const uint64_t t[2]{data.size(), 0};

    auto h = h_init;
    blake2b_compress(12, h.data(), m, t, true);
    EXPECT_EQ(hex({reinterpret_cast<const uint8_t*>(h.data()), sizeof(h)}),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

    // https://github.com/ethereum/tests/blob/v13.2/src/GeneralStateTestsFiller/stPreCompiledContracts/blake2BFiller.yml#L301-L302
    h = h_init;
    blake2b_compress(12, h.data(), m, t, false);
    EXPECT_EQ(hex({reinterpret_cast<const uint8_t*>(h.data()), sizeof(h)}),
        "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d28752"
        "98743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735");

    // https://github.com/ethereum/tests/blob/v13.2/src/GeneralStateTestsFiller/stPreCompiledContracts/blake2BFiller.yml#L268-L269
    h = h_init;
    blake2b_compress(0, h.data(), m, t, true);
    EXPECT_EQ(hex({reinterpret_cast<const uint8_t*>(h.data()), sizeof(h)}),
        "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
        "d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b");

    // this gives the same result because the xor zeros out the "last" flag
    h = h_init;
    blake2b_compress(0, h.data(), m, t, false);
    EXPECT_EQ(hex({reinterpret_cast<const uint8_t*>(h.data()), sizeof(h)}),
        "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
        "d282e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b");
}

TEST(blake2b_compress, null_input)
{
    std::array<uint64_t, 8> h{};
    const uint64_t t[2]{};

    // the data block is unused so be pass nullptr.
    blake2b_compress(0, h.data(), nullptr, t, false);

    // For null input you get the IV as the result.
    EXPECT_EQ(h, blake2b_iv);
}

TEST(blake2b_compress, big_rounds)
{
    static constexpr uint32_t ROUNDS = 10'000'000;
    uint64_t h[8]{};
    const uint64_t t[2]{};
    const uint64_t m[16]{};
    blake2b_compress(ROUNDS, h, m, t, false);
    EXPECT_EQ(h[0], 0xb6e24bc8cf57cc7a);
    EXPECT_EQ(h[7], 0x130a505b44404122);
}
