// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmc/hex.hpp>
#include <evmone_precompiles/sha256.hpp>
#include <gtest/gtest.h>

using evmone::crypto::sha256;

TEST(sha256, test_vectors)
{
    // Some test vectors from https://www.di-mgt.com.au/sha_testvectors.html.

    const std::pair<std::string_view, std::string_view> test_cases[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };

    for (const auto& [input, expected_hash_hex] : test_cases)
    {
        std::byte hash[evmone::crypto::SHA256_HASH_SIZE];
        sha256(hash, reinterpret_cast<const std::byte*>(input.data()), input.size());
        const auto hash_hex = evmc::hex({reinterpret_cast<const uint8_t*>(hash), std::size(hash)});
        EXPECT_EQ(hash_hex, expected_hash_hex);
    }
}
