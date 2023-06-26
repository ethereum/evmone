
#include "ripemd160.hpp"
#include <evmc/hex.hpp>
#include <gtest/gtest.h>

TEST(ripemd160, empty)
{
    uint8_t h[20];
    ripemd160(h, nullptr, 0);
    EXPECT_EQ(evmc::hex({h, sizeof(h)}), "9c1185a5c5e9fc54612808977ee8f548b2258d31");


    const std::string_view s = "The quick brown fox jumps over the lazy dog";
    ripemd160(h, (const uint8_t*)s.data(), s.size());
    EXPECT_EQ(evmc::hex({h, sizeof(h)}), "37f332f68db77bd9d7edd4969571ad671cf9dd3b");
}
