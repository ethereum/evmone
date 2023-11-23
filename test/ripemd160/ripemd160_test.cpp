
#include "ripemd160.hpp"
#include <evmc/hex.hpp>
#include <gtest/gtest.h>

TEST(ripemd160, test_vectors)
{
    // From https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

    struct TestCase
    {
        std::string input;
        std::string_view hash_hex;
    };

    const TestCase test_cases[] = {
        {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
        {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
        {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
        {"The quick brown fox jumps over the lazy dog", "37f332f68db77bd9d7edd4969571ad671cf9dd3b"},
    };

    for (const auto& t : test_cases)
    {
        uint8_t hash[20];
        ripemd160(hash, reinterpret_cast<const uint8_t*>(t.input.data()), t.input.size());
        EXPECT_EQ(evmc::hex({hash, std::size(hash)}), t.hash_hex);
    }
}


TEST(ripemd160, input_length)
{
    struct TestCase
    {
        std::size_t input_length;
        std::string_view hash_hex;
    };

    const TestCase test_cases[] = {
        {0, "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
        {1, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
        {55, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"},
        {56, "e72334b46c83cc70bef979e15453706c95b888be"},  // length fits into the first block
        {57, "eed82d19d597ab275b550ff3d6e0bc2a75350388"},
        {63, "e640041293fe663b9bf3f8c21ffecac03819e6b2"},
        {64, "9dfb7d374ad924f3f88de96291c33e9abed53e32"},  // full block
        {65, "99724bb11811e7166af38f671b6a082d8ab4960b"},
        {119, "23e398ff2bac815aa1bbb57ca2a669c841872919"},
        {120, "c476770a6dae31fcee8d25efe6559a05c8024595"},
        {121, "725c88a6f41605e99477a1478607d3fe25ced606"},
        {127, "64f2d68b85f394e2e4f49009c4bd50224c2698ed"},
        {128, "8dfdfb32b2ed5cb41a73478b4fd60cc5b4648b15"},  // two blocks
        {129, "62bb9091f499f294f15aa5b951df4d9744d50cf2"},
        {1'000'000, "52783243c1697bdbe16d37f97f68f08325dc1528"},
        {536'870'912, "2d253ceb06fb13e1fa3c7756e37bb5562b1bf3ba"},  // length overflows uint32
    };

    for (const auto& t : test_cases)
    {
        std::string input(t.input_length, 'a');
        uint8_t hash[20];
        ripemd160(hash, reinterpret_cast<const uint8_t*>(input.data()), input.size());
        EXPECT_EQ(evmc::hex({hash, std::size(hash)}), t.hash_hex) << t.input_length;
    }
}

// TODO: More tests: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
