// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2024 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/lru_cache.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <numeric>
#include <random>

using evmone::LRUCache;

TEST(lru_cache, capacity1)
{
    LRUCache<char, int> c(1);
    c.put('a', 2);
    EXPECT_EQ(c.get('a'), 2);
}

TEST(lru_cache, not_found)
{
    LRUCache<char, int> c(1);
    EXPECT_EQ(c.get('a'), std::nullopt);
}

TEST(lru_cache, evict_capacity1)
{
    LRUCache<char, int> c(1);
    c.put('a', 2);
    c.put('b', 3);
    EXPECT_EQ(c.get('a'), std::nullopt);
    EXPECT_EQ(c.get('b'), 3);
}

TEST(lru_cache, double_evict_capacity1)
{
    LRUCache<char, int> c(1);
    c.put('a', 2);
    c.put('b', 3);
    c.put('c', 4);  // the second eviction works properly provided the list iterator has a valid key
    EXPECT_EQ(c.get('c'), 4);
}

TEST(lru_cache, evict_capacity3)
{
    LRUCache<char, int> c(3);
    c.put('a', 1);
    c.put('b', 2);
    c.put('c', 3);
    EXPECT_EQ(c.get('a'), 1);
    EXPECT_EQ(c.get('b'), 2);
    EXPECT_EQ(c.get('c'), 3);

    c.put('d', 4);
    EXPECT_EQ(c.get('a'), std::nullopt);
    EXPECT_EQ(c.get('b'), 2);
    EXPECT_EQ(c.get('c'), 3);
    EXPECT_EQ(c.get('d'), 4);
}

TEST(lru_cache, evict_get3)
{
    LRUCache<char, std::optional<int>> c(3);
    c.put('a', 1);
    c.put('b', 2);
    c.put('c', 3);
    EXPECT_EQ(*c.get('c'), 3);
    EXPECT_EQ(*c.get('b'), 2);
    EXPECT_EQ(*c.get('a'), 1);

    c.put('d', 4);
    EXPECT_EQ(c.get('c'), std::nullopt);
    EXPECT_EQ(*c.get('b'), 2);
    EXPECT_EQ(*c.get('a'), 1);
    EXPECT_EQ(*c.get('d'), 4);

    c.put('e', 5);
    EXPECT_EQ(c.get('c'), std::nullopt);
    EXPECT_EQ(c.get('b'), std::nullopt);
    EXPECT_EQ(*c.get('a'), 1);
    EXPECT_EQ(*c.get('d'), 4);
    EXPECT_EQ(*c.get('e'), 5);
}

TEST(lru_cache, update_capacity1)
{
    LRUCache<char, int> c(1);
    c.put('a', 1);
    c.put('a', 2);
    EXPECT_EQ(c.get('a'), 2);
}

TEST(lru_cache, update_first_capacity2)
{
    LRUCache<char, int> c(2);
    c.put('a', 1);
    c.put('a', 2);
    EXPECT_EQ(c.get('a'), 2);

    c.put('b', 2);
    EXPECT_EQ(c.get('a'), 2);
    EXPECT_EQ(c.get('b'), 2);
}

TEST(lru_cache, update_second_capacity2)
{
    LRUCache<char, int> c(2);
    c.put('a', 1);
    c.put('b', 2);
    c.put('b', 3);
    EXPECT_EQ(c.get('b'), 3);
    EXPECT_EQ(c.get('a'), 1);
}

TEST(lru_cache, update_evict_capacity2)
{
    LRUCache<char, int> c(2);
    c.put('a', 1);
    c.put('b', 2);
    EXPECT_EQ(c.get('a'), 1);
    EXPECT_EQ(c.get('b'), 2);

    c.put('a', 3);  // updates access for 'a'.
    c.put('c', 4);  // evicts 'b'.
    EXPECT_EQ(c.get('a'), 3);
    EXPECT_EQ(c.get('c'), 4);
}

TEST(lru_cache, update_evict_capacity3)
{
    LRUCache<char, int> c(3);
    c.put('a', 1);
    c.put('b', 2);
    c.put('a', 3);  // updates 'a' and its access.
    c.put('c', 4);
    c.put('e', 5);  // evicts 'b'.
    EXPECT_EQ(c.get('a'), 3);
    EXPECT_EQ(c.get('c'), 4);
    EXPECT_EQ(c.get('e'), 5);
}

TEST(lru_cache, update_full_evict_capacity3)
{
    LRUCache<char, int> c(3);
    c.put('a', 1);
    c.put('b', 2);
    c.put('c', 3);  // full
    c.put('b', 4);  // update 'b' and its access.
    c.put('e', 5);  // evicts 'a' → 'e'.
    c.put('f', 6);  // evicts 'c' → 'f'.
    EXPECT_EQ(c.get('f'), 6);
    EXPECT_EQ(c.get('e'), 5);
    EXPECT_EQ(c.get('b'), 4);
}

TEST(lru_cache, clear)
{
    LRUCache<char, int> c(2);
    c.put('a', 1);
    c.clear();
    EXPECT_EQ(c.get('a'), std::nullopt);
    c.put('b', 2);
    c.put('a', 3);
    c.clear();
    EXPECT_EQ(c.get('a'), std::nullopt);
    EXPECT_EQ(c.get('b'), std::nullopt);
    c.put('a', 4);
    EXPECT_EQ(c.get('a'), 4);
}

static auto get_rng()
{
    const auto seed = testing::UnitTest::GetInstance()->random_seed();
    return std::mt19937_64(static_cast<uint64_t>(seed));
}

template <typename T>
static std::vector<T> shuffled_values(size_t n, auto& rng)
{
    std::vector<T> values(n);
    std::iota(values.begin(), values.end(), 0);
    std::ranges::shuffle(values, rng);
    return values;
}

TEST(lru_cache, mass_put)
{
    static constexpr auto N = 100'000;
    auto rng = get_rng();
    const auto values = shuffled_values<int>(N, rng);

    LRUCache<int, int> c(N);
    for (const auto v : values)
        c.put(v, v);

    for (const auto v : values)
        EXPECT_EQ(*c.get(v), v);
}

TEST(lru_cache, mass_update)
{
    static constexpr auto N = 100'000;
    auto rng = get_rng();
    const auto values = shuffled_values<size_t>(N, rng);

    LRUCache<size_t, int> c(N);
    for (const auto v : values)
        c.put(v, 0);

    std::vector counts(N, 0);
    for (int i = 0; i < N; ++i)
    {
        const auto v = static_cast<size_t>(rng() % N);
        c.put(v, ++counts[v]);
    }

    for (const auto v : values)
        EXPECT_EQ(*c.get(v), counts[v]);
}

TEST(lru_cache, mass_put_over_capacity)
{
    static constexpr auto N = 100'000;
    auto rng = get_rng();
    const auto values = shuffled_values<int>(N, rng);

    LRUCache<int, int> c(N / 2);
    for (const auto v : values)
        c.put(v, v);

    // Expect the second half of the values to be in the cache.
    for (size_t i = N / 2; i < N; ++i)
        EXPECT_EQ(*c.get(values[i]), values[i]);
}
