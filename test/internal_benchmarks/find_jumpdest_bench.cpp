// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <benchmark/benchmark.h>
#include <array>

namespace
{
constexpr size_t jumpdest_map_size = 0x6000;

using jumpdest_t = std::pair<int, int>;
using jumpdest_map = std::array<jumpdest_t, jumpdest_map_size>;
using find_fn = int (*)(const jumpdest_t*, size_t, int) noexcept;

template <typename T>
inline T linear(const std::pair<T, T>* it, size_t size, T offset) noexcept
{
    for (const auto end = it + size; it != end; ++it)
    {
        if (it->first == offset)
            return it->second;
    }
    return T(-1);
}

template <typename T>
inline T lower_bound(const std::pair<T, T>* begin, size_t size, T offset) noexcept
{
    const auto end = begin + size;
    const auto it = std::lower_bound(
        begin, end, offset, [](std::pair<int, int> p, int v) noexcept { return p.first < v; });
    return (it != end && it->first == offset) ? it->second : T(-1);
}

template <typename T>
inline T binary_search(const std::pair<T, T>* arr, size_t size, T offset) noexcept
{
    int first = 0;
    int last = static_cast<int>(size) - 1;

    while (first <= last)
    {
        const auto middle = (first + last) / 2;
        const auto& e = arr[middle];
        if (e.first == offset)
            return e.second;
        else if (e.first < offset)
            first = middle + 1;
        else
            last = middle - 1;
    }
    return T(-1);
}

template <typename T>
inline T binary_search2(const std::pair<T, T>* first, size_t count, T offset) noexcept
{
    while (count > 0)
    {
        auto it = first;
        auto step = count / 2;
        it += step;
        if (it->first == offset)
            return it->second;
        else if (it->first < offset)
        {
            first = ++it;
            count -= step + 1;
        }
        else
            count = step;
    }

    return T(-1);
}

template <typename T>
struct map_builder
{
    static const std::array<std::pair<T, T>, jumpdest_map_size> map;
};

template <typename T>
const std::array<std::pair<T, T>, jumpdest_map_size> map_builder<T>::map = []() noexcept {
    auto m = std::array<std::pair<T, T>, jumpdest_map_size>{};
    for (int i = 0; i < static_cast<int>(m.size()); ++i)
        m[i] = {2 * i + 1, 2 * i + 2};
    return m;
}();

template <typename T, T (*F)(const std::pair<T, T>*, size_t, T) noexcept>
void find_jumpdest(benchmark::State& state)
{
    const auto& map = map_builder<T>::map;
    const auto begin = map.data();
    const auto size = state.range(0);
    const auto niddle = state.range(1);
    benchmark::ClobberMemory();

    int x = -1;
    for (auto _ : state)
    {
        x = F(begin, size, niddle);
        benchmark::DoNotOptimize(x);
    }

    if (niddle % 2 == 1)
    {
        if (x != niddle + 1)
            state.SkipWithError("incorrect element found");
    }
    else if (x != T(-1))
        state.SkipWithError("element should not have been found");
}

#define ARGS                             \
    ->Args({0, 0})                       \
        ->Args({3, 0})                   \
        ->Args({16, 0})                  \
        ->Args({256, 1})                 \
        ->Args({256, 255})               \
        ->Args({256, 511})               \
        ->Args({256, 0})                 \
        ->Args({jumpdest_map_size, 1})   \
        ->Args({jumpdest_map_size, 359}) \
        ->Args({jumpdest_map_size, 0})

BENCHMARK_TEMPLATE(find_jumpdest, int, linear) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, int, lower_bound) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, int, binary_search) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, int, binary_search2) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, uint16_t, linear) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, uint16_t, lower_bound) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, uint16_t, binary_search) ARGS;
BENCHMARK_TEMPLATE(find_jumpdest, uint16_t, binary_search2) ARGS;

}  // namespace

BENCHMARK_MAIN();