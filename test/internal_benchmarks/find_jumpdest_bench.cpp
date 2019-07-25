// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <benchmark/benchmark.h>
#include <array>

namespace
{
constexpr size_t jumpdest_map_size = 0x10000;

using jumpdest_t = std::pair<int, int>;
using jumpdest_map = std::array<jumpdest_t, jumpdest_map_size>;
using find_fn = int (*)(const jumpdest_map&, int) noexcept;

inline int linear(const jumpdest_map& map, int offset) noexcept
{
    for (const auto& d : map)
    {
        if (d.first == offset)
            return d.second;
    }
    return -1;
}

const auto map = []() noexcept {
    auto m = jumpdest_map{};
    for (int i = 0; i < static_cast<int>(m.size()); ++i)
        m[i] = {i, 2 * i};
    return m;
}();

template <find_fn F>
void find_jumpdest(benchmark::State& state)
{
    int niddle = 0x1234;
    benchmark::ClobberMemory();

    for (auto _ : state)
    {
        auto x = F(map, niddle);
        benchmark::DoNotOptimize(x);
    }
}

BENCHMARK_TEMPLATE(find_jumpdest, linear);

}  // namespace

BENCHMARK_MAIN();