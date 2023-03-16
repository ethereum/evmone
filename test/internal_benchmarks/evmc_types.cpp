// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <array>
#include <random>

namespace
{
[[gnu::noinline]] auto noinline_eq(const evmc::address& a, const evmc::address& b) noexcept
{
    return a == b;
}
[[gnu::noinline]] auto noinline_eq(const evmc::bytes32& a, const evmc::bytes32& b) noexcept
{
    return a == b;
}
[[gnu::noinline]] auto noinline_lt(const evmc::address& a, const evmc::address& b) noexcept
{
    return a < b;
}
[[gnu::noinline]] auto noinline_lt(const evmc::bytes32& a, const evmc::bytes32& b) noexcept
{
    return a < b;
}
[[gnu::noinline]] auto noinline_le(const evmc::address& a, const evmc::address& b) noexcept
{
    return a <= b;
}
[[gnu::noinline]] auto noinline_le(const evmc::bytes32& a, const evmc::bytes32& b) noexcept
{
    return a <= b;
}

template <typename T>
inline auto hash(const T& a) noexcept
{
    return std::hash<T>{}(a);
}
template <typename T>
[[gnu::noinline]] auto noinline_hash(const T& a) noexcept
{
    return std::hash<T>{}(a);
}


constexpr size_t num_operations = 1024;
constexpr size_t num_samples = num_operations + 1;
auto rng = std::mt19937{std::random_device{}()};

template <typename T>
std::array<T, num_samples> generate_samples()
{
    std::array<T, num_samples> samples;
    for (auto& sample : samples)
    {
        for (auto& b : sample.bytes)
            b = static_cast<uint8_t>(rng());
    }
    return samples;
}


template <typename T, bool (*Op)(const T&, const T&) noexcept>
void compare(benchmark::State& state)
{
    const auto samples = generate_samples<T>();

    int accumulator = 0;
    for (auto _ : state)
    {
#pragma nounroll
        for (size_t i = 0; i < num_operations; ++i)
        {
            accumulator += Op(samples[i], samples[i + 1]);
        }
    }
    benchmark::DoNotOptimize(accumulator);
}

template <typename T, bool (*Op)(const T&, const T&) noexcept>
void compare_zero1(benchmark::State& state)
{
    static constexpr auto zero = T{};
    const auto samples = generate_samples<T>();

    int accumulator = 0;
    for (auto _ : state)
    {
#pragma nounroll
        for (size_t i = 0; i < num_operations; ++i)
        {
            accumulator += Op(zero, samples[i]);
        }
    }
    benchmark::DoNotOptimize(accumulator);
}

template <typename T, bool (*Op)(const T&, const T&) noexcept>
void compare_zero2(benchmark::State& state)
{
    static constexpr auto zero = T{};
    const auto samples = generate_samples<T>();

    int accumulator = 0;
    for (auto _ : state)
    {
#pragma nounroll
        for (size_t i = 0; i < num_operations; ++i)
        {
            accumulator += Op(samples[i], zero);
        }
    }
    benchmark::DoNotOptimize(accumulator);
}

BENCHMARK_TEMPLATE(compare, evmc::address, evmc::operator==);
BENCHMARK_TEMPLATE(compare, evmc::address, noinline_eq);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, evmc::operator==);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, noinline_eq);
BENCHMARK_TEMPLATE(compare, evmc::address, evmc::operator<);
BENCHMARK_TEMPLATE(compare, evmc::address, noinline_lt);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, evmc::operator<);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, noinline_lt);
BENCHMARK_TEMPLATE(compare, evmc::address, evmc::operator<=);
BENCHMARK_TEMPLATE(compare, evmc::address, noinline_le);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, evmc::operator<=);
BENCHMARK_TEMPLATE(compare, evmc::bytes32, noinline_le);

BENCHMARK_TEMPLATE(compare_zero1, evmc::address, evmc::operator==);
BENCHMARK_TEMPLATE(compare_zero1, evmc::address, noinline_eq);
BENCHMARK_TEMPLATE(compare_zero1, evmc::bytes32, evmc::operator==);
BENCHMARK_TEMPLATE(compare_zero1, evmc::bytes32, noinline_eq);
BENCHMARK_TEMPLATE(compare_zero1, evmc::address, evmc::operator<);
BENCHMARK_TEMPLATE(compare_zero1, evmc::address, noinline_lt);
BENCHMARK_TEMPLATE(compare_zero1, evmc::bytes32, evmc::operator<);
BENCHMARK_TEMPLATE(compare_zero1, evmc::bytes32, noinline_lt);
BENCHMARK_TEMPLATE(compare_zero2, evmc::address, evmc::operator<=);
BENCHMARK_TEMPLATE(compare_zero2, evmc::address, noinline_le);
BENCHMARK_TEMPLATE(compare_zero2, evmc::bytes32, evmc::operator<=);
BENCHMARK_TEMPLATE(compare_zero2, evmc::bytes32, noinline_le);


template <typename T, size_t (*HashFn)(const T&) noexcept>
void hash_(benchmark::State& state)
{
    const auto samples = generate_samples<T>();

    size_t accumulator = 0;
    for (auto _ : state)
    {
        for (size_t i = 0; i < num_operations; ++i)
        {
            accumulator |= HashFn(samples[i]);
        }
    }
    benchmark::DoNotOptimize(accumulator);
}

BENCHMARK_TEMPLATE(hash_, evmc::bytes32, hash<evmc::bytes32>);
BENCHMARK_TEMPLATE(hash_, evmc::bytes32, noinline_hash<evmc::bytes32>);
BENCHMARK_TEMPLATE(hash_, evmc::address, hash<evmc::address>);
BENCHMARK_TEMPLATE(hash_, evmc::address, noinline_hash<evmc::address>);

}  // namespace
