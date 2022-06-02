// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmc/hex.hpp>
#include <random>
#include <string_view>

namespace
{
constexpr auto max_size = 32 * 1024;
uint8_t sink[max_size];

[[gnu::noinline]] void evmc_from_hex(const char* in, const char* end, uint8_t* out)
{
    evmc::from_hex(in, end, out);
}

const int8_t unhex_table[256] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11,
    12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

// ASCII -> hex value << 4 (upper nibble)
const uint8_t unhex_table4[256] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 160, 176, 192, 208, 224, 240, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 160, 176, 192, 208, 224, 240, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

[[gnu::noinline]] void single_table_no_validation(const char* in, const char* end, uint8_t* out)
{
    while (in != end)
    {
        auto h = unhex_table[static_cast<uint8_t>(*in++)];
        auto l = unhex_table[static_cast<uint8_t>(*in++)];
        *out++ = static_cast<uint8_t>((h << 4) | l);
    }
}

[[gnu::noinline]] void double_table_no_validation(const char* in, const char* end, uint8_t* out)
{
    while (in != end)
    {
        auto h = unhex_table4[static_cast<uint8_t>(*in++)];
        auto l = unhex_table[static_cast<uint8_t>(*in++)];
        *out++ = static_cast<uint8_t>(h | l);
    }
}

[[gnu::noinline]] void single_table(const char* in, const char* end, uint8_t* out)
{
    while (true)
    {
        if (in == end) [[unlikely]]
            break;
        int h = unhex_table[static_cast<uint8_t>(*in++)];
        if (in == end) [[unlikely]]
            break;
        int l = unhex_table[static_cast<uint8_t>(*in++)];
        int r = (h << 4) | l;
        if (r < 0) [[unlikely]]
            break;
        *out++ = static_cast<uint8_t>(r);
    }
}

[[gnu::noinline]] void single_table_iter(const char* in, const char* end, uint8_t* out)
{
    auto size = static_cast<size_t>(end - in);
    size_t i = 0;
    while (true)
    {
        if (i >= size) [[unlikely]]
            break;
        int h = unhex_table[static_cast<uint8_t>(in[i])];
        ++i;
        if (i >= size) [[unlikely]]
            break;
        int l = unhex_table[static_cast<uint8_t>(in[i])];
        int r = (h << 4) | l;
        if (r < 0) [[unlikely]]
            break;
        *out++ = static_cast<uint8_t>(r);
        ++i;
    }
}


template <void (*F)(const char*, const char*, uint8_t*)>
void hex_decode(benchmark::State& state)
{
    const auto size = static_cast<size_t>(state.range(0));

    evmc::bytes data;
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe{
        static_cast<uint8_t>(std::random_device{}())};
    std::generate_n(std::back_inserter(data), size, std::ref(rbe));
    const auto hex = evmc::hex(data);

    const auto begin = hex.data();
    const auto end = begin + hex.size();
    F(begin, end, sink);
    if (evmc::bytes_view{sink, size} != data)
        return state.SkipWithError("wrong implementation");

    for (auto _ : state)
        F(begin, end, sink);

    state.SetBytesProcessed(static_cast<int64_t>(size * state.iterations()));
}

BENCHMARK_TEMPLATE(hex_decode, evmc_from_hex)->Range(32, max_size);
BENCHMARK_TEMPLATE(hex_decode, single_table_no_validation)->Range(32, max_size);
BENCHMARK_TEMPLATE(hex_decode, double_table_no_validation)->Range(32, max_size);
BENCHMARK_TEMPLATE(hex_decode, single_table)->Range(32, max_size);
BENCHMARK_TEMPLATE(hex_decode, single_table_iter)->Range(32, max_size);
}  // namespace
