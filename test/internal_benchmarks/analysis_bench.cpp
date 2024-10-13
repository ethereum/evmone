// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evmone/baseline.hpp"
#include "test/experimental/jumpdest_analysis.hpp"
#include "test/utils/utils.hpp"
#include "test_bytecodes.hpp"
#include <benchmark/benchmark.h>
#include <numeric>

#include <evmc/hex.hpp>
#include <cstring>
#include <iostream>

using namespace evmone::test;


namespace
{


enum : uint8_t
{
    OP_JUMPDEST = 0x5b,
    OP_PUSH1 = 0x60,
    OP_PUSH32 = 0x7f,
};

[[gnu::noinline]] auto build_bitset2(const uint8_t* code, size_t code_size)
{
    evmone::exp::jda::JumpdestMap m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (op == OP_JUMPDEST)
            m[i] = true;

        if ((op >> 5) == 0b11)
            i += static_cast<size_t>((op & 0b11111) + 1);
    }
    return m;
}

[[gnu::noinline]] auto build_vec(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
        else if (op >= OP_PUSH1 && op <= OP_PUSH32)
            i += static_cast<size_t>(op - OP_PUSH1 + 1);
    }
    return m;
}

inline bool is_push(uint8_t op)
{
    //    return op >= OP_PUSH1 && op <= OP_PUSH32;
    // return (op >> 5) == 0b11;
    return (op & uint8_t{0b11100000}) == 0b01100000;
}

// [[maybe_unused]] bool x = []() noexcept {
//     size_t last_push = size_t(-1);
//     std::vector<int> dists;
//     for (size_t i = 0; i < test_bytecode.size();)
//     {
//         const auto op = test_bytecode[i];
//
//         if (is_push(op))
//         {
//             if (last_push != size_t(-1))
//                 dists.push_back(static_cast<int>(i - last_push));
//             last_push = i;
//         }
//
//         i += is_push(op) ? static_cast<size_t>(op - OP_PUSH1 + 2) : 1;
//     }
//
//     auto sum = std::accumulate(dists.begin(), dists.end(), 0);
//     std::sort(dists.begin(), dists.end());
//
//     std::cerr << "AVG: " << double(sum) / double(dists.size()) << "\n";
//     std::cerr << "MED: " << dists[dists.size() / 2] << "\n";
//
//     int last = 0;
//     int count = 0;
//     for (auto d : dists)
//     {
//         if (d == last)
//             ++count;
//         else
//         {
//             std::cerr << last << " x" << count << "\n";
//             count = 1;
//             last = d;
//         }
//     }
//     return true;
// }();

[[gnu::noinline]] auto build_vec3(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size;)
    {
        const auto op = code[i];
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;

        i += is_push(op) ? static_cast<size_t>(op - OP_PUSH1 + 2) : 1;
    }
    return m;
}

[[gnu::noinline]] auto build_vec4(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    const auto code_beg = code;
    const auto code_end = code + code_size;
    for (; code < code_end; ++code)
    {
        const auto op = *code;
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[size_t(code - code_beg)] = true;
        else if (is_push(op))
            code += static_cast<size_t>(op - OP_PUSH1 + 1);
    }
    return m;
}

[[gnu::noinline]] auto build_vec5(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        const auto s = size_t(op - OP_PUSH1);
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
        else if (s <= 31)
            i += s + 1;
    }
    return m;
}

[[gnu::noinline]] auto build_vec6(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size;)
    {
        const auto op = code[i];
        const auto s = size_t(op - OP_PUSH1);
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;

        i += (s <= 31) ? s + 1 : 1;
    }
    return m;
}

[[gnu::noinline]] auto build_vec7(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size;)
    {
        const auto op = code[i];
        const auto s = size_t(op - OP_PUSH1);
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;

        const auto a = (s <= 31) ? s : 0;

        i += a + 1;
    }
    return m;
}

[[gnu::noinline]] auto build_bytes(const uint8_t* code, size_t code_size)
{
    std::vector<uint8_t> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (__builtin_expect(op == OP_JUMPDEST, false))
            m[i] = true;
        else if (op >= OP_PUSH1 && op <= OP_PUSH32)
            i += static_cast<size_t>(op - OP_PUSH1 + 1);
    }
    return m;
}

[[gnu::noinline]] auto build_shadow_code2p(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + 32]};
    long push_data = 0;
    auto p = m.get();
    const auto end = p + code_size;
    while (p != end)
    {
        const auto op = *code;
        *p = push_data <= 0 ? op : 0;
        --push_data;
        if (op >= OP_PUSH1 && op <= OP_PUSH32)
            push_data = op - OP_PUSH1 + 1;
        ++p;
        ++code;
    }
    return m;
}

[[gnu::noinline]] auto build_shadow_code3p(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + 32]};
    std::memcpy(m.get(), code, code_size);
    auto p = m.get();
    const auto end = p + code_size;
    while (p < end)
    {
        const auto op = *p++;
        if ((op >> 5) == 0b11)
        {
            const size_t s = (op & 0b11111);
            std::memset(p, 0, s + 1);
            p += s;
        }
    }
    return m;
}

[[gnu::noinline]] auto build_shadow_code4(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + 33]};
    std::memcpy(m.get(), code, code_size);
    long push_data = 0;
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = m[i];
        bool is_push_data = push_data > 0;
        --push_data;
        if (!is_push_data && (op >> 5) == 0b11)
        {
            push_data = op - OP_PUSH1 + 1;
        }
        else if (is_push_data && op == OP_JUMPDEST)
        {
            m[i] = 0;
        }
    }
    return m;
}

[[gnu::noinline]] auto copy_by1(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + 32]};
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        m[i] = op;
    }
    return m;
}

#pragma GCC push_options
#pragma GCC optimize("no-tree-loop-distribute-patterns")
[[gnu::noinline]] auto copy_by1p(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + 32]};
    auto p = m.get();
    const auto end = p + code_size;
    while (p != end)
        *p++ = *code++;
    return m;
}
#pragma GCC pop_options

[[gnu::noinline]] auto memcpy(const uint8_t* code, size_t code_size)
{
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size]};
    std::memcpy(m.get(), code, code_size);
    return m;
}

template <typename MapT, MapT Fn(const uint8_t*, size_t)>
void build_jumpdest(benchmark::State& state)
{
    const bytes_view code = test_bytecodes[static_cast<size_t>(state.range(0))];
    for (auto _ : state)
    {
        auto r = Fn(code.data(), code.size());
        benchmark::DoNotOptimize(r);
    }

    using namespace benchmark;
    state.counters["bytes"] = {
        static_cast<double>(static_cast<IterationCount>(code.size()) * state.iterations()),
        Counter::kIsRate};
    state.counters["size"] = {static_cast<double>(static_cast<IterationCount>(code.size()))};
}

using namespace evmone;
using namespace evmone::exp::jda;
using namespace benchmark;

template <typename ResultT, ResultT AnalyzeFn(bytes_view)>
void jumpdest_analysis(State& state)
{
    const bytes_view code = test_bytecodes[static_cast<size_t>(state.range(0))];
    for (auto _ : state)
    {
        auto r = AnalyzeFn(code);
        DoNotOptimize(r);
    }

    state.counters["rate"] = {
        static_cast<double>(static_cast<IterationCount>(code.size()) * state.iterations()),
        Counter::kIsRate};
    state.counters["size"] = {static_cast<double>(static_cast<IterationCount>(code.size()))};
}

}  // namespace

#define ARGS ->DenseRange(0, test_bytecodes.size() - 1)

BENCHMARK(jumpdest_analysis<JumpdestBitset, reference>) ARGS;
BENCHMARK(jumpdest_analysis<JumpdestBitset, build_jumpdest_map_sttni>) ARGS;
BENCHMARK(jumpdest_analysis<JumpdestBitset, speculate_push_data_size>) ARGS;
BENCHMARK(jumpdest_analysis<JumpdestBitset, jda_speculate_push_data_size2>) ARGS;

BENCHMARK_TEMPLATE(
    build_jumpdest, evmone::exp::jda::JumpdestMap, evmone::exp::jda::build_jumpdest_map_bitset1)
ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, evmone::exp::jda::JumpdestMap, build_bitset2) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, evmone::exp::jda::build_jumpdest_map_str_avx2)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::vector<bool>, evmone::exp::jda::build_jumpdest_map_str_avx2_mask)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::vector<bool>, evmone::exp::jda::build_jumpdest_map_str_avx2_mask_v2)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::vector<bool>, evmone::exp::jda::build_jumpdest_map_str_avx2_mask2)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, evmone::exp::jda::bitset32, evmone::exp::jda::build_jumpdest_map_simd1)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, evmone::exp::jda::bitset32, evmone::exp::jda::build_jumpdest_map_simd2)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, evmone::exp::jda::bitset32, evmone::exp::jda::build_jumpdest_map_simd3)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, evmone::exp::jda::bitset32, evmone::exp::jda::build_jumpdest_map_simd4)
ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec3) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec4) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec5) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec6) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<bool>, build_vec7) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::vector<uint8_t>, build_bytes) ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::unique_ptr<uint8_t[]>, evmone::exp::jda::build_internal_code_v1)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::unique_ptr<uint8_t[]>, evmone::exp::jda::build_internal_code_v2)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::unique_ptr<uint8_t[]>, evmone::exp::jda::build_internal_code_v3)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::unique_ptr<uint8_t[]>, evmone::exp::jda::build_internal_code_v4)
ARGS;
BENCHMARK_TEMPLATE(
    build_jumpdest, std::unique_ptr<uint8_t[]>, evmone::exp::jda::build_internal_code_v8)
ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, build_shadow_code2p) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, build_shadow_code3p) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, build_shadow_code4) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, copy_by1) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, copy_by1p) ARGS;
BENCHMARK_TEMPLATE(build_jumpdest, std::unique_ptr<uint8_t[]>, memcpy) ARGS;
