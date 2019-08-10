// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <benchmark/benchmark.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace
{
enum push_opcode
{
    PUSH1,
    PUSH2,
    PUSH3,
    PUSH4,
    PUSH5,
    PUSH6,
    PUSH7,
    PUSH8,
};
constexpr auto num_push_opcodes = PUSH8 + 1;

inline constexpr uint64_t load64be(const unsigned char* data) noexcept
{
    return uint64_t{data[7]} | (uint64_t{data[6]} << 8) | (uint64_t{data[5]} << 16) |
           (uint64_t{data[4]} << 24) | (uint64_t{data[3]} << 32) | (uint64_t{data[2]} << 40) |
           (uint64_t{data[1]} << 48) | (uint64_t{data[0]} << 56);
}

inline uint64_t load64be_fast(const unsigned char* data) noexcept
{
    uint64_t x;
    __builtin_memcpy(&x, data, sizeof(x));
    return __builtin_bswap64(x);
}


inline uint64_t orig(push_opcode opcode, const uint8_t*& code_pos, const uint8_t* code,
    const uint8_t* code_end) noexcept
{
    const auto code_size = size_t(code_end - code);
    const auto push_size = size_t(opcode - PUSH1 + 1);
    uint8_t data[8]{};

    const auto leading_zeros = 8 - push_size;
    const auto i = code_pos - code;
    for (size_t j = 0; j < push_size && (i + j) < code_size; ++j)
        data[leading_zeros + j] = code[i + j];
    code_pos += push_size;
    return load64be(data);
}

inline uint64_t orig_noend(
    push_opcode opcode, const uint8_t*& code_pos, const uint8_t* code, const uint8_t*) noexcept
{
    const auto push_size = size_t(opcode - PUSH1 + 1);
    uint8_t data[8]{};

    const auto leading_zeros = 8 - push_size;
    const auto i = code_pos - code;
    for (size_t j = 0; j < push_size; ++j)
        data[leading_zeros + j] = code[i + j];
    code_pos += push_size;
    return load64be(data);
}

inline uint64_t ptr_noend(
    push_opcode opcode, const uint8_t*& code_pos, const uint8_t*, const uint8_t*) noexcept
{
    const auto push_size = size_t(opcode - PUSH1 + 1);
    uint8_t data[8]{};
    const auto leading_zeros = 8 - push_size;
    auto d = &data[leading_zeros];

    auto p = code_pos;
    auto p_end = p + push_size;
    for (; p < p_end; ++d, ++p)
        *d = *p;
    code_pos = p;
    return load64be(data);
}

inline uint64_t ptr(
    push_opcode opcode, const uint8_t*& pos, const uint8_t*, const uint8_t* code_end) noexcept
{
    const auto push_size = size_t(opcode - PUSH1 + 1);

    uint8_t data[8]{};
    auto d = &data[8 - push_size];

    auto p = pos;
    auto p_end = p + push_size;


    if (__builtin_expect(code_end < p_end, false))
        pos = code_end;
    else
        for (; p < p_end; ++d, ++p)
            *d = *p;

    pos = p_end;

    return load64be_fast(data);
}

inline uint64_t ptr2(
    push_opcode opcode, const uint8_t*& pos, const uint8_t*, const uint8_t* code_end) noexcept
{
    const auto push_size = size_t(opcode - PUSH1 + 1);

    uint64_t value = 0;
    uint8_t* data = (uint8_t*)&value;
    auto d = &data[8 - push_size];

    auto p = pos;
    auto p_end = p + push_size;


    if (__builtin_expect(code_end < p_end, false))
        pos = code_end;
    else
        for (; p < p_end; ++d, ++p)
            *d = *p;

    pos = p_end;

    return __builtin_bswap64(value);
}

inline uint64_t memcpy(
    push_opcode opcode, const uint8_t*& code_pos, const uint8_t*, const uint8_t* code_end) noexcept
{
    const auto push_size = size_t(opcode - PUSH1 + 1);
    const auto push_begin = code_pos;
    const auto push_end = push_begin + push_size;

    uint64_t value = 0;
    uint8_t* data = (uint8_t*)&value;
    auto d = &data[sizeof(data) - push_size];

    if (__builtin_expect(code_end < push_end, false))
    {
        code_pos = code_end;
        return value;
    }

    std::memcpy(d, code_pos, push_size);

    code_pos += push_size;
    return __builtin_bswap64(value);
}

std::vector<uint8_t> gen_push_code_random(size_t num_instructions)
{
    std::mt19937_64 g{std::random_device{}()};

    const auto num_per_opcode = num_instructions / num_push_opcodes;
    std::vector<uint8_t> order;
    order.reserve(num_instructions);
    for (uint8_t op = PUSH1; op <= PUSH8; ++op)
        order.insert(order.end(), num_per_opcode, op);
    std::shuffle(order.begin(), order.end(), g);

    std::vector<uint8_t> code;
    for (auto op : order)
    {
        const auto data_size = op - PUSH1 + 1;
        code.emplace_back(op);
        std::generate_n(std::back_inserter(code), data_size, g);
    }

    return code;
}

constexpr auto num_instructions = 1000 * num_push_opcodes;
const auto push_code_random = gen_push_code_random(num_instructions);


template <decltype(orig) F>
void parse_push_data(benchmark::State& state)
{
    const auto code = push_code_random;
    const auto code_begin = code.data();
    const auto code_end = code_begin + code.size();

    int64_t num_instructions_processed = 0;
    for (auto _ : state)
    {
        for (auto pos = code_begin; pos < code_end;)
        {
            auto op = static_cast<push_opcode>(*pos++);
            const auto data = F(op, pos, code_begin, code_end);
            benchmark::DoNotOptimize(data);
        }
        num_instructions_processed += num_instructions;
    }

    state.counters["rate"] = benchmark::Counter(
        static_cast<double>(num_instructions_processed), benchmark::Counter::kIsRate);
}

template <decltype(orig) F>
void parse_push_data_switch(benchmark::State& state)
{
    const auto code = push_code_random;
    const auto code_begin = code.data();
    const auto code_end = code_begin + code.size();

    int64_t num_instructions_processed = 0;
    for (auto _ : state)
    {
        for (auto pos = code_begin; pos < code_end;)
        {
            uint64_t data;
            const auto op = static_cast<push_opcode>(*pos++);
            switch (op)
            {
            case PUSH1:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH2:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH3:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH4:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH5:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH6:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH7:
                data = F(op, pos, code_begin, code_end);
                break;
            case PUSH8:
                data = F(op, pos, code_begin, code_end);
                break;
            }
            benchmark::DoNotOptimize(data);
        }
        num_instructions_processed += num_instructions;
    }

    state.counters["rate"] = benchmark::Counter(
        static_cast<double>(num_instructions_processed), benchmark::Counter::kIsRate);
}


BENCHMARK_TEMPLATE(parse_push_data, orig);
BENCHMARK_TEMPLATE(parse_push_data, orig_noend);
BENCHMARK_TEMPLATE(parse_push_data, ptr_noend);
BENCHMARK_TEMPLATE(parse_push_data, ptr);
BENCHMARK_TEMPLATE(parse_push_data, ptr2);
BENCHMARK_TEMPLATE(parse_push_data, memcpy);
BENCHMARK_TEMPLATE(parse_push_data_switch, orig);
BENCHMARK_TEMPLATE(parse_push_data_switch, orig_noend);
BENCHMARK_TEMPLATE(parse_push_data_switch, ptr_noend);
BENCHMARK_TEMPLATE(parse_push_data_switch, ptr);
BENCHMARK_TEMPLATE(parse_push_data_switch, ptr2);
BENCHMARK_TEMPLATE(parse_push_data_switch, memcpy);
}  // namespace
