// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2025 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmone/eof.hpp>
#include <test/utils/bytecode.hpp>

namespace
{
using namespace evmone::test;

const bytes max_code_sections = [] {
    auto eof_code_sections_1023 = eof_bytecode(jumpf(1));
    for (int i = 1; i < 1022; ++i)
        eof_code_sections_1023 =
            eof_code_sections_1023.code(jumpf(static_cast<uint16_t>(i + 1)), 0, 0x80, 0);

    auto eof_code_sections_1024 = eof_code_sections_1023;
    eof_code_sections_1023 = eof_code_sections_1023.code(OP_STOP, 0, 0x80, 0);
    eof_code_sections_1024 = eof_code_sections_1024.code(jumpf(1023), 0, 0x80, 0);
    eof_code_sections_1024 = eof_code_sections_1024.code(OP_STOP, 0, 0x80, 0);
    return eof_code_sections_1024;
}();

void eof_validation(benchmark::State& state, evmone::ContainerKind kind, const bytes& container)
{
    for (auto _ : state)
    {
        const auto res = evmone::validate_eof(EVMC_OSAKA, kind, container);
        if (res != evmone::EOFValidationError::success)
            state.SkipWithError(evmone::get_error_message(res).data());
    }

    using namespace benchmark;
    const auto total_size =
        static_cast<double>(state.iterations() * static_cast<IterationCount>(container.size()));
    state.counters["size"] = {static_cast<double>(container.size()), {}, Counter::kIs1024};
    state.counters["bytes_rate"] = {total_size, Counter::kIsRate, Counter::kIs1024};
    state.counters["gas_rate"] = {total_size / 16, Counter::kIsRate};
}

using enum evmone::ContainerKind;
BENCHMARK_CAPTURE(eof_validation, max_code_sections, runtime, max_code_sections)
    ->Unit(benchmark::kMicrosecond);
}  // namespace
