// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "execution.hpp"
#include "analysis.hpp"
#include "eof.hpp"
#include <memory>

namespace evmone
{
evmc_result execute(AdvancedExecutionState& state, const AdvancedCodeAnalysis& analysis) noexcept
{
    state.analysis.advanced = &analysis;  // Allow accessing the analysis by instructions.

    const auto* instr = &state.analysis.advanced->instrs[0];  // Start with the first instruction.
    while (instr != nullptr)
        instr = instr->fn(instr, state);

    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;

    return evmc::make_result(
        state.status, gas_left, state.memory.data() + state.output_offset, state.output_size);
}

evmc_result execute(evmc_vm* /*unused*/, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    AdvancedCodeAnalysis analysis;
    if (is_eof_code(code, code_size))
    {
        if (rev >= EVMC_SHANGHAI)
        {
            const auto eof1_header = read_valid_eof1_header(code);
            analysis = analyze(rev, code, eof1_header.code_begin(), eof1_header.code_end());
        }
        else
            // Skip analysis, because it will recognize 01 section id as OP_ADD and return
            // EVMC_STACKUNDERFLOW.
            return evmc::make_result(EVMC_UNDEFINED_INSTRUCTION, 0, nullptr, 0);
    }
    else
        analysis = analyze(rev, code, 0, code_size);
    auto state = std::make_unique<AdvancedExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return execute(*state, analysis);
}
}  // namespace evmone
