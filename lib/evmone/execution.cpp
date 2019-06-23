// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

namespace evmone
{
extern const exec_fn_table op_table[];

evmc_result execute(evmc_instance*, evmc_context* ctx, evmc_revision rev, const evmc_message* msg,
    const uint8_t* code, size_t code_size) noexcept
{
    auto analysis = analyze(op_table[rev], rev, code, code_size);

    execution_state state;
    state.analysis = &analysis;
    state.msg = msg;
    state.code = code;
    state.code_size = code_size;
    state.host = evmc::HostContext{ctx};
    state.gas_left = msg->gas;
    state.rev = rev;
    while (state.run)
    {
        auto& instr = analysis.instrs[state.pc];

        // Advance the PC not to allow jump opcodes to overwrite it.
        ++state.pc;

        instr.fn(state, instr.arg);
    }

    evmc_result result{};
    result.status_code = state.status;
    if (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
        result.gas_left = state.gas_left;

    if (state.output_size > 0)
    {
        result.output_size = state.output_size;
        auto output_data = static_cast<uint8_t*>(std::malloc(result.output_size));
        std::memcpy(output_data, &state.memory[state.output_offset], result.output_size);
        result.output_data = output_data;
        result.release = [](const evmc_result* r) noexcept
        {
            std::free(const_cast<uint8_t*>(r->output_data));
        };
    }

    return result;
}
}  // namespace evmone
