// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"

#include <ethash/keccak.hpp>
#include <evmc/helpers.hpp>
#include <evmc/instructions.h>

#include <fstream>
#include <mutex>
#include <numeric>

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
        if (instr.block_index >= 0)
        {
            auto& block = analysis.blocks[static_cast<size_t>(instr.block_index)];

            state.gas_left -= block.gas_cost;
            if (state.gas_left < 0)
            {
                state.status = EVMC_OUT_OF_GAS;
                break;
            }

            if (static_cast<int>(state.stack.size()) < block.stack_req)
            {
                state.status = EVMC_STACK_UNDERFLOW;
                break;
            }

            if (static_cast<int>(state.stack.size()) + block.stack_max > 1024)
            {
                state.status = EVMC_STACK_OVERFLOW;
                break;
            }

            state.max_stack_size = std::max(
                state.max_stack_size, static_cast<int>(state.stack.size()) + block.stack_max);

            state.current_block_cost = block.gas_cost;
        }

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

    static std::mutex mx;
    {
        auto lock = std::lock_guard{mx};

        static auto f = std::ofstream{"evmone-stats.csv", std::ios::out | std::ios::app};
        static int last_period_number;
        static std::vector<int> memory_sizes;
        static std::vector<int> stack_sizes;

        constexpr auto period_length = 1000;
        auto block_number = int(state.host.get_tx_context().block_number);
        auto period_number = block_number / period_length;
        if (period_number > last_period_number)
        {
            if (const auto s = stack_sizes.size(); s != 0)
            {
                std::sort(memory_sizes.begin(), memory_sizes.end());
                std::sort(stack_sizes.begin(), stack_sizes.end());
                auto total_memory =
                    std::accumulate(memory_sizes.begin(), memory_sizes.end(), int64_t{0});
                auto p = [s](int x) noexcept { return s * x / 1000; };
                auto start_block = last_period_number * period_length;
                auto end_block = start_block + period_length - 1;
                f << start_block << "," << end_block << "," << s << ",";
                f << total_memory << "," << memory_sizes[0] << "," << memory_sizes[p(1)] << ","
                  << memory_sizes[p(10)] << "," << memory_sizes[p(20)] << "," << memory_sizes[p(30)]
                  << "," << memory_sizes[p(50)] << "," << memory_sizes[p(500)] << ","
                  << memory_sizes[s - 1 - p(50)] << "," << memory_sizes[s - 1 - p(30)] << ","
                  << memory_sizes[s - 1 - p(20)] << "," << memory_sizes[s - 1 - p(10)] << ","
                  << memory_sizes[s - 1 - p(1)] << "," << memory_sizes[s - 1] << ",";
                f << stack_sizes[0] << "," << stack_sizes[p(1)] << "," << stack_sizes[p(10)] << ","
                  << stack_sizes[p(20)] << "," << stack_sizes[p(30)] << "," << stack_sizes[p(50)]
                  << "," << stack_sizes[p(500)] << "," << stack_sizes[s - 1 - p(50)] << ","
                  << stack_sizes[s - 1 - p(30)] << "," << stack_sizes[s - 1 - p(20)] << ","
                  << stack_sizes[s - 1 - p(10)] << "," << stack_sizes[s - 1 - p(1)] << ","
                  << stack_sizes[s - 1] << "\n";
                f << std::flush;

                memory_sizes.clear();
                stack_sizes.clear();

                last_period_number = period_number;
            }
        }

        memory_sizes.emplace_back(state.memory.size());
        stack_sizes.emplace_back(state.max_stack_size);
    }

    return result;
}
}  // namespace evmone
