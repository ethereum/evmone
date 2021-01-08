// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "execution.hpp"
#include "analysis.hpp"
#include <chrono>
#include <iostream>
#include <memory>

namespace evmone
{

evmc_result execute_measure_collective_time(const evmc_host_interface* host,
    evmc_host_context* ctx, evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto analysis = analyze(rev, code, code_size);

    auto state = std::make_unique<execution_state>(*msg, rev, *host, ctx, code, code_size);
    state->analysis = &analysis;

    const auto* instr = &state->analysis->instrs[0];
    std::chrono::steady_clock::time_point start_time, end_time;
    start_time = std::chrono::steady_clock::now();
    while (instr != nullptr)
        instr = instr->fn(instr, *state);
    end_time = std::chrono::steady_clock::now();
    std::chrono::nanoseconds elapsed_nanoseconds = end_time - start_time;
    std::cout << "Collective time: " << elapsed_nanoseconds.count() << std::endl;
    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(
        state->status, gas_left, &state->memory[state->output_offset], state->output_size);
}

evmc_result execute_measure_each_time(const evmc_host_interface* host, evmc_host_context* ctx, evmc_revision rev,
    const evmc_message* msg, const uint8_t* code, size_t code_size, unsigned int run_id) noexcept
{
    auto analysis = analyze(rev, code, code_size);

    auto state = std::make_unique<execution_state>(*msg, rev, *host, ctx, code, code_size);
    state->analysis = &analysis;

    const auto* instr = &state->analysis->instrs[0];
    unsigned int instruction_counter = 0;

    std::chrono::steady_clock::time_point start_time, end_time;
    start_time = std::chrono::steady_clock::now();
    while (instr != nullptr) {
        instr = instr->fn(instr, *state);
        end_time = std::chrono::steady_clock::now();
        std::chrono::nanoseconds elapsed_nanoseconds = end_time - start_time;
        std::cout << run_id << ","<< instruction_counter << "," << elapsed_nanoseconds.count() << "," << std::endl;
        ++instruction_counter;
        start_time = std::chrono::steady_clock::now();
    }
    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(
        state->status, gas_left, &state->memory[state->output_offset], state->output_size);
}

void print_opcode(const instruction* instr, const evmc_revision rev) {
    const auto& op_tbl = get_op_table(rev);
    unsigned int opcode = 0;
    while (instr->fn != op_tbl[opcode].fn) {
        ++opcode;
    }
    printf("%02X\n", opcode);
}

evmc_result execute_no_measure(const evmc_host_interface* host, evmc_host_context* ctx, evmc_revision rev,
  const evmc_message* msg, const uint8_t* code, size_t code_size, bool print_opcodes) noexcept
{
    auto analysis = analyze(rev, code, code_size);

    auto state = std::make_unique<execution_state>(*msg, rev, *host, ctx, code, code_size);
    state->analysis = &analysis;

    const auto* instr = &state->analysis->instrs[0];
    while (instr != nullptr) {
        if (print_opcodes)
            print_opcode(instr, rev);
        instr = instr->fn(instr, *state);
    }

    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(
        state->status, gas_left, &state->memory[state->output_offset], state->output_size);
}


evmc_result execute_measure_one_time(const evmc_host_interface* host, evmc_host_context* ctx, evmc_revision rev,
                                     const evmc_message* msg, const uint8_t* code, size_t code_size,
                                     unsigned int instruction_to_measure) noexcept
{
    auto analysis = analyze(rev, code, code_size);

    auto state = std::make_unique<execution_state>(*msg, rev, *host, ctx, code, code_size);
    state->analysis = &analysis;

    const auto* instr = &state->analysis->instrs[0];
    unsigned int instruction_counter = 1;
    while (instr != nullptr) {
        if (instruction_counter == instruction_to_measure) {
            std::chrono::steady_clock::time_point start_time, end_time;
            start_time = std::chrono::steady_clock::now();
            instr = instr->fn(instr, *state);
            end_time = std::chrono::steady_clock::now();
            std::chrono::nanoseconds elapsed_seconds = end_time - start_time;
            std::cout << "Instruction: "<< instruction_counter << ", time: " << elapsed_seconds.count() << std::endl;
        }
        else
            instr = instr->fn(instr, *state);
        ++instruction_counter;
    }
    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(
        state->status, gas_left, &state->memory[state->output_offset], state->output_size);
}


evmc_result execute(evmc_vm* /*unused*/, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size, unsigned int repeat,
    bool print_opcodes, bool measure_collective_time, bool measure_each_time,
    unsigned int instruction_to_measure) noexcept
{
    for (unsigned int run_id = 0; run_id < repeat; ++run_id) {
        if (measure_collective_time)
            execute_measure_collective_time(host, ctx, rev, msg, code, code_size);
        if (measure_each_time)
            execute_measure_each_time(host, ctx, rev, msg, code, code_size, run_id);
        if (instruction_to_measure)
            execute_measure_one_time(host, ctx, rev, msg, code, code_size, instruction_to_measure);
    }
    return execute_no_measure(host, ctx, rev, msg, code, code_size, print_opcodes);
}
}  // namespace evmone
