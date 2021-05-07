// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// @file
/// EVMC instance and entry point of evmone is defined here.
/// The file name matches the evmone.h public header.

#include "baseline.hpp"
#include "execution.hpp"
#include <evmone/evmone.h>

#include "instruction_traits.hpp"
#include <evmc/instructions.h>
#include <cstdio>
#include <cstring>
#include <map>

#include <intx/intx.hpp>
#include <iostream>

namespace evmone
{
namespace
{
struct EVMTracer : VMTracer
{
    uint64_t step_pc;
    std::string step_op_name;
    std::unique_ptr<VMTracer> next_tracer;

    EVMTracer(std::unique_ptr<VMTracer> _next_tracer = nullptr)
      : next_tracer{std::move(_next_tracer)}
    {}

    void onBeginExecution() noexcept final
    {
        if (next_tracer)
            next_tracer->onBeginExecution();
    }

    void onOpcodeBefore(evmc_opcode opcode, uint64_t pc) noexcept final
    {
        this->step_pc = pc;
        this->step_op_name = instr::traits[opcode].name;

        if (next_tracer)
            next_tracer->onOpcodeBefore(opcode, pc);
    }

    void onOpcodeAfter() noexcept final
    {
        std::cout << "{pc:" << this->step_pc << ", op:\"" << this->step_op_name.c_str() << "\"}\n";

        if (next_tracer)
            next_tracer->onOpcodeAfter();
    }

    void onEndExecution() noexcept final
    {
        if (next_tracer)
            next_tracer->onEndExecution();
    }
};

struct BasicTracer : VMTracer
{
    std::unique_ptr<VMTracer> next_tracer;

    BasicTracer(std::unique_ptr<VMTracer> _next_tracer = nullptr)
      : next_tracer{std::move(_next_tracer)}
    {}

    void onBeginExecution() noexcept final
    {
        if (next_tracer)
            next_tracer->onBeginExecution();
    }

    void onOpcodeBefore(evmc_opcode opcode, uint64_t pc) noexcept final
    {
        std::puts(instr::traits[opcode].name);
        if (next_tracer)
            next_tracer->onOpcodeBefore(opcode, pc);
    }

    void onOpcodeAfter() noexcept final {}

    void onEndExecution() noexcept final
    {
        if (next_tracer)
            next_tracer->onEndExecution();
    }
};

struct HistogramTracer : VMTracer
{
    std::unique_ptr<VMTracer> next_tracer;
    std::map<evmc_opcode, int> opcode_counter;

    HistogramTracer(std::unique_ptr<VMTracer> _next_tracer = nullptr)
      : next_tracer{std::move(_next_tracer)}
    {}

    void onBeginExecution() noexcept final
    {
        opcode_counter.clear();
        if (next_tracer)
            next_tracer->onBeginExecution();
    }

    void onOpcodeBefore(evmc_opcode opcode, uint64_t pc) noexcept final
    {
        ++opcode_counter[opcode];
        if (next_tracer)
            next_tracer->onOpcodeBefore(opcode, pc);
    }

    void onOpcodeAfter() noexcept final
    {
        if (next_tracer)
            next_tracer->onOpcodeAfter();
    }

    void onEndExecution() noexcept final
    {
        std::puts("\nHistogram:");
        int all = 0;
        for (const auto [opcode, count] : opcode_counter)
        {
            printf("%s,%d\n", instr::traits[opcode].name, count);
            all += count;
        }
        printf("all,%d\n", all);
        if (next_tracer)
            next_tracer->onEndExecution();
    }
};

void destroy(evmc_vm* vm) noexcept
{
    // TODO: Mark function with [[gnu:nonnull]] or add CHECK().
    delete static_cast<VM*>(vm);
}

constexpr evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept
{
    return EVMC_CAPABILITY_EVM1;
}

evmc_set_option_result set_option(evmc_vm* vm, char const* name, char const* value) noexcept
{
    if (name[0] == 'O' && name[1] == '\0')
    {
        if (value[0] == '0' && value[1] == '\0')  // O=0
        {
            vm->execute = evmone::baseline::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        else if (value[0] == '2' && value[1] == '\0')  // O=2
        {
            vm->execute = evmone::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        return EVMC_SET_OPTION_INVALID_VALUE;
    }
    else if (std::strcmp(name, "evmtrace") == 0)
    {
        auto& tracer = static_cast<VM*>(vm)->tracer;
        tracer = std::make_unique<EVMTracer>(std::move(tracer));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (std::strcmp(name, "basictrace") == 0)
    {
        auto& tracer = static_cast<VM*>(vm)->tracer;
        tracer = std::make_unique<BasicTracer>(std::move(tracer));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (std::strcmp(name, "histogram") == 0)
    {
        auto& tracer = static_cast<VM*>(vm)->tracer;
        tracer = std::make_unique<HistogramTracer>(std::move(tracer));
        return EVMC_SET_OPTION_SUCCESS;
    }
    return EVMC_SET_OPTION_INVALID_NAME;
}

}  // namespace


inline constexpr VM::VM() noexcept
  : evmc_vm{
        EVMC_ABI_VERSION,
        "evmone",
        PROJECT_VERSION,
        evmone::destroy,
        evmone::execute,
        evmone::get_capabilities,
        evmone::set_option,
    }
{}

}  // namespace evmone

extern "C" {
EVMC_EXPORT evmc_vm* evmc_create_evmone() noexcept
{
    return new evmone::VM{};
}
}
