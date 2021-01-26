// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// @file
/// EVMC instance (class VM) and entry point of evmone is defined here.

#include "vm.hpp"
#include "baseline.hpp"
#include "execution.hpp"
#include <evmone/evmone.h>

#include "instruction_traits.hpp"
#include <evmc/instructions.h>
#include <cstdio>
#include <cstring>
#include <map>

namespace evmone
{
namespace
{
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

    void onOpcode(evmc_opcode opcode) noexcept final
    {
        std::puts(instr::traits[opcode].name);
        if (next_tracer)
            next_tracer->onOpcode(opcode);
    }

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

    void onOpcode(evmc_opcode opcode) noexcept final
    {
        ++opcode_counter[opcode];
        if (next_tracer)
            next_tracer->onOpcode(opcode);
    }

    void onEndExecution() noexcept final
    {
        std::puts("\nTotal:");
        for (const auto [opcode, count] : opcode_counter)
            printf("%s,%d\n", instr::traits[opcode].name, count);
        if (next_tracer)
            next_tracer->onEndExecution();
    }
};

void destroy(evmc_vm* vm) noexcept
{
    assert(vm != nullptr);
    delete static_cast<VM*>(vm);
}

constexpr evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept
{
    return EVMC_CAPABILITY_EVM1;
}

evmc_set_option_result set_option(evmc_vm* c_vm, char const* name, char const* value) noexcept
{
    assert(c_vm != nullptr);
    auto& vm = *static_cast<VM*>(c_vm);

    if (name[0] == 'O' && name[1] == '\0')
    {
        if (value[0] == '0' && value[1] == '\0')  // O=0
        {
            vm.execute = evmone::baseline::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        else if (value[0] == '2' && value[1] == '\0')  // O=2
        {
            vm.execute = evmone::execute;
            return EVMC_SET_OPTION_SUCCESS;
        }
        return EVMC_SET_OPTION_INVALID_VALUE;
    }
    else if (std::strcmp(name, "trace") == 0)
    {
        vm.tracer = std::make_unique<BasicTracer>(std::move(vm.tracer));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (std::strcmp(name, "histogram") == 0)
    {
        vm.tracer = std::make_unique<HistogramTracer>(std::move(vm.tracer));
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
