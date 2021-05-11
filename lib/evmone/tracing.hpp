// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/instructions.h>
#include <memory>

namespace evmone
{
class VMTracer
{
    friend class VM;  // Has access the the m_next_tracer to traverse the list forward.
    std::unique_ptr<VMTracer> m_next_tracer;

public:
    virtual ~VMTracer() = default;

    void notify_execution_start() noexcept  // NOLINT(misc-no-recursion)
    {
        onBeginExecution();
        if (m_next_tracer)
            m_next_tracer->notify_execution_start();
    }

    void notify_execution_end() noexcept  // NOLINT(misc-no-recursion)
    {
        onEndExecution();
        if (m_next_tracer)
            m_next_tracer->notify_execution_end();
    }

    void notify_instruction_start(evmc_opcode opcode) noexcept  // NOLINT(misc-no-recursion)
    {
        onOpcode(opcode);
        if (m_next_tracer)
            m_next_tracer->notify_instruction_start(opcode);
    }

private:
    virtual void onBeginExecution() noexcept = 0;
    virtual void onOpcode(evmc_opcode opcode) noexcept = 0;
    virtual void onEndExecution() noexcept = 0;
};

}  // namespace evmone
