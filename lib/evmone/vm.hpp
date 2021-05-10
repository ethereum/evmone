// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <memory>

namespace evmone
{
class VMTracer
{
    std::unique_ptr<VMTracer> m_next_tracer;

public:
    virtual ~VMTracer() = default;

    void add_tracer(std::unique_ptr<VMTracer> tracer) noexcept
    {
        if (m_next_tracer)
            m_next_tracer->add_tracer(std::move(tracer));
        else
            m_next_tracer = std::move(tracer);
    }

    void notify_execution_start() noexcept
    {
        onBeginExecution();
        if (m_next_tracer)
            m_next_tracer->notify_execution_start();
    }

    void notify_execution_end() noexcept
    {
        onEndExecution();
        if (m_next_tracer)
            m_next_tracer->notify_execution_end();
    }

    void notify_instruction_start(evmc_opcode opcode) noexcept
    {
        onOpcode(opcode);
        if (m_next_tracer)
            m_next_tracer->notify_instruction_start(opcode);
    }

protected:
    virtual void onBeginExecution() noexcept = 0;
    virtual void onOpcode(evmc_opcode opcode) noexcept = 0;
    virtual void onEndExecution() noexcept = 0;
};

/// The evmone EVMC instance.
class VM : public evmc_vm
{
    std::unique_ptr<VMTracer> m_tracer;

public:
    inline constexpr VM() noexcept;

    [[nodiscard]] VMTracer* get_tracer() const noexcept { return m_tracer.get(); }

    void add_tracer(std::unique_ptr<VMTracer> tracer) noexcept
    {
        if (m_tracer)
            m_tracer->add_tracer(std::move(tracer));
        else
            m_tracer = std::move(tracer);
    }
};
}  // namespace evmone
