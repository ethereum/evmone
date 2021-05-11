// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <memory>

namespace evmone
{
class VMTracer;

class TracerListNode
{
    std::unique_ptr<VMTracer> m_next_tracer;

public:
    [[nodiscard]] VMTracer* get_next_tracer() const noexcept { return m_next_tracer.get(); }

    inline void add_tracer(std::unique_ptr<VMTracer> tracer) noexcept;
};

class VMTracer : public TracerListNode
{
public:
    virtual ~VMTracer() = default;

    void notify_execution_start() noexcept
    {
        onBeginExecution();
        if (auto* tracer = get_next_tracer())
            tracer->notify_execution_start();
    }

    void notify_execution_end() noexcept
    {
        onEndExecution();
        if (auto* tracer = get_next_tracer())
            tracer->notify_execution_end();
    }

    void notify_instruction_start(evmc_opcode opcode) noexcept
    {
        onOpcode(opcode);
        if (auto* tracer = get_next_tracer())
            tracer->notify_instruction_start(opcode);
    }

protected:
    virtual void onBeginExecution() noexcept = 0;
    virtual void onOpcode(evmc_opcode opcode) noexcept = 0;
    virtual void onEndExecution() noexcept = 0;
};

void TracerListNode::add_tracer(std::unique_ptr<VMTracer> tracer) noexcept
{
    if (m_next_tracer)
        m_next_tracer->add_tracer(std::move(tracer));
    else
        m_next_tracer = std::move(tracer);
}

/// The evmone EVMC instance.
class VM : public evmc_vm, TracerListNode
{
public:
    inline constexpr VM() noexcept;

    using TracerListNode::add_tracer;

    [[nodiscard]] VMTracer* get_tracer() const noexcept
    {
        return TracerListNode::get_next_tracer();
    }
};
}  // namespace evmone
